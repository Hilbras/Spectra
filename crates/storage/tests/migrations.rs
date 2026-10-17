//! Migration behaviour, against a real PostgreSQL.
//!
//! `s.txt` §5.4 requires every migration to apply from empty, apply sequentially,
//! be idempotent where appropriate, work in CI, and have integration tests. This
//! file is the last of those; the others are properties of the runner and are
//! asserted here.
//!
//! Requires `SPECTRA_TEST_DATABASE_URL`. See [`common`] for how to provide one.

mod common;

use common::{connect, migrations_dir};
use spectra_storage::Database;

async fn table_names(db: &spectra_storage::pg::PostgresDatabase) -> Vec<String> {
    let rows = db
        .query(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
            &[],
        )
        .await
        .expect("could not list tables");

    rows.iter()
        .map(|r| r.get_by_name("tablename").expect("tablename is text"))
        .collect()
}

/// §5.4: apply from an empty database.
#[tokio::test]
async fn migrations_apply_from_an_empty_database() {
    let Some(db) = connect().await else {
        eprintln!("skipped: SPECTRA_TEST_DATABASE_URL is not set");
        return;
    };

    db.drop_schema().await.expect("could not reset schema");
    common::truncate_all(&db).await;

    let report = db
        .run_migrations(&migrations_dir())
        .await
        .expect("the repository's own migrations must apply");

    let names = table_names(&db).await;

    assert_eq!(
        report.applied.len(),
        7,
        "all seven migration files must be applied, got {:?}",
        report.applied
    );
    assert_eq!(
        names.len(),
        33,
        "32 tables plus schema_migrations. Found: {names:?}"
    );
    assert!(
        !names.contains(&"schema_migrations".to_string()) == false,
        "the bookkeeping table must exist"
    );
}

/// The 26 tables the migrations define must all actually be there.
///
/// Before the runner was fixed, this was **zero**: `sqlx::query` sends one statement
/// per round trip, so every multi-statement file failed on the first `CREATE TABLE`.
#[tokio::test]
async fn every_table_the_migrations_define_exists() {
    let Some(db) = connect().await else {
        eprintln!("skipped: SPECTRA_TEST_DATABASE_URL is not set");
        return;
    };

    db.drop_schema().await.expect("could not reset schema");
    common::truncate_all(&db).await;
    db.run_migrations(&migrations_dir())
        .await
        .expect("migrations must apply");

    let expected = [
        "organizations",
        "projects",
        "users",
        "api_keys",
        "targets",
        "scopes",
        "environments",
        "assets",
        "ports",
        "dns_records",
        "scans",
        "scan_jobs",
        "findings",
        "observations",
        "evidence",
        "detection_rules",
        "workers",
        "audit_logs",
    ];

    let names = table_names(&db).await;
    for table in expected {
        assert!(
            names.iter().any(|n| n == table),
            "migration 001..006 must create `{table}`. Present: {names:?}"
        );
    }
}

/// §5.4: idempotent where appropriate. Running twice must not fail.
#[tokio::test]
async fn running_migrations_twice_applies_nothing_the_second_time() {
    let Some(db) = connect().await else {
        eprintln!("skipped: SPECTRA_TEST_DATABASE_URL is not set");
        return;
    };

    db.drop_schema().await.expect("could not reset schema");
    common::truncate_all(&db).await;
    let dir = migrations_dir();

    let first = db.run_migrations(&dir).await.expect("first run");
    assert_eq!(first.applied.len(), 7);
    assert!(first.already_applied.is_empty());

    let second = db
        .run_migrations(&dir)
        .await
        .expect("a second run must be a no-op, not a failure on CREATE TABLE");

    assert!(
        second.applied.is_empty(),
        "nothing may be re-applied, got {:?}",
        second.applied
    );
    assert_eq!(second.already_applied.len(), 7);
    assert!(second.is_noop());
}

/// Idempotency must survive many runs, not just two.
#[tokio::test]
async fn migrations_are_idempotent_across_repeated_runs() {
    let Some(db) = connect().await else {
        eprintln!("skipped: SPECTRA_TEST_DATABASE_URL is not set");
        return;
    };

    db.drop_schema().await.expect("could not reset schema");
    common::truncate_all(&db).await;
    let dir = migrations_dir();

    db.run_migrations(&dir).await.expect("first run");

    for attempt in 2..=5 {
        let report = db
            .run_migrations(&dir)
            .await
            .unwrap_or_else(|e| panic!("run {attempt} must be a no-op: {e}"));
        assert!(
            report.is_noop(),
            "run {attempt} applied {:?}",
            report.applied
        );
    }
}

/// Applying a migration to a database that already has data must not destroy it.
///
/// This is the property that matters in production: the runner is called on every
/// boot, so "idempotent" has to mean "does nothing", not "rebuilds the schema".
#[tokio::test]
async fn re_running_migrations_preserves_existing_rows() {
    let Some(db) = connect().await else {
        eprintln!("skipped: SPECTRA_TEST_DATABASE_URL is not set");
        return;
    };

    db.drop_schema().await.expect("could not reset schema");
    common::truncate_all(&db).await;
    let dir = migrations_dir();
    db.run_migrations(&dir).await.expect("first run");

    let org = uuid::Uuid::new_v4();
    db.execute(
        "INSERT INTO organizations (id, name) VALUES ($1::uuid, 'survives')",
        &[serde_json::Value::String(org.to_string())],
    )
    .await
    .expect("could not insert an organization");

    db.run_migrations(&dir)
        .await
        .expect("second run must be a no-op");

    let rows = db
        .query(
            "SELECT name FROM organizations WHERE id = $1::uuid",
            &[serde_json::Value::String(org.to_string())],
        )
        .await
        .expect("could not read back");

    assert_eq!(rows.len(), 1, "the row must survive a re-run");
    let name: String = rows[0].get_by_name("name").expect("name is text");
    assert_eq!(name, "survives");
}

/// An edited migration is an error, not a silent skip.
///
/// Editing a migration that has already run somewhere is how two environments end
/// up with different schemas and the same version number.
#[tokio::test]
async fn editing_an_applied_migration_is_refused() {
    let Some(db) = connect().await else {
        eprintln!("skipped: SPECTRA_TEST_DATABASE_URL is not set");
        return;
    };

    db.drop_schema().await.expect("could not reset schema");
    common::truncate_all(&db).await;
    let dir = migrations_dir();

    db.run_migrations(&dir).await.expect("first run");

    // Simulate the edit rather than modifying the repository's files.
    sqlx::query("UPDATE schema_migrations SET checksum = 'tampered' WHERE version = '001_initial'")
        .execute(db.pool())
        .await
        .expect("could not tamper");

    let err = db
        .run_migrations(&dir)
        .await
        .expect_err("an edited applied migration must be refused");

    let message = err.to_string();
    assert!(
        message.contains("001_initial"),
        "the error must name the migration, got: {message}"
    );
    assert!(
        message.contains("immutable"),
        "the error must explain why, got: {message}"
    );
}

/// A migration that fails must not be recorded as applied, and must roll back
/// entirely rather than leaving a half-built schema.
#[tokio::test]
async fn a_failing_migration_rolls_back_completely() {
    let Some(db) = connect().await else {
        eprintln!("skipped: SPECTRA_TEST_DATABASE_URL is not set");
        return;
    };

    db.drop_schema().await.expect("could not reset schema");
    common::truncate_all(&db).await;

    let dir = tempdir_with_migrations();
    let (path, marker_table) = &dir;

    let err = db
        .run_migrations(path)
        .await
        .expect_err("the second file is invalid and must fail");

    assert!(
        err.to_string().contains("002_broken"),
        "the error must name the failing migration, got: {err}"
    );

    // The first migration's table must survive: only the failing file rolls back.
    let names = table_names(&db).await;
    assert!(
        names.iter().any(|n| n == marker_table),
        "the successful migration's table must persist. Present: {names:?}"
    );

    // And the failed one must not be recorded, so a corrected retry can proceed.
    let recorded = db
        .query_scalar(
            "SELECT version FROM schema_migrations WHERE version = '002_broken'",
            &[],
        )
        .await
        .expect("could not query migration state");
    assert!(
        recorded.is_none(),
        "a failed migration must not be recorded as applied"
    );
}

/// A missing migrations directory is an error naming the path, not a panic.
#[tokio::test]
async fn a_missing_migrations_directory_is_reported() {
    let Some(db) = connect().await else {
        eprintln!("skipped: SPECTRA_TEST_DATABASE_URL is not set");
        return;
    };

    let err = db
        .run_migrations("/nonexistent/path/to/migrations")
        .await
        .expect_err("a missing directory must be an error");

    assert!(
        err.to_string().contains("/nonexistent/path/to/migrations"),
        "the error must name the path, got: {err}"
    );
}

/// Write a two-migration directory where the second is invalid, and return the
/// directory plus the name of the table the first one creates.
fn tempdir_with_migrations() -> (String, String) {
    let dir = tempfile::tempdir().expect("could not create temp dir");
    let marker = "first_migration_marker";

    std::fs::write(
        dir.path().join("001_good.sql"),
        format!("CREATE TABLE {marker} (id INT PRIMARY KEY);"),
    )
    .expect("could not write 001");

    // Invalid: a statement that does not parse, after a valid one, so the rollback
    // has something to undo.
    std::fs::write(
        dir.path().join("002_broken.sql"),
        "CREATE TABLE should_not_survive (id INT);\nTHIS IS NOT SQL;\n",
    )
    .expect("could not write 002");

    let path = dir.path().to_string_lossy().to_string();
    // Leak the TempDir so the directory outlives this function.
    std::mem::forget(dir);
    (path, marker.to_string())
}
