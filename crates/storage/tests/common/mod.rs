//! Shared helpers for the PostgreSQL integration tests.
//!
//! These tests need a real database, so they are skipped rather than failed when
//! `SPECTRA_TEST_DATABASE_URL` is unset. A skipped test that reports itself as
//! skipped is honest; one that silently passes because it never connected is not.
//!
//! CI sets the variable and runs a `postgres:16` service, so there the tests do run.
//! Locally, start one with:
//!
//! ```text
//! docker run -d --name spectra-test-postgres \
//!   -e POSTGRES_USER=spectra -e POSTGRES_PASSWORD=spectra_test_pw \
//!   -e POSTGRES_DB=spectra_test -p 55432:5432 postgres:16-alpine
//! export SPECTRA_TEST_DATABASE_URL=postgres://spectra:spectra_test_pw@127.0.0.1:55432/spectra_test
//! ```

use spectra_storage::pg::PostgresDatabase;
use spectra_storage::Database;

/// The URL the integration tests connect to, or `None` if they should be skipped.
pub fn test_database_url() -> Option<String> {
    std::env::var("SPECTRA_TEST_DATABASE_URL")
        .ok()
        .filter(|u| !u.is_empty())
}

/// The repository's own migrations, resolved from the workspace root.
pub fn migrations_dir() -> String {
    // CARGO_MANIFEST_DIR is .../crates/storage; migrations live two levels up.
    let manifest = env!("CARGO_MANIFEST_DIR");
    format!("{manifest}/../../migrations")
}

/// A database with every table dropped, so each test starts from empty.
///
/// Drops in reverse dependency order via `CASCADE`, so it does not need to know the
/// foreign keys: one statement per table is enough because `CASCADE` takes the
/// dependants with it.
pub async fn truncate_all(db: &PostgresDatabase) {
    let rows = db
        .query(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
            &[],
        )
        .await
        .expect("could not list tables");

    for row in rows {
        let table: String = row.get_by_name("tablename").expect("tablename is text");
        // `schema_migrations` is bookkeeping, not data, but it is reset too so a
        // test that asserts migration behaviour starts from nothing applied.
        db.execute(&format!("DROP TABLE IF EXISTS \"{table}\" CASCADE"), &[])
            .await
            .unwrap_or_else(|e| panic!("could not drop {table}: {e}"));
    }
}

/// Connect, returning `None` when no test database is configured.
pub async fn connect() -> Option<PostgresDatabase> {
    let url = test_database_url()?;
    Some(
        PostgresDatabase::new(&url)
            .await
            .unwrap_or_else(|e| panic!("SPECTRA_TEST_DATABASE_URL is set but unreachable: {e}")),
    )
}
