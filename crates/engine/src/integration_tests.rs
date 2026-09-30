use spectra_core::audit::{AuditCategory, AuditLogger};
use spectra_core::governance::{ResourceGovernor, ResourceLimits};
use spectra_core::recovery::RecoveryManager;
use spectra_findings::{
    DetectionEngine, DetectionSource, Finding, FindingsManager, InMemoryFindingsManager,
    InMemoryObservationStore, ManagedFinding, Observation, ObservationEngine, ObservationSeverity,
    ObservationType, Severity,
};
use spectra_scanner::VulnerabilityCategory;
use spectra_verification::{VerificationEngine, VerificationStrategy};

#[tokio::test]
async fn observation_pipeline() {
    // 1. Create observation store and engine
    let observation_store = InMemoryObservationStore::new();
    let observation_engine = ObservationEngine::new(observation_store);

    // 2. Record an observation
    let observation = Observation::new(
        "scan-1",
        "scanner",
        ObservationType::ScannerOutput,
        serde_json::json!({"response_body": "You have an error in your SQL syntax"}),
    )
    .with_confidence(0.9)
    .with_severity(ObservationSeverity::High);

    observation_engine.record_with(observation).await.unwrap();

    // 3. Run detection on observations - pipeline should work without errors
    let test_observations = vec![Observation::new(
        "scan-1",
        "scanner",
        ObservationType::ScannerOutput,
        serde_json::json!({"response_body": "You have an error in your SQL syntax"}),
    )
    .with_confidence(0.95)
    .with_severity(ObservationSeverity::High)];

    let detection_engine = DetectionEngine::new();
    let result = detection_engine.detect(&test_observations);

    // Detection pipeline should not error (may or may not find matches)
    assert!(result.is_ok(), "Detection should not fail");

    // 4. If findings were produced, store one
    let findings = result.unwrap();
    if let Some(first_finding) = findings.into_iter().next() {
        let findings_manager = InMemoryFindingsManager::new();
        findings_manager.save_finding(first_finding).await.unwrap();
    }
}

#[tokio::test]
async fn finding_lifecycle() {
    // 1. Create finding
    let finding = Finding::new(
        "SQL Injection in /api/users",
        "Error-based SQL injection detected",
        Severity::Critical,
        VulnerabilityCategory::Injection,
    );
    let managed = ManagedFinding::new(finding, DetectionSource::SqlInjectionScanner);

    // 2. Store finding
    let findings_manager = InMemoryFindingsManager::new();
    findings_manager.save_finding(managed).await.unwrap();

    // 3. Create verification engine
    let verification_engine = VerificationEngine::with_strategy(VerificationStrategy::default());
    assert_eq!(verification_engine.summary().await.total_verifications, 0);
}

#[tokio::test]
async fn audit_logger_records_events() {
    let logger = AuditLogger::with_in_memory();

    // Record various events
    logger
        .auth("login", Some("user1".to_string()), true)
        .await
        .unwrap();
    logger
        .auth("logout", Some("user1".to_string()), true)
        .await
        .unwrap();
    logger.auth("login_failed", None, false).await.unwrap();

    assert_eq!(logger.count().await, 3);

    // Query by category
    let auth_events = logger
        .query(Some(AuditCategory::Authentication), None, 10)
        .await;
    assert_eq!(auth_events.len(), 3);
}

#[tokio::test]
async fn recovery_manager_lifecycle() {
    let manager = RecoveryManager::with_defaults();

    // Register operation
    manager.register("scan-1").await;

    // Start execution
    manager
        .update_state("scan-1", spectra_core::recovery::OperationState::Running)
        .await
        .unwrap();

    // Send heartbeat
    manager.heartbeat("scan-1", "worker-1").await.unwrap();

    // Verify state
    let record = manager.get("scan-1").await.unwrap();
    assert_eq!(
        record.state,
        spectra_core::recovery::OperationState::Running
    );
    assert!(record.heartbeat.is_some());

    // Complete
    manager.complete("scan-1").await.unwrap();
    let record = manager.get("scan-1").await.unwrap();
    assert_eq!(
        record.state,
        spectra_core::recovery::OperationState::Completed
    );
}

#[tokio::test]
async fn resource_governor_limits() {
    let governor = ResourceGovernor::new(ResourceLimits {
        max_requests_per_second: 5,
        max_concurrent: 2,
        ..Default::default()
    });

    // Acquire up to limit
    assert!(governor.try_acquire().await.is_ok());
    assert!(governor.try_acquire().await.is_ok());

    // Should fail when at limit
    assert!(governor.try_acquire().await.is_err());

    // Release one
    governor.release().await;

    // Should succeed again
    assert!(governor.try_acquire().await.is_ok());
}

#[tokio::test]
async fn secret_redaction() {
    use spectra_core::secrets::SecretRedactor;

    let redactor = SecretRedactor::new().with_default_patterns();

    // Test password redaction
    let input = "password=secret123 api_key=my-key";
    let redacted = redactor.redact(input);
    assert!(!redacted.contains("secret123"));
    assert!(!redacted.contains("my-key"));
    assert!(redacted.contains("********"));

    // Test JSON redaction
    let json = r#"{"password": "secret123", "username": "admin"}"#;
    let redacted = redactor.redact_json(json);
    assert!(!redacted.contains("secret123"));
    assert!(redacted.contains("admin"));
}

#[test]
fn scope_engine_private_ip_blocks() {
    use spectra_target::scope::ScopeEngine;

    assert!(ScopeEngine::is_private_ip("127.0.0.1"));
    assert!(ScopeEngine::is_private_ip("10.0.0.1"));
    assert!(ScopeEngine::is_private_ip("192.168.1.1"));
    assert!(ScopeEngine::is_private_ip("169.254.1.1"));
    assert!(!ScopeEngine::is_private_ip("8.8.8.8"));
    assert!(!ScopeEngine::is_private_ip("1.1.1.1"));
}

#[test]
fn ssrf_guard_blocks_private() {
    use spectra_core::ssrf::SSRFGuard;

    let guard = SSRFGuard::new();

    // Should block private IPs
    assert!(guard.validate_url("http://127.0.0.1/admin").is_err());
    assert!(guard.validate_url("http://10.0.0.1/secret").is_err());
    assert!(guard.validate_url("http://192.168.1.1/internal").is_err());

    // Should block bad schemes
    assert!(guard.validate_url("file:///etc/passwd").is_err());
    assert!(guard.validate_url("ftp://example.com").is_err());

    // Should allow public URLs
    assert!(guard.validate_url("https://example.com").is_ok());
}
