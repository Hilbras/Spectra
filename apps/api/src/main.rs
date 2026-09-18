use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

use spectra_evidence::EvidenceEngine;
use spectra_findings::{
    FindingStatus, FindingsManager, InMemoryFindingsManager, InMemoryObservationStore,
    ObservationEngine,
};
use spectra_target::{
    Environment, Organization, Project, Target, TargetError, TargetService, TargetType,
};
use spectra_verification::VerificationEngine;

// =============================================================================
// Application State
// =============================================================================

#[derive(Clone)]
struct AppState {
    #[allow(dead_code)]
    config: spectra_config::Config,
    target_service: Arc<TargetService>,
    findings_manager: Arc<InMemoryFindingsManager>,
    observation_engine: Arc<ObservationEngine<InMemoryObservationStore>>,
    evidence_engine: Arc<EvidenceEngine>,
    verification_engine: Arc<VerificationEngine>,
}

// =============================================================================
// Error Handling
// =============================================================================

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: String,
}

fn target_error_to_response(e: TargetError) -> (StatusCode, Json<ErrorResponse>) {
    let (status, code) = match &e {
        TargetError::OrganizationNotFound(_)
        | TargetError::ProjectNotFound(_)
        | TargetError::TargetNotFound(_)
        | TargetError::ScopeNotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
        TargetError::InvalidTargetValue(_) | TargetError::Validation(_) => {
            (StatusCode::BAD_REQUEST, "VALIDATION_ERROR")
        }
        TargetError::ScopeViolation(_) => (StatusCode::FORBIDDEN, "SCOPE_VIOLATION"),
        TargetError::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
        TargetError::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
    };
    (
        status,
        Json(ErrorResponse {
            error: e.to_string(),
            code: code.to_string(),
        }),
    )
}

fn uuid_error_to_response(_: uuid::Error) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: "Invalid UUID".to_string(),
            code: "INVALID_UUID".to_string(),
        }),
    )
}

type ApiResult<T> = Result<T, (StatusCode, Json<ErrorResponse>)>;

// =============================================================================
// Health
// =============================================================================

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

// =============================================================================
// Organization Handlers
// =============================================================================

#[derive(Deserialize)]
struct CreateOrganizationRequest {
    name: String,
    slug: String,
}

#[derive(Serialize)]
struct OrganizationResponse {
    id: String,
    name: String,
    slug: String,
    description: Option<String>,
}

impl From<Organization> for OrganizationResponse {
    fn from(org: Organization) -> Self {
        Self {
            id: org.id.to_string(),
            name: org.name,
            slug: org.slug,
            description: org.description,
        }
    }
}

async fn create_organization(
    State(state): State<AppState>,
    Json(req): Json<CreateOrganizationRequest>,
) -> ApiResult<(StatusCode, Json<OrganizationResponse>)> {
    let org = state
        .target_service
        .create_organization(req.name, req.slug)
        .await
        .map_err(target_error_to_response)?;
    info!(org_id = %org.id, "Organization created");
    Ok((StatusCode::CREATED, Json(OrganizationResponse::from(org))))
}

async fn list_organizations(State(state): State<AppState>) -> Json<Vec<OrganizationResponse>> {
    let orgs = state.target_service.list_organizations().await;
    Json(orgs.into_iter().map(OrganizationResponse::from).collect())
}

async fn get_organization(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<OrganizationResponse>> {
    let org_id = spectra_core::Id::from_uuid(Uuid::parse_str(&id).map_err(uuid_error_to_response)?);
    let org = state
        .target_service
        .get_organization(&org_id)
        .await
        .map_err(target_error_to_response)?;
    Ok(Json(OrganizationResponse::from(org)))
}

async fn delete_organization(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let org_id = spectra_core::Id::from_uuid(Uuid::parse_str(&id).map_err(uuid_error_to_response)?);
    state
        .target_service
        .delete_organization(&org_id)
        .await
        .map_err(target_error_to_response)?;
    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Project Handlers
// =============================================================================

#[derive(Deserialize)]
struct CreateProjectRequest {
    organization_id: String,
    name: String,
    slug: String,
}

#[derive(Serialize)]
struct ProjectResponse {
    id: String,
    organization_id: String,
    name: String,
    slug: String,
    description: Option<String>,
    status: String,
}

impl From<Project> for ProjectResponse {
    fn from(project: Project) -> Self {
        Self {
            id: project.id.to_string(),
            organization_id: project.organization_id.to_string(),
            name: project.name,
            slug: project.slug,
            description: project.description,
            status: format!("{:?}", project.status).to_lowercase(),
        }
    }
}

async fn create_project(
    State(state): State<AppState>,
    Json(req): Json<CreateProjectRequest>,
) -> ApiResult<(StatusCode, Json<ProjectResponse>)> {
    let org_id = spectra_core::Id::from_uuid(
        Uuid::parse_str(&req.organization_id).map_err(uuid_error_to_response)?,
    );
    let project = state
        .target_service
        .create_project(org_id, req.name, req.slug)
        .await
        .map_err(target_error_to_response)?;
    info!(project_id = %project.id, "Project created");
    Ok((StatusCode::CREATED, Json(ProjectResponse::from(project))))
}

async fn list_projects(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
) -> ApiResult<Json<Vec<ProjectResponse>>> {
    let org_uuid =
        spectra_core::Id::from_uuid(Uuid::parse_str(&org_id).map_err(uuid_error_to_response)?);
    let projects = state.target_service.list_projects(&org_uuid).await;
    Ok(Json(
        projects.into_iter().map(ProjectResponse::from).collect(),
    ))
}

// =============================================================================
// Target Handlers
// =============================================================================

#[derive(Deserialize)]
struct CreateTargetRequest {
    project_id: String,
    name: String,
    target_type: String,
    value: String,
    environment: Option<String>,
}

#[derive(Serialize)]
struct TargetResponse {
    id: String,
    project_id: String,
    name: String,
    target_type: String,
    value: String,
    environment: String,
    active: bool,
}

impl From<Target> for TargetResponse {
    fn from(target: Target) -> Self {
        Self {
            id: target.id.to_string(),
            project_id: target.project_id.to_string(),
            name: target.name,
            target_type: target.target_type.to_string(),
            value: target.value,
            environment: target.environment.to_string(),
            active: target.active,
        }
    }
}

fn parse_target_type(s: &str) -> Result<TargetType, String> {
    match s.to_lowercase().as_str() {
        "domain" => Ok(TargetType::Domain),
        "url" => Ok(TargetType::Url),
        "ip" | "ipaddress" => Ok(TargetType::IpAddress),
        "cidr" => Ok(TargetType::CidrRange),
        _ => Err(format!("Unknown target type: {}", s)),
    }
}

fn parse_environment(s: &str) -> Environment {
    match s.to_lowercase().as_str() {
        "production" | "prod" => Environment::Production,
        "staging" | "stage" => Environment::Staging,
        "development" | "dev" => Environment::Development,
        "testing" | "test" => Environment::Testing,
        other => Environment::Custom(other.to_string()),
    }
}

async fn create_target(
    State(state): State<AppState>,
    Json(req): Json<CreateTargetRequest>,
) -> ApiResult<(StatusCode, Json<TargetResponse>)> {
    let project_id = spectra_core::Id::from_uuid(
        Uuid::parse_str(&req.project_id).map_err(uuid_error_to_response)?,
    );
    let target_type = parse_target_type(&req.target_type).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e,
                code: "INVALID_TARGET_TYPE".to_string(),
            }),
        )
    })?;

    let mut target = state
        .target_service
        .create_target(project_id, req.name, target_type, req.value)
        .await
        .map_err(target_error_to_response)?;

    if let Some(env_str) = &req.environment {
        target.environment = parse_environment(env_str);
    }

    info!(target_id = %target.id, "Target created");
    Ok((StatusCode::CREATED, Json(TargetResponse::from(target))))
}

async fn list_targets(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
) -> ApiResult<Json<Vec<TargetResponse>>> {
    let proj_id =
        spectra_core::Id::from_uuid(Uuid::parse_str(&project_id).map_err(uuid_error_to_response)?);
    let targets = state.target_service.list_targets(&proj_id).await;
    Ok(Json(
        targets.into_iter().map(TargetResponse::from).collect(),
    ))
}

async fn get_target(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<TargetResponse>> {
    let target_id =
        spectra_core::Id::from_uuid(Uuid::parse_str(&id).map_err(uuid_error_to_response)?);
    let target = state
        .target_service
        .get_target(&target_id)
        .await
        .map_err(target_error_to_response)?;
    Ok(Json(TargetResponse::from(target)))
}

async fn delete_target(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let target_id =
        spectra_core::Id::from_uuid(Uuid::parse_str(&id).map_err(uuid_error_to_response)?);
    state
        .target_service
        .delete_target(&target_id)
        .await
        .map_err(target_error_to_response)?;
    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Scan Handlers
// =============================================================================

#[derive(Deserialize)]
struct ScanRequest {
    target_id: String,
    #[allow(dead_code)]
    scan_type: Option<String>,
}

#[derive(Serialize)]
struct ScanResponse {
    id: String,
    target_id: String,
    status: String,
}

async fn create_scan(
    State(_state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> ApiResult<Json<ScanResponse>> {
    let id = Uuid::new_v4().to_string();
    info!(scan_id = %id, target_id = %req.target_id, "Creating scan");
    Ok(Json(ScanResponse {
        id,
        target_id: req.target_id,
        status: "pending".to_string(),
    }))
}

// =============================================================================
// Findings Handlers
// =============================================================================

#[derive(Serialize)]
struct FindingsListResponse {
    findings: Vec<serde_json::Value>,
    total: usize,
}

async fn list_findings(State(state): State<AppState>) -> Json<FindingsListResponse> {
    let ids = state.findings_manager.ids().await;
    let total = ids.len();
    let mut findings = Vec::new();
    for id in &ids {
        if let Ok(f) = state.findings_manager.get_finding(id).await {
            findings.push(serde_json::json!({
                "id": f.finding.id.to_string(),
                "title": f.finding.title,
                "severity": f.finding.severity,
                "status": f.status,
                "finding_type": f.finding_type,
                "detection_source": f.detection_source,
                "affected_url": f.finding.affected_url,
            }));
        }
    }
    Json(FindingsListResponse { findings, total })
}

async fn get_finding(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let finding = state.findings_manager.get_finding(&id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "NOT_FOUND".to_string(),
            }),
        )
    })?;
    Ok(Json(serde_json::json!({
        "id": finding.finding.id.to_string(),
        "title": finding.finding.title,
        "description": finding.finding.description,
        "severity": finding.finding.severity,
        "status": finding.status,
        "finding_type": finding.finding_type,
        "detection_source": finding.detection_source,
        "affected_url": finding.finding.affected_url,
        "evidence": finding.finding.evidence,
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "occurrence_count": finding.occurrence_count,
    })))
}

#[derive(Deserialize)]
struct UpdateFindingStatusRequest {
    status: String,
}

fn parse_finding_status(s: &str) -> Result<FindingStatus, String> {
    match s.to_lowercase().as_str() {
        "new" => Ok(FindingStatus::New),
        "confirmed" => Ok(FindingStatus::Confirmed),
        "false_positive" => Ok(FindingStatus::FalsePositive),
        "investigating" => Ok(FindingStatus::Investigating),
        "fixed" => Ok(FindingStatus::Fixed),
        "accepted" => Ok(FindingStatus::Accepted),
        "duplicate" => Ok(FindingStatus::Duplicate),
        _ => Err(format!("Unknown status: {}", s)),
    }
}

async fn update_finding_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateFindingStatusRequest>,
) -> ApiResult<StatusCode> {
    let status = parse_finding_status(&req.status).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e,
                code: "INVALID_STATUS".to_string(),
            }),
        )
    })?;
    state
        .findings_manager
        .update_status(&id, status)
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: "NOT_FOUND".to_string(),
                }),
            )
        })?;
    Ok(StatusCode::OK)
}

// =============================================================================
// Observation Handlers
// =============================================================================

#[derive(Serialize)]
struct ObservationsListResponse {
    observations: Vec<serde_json::Value>,
    total: usize,
}

async fn list_observations(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Json<ObservationsListResponse> {
    let observations = state
        .observation_engine
        .get_scan_observations(&scan_id)
        .await
        .unwrap_or_default();
    let total = observations.len();
    let obs_json: Vec<serde_json::Value> = observations
        .iter()
        .map(|o| {
            serde_json::json!({
                "id": o.id.to_string(),
                "source": o.source,
                "observation_type": o.observation_type,
                "confidence": o.confidence,
                "severity": o.severity,
                "data": o.data,
                "observed_at": o.observed_at,
            })
        })
        .collect();
    Json(ObservationsListResponse {
        observations: obs_json,
        total,
    })
}

// =============================================================================
// Evidence Handlers
// =============================================================================

#[derive(Serialize)]
struct EvidenceListResponse {
    evidence: Vec<serde_json::Value>,
    total: usize,
}

async fn list_evidence(
    State(state): State<AppState>,
    Path(finding_id): Path<String>,
) -> ApiResult<Json<EvidenceListResponse>> {
    let evidence = state
        .evidence_engine
        .store()
        .get_by_finding(&finding_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: "EVIDENCE_ERROR".to_string(),
                }),
            )
        })?;
    let total = evidence.len();
    let ev_json: Vec<serde_json::Value> = evidence
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id.to_string(),
                "finding_id": e.finding_id.to_string(),
                "evidence_type": e.evidence_type,
                "title": e.title,
                "description": e.description,
                "collector": e.collector,
                "collected_at": e.collected_at,
                "tags": e.tags,
                "redacted": e.redacted,
            })
        })
        .collect();
    Ok(Json(EvidenceListResponse {
        evidence: ev_json,
        total,
    }))
}

// =============================================================================
// Verification Handlers
// =============================================================================

#[derive(Serialize)]
struct VerificationListResponse {
    records: Vec<serde_json::Value>,
    total: usize,
}

async fn list_verifications(
    State(state): State<AppState>,
    Path(finding_id): Path<String>,
) -> Json<VerificationListResponse> {
    let records = state
        .verification_engine
        .store()
        .get_records(&finding_id)
        .await;
    let total = records.len();
    let rec_json: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "finding_id": r.finding_id,
                "status": r.status,
                "method": r.method,
                "confidence": r.confidence,
                "details": r.details,
                "verified_at": r.verified_at,
                "verifier": r.verifier,
            })
        })
        .collect();
    Json(VerificationListResponse {
        records: rec_json,
        total,
    })
}

#[derive(Serialize)]
struct VerificationSummaryResponse {
    total_verifications: usize,
    verified: usize,
    not_verified: usize,
    partially_verified: usize,
}

async fn verification_summary(State(state): State<AppState>) -> Json<VerificationSummaryResponse> {
    let summary = state.verification_engine.summary().await;
    Json(VerificationSummaryResponse {
        total_verifications: summary.total_verifications,
        verified: summary.verified,
        not_verified: summary.not_verified,
        partially_verified: summary.partially_verified,
    })
}

// =============================================================================
// Stats Handler
// =============================================================================

#[derive(Serialize)]
struct StatsResponse {
    findings_total: usize,
    findings_by_severity: serde_json::Value,
    observations_total: usize,
    evidence_total: usize,
    verification_summary: VerificationSummaryResponse,
}

async fn get_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let summary = state.verification_engine.summary().await;
    let findings_count = state.findings_manager.count().await;
    let critical = state
        .findings_manager
        .count_by_severity(&spectra_scanner::Severity::Critical)
        .await;
    let high = state
        .findings_manager
        .count_by_severity(&spectra_scanner::Severity::High)
        .await;
    let medium = state
        .findings_manager
        .count_by_severity(&spectra_scanner::Severity::Medium)
        .await;
    let low = state
        .findings_manager
        .count_by_severity(&spectra_scanner::Severity::Low)
        .await;
    let info = state
        .findings_manager
        .count_by_severity(&spectra_scanner::Severity::Info)
        .await;
    let evidence_total = state.evidence_engine.store().count().await;

    Json(StatsResponse {
        findings_total: findings_count,
        findings_by_severity: serde_json::json!({
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        }),
        observations_total: 0,
        evidence_total,
        verification_summary: VerificationSummaryResponse {
            total_verifications: summary.total_verifications,
            verified: summary.verified,
            not_verified: summary.not_verified,
            partially_verified: summary.partially_verified,
        },
    })
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = spectra_config::Config::load().unwrap_or_default();

    spectra_telemetry::init_logging(&config);
    spectra_telemetry::init_telemetry(&config)?;

    let state = AppState {
        config: config.clone(),
        target_service: Arc::new(TargetService::new()),
        findings_manager: Arc::new(InMemoryFindingsManager::new()),
        observation_engine: Arc::new(ObservationEngine::new(InMemoryObservationStore::new())),
        evidence_engine: Arc::new(EvidenceEngine::new()),
        verification_engine: Arc::new(VerificationEngine::new()),
    };

    let app = Router::new()
        // Health
        .route("/api/v1/health", get(health_check))
        // Organizations
        .route(
            "/api/v1/organizations",
            post(create_organization).get(list_organizations),
        )
        .route(
            "/api/v1/organizations/:id",
            get(get_organization).delete(delete_organization),
        )
        // Projects
        .route("/api/v1/projects", post(create_project))
        .route("/api/v1/organizations/:org_id/projects", get(list_projects))
        // Targets
        .route("/api/v1/targets", post(create_target))
        .route("/api/v1/projects/:project_id/targets", get(list_targets))
        .route("/api/v1/targets/:id", get(get_target).delete(delete_target))
        // Scans
        .route("/api/v1/scans", post(create_scan))
        // Findings
        .route("/api/v1/findings", get(list_findings))
        .route("/api/v1/findings/:id", get(get_finding))
        .route("/api/v1/findings/:id/status", post(update_finding_status))
        // Observations
        .route(
            "/api/v1/scans/:scan_id/observations",
            get(list_observations),
        )
        // Evidence
        .route("/api/v1/findings/:finding_id/evidence", get(list_evidence))
        // Verification
        .route(
            "/api/v1/findings/:finding_id/verification",
            get(list_verifications),
        )
        .route("/api/v1/verification/summary", get(verification_summary))
        // Stats
        .route("/api/v1/stats", get(get_stats))
        .with_state(state);

    let addr = config.server_address();
    info!(address = %addr, "Starting Spectra API server");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    spectra_telemetry::shutdown_telemetry();

    Ok(())
}
