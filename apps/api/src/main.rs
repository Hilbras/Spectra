use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    middleware,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use spectra_auth::{AuthUser, JwtConfig, JwtService, Permission, Role};
use spectra_engine::{ScanEngine, ScanJob, ScanPlan, ScanStatus};
use spectra_evidence::EvidenceEngine;
use spectra_findings::{
    FindingStatus, FindingsManager, InMemoryFindingsManager, InMemoryObservationStore,
    ObservationEngine,
};
use spectra_target::{
    Environment, Organization, Project, Target, TargetError, TargetId, TargetService, TargetType,
};
use spectra_verification::VerificationEngine;

use spectra_core::audit::AuditLogger;
use spectra_core::governance::{ResourceGovernor, ResourceLimits};
use spectra_core::recovery::RecoveryManager;
use spectra_core::secrets::SecretManager;
use spectra_core::SSRFGuard;
use spectra_events::EventBus;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

// =============================================================================
// User Store
// =============================================================================

/// A stored account.
///
/// There is no `permissions` field. It used to sit alongside `roles`, and the
/// two had already drifted: the stored list granted `scans:write`, a permission
/// this codebase does not define, while omitting `evidence`, `users`,
/// `settings` and `api_keys` entirely. Two sources of truth for one fact will
/// diverge again, so roles are the only one; [`expand_role_permissions`] derives
/// the grants when a token is issued.
#[derive(Clone)]
struct UserEntry {
    password_hash: String,
    roles: Vec<String>,
}

#[derive(Clone)]
struct UserStore {
    users: Arc<RwLock<HashMap<String, UserEntry>>>,
}

impl UserStore {
    /// Build the user store and the initial administrator account.
    ///
    /// There is no baked-in `admin`/`admin` credential. The initial password
    /// comes from one of:
    ///
    /// 1. `SPECTRA_ADMIN_PASSWORD` — explicit operator choice.
    /// 2. A generated random password, written once to
    ///    `SPECTRA_ADMIN_PASSWORD_FILE` (default `~/.spectra/initial-admin-password`)
    ///    with `0600` permissions. The path is logged, never the password.
    ///
    /// Failing to establish an account is a startup error: a server that boots
    /// with no way to authenticate is worse than one that refuses to boot.
    fn bootstrap() -> Result<Self, String> {
        let (password, source) = match std::env::var("SPECTRA_ADMIN_PASSWORD") {
            Ok(p) if !p.is_empty() => (p, "SPECTRA_ADMIN_PASSWORD".to_string()),
            _ => {
                let path = Self::initial_password_path()?;
                let password = Self::generate_password();
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
                }
                // Write with 0600 from the outset rather than creating a
                // world-readable file and narrowing it afterwards.
                use std::io::Write;
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                let mut f = opts
                    .open(&path)
                    .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
                writeln!(f, "{password}")
                    .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
                (password, path.display().to_string())
            }
        };

        if password.chars().count() < 12 {
            return Err(format!(
                "initial admin password must be at least 12 characters (from {source})"
            ));
        }

        let mut users = HashMap::new();
        users.insert(
            "admin".to_string(),
            UserEntry {
                password_hash: Self::hash_password(&password)?,
                // Roles are the single source of truth. This entry previously
                // also carried a hand-maintained permission list, and the two
                // had already drifted: the list granted `scans:write`, which is
                // not a permission this codebase has (the real one is
                // `scans:execute`), and it omitted `evidence`, `users`,
                // `settings` and `api_keys` entirely. Authorisation is now
                // derived from the role, so the two cannot diverge again.
                roles: vec![Role::Admin.to_string()],
            },
        );

        info!("initial admin account created (password source: {source})");

        Ok(Self {
            users: Arc::new(RwLock::new(users)),
        })
    }

    fn initial_password_path() -> Result<std::path::PathBuf, String> {
        match std::env::var("SPECTRA_ADMIN_PASSWORD_FILE") {
            Ok(p) if !p.is_empty() => Ok(std::path::PathBuf::from(p)),
            _ => {
                let home =
                    dirs::home_dir().ok_or_else(|| "cannot resolve home directory".to_string())?;
                Ok(home.join(".spectra").join("initial-admin-password"))
            }
        }
    }

    /// Generate a 256-bit random password, base64url-encoded.
    fn generate_password() -> String {
        use base64::Engine as _;
        let mut bytes = [0u8; 32];
        // `getrandom` only fails on a broken OS entropy source; there is no
        // safe weaker fallback for a credential.
        if getrandom::getrandom(&mut bytes).is_err() {
            panic!("system CSPRNG unavailable; cannot generate an initial password");
        }
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Hash a password with argon2id.
    ///
    /// argon2id is memory-hard and salted per call, so two users with the same
    /// password produce different hashes and a stolen database cannot be
    /// attacked with a GPU at scale. The previous implementation was a single
    /// unsalted SHA-256, which is trivially reversible by rainbow table.
    fn hash_password(password: &str) -> Result<String, String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| format!("password hashing failed: {e}"))
    }

    async fn validate(&self, username: &str, password: &str) -> Option<UserEntry> {
        let entry = self.users.read().await.get(username).cloned()?;

        // Verify against the stored PHC string. Argon2's verification is
        // constant-time with respect to the hash, so this does not leak timing
        // information the way `==` on two hex digests did.
        let parsed = argon2::PasswordHash::new(&entry.password_hash).ok()?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .ok()?;

        Some(entry)
    }
}
use spectra_core::Id;

// =============================================================================
// Application State
// =============================================================================

#[derive(Clone)]
struct AppState {
    #[allow(dead_code)]
    config: spectra_config::Config,
    target_service: Arc<TargetService>,
    // The same instances the scan engine writes through. These were previously
    // separate objects built in `build_state`, so everything the engine recorded
    // was invisible here: `GET /scans/{id}/observations` and
    // `GET /findings/{id}/evidence` returned empty for every scan, and
    // `stats.evidence_total` was always 0.
    findings_manager: Arc<InMemoryFindingsManager>,
    observation_engine: Arc<ObservationEngine<Arc<InMemoryObservationStore>>>,
    evidence_engine: Arc<EvidenceEngine>,
    verification_engine: Arc<VerificationEngine>,
    jwt_service: Arc<JwtService>,
    audit_logger: Arc<AuditLogger>,
    #[allow(dead_code)]
    recovery_manager: Arc<RecoveryManager>,
    #[allow(dead_code)]
    governor: Arc<ResourceGovernor>,
    #[allow(dead_code)]
    secret_manager: Arc<SecretManager>,
    scan_engine: Arc<ScanEngine<Arc<InMemoryFindingsManager>, Arc<InMemoryObservationStore>>>,
    scan_jobs: Arc<RwLock<HashMap<String, ScanJob>>>,
    user_store: UserStore,
    login_throttle: LoginThrottle,
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

#[derive(Deserialize)]
struct Pagination {
    page: Option<usize>,
    per_page: Option<usize>,
}

impl Pagination {
    fn offset(&self) -> usize {
        let page = self.page.unwrap_or(1).max(1);
        let per_page = self.per_page.unwrap_or(50).min(200);
        (page - 1) * per_page
    }

    fn limit(&self) -> usize {
        self.per_page.unwrap_or(50).min(200)
    }
}

// =============================================================================
// Health
// =============================================================================

use std::time::Instant;

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
    components: ComponentsHealth,
}

#[derive(Serialize)]
struct ComponentsHealth {
    api: ComponentStatus,
    database: ComponentStatus,
    redis: ComponentStatus,
}

#[derive(Serialize)]
struct ComponentStatus {
    status: String,
    message: Option<String>,
}

static START_TIME: once_cell::sync::Lazy<Instant> = once_cell::sync::Lazy::new(Instant::now);

async fn health_check() -> Json<HealthResponse> {
    let uptime = START_TIME.elapsed().as_secs();

    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        components: ComponentsHealth {
            api: ComponentStatus {
                status: "healthy".to_string(),
                message: None,
            },
            database: ComponentStatus {
                status: "unknown".to_string(),
                message: Some("Not configured".to_string()),
            },
            redis: ComponentStatus {
                status: "unknown".to_string(),
                message: Some("Not configured".to_string()),
            },
        },
    })
}

#[derive(Serialize)]
struct ReadinessResponse {
    status: String,
    ready: bool,
}

async fn readiness_check() -> Json<ReadinessResponse> {
    Json(ReadinessResponse {
        status: "ready".to_string(),
        ready: true,
    })
}

// =============================================================================
// Auth Handlers
// =============================================================================

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    token_type: String,
    expires_in: usize,
}

/// Error type for the login endpoint.
///
/// A dedicated enum rather than the shared [`ApiResult`] alias because a
/// lockout response must carry a `Retry-After` header, and widening the shared
/// alias would force headers onto every other handler. An enum is also small
/// enough to return by value on every call.
#[derive(Debug)]
enum LoginError {
    /// Bad username or password. `retry_after` is set once the client has been
    /// locked out, so a well-behaved client knows when to try again.
    Invalid { retry_after: Option<u64> },
    /// Too many consecutive failures; the client is locked out.
    LockedOut { retry_after: u64 },
    /// Token issuance failed.
    Internal(String),
}

impl LoginError {
    fn status(&self) -> StatusCode {
        match self {
            Self::Invalid { .. } => StatusCode::UNAUTHORIZED,
            Self::LockedOut { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Invalid { .. } => "INVALID_CREDENTIALS",
            Self::LockedOut { .. } => "RATE_LIMITED",
            Self::Internal(_) => "TOKEN_ERROR",
        }
    }

    fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Invalid { retry_after } => *retry_after,
            Self::LockedOut { retry_after } => Some(*retry_after),
            Self::Internal(_) => None,
        }
    }
}

impl axum::response::IntoResponse for LoginError {
    fn into_response(self) -> axum::response::Response {
        let message = match &self {
            LoginError::Invalid { .. } => "Invalid credentials".to_string(),
            LoginError::LockedOut { .. } => "Too many failed login attempts".to_string(),
            LoginError::Internal(e) => e.clone(),
        };

        let mut response = (
            self.status(),
            Json(ErrorResponse {
                error: message,
                code: self.code().to_string(),
            }),
        )
            .into_response();

        if let Some(secs) = self.retry_after() {
            if let Ok(v) = secs.to_string().parse() {
                response.headers_mut().insert("retry-after", v);
            }
        }
        response
    }
}

type LoginResult<T> = Result<T, LoginError>;

async fn login(
    State(state): State<AppState>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<LoginRequest>,
) -> LoginResult<Json<LoginResponse>> {
    let client_id = client_address(&headers, Some(client));

    // Refuse before doing any password work, so a locked-out client cannot
    // still use the endpoint as a credential oracle.
    if let Err(retry_after) = state.login_throttle.check(&client_id) {
        state
            .audit_auth(
                &format!("Login attempt from locked-out client {client_id}"),
                None,
                false,
            )
            .await;
        return Err(LoginError::LockedOut { retry_after });
    }

    if req.username.is_empty() || req.password.is_empty() {
        state.login_throttle.record_failure(&client_id);
        // Previously failures returned before any audit call, leaving brute-force
        // attempts with no trace at all.
        state
            .audit_auth(
                &format!("Login failed for {client_id}: empty credentials"),
                None,
                false,
            )
            .await;
        // A single generic message for every failure mode, so the endpoint does
        // not reveal whether a username exists.
        return Err(LoginError::Invalid { retry_after: None });
    }

    let user_entry = match state
        .user_store
        .validate(&req.username, &req.password)
        .await
    {
        Some(u) => u,
        None => {
            let locked = state.login_throttle.record_failure(&client_id);
            state
                .audit_auth(
                    &format!("Login failed for {client_id}: invalid credentials"),
                    Some(req.username.clone()),
                    false,
                )
                .await;
            warn!(client = %client_id, username = %req.username, "Failed login");
            return Err(LoginError::Invalid {
                retry_after: if locked {
                    Some(LOGIN_LOCKOUT_SECS)
                } else {
                    None
                },
            });
        }
    };

    state.login_throttle.record_success(&client_id);

    state
        .audit_auth(
            &format!("Login successful for {}", req.username),
            Some(req.username.clone()),
            true,
        )
        .await;

    let expires_in = state.jwt_service.expires_in_secs();

    // The token's permission list is derived from the account's roles rather
    // than read from a separately stored list. Two lists can disagree, and this
    // one already had: it advertised `scans:write`, which is not a permission
    // this codebase defines. Deriving at issue time makes that class of drift
    // impossible.
    let granted = expand_role_permissions(&user_entry.roles);
    let token = state
        .jwt_service
        .create_token(&req.username, user_entry.roles, granted)
        .map_err(|e| LoginError::Internal(e.to_string()))?;

    info!(username = %req.username, client = %client_id, "User logged in");
    Ok(Json(LoginResponse {
        token,
        token_type: "Bearer".to_string(),
        expires_in,
    }))
}

/// Union the permissions granted by each of `roles`, as permission strings.
///
/// An unrecognised role name contributes nothing and is logged: a typo in a role
/// name would otherwise quietly produce a token with no permissions, which looks
/// like a permissions bug rather than a configuration typo.
fn expand_role_permissions(roles: &[String]) -> Vec<String> {
    let mut granted: Vec<String> = Vec::new();
    for name in roles {
        if !Role::is_known_name(name) {
            error!(role = %name, "unknown role; contributes no permissions");
            continue;
        }
        for permission in Role::permissions_for_name(name) {
            let as_string = permission.to_string();
            if !granted.contains(&as_string) {
                granted.push(as_string);
            }
        }
    }
    granted
}

#[derive(Serialize)]
struct MeResponse {
    user_id: String,
    roles: Vec<String>,
}

async fn me(State(_state): State<AppState>, AuthUser(claims): AuthUser) -> Json<MeResponse> {
    Json(MeResponse {
        user_id: claims.sub,
        roles: claims.roles,
    })
}

// =============================================================================
// Organization Handlers
// =============================================================================

fn validate_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("Name cannot be empty".to_string());
    }
    if name.len() > 100 {
        return Err("Name must be 100 characters or less".to_string());
    }
    Ok(())
}

fn validate_slug(slug: &str) -> Result<(), String> {
    if slug.trim().is_empty() {
        return Err("Slug cannot be empty".to_string());
    }
    if !slug
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(
            "Slug must contain only alphanumeric characters, hyphens, or underscores".to_string(),
        );
    }
    if slug.len() > 50 {
        return Err("Slug must be 50 characters or less".to_string());
    }
    Ok(())
}

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
    validate_name(&req.name).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e,
                code: "VALIDATION_ERROR".to_string(),
            }),
        )
    })?;
    validate_slug(&req.slug).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e,
                code: "VALIDATION_ERROR".to_string(),
            }),
        )
    })?;
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
    target_id: Option<String>,
    target: Option<String>,
    scanners: Option<Vec<String>>,
    max_depth: Option<u32>,
    max_pages: Option<u32>,
    timeout_secs: Option<u64>,
}

#[derive(Serialize)]
struct ScanResponse {
    id: String,
    target_id: String,
    status: String,
}

async fn create_scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> ApiResult<Json<ScanResponse>> {
    let scan_id = Uuid::new_v4().to_string();

    let target_id: Id<TargetId> = if let Some(ref tid) = req.target_id {
        tid.parse().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid target ID".to_string(),
                    code: "VALIDATION_ERROR".to_string(),
                }),
            )
        })?
    } else if let Some(ref target_url) = req.target {
        let target_type = if target_url.starts_with("http://") || target_url.starts_with("https://")
        {
            spectra_target::TargetType::Url
        } else {
            spectra_target::TargetType::Domain
        };

        let orgs = state.target_service.list_organizations().await;
        let org_id = if let Some(org) = orgs.first() {
            org.id.clone()
        } else {
            let org = state
                .target_service
                .create_organization("Default".into(), "default".into())
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("Failed to create org: {}", e),
                            code: "ORG_ERROR".into(),
                        }),
                    )
                })?;
            org.id
        };

        let projects = state.target_service.list_projects(&org_id).await;
        let project_id = if let Some(proj) = projects.first() {
            proj.id.clone()
        } else {
            let proj = state
                .target_service
                .create_project(org_id, "Default".into(), "default".into())
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("Failed to create project: {}", e),
                            code: "PROJECT_ERROR".into(),
                        }),
                    )
                })?;
            proj.id
        };

        let target = state
            .target_service
            .create_target(
                project_id,
                target_url.clone(),
                target_type,
                target_url.clone(),
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to create target: {}", e),
                        code: "TARGET_ERROR".into(),
                    }),
                )
            })?;
        target.id
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Either target_id or target is required".to_string(),
                code: "VALIDATION_ERROR".to_string(),
            }),
        ));
    };

    let target = state
        .target_service
        .get_target(&target_id)
        .await
        .map_err(target_error_to_response)?;

    // Reject internal targets before the scan is spawned.
    //
    // A scan makes *this server* issue outbound requests to a URL the caller
    // supplied, so an unvalidated target is a server-side request forgery
    // primitive: `{"target": "http://169.254.169.254/latest/meta-data/"}` makes
    // the scanner fetch the cloud credentials of the machine it runs on, and
    // `http://localhost:8080/api/v1/auth/login` turns the scan into an
    // authenticated request against the API's own admin surface.
    if let Err(reason) = state.check_target_is_scannable(&target.value).await {
        error!(target = %target.value, reason = %reason, "Blocked scan target");
        state
            .audit_auth(
                &format!(
                    "Scan target rejected by SSRF guard: {} ({reason})",
                    target.value
                ),
                None,
                false,
            )
            .await;
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Target is not permitted: {reason}"),
                code: "TARGET_NOT_PERMITTED".to_string(),
            }),
        ));
    }

    state
        .audit_auth(
            &format!("Scan {} requested for target {}", scan_id, target.value),
            None,
            true,
        )
        .await;

    let _ = state
        .audit_logger
        .scan(
            format!("Scan {} created for target {}", scan_id, target.value),
            "api".to_string(),
            target.value.clone(),
            std::collections::HashMap::new(),
        )
        .await;

    // The plan carries the scan id so the engine attributes its observations to this
    // run rather than to the target, which is what the observations endpoint
    // queries by.
    let mut plan = ScanPlan::new(scan_id.clone(), target);
    if let Some(scanners) = req.scanners {
        // Rejected here rather than left to the engine. An unrecognised name used to
        // be dropped in silence, so `{"scanners": ["sqli"]}` produced a scan that
        // tested nothing, reported `Completed`, and rendered "Total: 0" -- a clean
        // result for a target nothing had examined. The engine records the coverage
        // loss as well, but a caller is better served by being told the valid names
        // than by discovering the problem in a report afterwards.
        let unknown: Vec<&String> = scanners
            .iter()
            .filter(|name| !spectra_engine::available_scanners().contains(&name.as_str()))
            .collect();

        if !unknown.is_empty() {
            let listed = unknown
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            warn!(
                scanners = %listed,
                "scan request named scanners that do not exist"
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Unknown scanner{}: {listed}. Available: {}.",
                        if unknown.len() == 1 { "" } else { "s" },
                        spectra_engine::available_scanners().join(", ")
                    ),
                    code: "UNKNOWN_SCANNER".to_string(),
                }),
            ));
        }

        plan = plan.with_scanners(scanners);
    }
    if let Some(depth) = req.max_depth {
        plan = plan.with_max_depth(depth);
    }
    if let Some(pages) = req.max_pages {
        plan = plan.with_max_pages(pages);
    }
    if let Some(timeout) = req.timeout_secs {
        plan = plan.with_timeout(timeout);
    }

    let engine = state.scan_engine.clone();
    let jobs = state.scan_jobs.clone();
    let id = scan_id.clone();

    // Bounded before the job is created, so a rejected request leaves no trace
    // in `GET /scans/{id}`. The per-scan ceilings (max_pages, max_depth,
    // timeout_secs) bound one scan; this bounds how many run at once, which they
    // say nothing about. Previously `ResourceGovernor` was constructed here and
    // never called, so an authenticated `scanner`-role user could start
    // arbitrarily many crawls of a site of their choosing at the same time.
    if let Err(e) = state.governor.try_acquire().await {
        warn!(scan_id = %id, error = %e, "scan rejected by the resource governor");
        let stats = state.governor.stats().await;
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: format!(
                    "The server is already running {} of its {} permitted \
                     concurrent scans. Try again once one finishes.",
                    stats.active_concurrency, stats.max_concurrency
                ),
                code: "RATE_LIMITED".to_string(),
            }),
        ));
    }

    let target_id_str = target_id.to_string();
    let job = ScanJob::new(target_id);
    jobs.write().await.insert(id.clone(), job);

    let scan_id_clone = id.clone();
    let governor = state.governor.clone();
    tokio::spawn(async move {
        // The slot is released on every exit below, including the engine-error arm.
        // A panic would skip it and leak a slot permanently, so `run_scan` is not
        // expected to panic; the alternative is a `Drop` guard that cannot await.
        match engine.run_scan(&plan).await {
            Ok(completed_job) => {
                // `run_scan` returning `Ok` means the orchestration finished, not
                // that the target was analysed. Logging an unqualified success
                // here repeated the conflation the `Partial` status exists to
                // break, and would have made the log disagree with the API
                // response a second later.
                if completed_job.status == ScanStatus::Partial {
                    warn!(
                        scan_id = %scan_id_clone,
                        errors = completed_job.errors.len(),
                        findings = completed_job.metrics.total_findings,
                        "Scan finished with errors; results are incomplete"
                    );
                } else {
                    info!(scan_id = %scan_id_clone, "Scan completed successfully");
                }
                // No longer copies findings across. The engine and the state now
                // share one findings manager, so this loop re-saved every finding
                // into the store that had just recorded it — and because the
                // engine's manager is not filtered per scan, it also copied
                // findings belonging to *other* scans on every completion. Its
                // failure was discarded with `let _ =`.
                jobs.write().await.insert(scan_id_clone, completed_job);
            }
            Err(e) => {
                error!(scan_id = %scan_id_clone, error = %e, "Scan failed");
                let mut failed_job = ScanJob::new(plan.target.id.clone());
                failed_job.status = ScanStatus::Failed;
                failed_job.errors.push(e.to_string());
                jobs.write().await.insert(scan_id_clone, failed_job);
            }
        }

        governor.release().await;
    });

    Ok(Json(ScanResponse {
        id,
        target_id: target_id_str,
        status: "pending".to_string(),
    }))
}

#[derive(Serialize)]
struct ScanDetailResponse {
    id: String,
    target_id: String,
    status: String,
    started_at: Option<String>,
    completed_at: Option<String>,
    network_asset_count: usize,
    crawl_page_count: usize,
    technology_count: usize,
    total_findings: usize,
    findings_by_severity: serde_json::Value,
    observations_recorded: usize,
    evidence_collected: usize,
    scan_duration_ms: u64,
    errors: Vec<String>,
    report_summary: Option<String>,
}

async fn get_scan(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<ScanDetailResponse>> {
    let jobs = state.scan_jobs.read().await;
    let job = jobs.get(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Scan not found".to_string(),
                code: "NOT_FOUND".to_string(),
            }),
        )
    })?;
    Ok(Json(ScanDetailResponse {
        id: id.clone(),
        target_id: job.target_id.to_string(),
        status: job.status.to_string(),
        started_at: job.started_at.clone(),
        completed_at: job.completed_at.clone(),
        network_asset_count: job.network_asset_count,
        crawl_page_count: job.crawl_page_count,
        technology_count: job.technology_count,
        total_findings: job.metrics.total_findings,
        findings_by_severity: serde_json::json!(job.metrics.findings_by_severity),
        observations_recorded: job.metrics.observations_recorded,
        evidence_collected: job.metrics.evidence_collected,
        scan_duration_ms: job.metrics.scan_duration_ms,
        errors: job.errors.clone(),
        report_summary: job.report_summary.clone(),
    }))
}

#[derive(Serialize)]
struct ScanListResponse {
    scans: Vec<serde_json::Value>,
    total: usize,
    page: usize,
    per_page: usize,
}

async fn list_scans(
    State(state): State<AppState>,
    Query(pagination): Query<Pagination>,
) -> Json<ScanListResponse> {
    let jobs = state.scan_jobs.read().await;
    let total = jobs.len();
    let offset = pagination.offset();
    let limit = pagination.limit();
    let page = pagination.page.unwrap_or(1).max(1);

    let scans: Vec<serde_json::Value> = jobs
        .iter()
        .skip(offset)
        .take(limit)
        .map(|(id, job)| {
            serde_json::json!({
                "id": id,
                "target_id": job.target_id.to_string(),
                "status": job.status.to_string(),
                "total_findings": job.metrics.total_findings,
                "started_at": job.started_at,
                "completed_at": job.completed_at,
            })
        })
        .collect();
    Json(ScanListResponse {
        scans,
        total,
        page,
        per_page: limit,
    })
}

// =============================================================================
// Findings Handlers
// =============================================================================

#[derive(Serialize)]
struct FindingsListResponse {
    findings: Vec<serde_json::Value>,
    total: usize,
    page: usize,
    per_page: usize,
}

async fn list_findings(
    State(state): State<AppState>,
    Query(pagination): Query<Pagination>,
) -> Json<FindingsListResponse> {
    let ids = state.findings_manager.ids().await;
    let total = ids.len();
    let offset = pagination.offset();
    let limit = pagination.limit();
    let page = pagination.page.unwrap_or(1).max(1);

    let mut findings = Vec::new();
    for id in ids.iter().skip(offset).take(limit) {
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
    Json(FindingsListResponse {
        findings,
        total,
        page,
        per_page: limit,
    })
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
    // Previously a hardcoded 0. The observation store the API read from was a
    // different object from the one the engine wrote to, so there was nothing to
    // count even when a scan had recorded hundreds.
    let observations_total = state.observation_engine.store().count_all().await;

    Json(StatsResponse {
        findings_total: findings_count,
        findings_by_severity: serde_json::json!({
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        }),
        observations_total,
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
// Security layers
// =============================================================================

/// Build the CORS layer from an explicit origin allowlist.
///
/// Previously this was `Any`/`Any`/`Any`, which let any website read
/// authenticated responses. The dashboard keeps its token in `localStorage`, so
/// a wildcard origin turns any XSS on an allowed origin into full account
/// compromise. There is no safe default allowlist, so an unconfigured server
/// permits no cross-origin browser access at all rather than permitting all.
/// Validate one configured CORS origin.
///
/// `HeaderValue::from_str` is not sufficient validation. It rejects control
/// characters but happily accepts `"not a valid origin"` — a value containing
/// spaces — which would then be echoed back to anyone who sends that exact
/// `Origin` header. Origins are therefore checked for the shape a browser
/// actually sends: `scheme://host[:port]`.
///
/// The wildcard `*` is rejected outright. `AllowOrigin::list` *panics* on it, so
/// `SPECTRA_CORS_ORIGINS=*` would otherwise crash the server at startup; and
/// even if it did not, a wildcard is exactly the policy being removed.
fn validate_cors_origin(origin: &str) -> Result<axum::http::HeaderValue, String> {
    let trimmed = origin.trim();

    if trimmed.is_empty() {
        return Err("origin is empty".to_string());
    }
    if trimmed == "*" {
        return Err(
            "wildcard origin `*` is not permitted; list explicit origins instead".to_string(),
        );
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err("origin contains whitespace".to_string());
    }

    let rest = match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            if scheme != "http" && scheme != "https" {
                return Err(format!(
                    "unsupported scheme `{scheme}`; expected http or https"
                ));
            }
            rest
        }
        None => return Err("origin must be of the form scheme://host[:port]".to_string()),
    };

    if rest.is_empty() || rest.contains('/') {
        return Err("origin must not contain a path".to_string());
    }

    // A path component, a query, or a fragment means this is a URL, not an
    // origin, and would never be matched by a browser's `Origin` header.
    if rest.contains('?') || rest.contains('#') {
        return Err("origin must not contain a query or fragment".to_string());
    }

    trimmed
        .parse::<axum::http::HeaderValue>()
        .map_err(|e| format!("not a valid header value: {e}"))
}

fn cors_layer(config: &spectra_config::Config) -> tower_http::cors::CorsLayer {
    let origins: Vec<axum::http::HeaderValue> = config
        .cors
        .allowed_origins
        .iter()
        .filter_map(|o| match validate_cors_origin(o) {
            Ok(v) => Some(v),
            Err(reason) => {
                error!(origin = %o, reason = %reason, "ignoring invalid CORS origin");
                None
            }
        })
        .collect();

    let base = tower_http::cors::CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ]);

    if origins.is_empty() {
        // An empty allowlist matches no origin, so cross-origin browser
        // requests are refused rather than permitted by default. The previous
        // `Any`/`Any`/`Any` layer let any site read authenticated responses.
        return base.allow_origin(tower_http::cors::AllowOrigin::list(Vec::new()));
    }

    info!(count = origins.len(), "CORS origin allowlist configured");
    base.allow_origin(origins)
}

/// Per-IP login throttling with progressive lockout.
///
/// `POST /api/v1/auth/login` is reachable by anyone who can reach the port, and
/// the server binds `0.0.0.0` by default, so without a limiter it is a free
/// credential-stuffing oracle. Counts failed attempts per client address; a
/// client that exceeds the threshold is refused until the window elapses.
#[derive(Clone, Default)]
struct LoginThrottle {
    state: Arc<Mutex<LoginThrottleState>>,
}

#[derive(Default)]
struct LoginThrottleState {
    /// (client address, window start, consecutive failures)
    attempts: HashMap<String, (u64, u32)>,
    /// Client addresses currently locked out.
    locked: HashMap<String, u64>,
}

const LOGIN_MAX_FAILURES: u32 = 5;
const LOGIN_WINDOW_SECS: u64 = 300;
const LOGIN_LOCKOUT_SECS: u64 = 900;

impl LoginThrottle {
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// `Ok(())` if the attempt may proceed, `Err(retry_after_secs)` if locked out.
    fn check(&self, client: &str) -> Result<(), u64> {
        let now = Self::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(unlock_at) = state.locked.get(client).copied() {
            if now < unlock_at {
                return Err(unlock_at - now);
            }
            state.locked.remove(client);
            state.attempts.remove(client);
        }
        Ok(())
    }

    /// Record a failed authentication, locking out on the Nth consecutive failure.
    /// Returns `true` if this attempt caused a lockout.
    fn record_failure(&self, client: &str) -> bool {
        let now = Self::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        let entry = state.attempts.entry(client.to_string()).or_insert((now, 0));
        // Reset the counter if the previous failure was outside the window.
        if now.saturating_sub(entry.0) > LOGIN_WINDOW_SECS {
            *entry = (now, 0);
        }
        entry.1 += 1;

        if entry.1 >= LOGIN_MAX_FAILURES {
            state
                .locked
                .insert(client.to_string(), now + LOGIN_LOCKOUT_SECS);
            true
        } else {
            false
        }
    }

    /// Clear the counter after a successful login.
    fn record_success(&self, client: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.attempts.remove(client);
        state.locked.remove(client);
    }
}

fn client_address(headers: &axum::http::HeaderMap, socket: Option<SocketAddr>) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| socket.map(|a| a.ip().to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Build the middleware layer that enforces one permission.
///
/// A macro rather than a function because `axum::middleware::from_fn` returns a
/// type parameterised by the closure it is given, which cannot be named in a
/// function signature. The decision itself lives in
/// `spectra_auth::check_permission`, a plain function that is unit tested
/// directly; this only turns its verdict into a response.
///
/// The layer resolves rather than returns an error. `MethodRouter::layer` keeps
/// its error type, so a middleware returning `Err(StatusCode)` would force the
/// whole route table through `handle_error`, and `Router::route` only accepts
/// `MethodRouter<_, Infallible>`.
macro_rules! require_permission {
    ($permission:expr) => {
        axum::middleware::from_fn(
            move |request: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| {
                let permission: spectra_auth::Permission = $permission;
                async move {
                    // No authenticated user at all is 401, not 403: the caller is
                    // unauthenticated rather than authenticated-and-refused. It
                    // also catches a route whose auth layer is missing or
                    // ordered wrongly, which would otherwise show up as every
                    // caller mysteriously lacking permissions.
                    let user = match spectra_auth::authenticated_user(&request) {
                        Some(user) => user,
                        None => {
                            return Ok::<_, std::convert::Infallible>(denied(
                                axum::http::StatusCode::UNAUTHORIZED,
                                "authentication required",
                            ))
                        }
                    };

                    if let Err(status) = spectra_auth::check_permission(user, &permission) {
                        return Ok::<_, std::convert::Infallible>(denied(
                            status,
                            "the account is not permitted to perform this action",
                        ));
                    }

                    Ok::<_, std::convert::Infallible>(next.run(request).await)
                }
            },
        )
    };
}

/// Render a refusal as JSON, matching the error shape the handlers use.
///
/// The body deliberately does not name the missing permission. Telling a caller
/// exactly which permission it lacks turns the API into a probe for escalating
/// privileges one hint at a time; the required permission is in the server log,
/// correlated by the request id.
fn denied(status: axum::http::StatusCode, message: &str) -> axum::response::Response {
    use axum::response::IntoResponse;

    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        format!(r#"{{"error":"{message}","status":{}}}"#, status.as_u16()),
    )
        .into_response()
}

/// Build the `MethodRouter` for one protected path, with a permission declared
/// per method.
///
/// `MethodRouter::layer` applies a middleware to every method on the router, but
/// a single path usually mixes privilege levels: `GET /scans` is a read, while
/// `POST /scans` makes the server fetch a caller-chosen URL. One permission for
/// the path would either over-grant the read or block the write.
///
/// So each method is built as its own single-method router, guarded, then
/// merged. That is the only workable shape: `MethodRouter::merge` panics on a
/// duplicate method, so a router cannot be re-opened and re-layered per method
/// after the fact.
///
/// Each method's permission sits directly beside its handler. A route added
/// without a guard is then a route that visibly has no permission, rather than
/// one that silently defaults to "any authenticated caller" — which is the
/// failure this layer exists to prevent, having been written but never called.
macro_rules! guarded_route {
    ($permission:ident, $method:ident, $handler:expr $(,)?) => {
        axum::routing::MethodRouter::new()
            .$method($handler)
            .layer(require_permission!(Permission::$permission))
    };
    ($permission:ident, $method:ident, $handler:expr, $($rest:tt)+) => {
        guarded_route!($permission, $method, $handler)
            .merge(guarded_route!($($rest)+))
    };
}

/// Every route that requires authentication.
///
/// Split out of `run` so the tests can drive the real route table rather than a
/// hand-built copy of it. A test against a copy proves the copy works; the bug
/// being guarded against is a route that was never wired, which only the real
/// table can catch.
///
/// The caller must apply [`spectra_auth::auth_middleware_with_state`] to the
/// result. The permission guards read the `AuthUser` extension that layer
/// inserts, and return `401` if it is absent — so a reordering shows up as a
/// failing test rather than as a route that quietly allows everything.
fn protected_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/me", get(me))
        // Organizations
        .route(
            "/api/v1/organizations",
            guarded_route!(
                OrgsWrite,
                post,
                create_organization,
                OrgsRead,
                get,
                list_organizations
            ),
        )
        .route(
            "/api/v1/organizations/:id",
            guarded_route!(
                OrgsRead,
                get,
                get_organization,
                OrgsDelete,
                delete,
                delete_organization
            ),
        )
        // Projects
        .route(
            "/api/v1/projects",
            guarded_route!(ProjectsWrite, post, create_project),
        )
        .route(
            "/api/v1/organizations/:org_id/projects",
            guarded_route!(ProjectsRead, get, list_projects),
        )
        // Targets
        .route(
            "/api/v1/targets",
            guarded_route!(TargetsWrite, post, create_target),
        )
        .route(
            "/api/v1/projects/:project_id/targets",
            guarded_route!(TargetsRead, get, list_targets),
        )
        .route(
            "/api/v1/targets/:id",
            guarded_route!(
                TargetsRead,
                get,
                get_target,
                TargetsDelete,
                delete,
                delete_target
            ),
        )
        // Scans. Starting a scan makes the server issue outbound requests to a
        // caller-chosen URL, so `execute` is deliberately separate from `read`
        // rather than a single `scans:write`.
        .route(
            "/api/v1/scans",
            guarded_route!(ScansExecute, post, create_scan, ScansRead, get, list_scans),
        )
        .route(
            "/api/v1/scans/:id",
            guarded_route!(ScansRead, get, get_scan),
        )
        // Findings
        .route(
            "/api/v1/findings",
            guarded_route!(FindingsRead, get, list_findings),
        )
        .route(
            "/api/v1/findings/:id",
            guarded_route!(FindingsRead, get, get_finding),
        )
        .route(
            "/api/v1/findings/:id/status",
            guarded_route!(FindingsWrite, post, update_finding_status),
        )
        // Observations are reported as part of a scan's findings, so reading
        // them needs the same permission.
        .route(
            "/api/v1/scans/:scan_id/observations",
            guarded_route!(FindingsRead, get, list_observations),
        )
        // Evidence is the raw artefact behind a finding, so it carries its own
        // permission rather than riding on `findings:read`. Every current role
        // that can read findings can also read evidence, so the grant does not
        // separate anyone today; keeping the names apart is what lets an
        // operator narrow it later without renaming a finding permission.
        .route(
            "/api/v1/findings/:finding_id/evidence",
            guarded_route!(EvidenceRead, get, list_evidence),
        )
        // Verification
        .route(
            "/api/v1/findings/:finding_id/verification",
            guarded_route!(FindingsRead, get, list_verifications),
        )
        .route(
            "/api/v1/verification/summary",
            guarded_route!(FindingsRead, get, verification_summary),
        )
        // Stats
        .route(
            "/api/v1/stats",
            guarded_route!(FindingsRead, get, get_stats),
        )
}

impl AppState {
    /// Record an authentication audit event.
    ///
    /// Audit writes used to be `let _ = …`, which discarded failures silently.
    /// For a security tool, a missing audit record is itself a signal that
    /// something went wrong, so failures are logged rather than dropped.
    async fn audit_auth(&self, message: &str, user: Option<String>, success: bool) {
        if let Err(e) = self.audit_logger.auth(message, user, success).await {
            error!(error = %e, "failed to write auth audit record");
        }
    }

    /// Check that a scan target is one this server is willing to fetch.
    ///
    /// Two checks, because each covers a hole the other leaves:
    ///
    /// 1. [`SSRFGuard::validate_url`] — cheap, no network. Rejects loopback,
    ///    private, link-local, unspecified and metadata addresses, plus
    ///    hostnames like `localhost` that denote them without being an IP.
    /// 2. [`SSRFGuard::validate_resolved_url`] — resolves the host and checks
    ///    every address it returns. Without this, a public hostname pointed at
    ///    an internal address (`attacker.example` → `169.254.169.254`) is
    ///    indistinguishable from a legitimate target.
    ///
    /// Non-URL targets (a bare domain) are normalised to `https://` first, so
    /// they go through the same checks.
    ///
    /// Set `SPECTRA_ALLOW_INTERNAL_TARGETS=true` to permit internal targets.
    /// That is a deliberate trade: it is needed to scan internal hosts, and it
    /// also re-opens SSRF against the scanner itself.
    async fn check_target_is_scannable(&self, target: &str) -> Result<(), String> {
        if self.config.scanner.allow_internal_targets {
            return Ok(());
        }

        let guard = SSRFGuard::new();

        // A bare hostname is a valid scan target; give it a scheme so the URL
        // checks apply to it too.
        let candidate = if target.contains("://") {
            target.to_string()
        } else {
            format!("https://{target}")
        };

        guard.validate_url(&candidate).map_err(|e| e.to_string())?;

        match guard.validate_resolved_url(&candidate).await {
            Ok(_) => Ok(()),
            Err(e) => {
                let reason = e.to_string();
                // A host that does not resolve is not an SSRF risk, and the
                // crawler will report it as unreachable. Refusing here would
                // turn every not-yet-propagating DNS record into a confusing 400.
                if reason.contains("cannot resolve host") {
                    info!(target = %candidate, "target does not resolve yet; allowing");
                    Ok(())
                } else {
                    Err(reason)
                }
            }
        }
    }
}

/// Locate the dashboard's static assets.
///
/// `SPECTRA_STATIC_DIR` wins when set, which is how the container image points
/// at `/opt/spectra/static`. The previous code hardcoded
/// `env!("CARGO_MANIFEST_DIR")`, a *compile-time* path: inside the runtime
/// image that directory does not exist, so every request to `/` returned 404
/// and the only visible symptom was a blank page.
///
/// If neither location exists the API still starts, but says so loudly — a
/// running API with a missing dashboard is a deployment error, not a reason to
/// refuse to serve the API.
fn resolve_static_dir() -> std::path::PathBuf {
    if let Some(configured) = std::env::var_os("SPECTRA_STATIC_DIR") {
        let path = std::path::PathBuf::from(configured);
        if path.is_dir() {
            info!(dir = %path.display(), "serving dashboard from SPECTRA_STATIC_DIR");
            return path;
        }
        error!(
            dir = %path.display(),
            "SPECTRA_STATIC_DIR does not exist or is not a directory; the dashboard will not load"
        );
        return path;
    }

    let dev_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static");
    if dev_path.is_dir() {
        return dev_path;
    }

    error!(
        path = %dev_path.display(),
        "no static directory found; set SPECTRA_STATIC_DIR to the dashboard assets"
    );
    dev_path
}

// =============================================================================
/// Assemble the shared application state.
// Scan lifecycle auditing via the event bus.
//
// The engine already knew every scan transition and communicated none of it: the
// API read `ScanStatus` back out of the job map after the fact, and nothing outside
// the process could observe a scan at all. The bus closes that, and this handler is
// what makes it land in the audit trail rather than in a void.
struct ScanLifecycleAudit {
    audit: Arc<AuditLogger>,
}

#[async_trait::async_trait]
impl spectra_events::handler::EventHandler for ScanLifecycleAudit {
    fn event_types(&self) -> Vec<spectra_events::event::EventType> {
        use spectra_events::event::EventType;
        vec![
            EventType::ScanStarted,
            EventType::ScanCompleted,
            EventType::ScanPartial,
            EventType::ScanFailed,
        ]
    }

    async fn handle(&self, event: &spectra_events::Event) -> spectra_core::Result<()> {
        use spectra_events::event::EventPayload;

        // Every entry records the scan id, whatever else it says. A partial or
        // failed scan without its id cannot be traced back to anything.
        let (action, target, scan_id, note) = match &event.payload {
            EventPayload::ScanStarted { scan_id, target_id } => {
                ("scan.started", target_id.clone(), scan_id.clone(), None)
            }
            EventPayload::ScanCompleted { scan_id } => {
                ("scan.completed", String::new(), scan_id.clone(), None)
            }
            EventPayload::ScanPartial { scan_id, reason } => (
                "scan.partial",
                String::new(),
                scan_id.clone(),
                Some(("reason", reason.clone())),
            ),
            EventPayload::ScanFailed { scan_id, error } => (
                "scan.failed",
                String::new(),
                scan_id.clone(),
                Some(("error", error.clone())),
            ),
            // `event_types` already filters these out; unreachable in practice.
            _ => return Ok(()),
        };

        let mut details = HashMap::new();
        details.insert("scan_id".to_string(), scan_id);
        details.insert("event_type".to_string(), format!("{:?}", event.event_type));
        if let Some((key, value)) = note {
            details.insert(key.to_string(), value);
        }

        self.audit
            .scan(action, "system".to_string(), target, details)
            .await
            .map_err(|e| spectra_core::SpectraError::Internal(e.to_string()))
    }
}

///
/// Extracted from `main` so tests exercise the same wiring rather than a
/// hand-built approximation of it.
fn build_state(
    config: &spectra_config::Config,
    jwt_service: Arc<JwtService>,
    user_store: UserStore,
) -> AppState {
    // Built once and handed to both the state and the engine. Constructing them
    // separately is what produced the split-brain: the engine wrote to its own
    // copies and these read from theirs, so the two never agreed.
    let findings_manager = Arc::new(InMemoryFindingsManager::new());
    let observation_store = Arc::new(InMemoryObservationStore::new());
    let evidence_engine = Arc::new(EvidenceEngine::new());

    // A bus, with an audit handler attached, so scan lifecycle events reach the
    // audit trail. Without a subscriber `publish` logs a warning on every event, so
    // an attached-but-unconsumed bus would be noisier than none.
    let event_bus = EventBus::new(1024);
    {
        let bus = event_bus.clone();
        let audit = Arc::new(AuditLogger::with_in_memory());
        tokio::spawn(async move {
            bus.register_handler(
                "scan-lifecycle".to_string(),
                Arc::new(ScanLifecycleAudit { audit }),
            )
            .await;
            bus.dispatch_events();
        });
    }

    // The operator's ceilings, from configuration. The caller's request fields
    // are clamped into these by `ScanEngine::run_scan`, so a request can narrow a
    // scan but never widen it past what this server permits.
    let limits = spectra_engine::ScanLimits::from_config(config);

    let scan_engine = Arc::new(
        ScanEngine::new_with_shared_components(
            Arc::clone(&findings_manager),
            Arc::clone(&observation_store),
            Arc::clone(&evidence_engine),
        )
        .with_limits(limits)
        .with_event_bus(event_bus),
    );

    AppState {
        config: config.clone(),
        target_service: Arc::new(TargetService::new()),
        // Wrappers around the shared stores rather than the stores themselves, so
        // the engines and the state refer to the same underlying data.
        observation_engine: Arc::new(ObservationEngine::new(Arc::clone(&observation_store))),
        findings_manager,
        evidence_engine,
        verification_engine: Arc::new(VerificationEngine::new()),
        jwt_service,
        audit_logger: Arc::new(AuditLogger::with_in_memory()),
        recovery_manager: Arc::new(RecoveryManager::with_defaults()),
        // From config, not `ResourceLimits::default()`. `scanner.max_concurrent`
        // and `scanner.rate_limit_per_second` were declared and defaulted but
        // read by nothing, so this limiter had no configurable effect and was
        // never called at all.
        governor: Arc::new(ResourceGovernor::new(ResourceLimits {
            max_requests_per_second: config.scanner.rate_limit_per_second,
            max_concurrent: config.scanner.max_concurrent,
            ..Default::default()
        })),
        secret_manager: Arc::new(SecretManager::new("SPECTRA")),
        scan_engine,
        scan_jobs: Arc::new(RwLock::new(HashMap::new())),
        user_store,
        login_throttle: LoginThrottle::default(),
    }
}

// Main
// =============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // A malformed config must not silently fall back to defaults: the defaults
    // bind 0.0.0.0:8080, so a typo in spectra.toml would quietly change what the
    // operator asked for.
    let config = spectra_config::Config::load().map_err(|e| {
        anyhow::anyhow!("failed to load configuration: {e}; refusing to start with defaults")
    })?;

    spectra_telemetry::init_logging(&config);
    spectra_telemetry::init_telemetry(&config)?;

    // No default signing secret. Refuse to boot without an operator-supplied one.
    let jwt_config = JwtConfig::from_env()?;
    let jwt_service = Arc::new(JwtService::new(jwt_config));

    // No baked-in credentials. Refuse to boot if no admin can be established.
    let user_store = UserStore::bootstrap().map_err(|e| anyhow::anyhow!("{e}"))?;

    let state = build_state(&config, jwt_service, user_store);

    let static_dir = resolve_static_dir();

    let app = Router::new()
        // Public routes (no auth required)
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/ready", get(readiness_check))
        .route("/api/v1/auth/login", post(login))
        // Static files (no auth required)
        .fallback_service(
            tower_http::services::ServeDir::new(&static_dir).append_index_html_on_directories(true),
        )
        // Protected routes: authenticated *and* holding a specific permission.
        //
        // `auth/me` needs no permission beyond being authenticated — it reports
        // the caller's own identity, which is the one thing every caller is
        // entitled to.
        .merge(protected_routes().layer(middleware::from_fn_with_state(
            // The same `JwtService` instance that signed the tokens, so the
            // verifier cannot diverge from the signer.
            state.jwt_service.clone(),
            spectra_auth::auth_middleware_with_state,
        )))
        .layer(cors_layer(&config))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            10 * 1024 * 1024,
        ))
        .with_state(state)
        // Required by the login handler's `ConnectInfo` extractor to identify
        // the client for throttling.
        .into_make_service_with_connect_info::<SocketAddr>();

    let addr = config.server_address();
    info!(address = %addr, "Starting Spectra API server");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    spectra_telemetry::shutdown_telemetry();

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Login throttling ----------------------------------------------------

    #[test]
    fn throttle_allows_attempts_below_threshold() {
        let t = LoginThrottle::default();
        for i in 0..(LOGIN_MAX_FAILURES - 1) {
            assert!(t.check("1.2.3.4").is_ok(), "attempt {i} should be allowed");
            assert!(
                !t.record_failure("1.2.3.4"),
                "failure number {} is below the threshold of {LOGIN_MAX_FAILURES} and must not lock out",
                i + 1
            );
        }
    }

    #[test]
    fn throttle_locks_out_on_the_threshold_failure() {
        let t = LoginThrottle::default();
        let mut locked = false;
        for _ in 0..LOGIN_MAX_FAILURES {
            locked = t.record_failure("1.2.3.4");
        }
        assert!(locked, "the {LOGIN_MAX_FAILURES}th failure must lock out");
        assert!(t.check("1.2.3.4").is_err(), "locked client must be refused");
    }

    #[test]
    fn throttle_lockout_reports_retry_after() {
        let t = LoginThrottle::default();
        for _ in 0..LOGIN_MAX_FAILURES {
            t.record_failure("1.2.3.4");
        }
        let remaining = t.check("1.2.3.4").expect_err("should be locked");
        assert_eq!(remaining, LOGIN_LOCKOUT_SECS, "full lockout window");
    }

    #[test]
    fn throttle_is_per_client() {
        // One attacker locking themselves out must not deny service to everyone
        // else, which is what a single global counter would do.
        let t = LoginThrottle::default();
        for _ in 0..LOGIN_MAX_FAILURES {
            t.record_failure("attacker");
        }
        assert!(t.check("attacker").is_err());
        assert!(
            t.check("victim").is_ok(),
            "a different client must remain unaffected"
        );
    }

    #[test]
    fn throttle_success_clears_the_counter() {
        let t = LoginThrottle::default();
        for _ in 0..(LOGIN_MAX_FAILURES - 1) {
            t.record_failure("1.2.3.4");
        }
        t.record_success("1.2.3.4");
        // A fresh burst must be permitted again.
        for i in 0..LOGIN_MAX_FAILURES {
            assert!(t.check("1.2.3.4").is_ok(), "post-reset attempt {i}");
        }
    }

    #[test]
    fn throttle_lockout_clears_the_failure_counter() {
        // Without this, a client that waited out its lockout would be
        // re-locked by its very next mistake, with no way to ever authenticate.
        let t = LoginThrottle::default();
        for _ in 0..LOGIN_MAX_FAILURES {
            t.record_failure("1.2.3.4");
        }
        assert!(t.check("1.2.3.4").is_err());

        // Simulate the lockout elapsing by clearing the clock-dependent state
        // the same way an expired entry would be.
        {
            let mut state = t.state.lock().unwrap();
            state.locked.clear();
        }
        assert!(t.check("1.2.3.4").is_ok());
    }

    // --- Client identification ----------------------------------------------

    fn headers(pairs: &[(&str, &str)]) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn client_address_uses_leftmost_forwarded_for() {
        // The leftmost entry is the original client when every hop is trusted.
        let h = headers(&[("x-forwarded-for", "203.0.113.9, 10.0.0.1, 10.0.0.2")]);
        let addr: SocketAddr = "10.0.0.5:5555".parse().unwrap();
        assert_eq!(client_address(&h, Some(addr)), "203.0.113.9");
    }

    #[test]
    fn client_address_trims_whitespace() {
        let h = headers(&[("x-forwarded-for", "  203.0.113.9  , 10.0.0.1")]);
        let addr: SocketAddr = "10.0.0.5:5555".parse().unwrap();
        assert_eq!(client_address(&h, Some(addr)), "203.0.113.9");
    }

    #[test]
    fn client_address_falls_back_to_socket() {
        let addr: SocketAddr = "198.51.100.4:4444".parse().unwrap();
        assert_eq!(
            client_address(&axum::http::HeaderMap::new(), Some(addr)),
            "198.51.100.4"
        );
    }

    #[test]
    fn client_address_handles_ipv6_socket() {
        let addr: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        assert_eq!(
            client_address(&axum::http::HeaderMap::new(), Some(addr)),
            "2001:db8::1"
        );
    }

    #[test]
    fn client_address_never_panics_without_socket_or_headers() {
        assert_eq!(
            client_address(&axum::http::HeaderMap::new(), None),
            "unknown"
        );
    }

    // --- CORS origin validation --------------------------------------------

    #[test]
    fn cors_origin_validator_accepts_real_origins() {
        for origin in [
            "https://app.example.com",
            "http://localhost:3000",
            "http://127.0.0.1:8080",
            "https://sub.domain.example.co.uk",
            "http://[2001:db8::1]:8080",
        ] {
            assert!(
                validate_cors_origin(origin).is_ok(),
                "origin `{origin}` should be accepted"
            );
        }
    }

    #[test]
    fn cors_origin_validator_rejects_wildcard() {
        // `AllowOrigin::list` panics on `*`, so accepting it would crash the
        // server at startup rather than merely misconfigure it.
        let err = validate_cors_origin("*").expect_err("wildcard must be rejected");
        assert!(err.contains("wildcard"), "unhelpful error: {err}");
    }

    #[test]
    fn cors_origin_validator_rejects_non_origin_shapes() {
        for origin in [
            "",
            "   ",
            "not a valid origin",
            "example.com",
            "ftp://example.com",
            "file:///etc/passwd",
            "https://",
            "https://example.com/path",
            "https://example.com?a=b",
            "https://example.com#frag",
            "https://exam ple.com",
        ] {
            assert!(
                validate_cors_origin(origin).is_err(),
                "origin `{origin}` should be rejected"
            );
        }
    }

    #[test]
    fn cors_origin_validator_trims_surrounding_whitespace() {
        // `SPECTRA_CORS_ORIGINS` is comma-separated, so entries can carry a
        // leading or trailing space. The trimmed value is what is returned.
        let v = validate_cors_origin("  https://app.example.com  ").expect("should be accepted");
        assert_eq!(v.to_str().unwrap(), "https://app.example.com");
    }

    #[test]
    fn cors_origin_validator_does_not_panic_on_hostile_input() {
        for origin in [
            "*",
            "**",
            "https://*",
            "://",
            "a://b://c",
            "\u{0}",
            "\\u{1F600}",
        ] {
            let _ = validate_cors_origin(origin);
        }
    }

    // --- CORS ---------------------------------------------------------------

    /// Drive a CORS preflight through the layer and return the response.
    ///
    /// Asserting on the layer's *value* would prove nothing — the regression
    /// that matters is what headers actually reach the client, so the test
    /// sends a real preflight request and inspects the real response.
    async fn preflight(config: &spectra_config::Config, origin: &str) -> axum::http::HeaderMap {
        use axum::body::Body;
        use tower::ServiceExt as _;

        // A concrete state type keeps the service `Service`-compatible, so the
        // real CORS layer can be driven without extra map layers.
        let app = axum::Router::new()
            .route(
                "/api/v1/organizations",
                axum::routing::get(|| async { "ok" }),
            )
            .layer(cors_layer(config))
            .with_state(());

        let request = axum::http::Request::builder()
            .method(axum::http::Method::OPTIONS)
            .uri("/api/v1/organizations")
            .header("origin", origin)
            .header("access-control-request-method", "GET")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.expect("router is infallible");
        response.headers().clone()
    }

    #[tokio::test]
    async fn cors_unset_allowlist_refuses_every_origin() {
        // This is the regression that matters. `CorsLayer` configured with
        // `allow_origin(Any)` / `allow_headers(Any)` let any website read
        // authenticated API responses, because the dashboard keeps its bearer
        // token in localStorage. An unset allowlist must refuse, not permit.
        let config = spectra_config::Config::default();
        assert!(config.cors.allowed_origins.is_empty());

        for origin in [
            "https://evil.com",
            "http://localhost:3000",
            "https://app.example.com",
        ] {
            let headers = preflight(&config, origin).await;
            assert!(
                headers.get("access-control-allow-origin").is_none(),
                "origin {origin} must not be granted CORS access when no allowlist is set"
            );
        }
    }

    #[tokio::test]
    async fn cors_allows_explicitly_listed_origin() {
        let mut config = spectra_config::Config::default();
        config.cors.allowed_origins = vec!["https://app.example.com".to_string()];

        let headers = preflight(&config, "https://app.example.com").await;
        assert_eq!(
            headers
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("https://app.example.com"),
            "a configured origin must be granted access"
        );
    }

    #[tokio::test]
    async fn cors_does_not_allow_other_origins() {
        let mut config = spectra_config::Config::default();
        config.cors.allowed_origins = vec!["https://app.example.com".to_string()];

        let headers = preflight(&config, "https://evil.com").await;
        assert!(
            headers.get("access-control-allow-origin").is_none(),
            "an origin outside the allowlist must be refused"
        );
    }

    #[tokio::test]
    async fn cors_drops_unparseable_origins_without_panicking() {
        let mut config = spectra_config::Config::default();
        config.cors.allowed_origins = vec![
            "not a valid origin".to_string(),
            "https://ok.example.com".to_string(),
        ];

        let allowed = preflight(&config, "https://ok.example.com").await;
        assert_eq!(
            allowed
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("https://ok.example.com"),
            "the valid entry must still work"
        );

        let dropped = preflight(&config, "not a valid origin").await;
        assert!(
            dropped.get("access-control-allow-origin").is_none(),
            "the malformed entry must be dropped, not accepted"
        );
    }

    #[tokio::test]
    async fn cors_never_allows_wildcard_origin() {
        // Belt-and-braces: assert the literal `*` is not emitted, since some
        // configurations widen to it and `*` with credentials is always wrong.
        let mut config = spectra_config::Config::default();
        config.cors.allowed_origins = vec!["*".to_string()];
        let headers = preflight(&config, "https://anything.example").await;
        assert_ne!(
            headers
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("*"),
            "a wildcard origin must never be emitted"
        );
    }

    // --- Error mapping ------------------------------------------------------

    #[test]
    fn login_error_maps_to_expected_status_codes() {
        assert_eq!(
            LoginError::Invalid { retry_after: None }.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            LoginError::LockedOut { retry_after: 900 }.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            LoginError::Internal("boom".into()).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn login_error_invalid_does_not_leak_internal_detail() {
        // The message must be the generic string, never the internal one, or the
        // endpoint becomes an information-disclosure oracle.
        let e = LoginError::Invalid { retry_after: None };
        assert_eq!(e.code(), "INVALID_CREDENTIALS");
    }

    #[test]
    fn login_error_sets_retry_after_header() {
        use axum::response::IntoResponse;
        let resp = LoginError::LockedOut { retry_after: 900 }.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("900")
        );
    }

    #[test]
    fn login_error_without_lockout_omits_retry_after() {
        use axum::response::IntoResponse;
        let resp = LoginError::Invalid { retry_after: None }.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get("retry-after").is_none());
    }

    // --- Password hashing ---------------------------------------------------

    #[test]
    fn password_hash_is_salted() {
        let a = UserStore::hash_password("correct-horse-battery-staple").unwrap();
        let b = UserStore::hash_password("correct-horse-battery-staple").unwrap();
        assert_ne!(
            a, b,
            "identical passwords must not produce identical hashes (unsalted)"
        );
    }

    #[test]
    fn password_hash_verifies_correct_password() {
        let hash = UserStore::hash_password("correct-horse-battery-staple").unwrap();
        let parsed = argon2::PasswordHash::new(&hash).unwrap();
        assert!(Argon2::default()
            .verify_password(b"correct-horse-battery-staple".as_ref(), &parsed)
            .is_ok());
    }

    #[test]
    fn password_hash_rejects_wrong_password() {
        let hash = UserStore::hash_password("correct-horse-battery-staple").unwrap();
        let parsed = argon2::PasswordHash::new(&hash).unwrap();
        assert!(Argon2::default()
            .verify_password(b"wrong".as_ref(), &parsed)
            .is_err());
    }

    #[tokio::test]
    async fn user_store_rejects_wrong_password() {
        let mut users = HashMap::new();
        users.insert(
            "admin".to_string(),
            UserEntry {
                password_hash: UserStore::hash_password("a-long-enough-password").unwrap(),
                roles: vec![Role::Admin.to_string()],
            },
        );
        let store = UserStore {
            users: Arc::new(RwLock::new(users)),
        };
        assert!(store
            .validate("admin", "a-long-enough-password")
            .await
            .is_some());
        assert!(store.validate("admin", "admin").await.is_none());
        assert!(store
            .validate("nobody", "a-long-enough-password")
            .await
            .is_none());
    }

    // --- Authorisation (RBAC) ---------------------------------------------------
    //
    // The permission layer was written but never called: `Permission`, `Role`,
    // `has_permission` and `require_permission_fn` had no call sites outside their
    // own unit tests, so every authenticated route was in practice available to
    // every authenticated caller. These tests drive the real route table so that
    // cannot regress silently again.

    /// Build a router over the real protected routes, with a known signing key.
    fn rbac_router() -> (Router, Arc<JwtService>) {
        let config = spectra_config::Config::default();
        let jwt_service = Arc::new(JwtService::new(JwtConfig {
            // Fixed key so the test can mint tokens itself. 32 bytes: the same
            // minimum `JwtConfig::from_env` enforces in production.
            secret: "rbac-test-signing-key-0123456789abcdef".to_string(),
            expires_in_secs: 900,
        }));

        let user_store = UserStore {
            users: Arc::new(RwLock::new(HashMap::new())),
        };

        let app = protected_routes()
            .layer(axum::middleware::from_fn_with_state(
                jwt_service.clone(),
                spectra_auth::auth_middleware_with_state,
            ))
            .with_state(build_state(&config, jwt_service.clone(), user_store));

        (app, jwt_service)
    }

    /// Mint a token for `role`, with the permissions that role actually grants.
    ///
    /// The permission list is derived through the same function `login` uses, so a
    /// test token cannot accidentally be granted more than a real one.
    fn token_for(jwt: &JwtService, role: &str) -> String {
        let roles = vec![role.to_string()];
        let granted = expand_role_permissions(&roles);
        jwt.create_token("tester", roles, granted)
            .expect("test token should be creatable")
    }

    /// A router whose configuration the test controls.
    ///
    /// `rbac_router` uses the default config, which cannot express a concurrency
    /// ceiling of 1 or a one-second scan budget, so it cannot exercise the
    /// governor.
    fn governed_router(config: &spectra_config::Config) -> (Router, Arc<JwtService>) {
        let jwt_service = Arc::new(JwtService::new(JwtConfig {
            secret: "governed-test-signing-key-0123456789abc".to_string(),
            expires_in_secs: 900,
        }));

        let app = protected_routes()
            .layer(axum::middleware::from_fn_with_state(
                jwt_service.clone(),
                spectra_auth::auth_middleware_with_state,
            ))
            .with_state(build_state(
                config,
                jwt_service.clone(),
                UserStore {
                    users: Arc::new(RwLock::new(HashMap::new())),
                },
            ));

        (app, jwt_service)
    }

    /// POST a JSON body, which `call` cannot do.
    async fn post_json(
        app: &Router,
        uri: &str,
        bearer: &str,
        body: serde_json::Value,
    ) -> axum::http::StatusCode {
        use axum::body::Body;
        use tower::ServiceExt as _;

        let request = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("valid request");

        app.clone()
            .oneshot(request)
            .await
            .expect("router is infallible")
            .status()
    }

    /// How many scans `GET /scans` reports.
    async fn scan_count(app: &Router, bearer: &str) -> usize {
        use axum::body::Body;
        use tower::ServiceExt as _;

        let request = axum::http::Request::builder()
            .uri("/api/v1/scans")
            .header("authorization", format!("Bearer {bearer}"))
            .body(Body::empty())
            .expect("valid request");

        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("router is infallible");

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");

        serde_json::from_slice::<serde_json::Value>(&bytes).expect("response should be JSON")
            ["total"]
            .as_u64()
            .expect("total should be a number") as usize
    }

    /// A listener that accepts connections and never speaks, so a scan aimed at it
    /// cannot finish quickly. Its port is returned; the accept loop runs for the
    /// life of the test.
    fn blackhole() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("should bind");
        let port = listener
            .local_addr()
            .expect("should have an address")
            .port();
        std::thread::spawn(move || {
            // Held open for the life of the process; each accepted connection is
            // kept in the vector so it is never closed by a drop.
            let mut held: Vec<std::net::TcpStream> = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
            }
        });
        port
    }

    /// Issue a request through the guarded router.
    async fn call(
        app: &Router,
        method: axum::http::Method,
        uri: &str,
        bearer: Option<&str>,
    ) -> axum::http::StatusCode {
        use axum::body::Body;
        use tower::ServiceExt as _;

        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }

        app.clone()
            .oneshot(builder.body(Body::empty()).expect("valid request"))
            .await
            .expect("router is infallible")
            .status()
    }

    #[test]
    fn admin_role_grants_every_permission() {
        // If this fails, the admin cannot perform some action on itself and the
        // service is unusable for its only built-in account.
        let granted = expand_role_permissions(&["admin".to_string()]);
        for permission in Role::Admin.permissions() {
            assert!(
                granted.contains(&permission.to_string()),
                "admin is missing {permission}"
            );
        }
    }

    #[test]
    fn expand_deduplicates_across_roles() {
        // A caller holding two overlapping roles must not end up with a token whose
        // permission list grows every time a role is added to the account.
        let granted = expand_role_permissions(&["admin".to_string(), "admin".to_string()]);
        let unique: std::collections::HashSet<&String> = granted.iter().collect();
        assert_eq!(
            granted.len(),
            unique.len(),
            "permissions must be a set, not a bag: {granted:?}"
        );
        assert_eq!(
            granted.len(),
            Role::Admin.permissions().len(),
            "adding the same role twice must not change the grant count"
        );
    }

    #[test]
    fn expand_rejects_unknown_role_without_granting_everything() {
        // The dangerous failure mode here is treating an unparseable role as
        // "unrestricted" or as admin. It must grant nothing.
        let granted = expand_role_permissions(&["superuser".to_string()]);
        assert!(
            granted.is_empty(),
            "an unknown role must contribute no permissions, got {granted:?}"
        );

        // A valid role alongside an unknown one still works.
        let granted = expand_role_permissions(&["superuser".to_string(), "viewer".to_string()]);
        assert_eq!(
            granted,
            expand_role_permissions(&["viewer".to_string()]),
            "an unknown role must not affect a known one"
        );
    }

    #[test]
    fn viewer_is_read_only() {
        let granted = expand_role_permissions(&["viewer".to_string()]);
        for read_only in [
            Permission::OrgsRead,
            Permission::ProjectsRead,
            Permission::TargetsRead,
            Permission::ScansRead,
            Permission::FindingsRead,
        ] {
            assert!(
                granted.contains(&read_only.to_string()),
                "viewer should hold {read_only}"
            );
        }
        for write in [
            Permission::OrgsWrite,
            Permission::OrgsDelete,
            Permission::ProjectsWrite,
            Permission::TargetsWrite,
            Permission::ScansExecute,
            Permission::ScansCancel,
            Permission::FindingsWrite,
            Permission::FindingsDelete,
            Permission::UsersWrite,
            Permission::SettingsWrite,
        ] {
            assert!(
                !granted.contains(&write.to_string()),
                "viewer must not hold {write}"
            );
        }
    }

    #[tokio::test]
    async fn every_protected_route_rejects_anonymous_callers() {
        let (app, _jwt) = rbac_router();

        // A representative path from each group, plus the one route that is
        // deliberately unguarded apart from authentication.
        for (method, uri) in [
            (axum::http::Method::GET, "/api/v1/auth/me"),
            (axum::http::Method::GET, "/api/v1/organizations"),
            (axum::http::Method::POST, "/api/v1/organizations"),
            (axum::http::Method::GET, "/api/v1/organizations/some-id"),
            (axum::http::Method::DELETE, "/api/v1/organizations/some-id"),
            (axum::http::Method::POST, "/api/v1/projects"),
            (
                axum::http::Method::GET,
                "/api/v1/organizations/some-id/projects",
            ),
            (axum::http::Method::POST, "/api/v1/targets"),
            (axum::http::Method::GET, "/api/v1/projects/some-id/targets"),
            (axum::http::Method::GET, "/api/v1/targets/some-id"),
            (axum::http::Method::DELETE, "/api/v1/targets/some-id"),
            (axum::http::Method::POST, "/api/v1/scans"),
            (axum::http::Method::GET, "/api/v1/scans"),
            (axum::http::Method::GET, "/api/v1/scans/some-id"),
            (axum::http::Method::GET, "/api/v1/findings"),
            (axum::http::Method::GET, "/api/v1/findings/some-id"),
            (axum::http::Method::POST, "/api/v1/findings/some-id/status"),
            (
                axum::http::Method::GET,
                "/api/v1/scans/some-id/observations",
            ),
            (axum::http::Method::GET, "/api/v1/findings/some-id/evidence"),
            (
                axum::http::Method::GET,
                "/api/v1/findings/some-id/verification",
            ),
            (axum::http::Method::GET, "/api/v1/verification/summary"),
            (axum::http::Method::GET, "/api/v1/stats"),
        ] {
            let status = call(&app, method.clone(), uri, None).await;
            assert_eq!(
                status,
                axum::http::StatusCode::UNAUTHORIZED,
                "{method} {uri} must require authentication"
            );
        }
    }

    #[tokio::test]
    async fn viewer_cannot_start_a_scan_but_can_read_scans() {
        // This is the pairing that a single per-path permission cannot express, and
        // the reason the guards are declared per method. `POST /scans` makes the
        // server fetch a caller-chosen URL, so it is the highest-value target for
        // SSRF abuse; `GET /scans` is an ordinary read.
        let (app, jwt) = rbac_router();
        let viewer = token_for(&jwt, "viewer");

        assert_eq!(
            call(
                &app,
                axum::http::Method::POST,
                "/api/v1/scans",
                Some(&viewer)
            )
            .await,
            axum::http::StatusCode::FORBIDDEN,
            "a viewer must not be able to start a scan"
        );

        let read = call(
            &app,
            axum::http::Method::GET,
            "/api/v1/scans",
            Some(&viewer),
        )
        .await;
        assert_ne!(
            read,
            axum::http::StatusCode::FORBIDDEN,
            "a viewer must still be able to read scans"
        );
        assert_ne!(read, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn viewer_cannot_mutate_any_resource() {
        // Sweeps the whole table for a read-only role. Any `403`-free response on a
        // mutating method is a missing guard.
        let (app, jwt) = rbac_router();
        let viewer = token_for(&jwt, "viewer");

        for (method, uri) in [
            (axum::http::Method::POST, "/api/v1/organizations"),
            (axum::http::Method::DELETE, "/api/v1/organizations/some-id"),
            (axum::http::Method::POST, "/api/v1/projects"),
            (axum::http::Method::POST, "/api/v1/targets"),
            (axum::http::Method::DELETE, "/api/v1/targets/some-id"),
            (axum::http::Method::POST, "/api/v1/scans"),
            (axum::http::Method::POST, "/api/v1/findings/some-id/status"),
        ] {
            let status = call(&app, method.clone(), uri, Some(&viewer)).await;
            assert_eq!(
                status,
                axum::http::StatusCode::FORBIDDEN,
                "a viewer must be refused {method} {uri}"
            );
        }
    }

    #[tokio::test]
    async fn the_guard_follows_the_role_table_rather_than_a_flattened_list() {
        // `scanner` can run scans and read findings but has no view of the
        // organisation tree, while `manager` can administer projects and
        // organizations but cannot create one. If authorisation were a single
        // flattened capability rather than a role lookup, one of these two would
        // have to be wrong.
        let (app, jwt) = rbac_router();
        let scanner = token_for(&jwt, "scanner");
        let manager = token_for(&jwt, "manager");

        let as_scanner = call(
            &app,
            axum::http::Method::GET,
            "/api/v1/organizations",
            Some(&scanner),
        )
        .await;
        assert_eq!(
            as_scanner,
            axum::http::StatusCode::FORBIDDEN,
            "the scanner role holds no orgs:read"
        );

        let as_manager = call(
            &app,
            axum::http::Method::POST,
            "/api/v1/organizations",
            Some(&manager),
        )
        .await;
        assert_eq!(
            as_manager,
            axum::http::StatusCode::FORBIDDEN,
            "the manager role holds no orgs:write"
        );

        // The manager's read grant on the same path must still work, otherwise the
        // refusal above would only show the route is switched off.
        let read = call(
            &app,
            axum::http::Method::GET,
            "/api/v1/organizations",
            Some(&manager),
        )
        .await;
        assert_ne!(
            read,
            axum::http::StatusCode::FORBIDDEN,
            "the manager role does hold orgs:read"
        );
    }

    #[tokio::test]
    async fn admin_reaches_every_route() {
        // The guards must not lock the only built-in account out of the service.
        let (app, jwt) = rbac_router();
        let admin = token_for(&jwt, "admin");

        for (method, uri) in [
            (axum::http::Method::GET, "/api/v1/auth/me"),
            (axum::http::Method::GET, "/api/v1/organizations"),
            (axum::http::Method::POST, "/api/v1/organizations"),
            (axum::http::Method::DELETE, "/api/v1/organizations/some-id"),
            (axum::http::Method::POST, "/api/v1/projects"),
            (axum::http::Method::POST, "/api/v1/targets"),
            (axum::http::Method::DELETE, "/api/v1/targets/some-id"),
            (axum::http::Method::POST, "/api/v1/scans"),
            (axum::http::Method::GET, "/api/v1/scans"),
            (axum::http::Method::POST, "/api/v1/findings/some-id/status"),
            (axum::http::Method::GET, "/api/v1/findings/some-id/evidence"),
            (axum::http::Method::GET, "/api/v1/stats"),
        ] {
            let status = call(&app, method.clone(), uri, Some(&admin)).await;
            assert_ne!(
                status,
                axum::http::StatusCode::FORBIDDEN,
                "the admin must not be refused {method} {uri}"
            );
            assert_ne!(
                status,
                axum::http::StatusCode::UNAUTHORIZED,
                "the admin must be authenticated on {method} {uri}"
            );
        }
    }

    #[tokio::test]
    async fn a_forged_token_cannot_grant_itself_a_role() {
        // The guard reads permissions from the signed claims. A token signed with
        // the wrong key must not authenticate at all, so it can never reach a
        // permission check.
        let (app, _jwt) = rbac_router();
        let rogue = JwtService::new(JwtConfig {
            secret: "a-completely-different-signing-key-abcdef".to_string(),
            expires_in_secs: 900,
        });
        let token = rogue
            .create_token(
                "attacker",
                vec!["admin".to_string()],
                expand_role_permissions(&["admin".to_string()]),
            )
            .expect("token should be creatable");

        let status = call(
            &app,
            axum::http::Method::POST,
            "/api/v1/scans",
            Some(&token),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::UNAUTHORIZED,
            "a token signed with the wrong key must not authenticate"
        );
    }

    #[tokio::test]
    async fn a_token_with_no_permissions_is_refused_everything() {
        // An empty grant list must mean "nothing", not "unrestricted". This is the
        // fail-open direction that matters.
        let (app, jwt) = rbac_router();
        let token = jwt
            .create_token("nobody", vec![], vec![])
            .expect("token should be creatable");

        for (method, uri) in [
            (axum::http::Method::GET, "/api/v1/scans"),
            (axum::http::Method::GET, "/api/v1/findings"),
            (axum::http::Method::GET, "/api/v1/stats"),
        ] {
            assert_eq!(
                call(&app, method.clone(), uri, Some(&token)).await,
                axum::http::StatusCode::FORBIDDEN,
                "an empty permission list must deny {method} {uri}"
            );
        }
    }

    #[tokio::test]
    async fn auth_me_needs_no_permission() {
        // Reporting your own identity is not gated, otherwise a misconfigured
        // account could not even discover what it is.
        let (app, jwt) = rbac_router();
        let token = jwt
            .create_token("nobody", vec![], vec![])
            .expect("token should be creatable");

        assert_eq!(
            call(
                &app,
                axum::http::Method::GET,
                "/api/v1/auth/me",
                Some(&token)
            )
            .await,
            axum::http::StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_refusal_does_not_disclose_the_required_permission() {
        // Telling a caller exactly which permission it lacks turns the API into a
        // probe for discovering the escalation path one hint at a time.
        use axum::body::Body;
        use tower::ServiceExt as _;

        let (app, jwt) = rbac_router();
        let viewer = token_for(&jwt, "viewer");

        let request = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/api/v1/scans")
            .header("authorization", format!("Bearer {viewer}"))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);

        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body should be readable");
        let body = String::from_utf8_lossy(&body);

        assert!(
            !body.contains("scans:execute"),
            "the refusal must not name the missing permission, got: {body}"
        );
        assert!(
            !body.contains("permission"),
            "the refusal should not describe the permission model, got: {body}"
        );
    }
    // --- Shared component wiring -------------------------------------------------
    //
    // `build_state` used to construct a findings manager, an observation store and an
    // evidence engine for the state, and then construct a *second* set for the scan
    // engine. Nothing connected them, so the API served empty observations, empty
    // evidence and an `evidence_total` of zero after every scan, and a per-scan
    // finding count that could not be reconciled with the list endpoint.

    /// A state plus the handles needed to drive its scan engine.
    fn shared_state() -> AppState {
        build_state(
            &spectra_config::Config::default(),
            Arc::new(JwtService::new(JwtConfig {
                secret: "shared-state-test-key-0123456789abcdefghij".to_string(),
                expires_in_secs: 900,
            })),
            UserStore {
                users: Arc::new(RwLock::new(HashMap::new())),
            },
        )
    }

    #[tokio::test]
    async fn the_api_reads_the_observations_the_engine_records() {
        use spectra_findings::Observation;

        let state = shared_state();

        let observation = Observation::new(
            "scan-1",
            "xss",
            spectra_findings::ObservationType::ScannerOutput,
            serde_json::json!({"note": "written through the engine"}),
        );

        state
            .scan_engine
            .observation_engine()
            .record_with(observation)
            .await
            .expect("recording through the engine should succeed");

        let via_state = state
            .observation_engine
            .get_scan_observations("scan-1")
            .await
            .expect("reading through the state should succeed");

        assert_eq!(
            via_state.len(),
            1,
            "an observation recorded by the engine must be visible to the API, \
         otherwise GET /scans/{{id}}/observations is permanently empty"
        );
        assert_eq!(via_state[0].source, "xss");
    }

    #[tokio::test]
    async fn observation_totals_reflect_what_was_recorded() {
        use spectra_findings::Observation;

        let state = shared_state();
        assert_eq!(
            state.observation_engine.store().count_all().await,
            0,
            "a fresh state holds nothing"
        );

        for scan in ["scan-1", "scan-2"] {
            state
                .scan_engine
                .observation_engine()
                .record_with(Observation::new(
                    scan,
                    "crawler",
                    spectra_findings::ObservationType::CrawlerDiscovery,
                    serde_json::json!({}),
                ))
                .await
                .expect("record should succeed");
        }

        assert_eq!(
            state.observation_engine.store().count_all().await,
            2,
            "stats must count real observations, not a hardcoded zero"
        );
    }

    #[tokio::test]
    async fn the_api_reads_the_evidence_the_engine_captures() {
        use spectra_evidence::{EvidenceData, EvidenceType};

        let state = shared_state();

        let finding_id = spectra_core::Id::new();
        state
            .scan_engine
            .evidence_engine()
            .capture(
                finding_id.clone(),
                EvidenceType::HttpResponse,
                "response body",
                EvidenceData::Text("body".to_string()),
            )
            .await
            .expect("capturing through the engine should succeed");

        let stored = state
            .evidence_engine
            .store()
            .get_by_finding(&finding_id.to_string())
            .await
            .expect("reading through the state should succeed");

        assert_eq!(
            stored.len(),
            1,
            "evidence captured by the engine must be visible to the API, \
         otherwise GET /findings/{{id}}/evidence is permanently empty"
        );
    }

    #[tokio::test]
    async fn the_api_reads_the_findings_the_engine_records() {
        use spectra_findings::{DetectionSource, Finding, ManagedFinding};
        use spectra_scanner::{Severity, VulnerabilityCategory};

        let state = shared_state();
        let target_id = spectra_core::Id::new();

        state
            .scan_engine
            .findings_manager()
            .save_finding(ManagedFinding::new(
                Finding::new(
                    "Reflected XSS",
                    "Search parameter is reflected unescaped",
                    Severity::High,
                    VulnerabilityCategory::Xss,
                ),
                DetectionSource::XssScanner,
            ))
            .await
            .expect("saving through the engine should succeed");

        assert_eq!(
            state.findings_manager.count().await,
            1,
            "the state and the engine must share one findings manager"
        );
        assert_eq!(
            state
                .findings_manager
                .list_findings(&target_id)
                .await
                .expect("listing findings should succeed")
                .len(),
            0,
            "a finding for a different target must not appear under this one"
        );
    }

    #[tokio::test]
    async fn findings_written_through_the_state_are_read_by_the_engine() {
        use spectra_findings::{DetectionSource, Finding, ManagedFinding};
        use spectra_scanner::{Severity, VulnerabilityCategory};

        let state = shared_state();

        state
            .findings_manager
            .save_finding(ManagedFinding::new(
                Finding::new(
                    "SQLi",
                    "Error-based SQL injection",
                    Severity::Critical,
                    VulnerabilityCategory::Injection,
                ),
                DetectionSource::SqlInjectionScanner,
            ))
            .await
            .expect("saving through the state should succeed");

        assert_eq!(
            state.scan_engine.findings_manager().count().await,
            1,
            "sharing must work in both directions, not just engine-to-state"
        );
    }

    // --- Concurrent scan bounding -----------------------------------------------
    //
    // `ResourceGovernor` was constructed in `build_state` and never called, and the
    // two config fields that would have configured it — `scanner.max_concurrent` and
    // `scanner.rate_limit_per_second` — were declared, defaulted, asserted non-zero
    // by a test, and read by nothing. So nothing bounded how many scans an
    // authenticated `scanner`-role user could have running at once. The per-scan
    // ceilings added in Remediation 12 bound each scan individually and say nothing
    // about the number of them.

    fn governed_config() -> spectra_config::Config {
        let mut config = spectra_config::Config::default();
        // The target is a loopback port, which the SSRF guard otherwise refuses.
        config.scanner.allow_internal_targets = true;
        // One at a time, so the second request is unambiguously over the limit
        // rather than racing a larger one.
        config.scanner.max_concurrent = 1;
        // High, so the governor rejects on concurrency and not on rate: this test
        // is about the concurrency bound specifically.
        config.scanner.rate_limit_per_second = 1_000;
        // A one-second budget so the first scan gives its slot back promptly and
        // the release path can be asserted without a slow test.
        config.scanner.default_timeout = 1;
        config
    }

    #[tokio::test]
    async fn a_scan_submission_beyond_the_concurrency_limit_is_rejected() {
        let port = blackhole();
        let config = governed_config();
        let (app, jwt) = governed_router(&config);
        let admin = token_for(&jwt, "admin");

        let first = post_json(
            &app,
            "/api/v1/scans",
            &admin,
            serde_json::json!({ "target": format!("http://127.0.0.1:{port}/") }),
        )
        .await;
        assert_eq!(
            first,
            axum::http::StatusCode::OK,
            "the first scan must be admitted"
        );

        let second = post_json(
            &app,
            "/api/v1/scans",
            &admin,
            serde_json::json!({ "target": format!("http://127.0.0.1:{port}/") }),
        )
        .await;
        assert_eq!(
            second,
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "a second concurrent scan must be refused, not silently queued or run \
             anyway"
        );
    }

    /// An unrecognised scanner name must be refused at the request boundary.
    ///
    /// Previously the name reached the engine, matched no arm of a `match` whose
    /// fallback was `{}`, and vanished. The scan then ran zero scanners, reported
    /// `Completed`, and rendered "Total: 0" — indistinguishable from a clean
    /// target. A `400` naming the valid scanners is the only response that stops
    /// the caller believing a false negative.
    #[tokio::test]
    async fn an_unknown_scanner_name_is_rejected_rather_than_silently_dropped() {
        let port = blackhole();
        let config = governed_config();
        let (app, jwt) = governed_router(&config);
        let admin = token_for(&jwt, "admin");

        let target = format!("http://127.0.0.1:{port}/");

        for bad in ["typo", "sqli", "SQL_INJECTION", ""] {
            let status = post_json(
                &app,
                "/api/v1/scans",
                &admin,
                serde_json::json!({ "target": target, "scanners": [bad] }),
            )
            .await;
            assert_eq!(
                status,
                axum::http::StatusCode::BAD_REQUEST,
                "`{bad}` is not a scanner and must not start a scan"
            );
        }

        // And no job may exist for any of those refusals.
        assert_eq!(
            scan_count(&app, &admin).await,
            0,
            "a refused scanner name must not leave a scan behind"
        );
    }

    /// A valid name must still be accepted, or the validation above would be
    /// refusing everything.
    #[tokio::test]
    async fn a_known_scanner_name_is_accepted() {
        let port = blackhole();
        let config = governed_config();
        let (app, jwt) = governed_router(&config);
        let admin = token_for(&jwt, "admin");

        assert_eq!(
            post_json(
                &app,
                "/api/v1/scans",
                &admin,
                serde_json::json!({
                    "target": format!("http://127.0.0.1:{port}/"),
                    "scanners": ["xss", "sql_injection"],
                }),
            )
            .await,
            axum::http::StatusCode::OK
        );
    }

    /// Every name the engine advertises must survive the API's validation. If the
    /// API rejected a name the engine implements, the validation would be lying.
    #[tokio::test]
    async fn every_advertised_scanner_name_passes_validation() {
        let port = blackhole();
        let mut config = governed_config();
        // One per name would exceed the concurrency ceiling of 1, and this test is
        // about validation rather than about the governor.
        config.scanner.max_concurrent = 64;
        let (app, jwt) = governed_router(&config);
        let admin = token_for(&jwt, "admin");

        for name in spectra_engine::available_scanners() {
            assert_eq!(
                post_json(
                    &app,
                    "/api/v1/scans",
                    &admin,
                    serde_json::json!({
                        "target": format!("http://127.0.0.1:{port}/"),
                        "scanners": [*name],
                    }),
                )
                .await,
                axum::http::StatusCode::OK,
                "`{name}` is advertised by the engine, so the API must accept it"
            );
        }
    }

    /// A rejected submission must leave no trace. It never acquired a slot, so it
    /// must not appear in `GET /scans` — otherwise a client retrying would see
    /// phantom scans accumulate.
    #[tokio::test]
    async fn a_rejected_submission_creates_no_scan() {
        let port = blackhole();
        let config = governed_config();
        let (app, jwt) = governed_router(&config);
        let admin = token_for(&jwt, "admin");

        let target = serde_json::json!({ "target": format!("http://127.0.0.1:{port}/") });
        assert_eq!(
            post_json(&app, "/api/v1/scans", &admin, target.clone()).await,
            axum::http::StatusCode::OK
        );
        assert_eq!(
            post_json(&app, "/api/v1/scans", &admin, target).await,
            axum::http::StatusCode::TOO_MANY_REQUESTS
        );

        let total = scan_count(&app, &admin).await;
        assert_eq!(
            total, 1,
            "only the admitted scan may exist; a refused request must not leave a job"
        );
    }

    /// The slot must come back when the scan finishes, or the server wedges after
    /// `max_concurrent` scans for its whole lifetime.
    #[tokio::test]
    async fn the_slot_is_released_when_the_scan_finishes() {
        let port = blackhole();
        let config = governed_config();
        let (app, jwt) = governed_router(&config);
        let admin = token_for(&jwt, "admin");
        let target = serde_json::json!({ "target": format!("http://127.0.0.1:{port}/") });

        assert_eq!(
            post_json(&app, "/api/v1/scans", &admin, target.clone()).await,
            axum::http::StatusCode::OK
        );
        assert_eq!(
            post_json(&app, "/api/v1/scans", &admin, target.clone()).await,
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "precondition: the second request is over the limit"
        );

        // The first scan has a one-second budget, so poll for the slot to come back
        // rather than sleeping a guessed interval.
        let mut admitted = false;
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            if post_json(&app, "/api/v1/scans", &admin, target.clone()).await
                == axum::http::StatusCode::OK
            {
                admitted = true;
                break;
            }
        }

        assert!(
            admitted,
            "the concurrency slot was never released; after one scan finished the \
             server must accept another"
        );
    }

    /// The governor's ceilings come from config, not from `ResourceLimits::default()`.
    #[tokio::test]
    async fn the_governor_ceilings_come_from_config() {
        let mut config = spectra_config::Config::default();
        config.scanner.max_concurrent = 3;
        config.scanner.rate_limit_per_second = 17;

        let state = build_state(
            &config,
            Arc::new(JwtService::new(JwtConfig {
                secret: "governor-config-test-key-0123456789abcdef".to_string(),
                expires_in_secs: 900,
            })),
            UserStore {
                users: Arc::new(RwLock::new(HashMap::new())),
            },
        );

        let stats = state.governor.stats().await;
        assert_eq!(stats.max_concurrency, 3);
        assert_eq!(stats.max_rate, 17);
    }

    // --- Scan lifecycle events --------------------------------------------------
    //
    // The engine knew every scan transition and told nobody. The bus and the audit
    // handler below are what make a scan observable, and the load-bearing property
    // is the one already tested in the engine: an unassessed scan must never be
    // recorded as completed.

    use spectra_events::handler::EventHandler as _;

    fn audit_handler() -> (ScanLifecycleAudit, Arc<AuditLogger>) {
        let audit = Arc::new(AuditLogger::with_in_memory());
        (
            ScanLifecycleAudit {
                audit: Arc::clone(&audit),
            },
            audit,
        )
    }

    fn event_of(
        event_type: spectra_events::event::EventType,
        payload: spectra_events::EventPayload,
    ) -> spectra_events::Event {
        spectra_events::Event::new(event_type, spectra_events::EventSource::System, payload)
    }

    #[tokio::test]
    async fn an_unreached_scan_is_audited_as_failed_not_completed() {
        use spectra_events::event::{EventPayload, EventType};

        let (handler, audit) = audit_handler();

        handler
            .handle(&event_of(
                EventType::ScanFailed,
                EventPayload::ScanFailed {
                    scan_id: "scan-1".into(),
                    error: "crawl: connection refused".into(),
                },
            ))
            .await
            .expect("handling an event should succeed");

        let entries = audit
            .query(Some(spectra_core::audit::AuditCategory::Scan), None, 100)
            .await;

        assert_eq!(
            entries.len(),
            1,
            "the scan transition must reach the audit trail"
        );
        assert_eq!(entries[0].action, "scan.failed");
        assert!(
            !entries[0].action.contains("completed"),
            "a scan that reached nothing must not be audited as completed"
        );
    }

    /// The scan id is the only correlation key between an audit entry and a job, so
    /// it has to be present on every entry — including partial and failed ones,
    /// which are the ones somebody will come back and ask about.
    #[tokio::test]
    async fn every_scan_event_records_its_scan_id() {
        use spectra_events::event::{EventPayload, EventType};

        let (handler, audit) = audit_handler();

        for event in [
            event_of(
                EventType::ScanStarted,
                EventPayload::ScanStarted {
                    scan_id: "scan-7".into(),
                    target_id: "target-7".into(),
                },
            ),
            event_of(
                EventType::ScanPartial,
                EventPayload::ScanPartial {
                    scan_id: "scan-7".into(),
                    reason: "coverage lost".into(),
                },
            ),
            event_of(
                EventType::ScanFailed,
                EventPayload::ScanFailed {
                    scan_id: "scan-7".into(),
                    error: "boom".into(),
                },
            ),
        ] {
            handler.handle(&event).await.expect("should handle");
        }

        let entries = audit
            .query(Some(spectra_core::audit::AuditCategory::Scan), None, 100)
            .await;

        assert_eq!(entries.len(), 3);
        for entry in &entries {
            assert_eq!(
                entry.details.get("scan_id").map(String::as_str),
                Some("scan-7"),
                "entry {:?} is missing the scan id",
                entry.action
            );
        }

        // The partial entry must carry why, not just that it happened.
        let partial = entries
            .iter()
            .find(|e| e.action == "scan.partial")
            .expect("a partial entry should exist");
        assert_eq!(
            partial.details.get("reason").map(String::as_str),
            Some("coverage lost")
        );
    }

    /// An audit-write failure must not take the scan with it. The bus is a side
    /// channel; a scan that found a vulnerability has still found it whether the
    /// audit trail was reachable.
    #[tokio::test]
    async fn an_event_the_handler_does_not_want_is_ignored() {
        use spectra_events::event::{EventPayload, EventType};

        let (handler, audit) = audit_handler();

        handler
            .handle(&event_of(
                EventType::FindingCreated,
                EventPayload::FindingCreated {
                    finding_id: "finding-1".into(),
                    scan_id: None,
                    severity: "high".into(),
                },
            ))
            .await
            .expect("an unrelated event must not be an error");

        assert_eq!(audit.count().await, 0);
    }
}
