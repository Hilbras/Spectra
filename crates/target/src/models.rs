use serde::{Deserialize, Serialize};
use spectra_core::{Id, Metadata, Timestamp};
use thiserror::Error;

// =============================================================================
// Marker Types
// =============================================================================

/// Marker type for organization identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrganizationId;

/// Marker type for project identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectId;

/// Marker type for target identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetId;

/// Marker type for scope identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScopeId;

/// Marker type for credential identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialId;

// =============================================================================
// Errors
// =============================================================================

/// Errors specific to target operations.
#[derive(Debug, Error)]
pub enum TargetError {
    #[error("Organization not found: {0}")]
    OrganizationNotFound(String),

    #[error("Project not found: {0}")]
    ProjectNotFound(String),

    #[error("Target not found: {0}")]
    TargetNotFound(String),

    #[error("Scope not found: {0}")]
    ScopeNotFound(String),

    #[error("Invalid target value: {0}")]
    InvalidTargetValue(String),

    #[error("Scope violation: {0}")]
    ScopeViolation(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Already exists: {0}")]
    Conflict(String),
}

/// Result type for target operations.
pub type TargetResult<T> = Result<T, TargetError>;

impl From<TargetError> for spectra_core::SpectraError {
    fn from(e: TargetError) -> Self {
        match &e {
            TargetError::OrganizationNotFound(id) => Self::NotFound(id.clone()),
            TargetError::ProjectNotFound(id) => Self::NotFound(id.clone()),
            TargetError::TargetNotFound(id) => Self::NotFound(id.clone()),
            TargetError::ScopeNotFound(id) => Self::NotFound(id.clone()),
            TargetError::InvalidTargetValue(msg) => Self::Validation(msg.clone()),
            TargetError::ScopeViolation(msg) => Self::ScopeViolation(msg.clone()),
            TargetError::Validation(msg) => Self::Validation(msg.clone()),
            TargetError::Storage(msg) => Self::Storage(msg.clone()),
            TargetError::Conflict(msg) => Self::Conflict(msg.clone()),
        }
    }
}

// =============================================================================
// Enums
// =============================================================================

/// The type of target being scanned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TargetType {
    /// A single domain name (e.g., example.com).
    Domain,
    /// A URL (e.g., https://example.com).
    Url,
    /// An IP address (e.g., 192.168.1.1).
    IpAddress,
    /// A CIDR range (e.g., 192.168.1.0/24).
    CidrRange,
    /// A custom target type.
    Custom(String),
}

impl std::fmt::Display for TargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain => write!(f, "domain"),
            Self::Url => write!(f, "url"),
            Self::IpAddress => write!(f, "ip"),
            Self::CidrRange => write!(f, "cidr"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Environment classification for a target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Environment {
    Production,
    Staging,
    Development,
    Testing,
    Custom(String),
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Production => write!(f, "production"),
            Self::Staging => write!(f, "staging"),
            Self::Development => write!(f, "development"),
            Self::Testing => write!(f, "testing"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Project status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProjectStatus {
    Active,
    Archived,
    Deleted,
}

// =============================================================================
// Core Models
// =============================================================================

/// An organization represents a top-level entity (company, team, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: Id<OrganizationId>,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub settings: OrganizationSettings,
    pub timestamp: Timestamp,
}

impl Organization {
    pub fn new(name: String, slug: String) -> Self {
        Self {
            id: Id::new(),
            name,
            slug,
            description: None,
            settings: OrganizationSettings::default(),
            timestamp: Timestamp::now(),
        }
    }
}

/// Organization-level settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrganizationSettings {
    pub max_projects: Option<u32>,
    pub max_targets_per_project: Option<u32>,
    pub allowed_target_types: Vec<TargetType>,
}

/// A project contains targets and scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Id<ProjectId>,
    pub organization_id: Id<OrganizationId>,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub status: ProjectStatus,
    pub settings: ProjectSettings,
    pub timestamp: Timestamp,
}

impl Project {
    pub fn new(organization_id: Id<OrganizationId>, name: String, slug: String) -> Self {
        Self {
            id: Id::new(),
            organization_id,
            name,
            slug,
            description: None,
            status: ProjectStatus::Active,
            settings: ProjectSettings::default(),
            timestamp: Timestamp::now(),
        }
    }
}

/// Project-level settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectSettings {
    pub default_scope_id: Option<Id<ScopeId>>,
    pub max_concurrent_scans: Option<u32>,
    pub scan_timeout: Option<u64>,
}

/// A target represents an entity to be scanned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: Id<TargetId>,
    pub project_id: Id<ProjectId>,
    pub name: String,
    pub target_type: TargetType,
    pub value: String,
    pub scope: Scope,
    pub credentials: Vec<CredentialRef>,
    pub environment: Environment,
    pub metadata: Metadata,
    pub active: bool,
    pub timestamp: Timestamp,
}

impl Target {
    pub fn new(
        project_id: Id<ProjectId>,
        name: String,
        target_type: TargetType,
        value: String,
    ) -> Self {
        Self {
            id: Id::new(),
            project_id,
            name,
            target_type,
            value,
            scope: Scope::default(),
            credentials: Vec::new(),
            environment: Environment::Production,
            metadata: Metadata::new(),
            active: true,
            timestamp: Timestamp::now(),
        }
    }

    /// Returns the target value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the target type.
    pub fn target_type(&self) -> &TargetType {
        &self.target_type
    }

    /// Checks if a URL/host is within this target's scope.
    pub fn is_in_scope(&self, value: &str) -> bool {
        self.scope.is_allowed(value)
    }
}

/// A credential reference stored separately for security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRef {
    pub id: Id<CredentialId>,
    pub name: String,
    pub credential_type: CredentialType,
    pub reference: String, // Encrypted reference to stored credential
}

/// Type of credential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CredentialType {
    UsernamePassword,
    ApiKey,
    Token,
    Certificate,
    Custom(String),
}

/// Defines the scope of allowed operations for a target.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scope {
    pub allowed: Vec<ScopeRule>,
    pub excluded: Vec<ScopeRule>,
    pub rate_limits: RateLimits,
    pub execution_limits: ExecutionLimits,
}

impl Scope {
    /// Checks if a value is allowed within this scope.
    pub fn is_allowed(&self, value: &str) -> bool {
        // Check exclusions first
        if self.excluded.iter().any(|rule| rule.matches(value)) {
            return false;
        }
        // Then check inclusions
        if self.allowed.is_empty() {
            return true; // No allow rules means everything is allowed
        }
        self.allowed.iter().any(|rule| rule.matches(value))
    }

    /// Validates an operation against this scope.
    pub fn validate(&self, operation: &str) -> TargetResult<()> {
        if !self.is_allowed(operation) {
            return Err(TargetError::ScopeViolation(format!(
                "Operation '{}' is not within scope",
                operation
            )));
        }
        Ok(())
    }
}

/// A single scope rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRule {
    pub rule_type: ScopeRuleType,
    pub value: String,
    pub description: Option<String>,
}

impl ScopeRule {
    pub fn allow(value: impl Into<String>) -> Self {
        Self {
            rule_type: ScopeRuleType::Allow,
            value: value.into(),
            description: None,
        }
    }

    pub fn exclude(value: impl Into<String>) -> Self {
        Self {
            rule_type: ScopeRuleType::Exclude,
            value: value.into(),
            description: None,
        }
    }

    /// Checks if this rule matches the given value.
    pub fn matches(&self, value: &str) -> bool {
        match self.rule_type {
            ScopeRuleType::Allow | ScopeRuleType::Exclude => {
                // Support exact match, suffix match, and wildcard
                if self.value == "*" {
                    return true;
                }
                if self.value.starts_with("*.") {
                    // Suffix match: *.example.com matches sub.example.com
                    // but NOT example.com itself
                    let suffix = &self.value[1..]; // .example.com
                    return value.ends_with(suffix) && value != &self.value[2..];
                }
                if self.value.contains('*') {
                    // Simple wildcard matching
                    let pattern = self.value.replace('*', "");
                    return value.contains(&pattern);
                }
                // Exact match
                value == self.value
            }
            ScopeRuleType::Port => {
                // Port matching
                if let Ok(port) = value.parse::<u16>() {
                    self.value
                        .split(',')
                        .any(|p| p.trim().parse::<u16>() == Ok(port))
                } else {
                    false
                }
            }
            ScopeRuleType::Path => {
                // Path prefix matching
                value.starts_with(&self.value)
            }
            ScopeRuleType::Protocol => {
                // Protocol matching
                value == self.value
            }
        }
    }
}

/// Type of scope rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScopeRuleType {
    Allow,
    Exclude,
    Port,
    Path,
    Protocol,
}

/// Rate limits for a target.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RateLimits {
    pub requests_per_second: Option<u32>,
    pub requests_per_minute: Option<u32>,
    pub concurrent_requests: Option<u32>,
}

/// Execution limits for a target.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionLimits {
    pub max_duration_secs: Option<u64>,
    pub max_depth: Option<u32>,
    pub max_pages: Option<u32>,
    pub max_requests: Option<u32>,
}

// =============================================================================
// Events
// =============================================================================

/// Events emitted by the target management system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetEvent {
    OrganizationCreated {
        organization_id: String,
        name: String,
    },
    OrganizationUpdated {
        organization_id: String,
    },
    OrganizationDeleted {
        organization_id: String,
    },
    ProjectCreated {
        project_id: String,
        organization_id: String,
        name: String,
    },
    ProjectUpdated {
        project_id: String,
    },
    ProjectDeleted {
        project_id: String,
    },
    TargetCreated {
        target_id: String,
        project_id: String,
        name: String,
    },
    TargetUpdated {
        target_id: String,
    },
    TargetDeleted {
        target_id: String,
    },
    TargetActivated {
        target_id: String,
    },
    TargetDeactivated {
        target_id: String,
    },
    ScopeUpdated {
        target_id: String,
    },
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_creation() {
        let org = Organization::new("Acme Corp".to_string(), "acme".to_string());
        assert_eq!(org.name, "Acme Corp");
        assert_eq!(org.slug, "acme");
    }

    #[test]
    fn project_creation() {
        let org = Organization::new("Acme Corp".to_string(), "acme".to_string());
        let project = Project::new(org.id.clone(), "Web App".to_string(), "web-app".to_string());
        assert_eq!(project.organization_id, org.id);
        assert_eq!(project.status, ProjectStatus::Active);
    }

    #[test]
    fn target_creation() {
        let org = Organization::new("Acme Corp".to_string(), "acme".to_string());
        let project = Project::new(org.id, "Web App".to_string(), "web-app".to_string());
        let target = Target::new(
            project.id.clone(),
            "Example".to_string(),
            TargetType::Domain,
            "example.com".to_string(),
        );
        assert_eq!(target.project_id, project.id);
        assert_eq!(target.target_type, TargetType::Domain);
        assert!(target.active);
    }

    #[test]
    fn scope_exact_match() {
        let scope = Scope {
            allowed: vec![ScopeRule::allow("example.com")],
            ..Default::default()
        };
        assert!(scope.is_allowed("example.com"));
        assert!(!scope.is_allowed("other.com"));
    }

    #[test]
    fn scope_wildcard_match() {
        let scope = Scope {
            allowed: vec![ScopeRule::allow("*.example.com")],
            ..Default::default()
        };
        assert!(scope.is_allowed("sub.example.com"));
        assert!(scope.is_allowed("deep.sub.example.com"));
        assert!(!scope.is_allowed("example.com"));
        assert!(!scope.is_allowed("other.com"));
    }

    #[test]
    fn scope_exclusion() {
        let scope = Scope {
            allowed: vec![ScopeRule::allow("*.example.com")],
            excluded: vec![ScopeRule::exclude("admin.example.com")],
            ..Default::default()
        };
        assert!(scope.is_allowed("sub.example.com"));
        assert!(!scope.is_allowed("admin.example.com"));
    }

    #[test]
    fn scope_empty_allows_all() {
        let scope = Scope::default();
        assert!(scope.is_allowed("anything"));
    }

    #[test]
    fn scope_validation() {
        let scope = Scope {
            allowed: vec![ScopeRule::allow("example.com")],
            ..Default::default()
        };
        assert!(scope.validate("example.com").is_ok());
        assert!(scope.validate("other.com").is_err());
    }

    #[test]
    fn target_in_scope() {
        let org = Organization::new("Acme Corp".to_string(), "acme".to_string());
        let project = Project::new(org.id, "Web App".to_string(), "web-app".to_string());
        let mut target = Target::new(
            project.id,
            "Example".to_string(),
            TargetType::Domain,
            "example.com".to_string(),
        );
        target.scope = Scope {
            allowed: vec![ScopeRule::allow("*.example.com")],
            ..Default::default()
        };

        assert!(target.is_in_scope("sub.example.com"));
        assert!(!target.is_in_scope("other.com"));
    }
}
