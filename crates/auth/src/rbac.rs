use serde::{Deserialize, Serialize};

use crate::middleware::AuthUser;

// =============================================================================
// Permissions
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Permission {
    // Organization
    OrgsRead,
    OrgsWrite,
    OrgsDelete,
    // Projects
    ProjectsRead,
    ProjectsWrite,
    ProjectsDelete,
    // Targets
    TargetsRead,
    TargetsWrite,
    TargetsDelete,
    // Scans
    ScansRead,
    ScansExecute,
    ScansCancel,
    // Findings
    FindingsRead,
    FindingsWrite,
    FindingsDelete,
    FindingsExport,
    // Evidence
    EvidenceRead,
    EvidenceWrite,
    // Users
    UsersRead,
    UsersWrite,
    UsersDelete,
    // Settings
    SettingsRead,
    SettingsWrite,
    // API Keys
    ApiKeysRead,
    ApiKeysWrite,
    ApiKeysDelete,
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OrgsRead => write!(f, "orgs:read"),
            Self::OrgsWrite => write!(f, "orgs:write"),
            Self::OrgsDelete => write!(f, "orgs:delete"),
            Self::ProjectsRead => write!(f, "projects:read"),
            Self::ProjectsWrite => write!(f, "projects:write"),
            Self::ProjectsDelete => write!(f, "projects:delete"),
            Self::TargetsRead => write!(f, "targets:read"),
            Self::TargetsWrite => write!(f, "targets:write"),
            Self::TargetsDelete => write!(f, "targets:delete"),
            Self::ScansRead => write!(f, "scans:read"),
            Self::ScansExecute => write!(f, "scans:execute"),
            Self::ScansCancel => write!(f, "scans:cancel"),
            Self::FindingsRead => write!(f, "findings:read"),
            Self::FindingsWrite => write!(f, "findings:write"),
            Self::FindingsDelete => write!(f, "findings:delete"),
            Self::FindingsExport => write!(f, "findings:export"),
            Self::EvidenceRead => write!(f, "evidence:read"),
            Self::EvidenceWrite => write!(f, "evidence:write"),
            Self::UsersRead => write!(f, "users:read"),
            Self::UsersWrite => write!(f, "users:write"),
            Self::UsersDelete => write!(f, "users:delete"),
            Self::SettingsRead => write!(f, "settings:read"),
            Self::SettingsWrite => write!(f, "settings:write"),
            Self::ApiKeysRead => write!(f, "api_keys:read"),
            Self::ApiKeysWrite => write!(f, "api_keys:write"),
            Self::ApiKeysDelete => write!(f, "api_keys:delete"),
        }
    }
}

impl std::str::FromStr for Permission {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "orgs:read" => Ok(Self::OrgsRead),
            "orgs:write" => Ok(Self::OrgsWrite),
            "orgs:delete" => Ok(Self::OrgsDelete),
            "projects:read" => Ok(Self::ProjectsRead),
            "projects:write" => Ok(Self::ProjectsWrite),
            "projects:delete" => Ok(Self::ProjectsDelete),
            "targets:read" => Ok(Self::TargetsRead),
            "targets:write" => Ok(Self::TargetsWrite),
            "targets:delete" => Ok(Self::TargetsDelete),
            "scans:read" => Ok(Self::ScansRead),
            "scans:execute" => Ok(Self::ScansExecute),
            "scans:cancel" => Ok(Self::ScansCancel),
            "findings:read" => Ok(Self::FindingsRead),
            "findings:write" => Ok(Self::FindingsWrite),
            "findings:delete" => Ok(Self::FindingsDelete),
            "findings:export" => Ok(Self::FindingsExport),
            "evidence:read" => Ok(Self::EvidenceRead),
            "evidence:write" => Ok(Self::EvidenceWrite),
            "users:read" => Ok(Self::UsersRead),
            "users:write" => Ok(Self::UsersWrite),
            "users:delete" => Ok(Self::UsersDelete),
            "settings:read" => Ok(Self::SettingsRead),
            "settings:write" => Ok(Self::SettingsWrite),
            "api_keys:read" => Ok(Self::ApiKeysRead),
            "api_keys:write" => Ok(Self::ApiKeysWrite),
            "api_keys:delete" => Ok(Self::ApiKeysDelete),
            _ => Err(format!("Unknown permission: {}", s)),
        }
    }
}

// =============================================================================
// Roles
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Admin,
    Manager,
    Scanner,
    Viewer,
    Custom(String),
}

impl Role {
    pub fn permissions(&self) -> Vec<Permission> {
        match self {
            Self::Admin => vec![
                Permission::OrgsRead,
                Permission::OrgsWrite,
                Permission::OrgsDelete,
                Permission::ProjectsRead,
                Permission::ProjectsWrite,
                Permission::ProjectsDelete,
                Permission::TargetsRead,
                Permission::TargetsWrite,
                Permission::TargetsDelete,
                Permission::ScansRead,
                Permission::ScansExecute,
                Permission::ScansCancel,
                Permission::FindingsRead,
                Permission::FindingsWrite,
                Permission::FindingsDelete,
                Permission::FindingsExport,
                Permission::EvidenceRead,
                Permission::EvidenceWrite,
                Permission::UsersRead,
                Permission::UsersWrite,
                Permission::UsersDelete,
                Permission::SettingsRead,
                Permission::SettingsWrite,
                Permission::ApiKeysRead,
                Permission::ApiKeysWrite,
                Permission::ApiKeysDelete,
            ],
            Self::Manager => vec![
                Permission::OrgsRead,
                Permission::ProjectsRead,
                Permission::ProjectsWrite,
                Permission::TargetsRead,
                Permission::TargetsWrite,
                Permission::ScansRead,
                Permission::ScansExecute,
                Permission::ScansCancel,
                Permission::FindingsRead,
                Permission::FindingsWrite,
                Permission::FindingsExport,
                Permission::EvidenceRead,
                Permission::UsersRead,
                Permission::SettingsRead,
            ],
            Self::Scanner => vec![
                Permission::TargetsRead,
                Permission::ScansRead,
                Permission::ScansExecute,
                Permission::FindingsRead,
                Permission::FindingsWrite,
                Permission::EvidenceRead,
                Permission::EvidenceWrite,
            ],
            Self::Viewer => vec![
                Permission::OrgsRead,
                Permission::ProjectsRead,
                Permission::TargetsRead,
                Permission::ScansRead,
                Permission::FindingsRead,
                Permission::EvidenceRead,
                Permission::SettingsRead,
            ],
            Self::Custom(_) => vec![],
        }
    }

    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions().contains(permission)
    }

    /// Expand a role name into its permissions.
    ///
    /// A name that is not one of [`Role::builtin_names`] yields nothing rather
    /// than everything. `Role::Custom` resolves to no permissions because a
    /// custom role's grants are not represented anywhere in this type; treating
    /// an unrecognised name as unrestricted would turn any typo into an
    /// escalation. Use [`Role::is_known_name`] to tell the two cases apart.
    pub fn permissions_for_name(name: &str) -> Vec<Permission> {
        match name.to_lowercase().as_str() {
            "admin" => Self::Admin.permissions(),
            "manager" => Self::Manager.permissions(),
            "scanner" => Self::Scanner.permissions(),
            "viewer" => Self::Viewer.permissions(),
            _ => Vec::new(),
        }
    }

    /// Whether a role name is one of the roles this build defines.
    ///
    /// This is *not* "does the name parse": [`FromStr`] accepts any string by
    /// falling through to `Role::Custom`, so a parse test would answer `true` for
    /// every input and quietly make a typo indistinguishable from a real role.
    /// Callers use this to warn that a name will resolve to no permissions.
    pub fn is_known_name(name: &str) -> bool {
        matches!(
            name.to_lowercase().as_str(),
            "admin" | "manager" | "scanner" | "viewer"
        )
    }

    /// The roles this build defines, for enumeration in UIs and diagnostics.
    pub fn builtin_names() -> [&'static str; 4] {
        ["admin", "manager", "scanner", "viewer"]
    }
}

impl AuthUser {
    /// Whether this caller holds `permission`.
    ///
    /// Checked against the permissions embedded in the token, which is the only
    /// information available at the point of authorisation. That is a deliberate
    /// trade-off: it means a permission change does not take effect until the
    /// token is refreshed, and it means a token revoked out-of-band stays valid
    /// until it expires. Both are acceptable while the only role assignment
    /// mechanism is a fixed account created at startup, and neither is
    /// acceptable once roles become user-assignable — at that point this needs
    /// a store lookup, not a claim.
    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.0
            .permissions
            .iter()
            .any(|granted| granted == &permission.to_string())
    }

    /// Whether this caller holds every one of `permissions`.
    pub fn has_all(&self, permissions: &[Permission]) -> bool {
        permissions.iter().all(|p| self.has_permission(p))
    }

    pub fn subject(&self) -> &str {
        &self.0.sub
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::Manager => write!(f, "manager"),
            Self::Scanner => write!(f, "scanner"),
            Self::Viewer => write!(f, "viewer"),
            Self::Custom(name) => write!(f, "{}", name),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "admin" => Ok(Self::Admin),
            "manager" => Ok(Self::Manager),
            "scanner" => Ok(Self::Scanner),
            "viewer" => Ok(Self::Viewer),
            other => Ok(Self::Custom(other.to_string())),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_has_all_permissions() {
        let admin = Role::Admin;
        assert!(admin.has_permission(&Permission::OrgsRead));
        assert!(admin.has_permission(&Permission::UsersDelete));
        assert!(admin.has_permission(&Permission::ScansExecute));
        assert!(admin.has_permission(&Permission::SettingsWrite));
    }

    #[test]
    fn viewer_limited_permissions() {
        let viewer = Role::Viewer;
        assert!(viewer.has_permission(&Permission::ScansRead));
        assert!(!viewer.has_permission(&Permission::ScansExecute));
        assert!(!viewer.has_permission(&Permission::UsersWrite));
        assert!(!viewer.has_permission(&Permission::SettingsWrite));
    }

    #[test]
    fn scanner_can_execute() {
        let scanner = Role::Scanner;
        assert!(scanner.has_permission(&Permission::ScansExecute));
        assert!(scanner.has_permission(&Permission::FindingsWrite));
        assert!(!scanner.has_permission(&Permission::UsersRead));
    }

    #[test]
    fn role_from_str() {
        assert_eq!("admin".parse::<Role>().unwrap(), Role::Admin);
        assert_eq!("manager".parse::<Role>().unwrap(), Role::Manager);
        assert_eq!("scanner".parse::<Role>().unwrap(), Role::Scanner);
        assert_eq!("viewer".parse::<Role>().unwrap(), Role::Viewer);
        assert_eq!(
            "custom_role".parse::<Role>().unwrap(),
            Role::Custom("custom_role".to_string())
        );
    }

    #[test]
    fn permission_display() {
        assert_eq!(Permission::OrgsRead.to_string(), "orgs:read");
        assert_eq!(Permission::ScansExecute.to_string(), "scans:execute");
        assert_eq!(Permission::SettingsWrite.to_string(), "settings:write");
    }

    #[test]
    fn permission_from_str() {
        assert_eq!(
            "orgs:read".parse::<Permission>().unwrap(),
            Permission::OrgsRead
        );
        assert_eq!(
            "scans:execute".parse::<Permission>().unwrap(),
            Permission::ScansExecute
        );
        assert!("unknown:perm".parse::<Permission>().is_err());
    }
}
