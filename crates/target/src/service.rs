use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::models::*;
use spectra_core::{Id, Metadata};

/// In-memory implementation of target management.
///
/// This service provides CRUD operations for organizations, projects, and targets.
/// In production, this would be backed by a database.
pub struct TargetService {
    organizations: Arc<RwLock<HashMap<String, Organization>>>,
    projects: Arc<RwLock<HashMap<String, Project>>>,
    targets: Arc<RwLock<HashMap<String, Target>>>,
}

impl TargetService {
    /// Creates a new target service.
    pub fn new() -> Self {
        Self {
            organizations: Arc::new(RwLock::new(HashMap::new())),
            projects: Arc::new(RwLock::new(HashMap::new())),
            targets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // =========================================================================
    // Organization Operations
    // =========================================================================

    /// Creates a new organization.
    pub async fn create_organization(
        &self,
        name: String,
        slug: String,
    ) -> TargetResult<Organization> {
        let org = Organization::new(name.clone(), slug.clone());
        let id = org.id.as_str();

        let mut orgs = self.organizations.write().await;
        if orgs.values().any(|o| o.slug == slug) {
            return Err(TargetError::Conflict(format!(
                "Organization with slug '{}' already exists",
                slug
            )));
        }

        orgs.insert(id.clone(), org.clone());
        info!(org_id = %id, name = %name, "Organization created");
        Ok(org)
    }

    /// Gets an organization by ID.
    pub async fn get_organization(&self, id: &Id<OrganizationId>) -> TargetResult<Organization> {
        let orgs = self.organizations.read().await;
        orgs.get(&id.as_str())
            .cloned()
            .ok_or_else(|| TargetError::OrganizationNotFound(id.to_string()))
    }

    /// Lists all organizations.
    pub async fn list_organizations(&self) -> Vec<Organization> {
        let orgs = self.organizations.read().await;
        orgs.values().cloned().collect()
    }

    /// Deletes an organization.
    pub async fn delete_organization(&self, id: &Id<OrganizationId>) -> TargetResult<()> {
        let mut orgs = self.organizations.write().await;
        orgs.remove(&id.as_str())
            .ok_or_else(|| TargetError::OrganizationNotFound(id.to_string()))?;
        info!(org_id = %id, "Organization deleted");
        Ok(())
    }

    // =========================================================================
    // Project Operations
    // =========================================================================

    /// Creates a new project.
    pub async fn create_project(
        &self,
        organization_id: Id<OrganizationId>,
        name: String,
        slug: String,
    ) -> TargetResult<Project> {
        // Verify organization exists
        self.get_organization(&organization_id).await?;

        let mut projects = self.projects.write().await;
        if projects
            .values()
            .any(|p| p.organization_id == organization_id && p.slug == slug)
        {
            return Err(TargetError::Conflict(format!(
                "Project with slug '{}' already exists in this organization",
                slug
            )));
        }

        let project = Project::new(organization_id, name.clone(), slug.clone());
        let id = project.id.as_str();

        projects.insert(id.clone(), project.clone());
        info!(project_id = %id, name = %name, "Project created");
        Ok(project)
    }

    /// Gets a project by ID.
    pub async fn get_project(&self, id: &Id<ProjectId>) -> TargetResult<Project> {
        let projects = self.projects.read().await;
        projects
            .get(&id.as_str())
            .cloned()
            .ok_or_else(|| TargetError::ProjectNotFound(id.to_string()))
    }

    /// Lists projects for an organization.
    pub async fn list_projects(&self, organization_id: &Id<OrganizationId>) -> Vec<Project> {
        let projects = self.projects.read().await;
        projects
            .values()
            .filter(|p| p.organization_id == *organization_id)
            .cloned()
            .collect()
    }

    /// Deletes a project.
    pub async fn delete_project(&self, id: &Id<ProjectId>) -> TargetResult<()> {
        let mut projects = self.projects.write().await;
        projects
            .remove(&id.as_str())
            .ok_or_else(|| TargetError::ProjectNotFound(id.to_string()))?;
        info!(project_id = %id, "Project deleted");
        Ok(())
    }

    // =========================================================================
    // Target Operations
    // =========================================================================

    /// Creates a new target.
    pub async fn create_target(
        &self,
        project_id: Id<ProjectId>,
        name: String,
        target_type: TargetType,
        value: String,
    ) -> TargetResult<Target> {
        // Verify project exists
        self.get_project(&project_id).await?;

        // Validate target value based on type
        Self::validate_target_value(&target_type, &value)?;

        let target = Target::new(project_id, name.clone(), target_type, value.clone());
        let id = target.id.as_str();

        let mut targets = self.targets.write().await;
        targets.insert(id.clone(), target.clone());

        info!(target_id = %id, name = %name, value = %value, "Target created");
        Ok(target)
    }

    /// Gets a target by ID.
    pub async fn get_target(&self, id: &Id<TargetId>) -> TargetResult<Target> {
        let targets = self.targets.read().await;
        targets
            .get(&id.as_str())
            .cloned()
            .ok_or_else(|| TargetError::TargetNotFound(id.to_string()))
    }

    /// Lists targets for a project.
    pub async fn list_targets(&self, project_id: &Id<ProjectId>) -> Vec<Target> {
        let targets = self.targets.read().await;
        targets
            .values()
            .filter(|t| t.project_id == *project_id)
            .cloned()
            .collect()
    }

    /// Updates a target.
    pub async fn update_target(
        &self,
        id: &Id<TargetId>,
        update: TargetUpdate,
    ) -> TargetResult<Target> {
        let mut targets = self.targets.write().await;
        let target = targets
            .get_mut(&id.as_str())
            .ok_or_else(|| TargetError::TargetNotFound(id.to_string()))?;

        if let Some(name) = update.name {
            target.name = name;
        }
        if let Some(scope) = update.scope {
            target.scope = scope;
        }
        if let Some(environment) = update.environment {
            target.environment = environment;
        }
        if let Some(active) = update.active {
            target.active = active;
        }
        if let Some(metadata) = update.metadata {
            target.metadata = metadata;
        }

        target.timestamp.touch();
        info!(target_id = %id, "Target updated");
        Ok(target.clone())
    }

    /// Deletes a target.
    pub async fn delete_target(&self, id: &Id<TargetId>) -> TargetResult<()> {
        let mut targets = self.targets.write().await;
        targets
            .remove(&id.as_str())
            .ok_or_else(|| TargetError::TargetNotFound(id.to_string()))?;
        info!(target_id = %id, "Target deleted");
        Ok(())
    }

    /// Validates a target value based on its type.
    fn validate_target_value(target_type: &TargetType, value: &str) -> TargetResult<()> {
        if value.is_empty() {
            return Err(TargetError::InvalidTargetValue(
                "Target value cannot be empty".to_string(),
            ));
        }

        match target_type {
            TargetType::Domain => {
                // Basic domain validation
                if value.contains(' ') {
                    return Err(TargetError::InvalidTargetValue(
                        "Domain cannot contain spaces".to_string(),
                    ));
                }
            }
            TargetType::Url => {
                // Basic URL validation
                if !value.starts_with("http://") && !value.starts_with("https://") {
                    return Err(TargetError::InvalidTargetValue(
                        "URL must start with http:// or https://".to_string(),
                    ));
                }
            }
            TargetType::IpAddress => {
                // Basic IP validation
                let parts: Vec<&str> = value.split('.').collect();
                if parts.len() != 4 {
                    return Err(TargetError::InvalidTargetValue(
                        "Invalid IPv4 address format".to_string(),
                    ));
                }
                for part in &parts {
                    if part.parse::<u8>().is_err() {
                        return Err(TargetError::InvalidTargetValue(format!(
                            "Invalid IP address octet: {}",
                            part
                        )));
                    }
                }
            }
            TargetType::CidrRange => {
                // Basic CIDR validation
                if let Some((ip, mask)) = value.split_once('/') {
                    Self::validate_target_value(&TargetType::IpAddress, ip)?;
                    if mask.parse::<u8>().is_err() || mask.parse::<u8>().unwrap() > 32 {
                        return Err(TargetError::InvalidTargetValue(
                            "Invalid CIDR mask".to_string(),
                        ));
                    }
                } else {
                    return Err(TargetError::InvalidTargetValue(
                        "CIDR range must include mask (e.g., 192.168.1.0/24)".to_string(),
                    ));
                }
            }
            TargetType::Custom(_) => {
                // No validation for custom types
            }
        }

        Ok(())
    }

    /// Validates a scope for a target.
    pub fn validate_scope(scope: &Scope, target_value: &str) -> TargetResult<()> {
        scope.validate(target_value)
    }
}

impl Default for TargetService {
    fn default() -> Self {
        Self::new()
    }
}

/// Update payload for targets.
#[derive(Debug, Default)]
pub struct TargetUpdate {
    pub name: Option<String>,
    pub scope: Option<Scope>,
    pub environment: Option<Environment>,
    pub active: Option<bool>,
    pub metadata: Option<Metadata>,
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup() -> (TargetService, Id<OrganizationId>) {
        let service = TargetService::new();
        let org = service
            .create_organization("Test Org".to_string(), "test-org".to_string())
            .await
            .unwrap();
        (service, org.id)
    }

    #[tokio::test]
    async fn organization_crud() {
        let service = TargetService::new();

        // Create
        let org = service
            .create_organization("Acme".to_string(), "acme".to_string())
            .await
            .unwrap();
        assert_eq!(org.name, "Acme");

        // Read
        let fetched = service.get_organization(&org.id).await.unwrap();
        assert_eq!(fetched.id, org.id);

        // List
        let list = service.list_organizations().await;
        assert_eq!(list.len(), 1);

        // Delete
        service.delete_organization(&org.id).await.unwrap();
        assert!(service.get_organization(&org.id).await.is_err());
    }

    #[tokio::test]
    async fn project_crud() {
        let (service, org_id) = setup().await;

        // Create
        let project = service
            .create_project(org_id.clone(), "Web App".to_string(), "web-app".to_string())
            .await
            .unwrap();
        assert_eq!(project.name, "Web App");

        // List
        let list = service.list_projects(&org_id).await;
        assert_eq!(list.len(), 1);

        // Delete
        service.delete_project(&project.id).await.unwrap();
    }

    #[tokio::test]
    async fn target_crud() {
        let (service, org_id) = setup().await;

        // Create a project first
        let project = service
            .create_project(
                org_id,
                "Test Project".to_string(),
                "test-project".to_string(),
            )
            .await
            .unwrap();

        // Create
        let target = service
            .create_target(
                project.id.clone(),
                "Example".to_string(),
                TargetType::Domain,
                "example.com".to_string(),
            )
            .await
            .unwrap();
        assert_eq!(target.name, "Example");
        assert_eq!(target.value, "example.com");

        // Read
        let fetched = service.get_target(&target.id).await.unwrap();
        assert_eq!(fetched.id, target.id);

        // List
        let list = service.list_targets(&project.id).await;
        assert_eq!(list.len(), 1);

        // Update
        let updated = service
            .update_target(
                &target.id,
                TargetUpdate {
                    name: Some("Updated Example".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "Updated Example");

        // Delete
        service.delete_target(&target.id).await.unwrap();
        assert!(service.get_target(&target.id).await.is_err());
    }

    #[test]
    fn validate_domain() {
        assert!(TargetService::validate_target_value(&TargetType::Domain, "example.com").is_ok());
        assert!(
            TargetService::validate_target_value(&TargetType::Domain, "sub.example.com").is_ok()
        );
        assert!(TargetService::validate_target_value(&TargetType::Domain, "").is_err());
        assert!(TargetService::validate_target_value(
            &TargetType::Domain,
            "example.com with space"
        )
        .is_err());
    }

    #[test]
    fn validate_url() {
        assert!(
            TargetService::validate_target_value(&TargetType::Url, "https://example.com").is_ok()
        );
        assert!(
            TargetService::validate_target_value(&TargetType::Url, "http://example.com").is_ok()
        );
        assert!(
            TargetService::validate_target_value(&TargetType::Url, "ftp://example.com").is_err()
        );
    }

    #[test]
    fn validate_ip() {
        assert!(
            TargetService::validate_target_value(&TargetType::IpAddress, "192.168.1.1").is_ok()
        );
        assert!(TargetService::validate_target_value(&TargetType::IpAddress, "256.1.1.1").is_err());
        assert!(TargetService::validate_target_value(&TargetType::IpAddress, "192.168.1").is_err());
    }

    #[test]
    fn validate_cidr() {
        assert!(
            TargetService::validate_target_value(&TargetType::CidrRange, "192.168.1.0/24").is_ok()
        );
        assert!(
            TargetService::validate_target_value(&TargetType::CidrRange, "192.168.1.0/33").is_err()
        );
        assert!(
            TargetService::validate_target_value(&TargetType::CidrRange, "192.168.1.0").is_err()
        );
    }
}
