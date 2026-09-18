use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

use spectra_target::{Environment, TargetService, TargetType};

#[derive(Parser)]
#[command(name = "spectra")]
#[command(about = "Spectra Security Testing Platform")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize Spectra configuration
    Init {
        /// Project directory
        #[arg(short, long)]
        path: Option<String>,
    },
    /// Manage organizations
    Organization {
        #[command(subcommand)]
        action: OrganizationAction,
    },
    /// Manage projects
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Manage targets
    Target {
        #[command(subcommand)]
        action: TargetAction,
    },
    /// Run scans
    Scan {
        #[command(subcommand)]
        action: ScanAction,
    },
    /// List and view findings
    Finding {
        #[command(subcommand)]
        action: FindingAction,
    },
    /// Worker management
    Worker {
        #[command(subcommand)]
        action: WorkerAction,
    },
    /// Plugin management
    Plugin {
        #[command(subcommand)]
        action: PluginAction,
    },
    /// Generate reports
    Report {
        #[command(subcommand)]
        action: ReportAction,
    },
    /// Manage observations
    Observation {
        #[command(subcommand)]
        action: ObservationAction,
    },
    /// Manage evidence
    Evidence {
        #[command(subcommand)]
        action: EvidenceAction,
    },
    /// Manage verification
    Verification {
        #[command(subcommand)]
        action: VerificationAction,
    },
    /// Show platform statistics
    Stats,
    /// Show configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum OrganizationAction {
    /// List all organizations
    List,
    /// Create a new organization
    Create {
        /// Organization name
        name: String,
        /// Organization slug
        #[arg(short, long)]
        slug: String,
    },
    /// Show organization details
    Show {
        /// Organization ID
        id: String,
    },
    /// Delete an organization
    Delete {
        /// Organization ID
        id: String,
    },
}

#[derive(Subcommand)]
enum ProjectAction {
    /// List all projects
    List {
        /// Organization ID
        #[arg(short, long)]
        organization: String,
    },
    /// Create a new project
    Create {
        /// Project name
        name: String,
        /// Organization ID
        #[arg(short, long)]
        organization: String,
        /// Project slug
        #[arg(short, long)]
        slug: String,
    },
    /// Show project details
    Show {
        /// Project ID
        id: String,
    },
    /// Delete a project
    Delete {
        /// Project ID
        id: String,
    },
}

#[derive(Subcommand)]
enum TargetAction {
    /// List all targets
    List {
        /// Project ID
        #[arg(short, long)]
        project: String,
    },
    /// Add a new target
    Add {
        /// Target name
        name: String,
        /// Target type (domain, url, ip, cidr)
        #[arg(short, long)]
        target_type: String,
        /// Target value
        value: String,
        /// Project ID
        #[arg(short, long)]
        project: String,
        /// Environment (production, staging, development, testing)
        #[arg(short, long, default_value = "production")]
        environment: String,
    },
    /// Show target details
    Show {
        /// Target ID
        id: String,
    },
    /// Delete a target
    Delete {
        /// Target ID
        id: String,
    },
    /// Check if a value is in scope
    Scope {
        /// Target ID
        #[arg(short, long)]
        target: String,
        /// Value to check
        value: String,
    },
}

#[derive(Subcommand)]
enum ScanAction {
    /// Run a new scan
    Run {
        /// Target ID
        #[arg(short, long)]
        target: String,
        /// Scan type
        #[arg(short, long, default_value = "full")]
        scan_type: String,
    },
    /// List all scans
    List,
    /// Show scan details
    Show {
        /// Scan ID
        id: String,
    },
    /// Cancel a running scan
    Cancel {
        /// Scan ID
        id: String,
    },
}

#[derive(Subcommand)]
enum FindingAction {
    /// List all findings
    List {
        /// Filter by severity
        #[arg(short, long)]
        severity: Option<String>,
        /// Filter by status
        #[arg(short, long)]
        status: Option<String>,
    },
    /// Show finding details
    Show {
        /// Finding ID
        id: String,
    },
    /// Update finding status
    UpdateStatus {
        /// Finding ID
        id: String,
        /// New status (new, confirmed, false_positive, investigating, fixed, accepted, duplicate)
        status: String,
    },
    /// Show findings statistics
    Stats,
}

#[derive(Subcommand)]
enum ObservationAction {
    /// List observations for a scan
    List {
        /// Scan ID
        scan_id: String,
        /// Filter by type
        #[arg(short, long)]
        observation_type: Option<String>,
    },
    /// Show observation details
    Show {
        /// Observation ID
        id: String,
    },
}

#[derive(Subcommand)]
enum EvidenceAction {
    /// List evidence for a finding
    List {
        /// Finding ID
        finding_id: String,
    },
    /// Show evidence details
    Show {
        /// Evidence ID
        id: String,
    },
}

#[derive(Subcommand)]
enum VerificationAction {
    /// List verification records for a finding
    List {
        /// Finding ID
        finding_id: String,
    },
    /// Show verification summary
    Summary,
}

#[derive(Subcommand)]
enum WorkerAction {
    /// List all workers
    List,
    /// Show worker status
    Status {
        /// Worker ID
        id: String,
    },
}

#[derive(Subcommand)]
enum PluginAction {
    /// List all plugins
    List,
    /// Install a plugin
    Install {
        /// Plugin path or URL
        path: String,
    },
    /// Remove a plugin
    Remove {
        /// Plugin name
        name: String,
    },
}

#[derive(Subcommand)]
enum ReportAction {
    /// Generate a report
    Generate {
        /// Scan ID
        #[arg(short, long)]
        scan: String,
        /// Output format (html, json, pdf)
        #[arg(short, long, default_value = "html")]
        format: String,
    },
    /// List all reports
    List,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current configuration
    Show,
    /// Set a configuration value
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let config = spectra_config::Config::load().unwrap_or_default();
    let log_level = if cli.verbose {
        "debug"
    } else {
        &config.logging.level
    };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_level))
        .init();

    let service = Arc::new(TargetService::new());

    match cli.command {
        Commands::Init { path } => {
            let path = path.unwrap_or_else(|| ".".to_string());
            info!(path = %path, "Initializing Spectra");
            println!("Initializing Spectra project in {}", path);
        }
        Commands::Organization { action } => match action {
            OrganizationAction::List => {
                let orgs = service.list_organizations().await;
                if orgs.is_empty() {
                    println!("No organizations found.");
                } else {
                    println!("{:<36} {:<30} {:<20}", "ID", "NAME", "SLUG");
                    println!("{}", "-".repeat(86));
                    for org in orgs {
                        println!("{:<36} {:<30} {:<20}", org.id, org.name, org.slug);
                    }
                }
            }
            OrganizationAction::Create { name, slug } => {
                match service
                    .create_organization(name.clone(), slug.clone())
                    .await
                {
                    Ok(org) => println!("Created organization: {} ({})", org.name, org.id),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            OrganizationAction::Show { id } => {
                let org_id = spectra_core::Id::from_uuid(Uuid::parse_str(&id)?);
                match service.get_organization(&org_id).await {
                    Ok(org) => {
                        println!("Organization: {}", org.name);
                        println!("  ID: {}", org.id);
                        println!("  Slug: {}", org.slug);
                        if let Some(desc) = &org.description {
                            println!("  Description: {}", desc);
                        }
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            OrganizationAction::Delete { id } => {
                let org_id = spectra_core::Id::from_uuid(Uuid::parse_str(&id)?);
                match service.delete_organization(&org_id).await {
                    Ok(()) => println!("Deleted organization {}", id),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
        },
        Commands::Project { action } => match action {
            ProjectAction::List { organization } => {
                let org_id = spectra_core::Id::from_uuid(Uuid::parse_str(&organization)?);
                let projects = service.list_projects(&org_id).await;
                if projects.is_empty() {
                    println!("No projects found.");
                } else {
                    println!(
                        "{:<36} {:<30} {:<20} {:<10}",
                        "ID", "NAME", "SLUG", "STATUS"
                    );
                    println!("{}", "-".repeat(96));
                    for project in projects {
                        println!(
                            "{:<36} {:<30} {:<20} {:<10}",
                            project.id,
                            project.name,
                            project.slug,
                            format!("{:?}", project.status).to_lowercase()
                        );
                    }
                }
            }
            ProjectAction::Create {
                name,
                organization,
                slug,
            } => {
                let org_id = spectra_core::Id::from_uuid(Uuid::parse_str(&organization)?);
                match service
                    .create_project(org_id, name.clone(), slug.clone())
                    .await
                {
                    Ok(project) => println!("Created project: {} ({})", project.name, project.id),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            ProjectAction::Show { id } => {
                let proj_id = spectra_core::Id::from_uuid(Uuid::parse_str(&id)?);
                match service.get_project(&proj_id).await {
                    Ok(project) => {
                        println!("Project: {}", project.name);
                        println!("  ID: {}", project.id);
                        println!("  Organization: {}", project.organization_id);
                        println!("  Slug: {}", project.slug);
                        println!("  Status: {:?}", project.status);
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            ProjectAction::Delete { id } => {
                let proj_id = spectra_core::Id::from_uuid(Uuid::parse_str(&id)?);
                match service.delete_project(&proj_id).await {
                    Ok(()) => println!("Deleted project {}", id),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
        },
        Commands::Target { action } => match action {
            TargetAction::List { project } => {
                let proj_id = spectra_core::Id::from_uuid(Uuid::parse_str(&project)?);
                let targets = service.list_targets(&proj_id).await;
                if targets.is_empty() {
                    println!("No targets found.");
                } else {
                    println!(
                        "{:<36} {:<30} {:<10} {:<30} {:<10}",
                        "ID", "NAME", "TYPE", "VALUE", "ACTIVE"
                    );
                    println!("{}", "-".repeat(96));
                    for target in targets {
                        println!(
                            "{:<36} {:<30} {:<10} {:<30} {:<10}",
                            target.id,
                            target.name,
                            target.target_type,
                            target.value,
                            if target.active { "yes" } else { "no" }
                        );
                    }
                }
            }
            TargetAction::Add {
                name,
                target_type,
                value,
                project,
                environment,
            } => {
                let proj_id = spectra_core::Id::from_uuid(Uuid::parse_str(&project)?);
                let tt = match target_type.to_lowercase().as_str() {
                    "domain" => TargetType::Domain,
                    "url" => TargetType::Url,
                    "ip" => TargetType::IpAddress,
                    "cidr" => TargetType::CidrRange,
                    _ => {
                        eprintln!("Unknown target type: {}", target_type);
                        return Ok(());
                    }
                };
                let env = match environment.to_lowercase().as_str() {
                    "production" | "prod" => Environment::Production,
                    "staging" | "stage" => Environment::Staging,
                    "development" | "dev" => Environment::Development,
                    "testing" | "test" => Environment::Testing,
                    other => Environment::Custom(other.to_string()),
                };
                match service
                    .create_target(proj_id, name.clone(), tt, value.clone())
                    .await
                {
                    Ok(mut target) => {
                        target.environment = env;
                        println!("Created target: {} ({})", target.name, target.id);
                        println!("  Type: {}", target.target_type);
                        println!("  Value: {}", target.value);
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            TargetAction::Show { id } => {
                let target_id = spectra_core::Id::from_uuid(Uuid::parse_str(&id)?);
                match service.get_target(&target_id).await {
                    Ok(target) => {
                        println!("Target: {}", target.name);
                        println!("  ID: {}", target.id);
                        println!("  Project: {}", target.project_id);
                        println!("  Type: {}", target.target_type);
                        println!("  Value: {}", target.value);
                        println!("  Environment: {}", target.environment);
                        println!("  Active: {}", target.active);
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            TargetAction::Delete { id } => {
                let target_id = spectra_core::Id::from_uuid(Uuid::parse_str(&id)?);
                match service.delete_target(&target_id).await {
                    Ok(()) => println!("Deleted target {}", id),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            TargetAction::Scope { target, value } => {
                let target_id = spectra_core::Id::from_uuid(Uuid::parse_str(&target)?);
                match service.get_target(&target_id).await {
                    Ok(t) => {
                        if t.is_in_scope(&value) {
                            println!("✓ '{}' is IN SCOPE for target {}", value, t.name);
                        } else {
                            println!("✗ '{}' is OUT OF SCOPE for target {}", value, t.name);
                        }
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
        },
        Commands::Scan { action } => match action {
            ScanAction::Run { target, scan_type } => {
                println!("Starting {} scan on target {}", scan_type, target);
            }
            ScanAction::List => {
                println!("Scans:");
                println!("  (no scans yet)");
            }
            ScanAction::Show { id } => {
                println!("Scan: {}", id);
            }
            ScanAction::Cancel { id } => {
                println!("Cancelling scan: {}", id);
            }
        },
        Commands::Finding { action } => match action {
            FindingAction::List { severity, status } => {
                println!("Findings:");
                if let Some(s) = severity {
                    println!("  Filtered by severity: {}", s);
                }
                if let Some(s) = status {
                    println!("  Filtered by status: {}", s);
                }
            }
            FindingAction::Show { id } => {
                println!("Finding: {}", id);
            }
            FindingAction::UpdateStatus { id, status } => {
                println!("Updating finding {} status to {}", id, status);
            }
            FindingAction::Stats => {
                println!("Finding Statistics:");
                println!("  Total: 0");
                println!("  Critical: 0");
                println!("  High: 0");
                println!("  Medium: 0");
                println!("  Low: 0");
                println!("  Info: 0");
            }
        },
        Commands::Worker { action } => match action {
            WorkerAction::List => {
                println!("Workers:");
                println!("  (no workers connected)");
            }
            WorkerAction::Status { id } => {
                println!("Worker: {}", id);
            }
        },
        Commands::Plugin { action } => match action {
            PluginAction::List => {
                println!("Plugins:");
                println!("  (no plugins installed)");
            }
            PluginAction::Install { path } => {
                println!("Installing plugin: {}", path);
            }
            PluginAction::Remove { name } => {
                println!("Removing plugin: {}", name);
            }
        },
        Commands::Report { action } => match action {
            ReportAction::Generate { scan, format } => {
                println!("Generating {} report for scan {}", format, scan);
            }
            ReportAction::List => {
                println!("Reports:");
                println!("  (no reports yet)");
            }
        },
        Commands::Observation { action } => match action {
            ObservationAction::List {
                scan_id,
                observation_type,
            } => {
                println!("Observations for scan {}:", scan_id);
                if let Some(t) = observation_type {
                    println!("  Filtered by type: {}", t);
                }
            }
            ObservationAction::Show { id } => {
                println!("Observation: {}", id);
            }
        },
        Commands::Evidence { action } => match action {
            EvidenceAction::List { finding_id } => {
                println!("Evidence for finding {}:", finding_id);
            }
            EvidenceAction::Show { id } => {
                println!("Evidence: {}", id);
            }
        },
        Commands::Verification { action } => match action {
            VerificationAction::List { finding_id } => {
                println!("Verification records for finding {}:", finding_id);
            }
            VerificationAction::Summary => {
                println!("Verification Summary:");
                println!("  Total verifications: 0");
                println!("  Verified: 0");
                println!("  Not verified: 0");
                println!("  Partially verified: 0");
            }
        },
        Commands::Stats => {
            println!("Platform Statistics:");
            println!("  Findings: 0");
            println!("  Observations: 0");
            println!("  Evidence: 0");
            println!("  Verifications: 0");
        }
        Commands::Config { action } => match action {
            ConfigAction::Show => {
                let config = spectra_config::Config::load().unwrap_or_default();
                println!("Configuration:");
                println!("  Server: {}:{}", config.server.host, config.server.port);
                println!("  Database: {}", config.database.url);
            }
            ConfigAction::Set { key, value } => {
                println!("Setting {} = {}", key, value);
            }
        },
    }

    Ok(())
}
