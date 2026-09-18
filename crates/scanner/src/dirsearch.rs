use tracing::info;

use crate::{
    Finding, ScanResult, Scanner, ScannerConfig, ScannerError, ScannerMetadata, ScannerResult,
    Severity, VulnerabilityCategory,
};

/// Common directories and files to check.
const COMMON_PATHS: &[&str] = &[
    ".env",
    ".git/config",
    ".git/HEAD",
    ".htaccess",
    ".htpasswd",
    "wp-config.php.bak",
    "config.php.bak",
    "config.yml",
    "config.json",
    "config.yaml",
    "database.yml",
    "settings.py",
    ".DS_Store",
    "Thumbs.db",
    "admin",
    "admin/",
    "administrator",
    "wp-admin",
    "phpmyadmin",
    "phpMyAdmin",
    "cpanel",
    "webmail",
    "manager",
    "console",
    "backup",
    "backups",
    "bak",
    "old",
    "temp",
    "tmp",
    "archive",
    "dump",
    "dump.sql",
    "backup.sql",
    "db.sql",
    "database.sql",
    "api",
    "api/",
    "api/v1",
    "api/v2",
    "graphql",
    "swagger",
    "swagger-ui",
    "api-docs",
    "docs",
    ".svn",
    ".svn/entries",
    ".bzr",
    "CVS",
    "CVS/Root",
    "server-status",
    "server-info",
    ".well-known",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "favicon.ico",
    "images",
    "img",
    "uploads",
    "files",
    "media",
    "static",
    "assets",
    "css",
    "js",
    "scripts",
    "includes",
    "lib",
    "vendor",
    "node_modules",
    "debug",
    "trace",
    "status",
    "health",
    "metrics",
    "prometheus",
    "actuator",
    "actuator/health",
    "env",
    "info",
    "login",
    "signin",
    "register",
    "signup",
    "auth",
    "oauth",
];

/// HTTP status codes indicating interesting findings.
fn interesting_status(status: u16) -> Option<Severity> {
    match status {
        200 => Some(Severity::Medium),
        301 | 302 => Some(Severity::Low),
        401 => Some(Severity::Low),
        403 => Some(Severity::Low),
        500 => Some(Severity::Medium),
        _ => None,
    }
}

/// Directory brute-force scanner.
pub struct DirSearchScanner {
    config: ScannerConfig,
    http_client: reqwest::Client,
    max_concurrent: usize,
}

impl DirSearchScanner {
    pub fn new() -> Self {
        Self {
            config: ScannerConfig::default(),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Failed to create HTTP client"),
            max_concurrent: 10,
        }
    }
}

impl Default for DirSearchScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Scanner for DirSearchScanner {
    fn metadata(&self) -> ScannerMetadata {
        ScannerMetadata {
            name: "Directory Search Scanner".to_string(),
            version: "0.1.0".to_string(),
            supported_targets: vec!["url".to_string(), "domain".to_string()],
            categories: vec![
                VulnerabilityCategory::SecurityMisconfiguration,
                VulnerabilityCategory::SensitiveDataExposure,
                VulnerabilityCategory::BrokenAccessControl,
            ],
        }
    }

    async fn initialize(&mut self, config: ScannerConfig) -> ScannerResult<()> {
        self.config = config;
        Ok(())
    }

    async fn scan(&self, target: &spectra_target::Target) -> ScannerResult<ScanResult> {
        let mut result = ScanResult::new(target.id.clone(), "dirsearch");

        let base_url = match target.target_type {
            spectra_target::TargetType::Url => target.value().to_string(),
            spectra_target::TargetType::Domain => format!("https://{}", target.value()),
            _ => {
                return Err(ScannerError::InvalidConfig(format!(
                    "Cannot scan target type {:?}",
                    target.target_type
                )));
            }
        };

        info!(url = %base_url, "Starting directory search");

        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.max_concurrent));
        let mut handles = Vec::new();

        for path in COMMON_PATHS {
            let sem = semaphore.clone();
            let base_url = base_url.clone();
            let path = path.to_string();
            let client = self.http_client.clone();

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let url = format!("{}/{}", base_url.trim_end_matches('/'), path);

                match client.get(&url).send().await {
                    Ok(response) => {
                        let status = response.status().as_u16();
                        let body = response.text().await.unwrap_or_default();

                        if let Some(severity) = interesting_status(status) {
                            if status == 200 && body.len() < 100 {
                                return None;
                            }

                            let title = format!("Accessible resource: /{}", path);
                            let description = match status {
                                200 => format!("Found accessible resource at /{}", path),
                                301 | 302 => format!("Redirect to /{}", path),
                                401 => format!("Authentication required for /{}", path),
                                403 => format!("Forbidden but exists: /{}", path),
                                500 => format!("Server error at /{}", path),
                                _ => format!("Status {} at /{}", status, path),
                            };

                            let category = if path.contains(".env")
                                || path.contains(".git")
                                || path.contains("config")
                                || path.contains("backup")
                                || path.contains("dump")
                            {
                                VulnerabilityCategory::SensitiveDataExposure
                            } else if path.contains("admin")
                                || path.contains("phpmyadmin")
                                || path.contains("manager")
                            {
                                VulnerabilityCategory::BrokenAccessControl
                            } else {
                                VulnerabilityCategory::SecurityMisconfiguration
                            };

                            Some(
                                Finding::new(title, description, severity, category)
                                    .with_url(&url)
                                    .with_evidence(format!("HTTP {} response", status)),
                            )
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            }));
        }

        for handle in handles {
            if let Ok(Some(finding)) = handle.await {
                result.add_finding(finding);
            }
        }

        result.finish();
        Ok(result)
    }

    async fn cleanup(&self) -> ScannerResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_metadata() {
        let scanner = DirSearchScanner::new();
        let meta = scanner.metadata();
        assert_eq!(meta.name, "Directory Search Scanner");
        assert!(meta
            .categories
            .contains(&VulnerabilityCategory::SecurityMisconfiguration));
    }

    #[test]
    fn interesting_status_codes() {
        assert_eq!(interesting_status(200), Some(Severity::Medium));
        assert_eq!(interesting_status(301), Some(Severity::Low));
        assert_eq!(interesting_status(403), Some(Severity::Low));
        assert_eq!(interesting_status(500), Some(Severity::Medium));
        assert_eq!(interesting_status(404), None);
    }

    #[test]
    fn common_paths_list() {
        assert!(COMMON_PATHS.contains(&".env"));
        assert!(COMMON_PATHS.contains(&".git/config"));
        assert!(COMMON_PATHS.contains(&"admin"));
        assert!(COMMON_PATHS.contains(&"wp-admin"));
        assert!(COMMON_PATHS.contains(&"backup.sql"));
    }
}
