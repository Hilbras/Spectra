use std::collections::HashMap;

use crate::{FindingStatus, ManagedFinding, Severity};

/// A group of related findings.
#[derive(Debug, Clone)]
pub struct FindingGroup {
    pub id: String,
    pub title: String,
    pub findings: Vec<String>,
    pub primary_finding: String,
    pub group_type: GroupType,
}

/// Types of finding groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupType {
    /// Same vulnerability on multiple endpoints.
    SameVulnerability,
    /// Related vulnerabilities forming an attack chain.
    AttackChain,
    /// Same root cause.
    RootCause,
    /// Same asset affected by multiple issues.
    AssetRelated,
}

/// Correlation engine for grouping related findings.
pub struct CorrelationEngine {
    /// Minimum severity to correlate.
    min_severity: Severity,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            min_severity: Severity::Low,
        }
    }

    pub fn with_min_severity(min_severity: Severity) -> Self {
        Self { min_severity }
    }

    /// Groups findings by the same vulnerability type across different URLs.
    pub fn correlate_by_vulnerability(&self, findings: &[ManagedFinding]) -> Vec<FindingGroup> {
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();

        for finding in findings {
            if !self.is_correlatable(finding) {
                continue;
            }

            let key = format!("{}:{}", finding.finding.title, finding.finding.category);
            groups
                .entry(key)
                .or_default()
                .push(finding.finding.id.to_string());
        }

        groups
            .into_iter()
            .filter(|(_, ids)| ids.len() > 1)
            .enumerate()
            .map(|(i, (title, ids))| FindingGroup {
                id: format!("group-{}", i),
                title,
                findings: ids.clone(),
                primary_finding: ids[0].clone(),
                group_type: GroupType::SameVulnerability,
            })
            .collect()
    }

    /// Groups findings affecting the same host/asset.
    pub fn correlate_by_asset(&self, findings: &[ManagedFinding]) -> Vec<FindingGroup> {
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();

        for finding in findings {
            if !self.is_correlatable(finding) {
                continue;
            }

            if let Some(url) = &finding.finding.affected_url {
                if let Ok(parsed) = url::Url::parse(url) {
                    let host = parsed.host_str().unwrap_or("unknown").to_string();
                    groups
                        .entry(host)
                        .or_default()
                        .push(finding.finding.id.to_string());
                }
            }
        }

        groups
            .into_iter()
            .filter(|(_, ids)| ids.len() > 1)
            .enumerate()
            .map(|(i, (host, ids))| FindingGroup {
                id: format!("asset-group-{}", i),
                title: format!("Findings on {}", host),
                findings: ids.clone(),
                primary_finding: ids[0].clone(),
                group_type: GroupType::AssetRelated,
            })
            .collect()
    }

    /// Detects potential attack chains (e.g., info disclosure → credential leak → injection).
    pub fn detect_attack_chains(&self, findings: &[ManagedFinding]) -> Vec<FindingGroup> {
        let mut chains = Vec::new();

        // Find information disclosures that could lead to other attacks
        let info_disclosures: Vec<&ManagedFinding> = findings
            .iter()
            .filter(|f| {
                self.is_correlatable(f)
                    && matches!(f.finding.severity, Severity::Low | Severity::Medium)
                    && matches!(
                        f.finding.category,
                        spectra_scanner::VulnerabilityCategory::SensitiveDataExposure
                            | spectra_scanner::VulnerabilityCategory::SecurityMisconfiguration
                    )
            })
            .collect();

        let high_severity: Vec<&ManagedFinding> = findings
            .iter()
            .filter(|f| {
                self.is_correlatable(f)
                    && matches!(f.finding.severity, Severity::High | Severity::Critical)
            })
            .collect();

        // Simple heuristic: if there's an info disclosure AND a high-severity finding
        // on the same URL, it could be an attack chain
        for disc in &info_disclosures {
            for high in &high_severity {
                if let (Some(disc_url), Some(high_url)) =
                    (&disc.finding.affected_url, &high.finding.affected_url)
                {
                    if disc_url == high_url {
                        chains.push(FindingGroup {
                            id: format!("chain-{}", chains.len()),
                            title: format!(
                                "Potential attack chain: {} → {}",
                                disc.finding.title, high.finding.title
                            ),
                            findings: vec![
                                disc.finding.id.to_string(),
                                high.finding.id.to_string(),
                            ],
                            primary_finding: high.finding.id.to_string(),
                            group_type: GroupType::AttackChain,
                        });
                    }
                }
            }
        }

        chains
    }

    /// Groups all correlations for a set of findings.
    pub fn correlate_all(&self, findings: &[ManagedFinding]) -> Vec<FindingGroup> {
        let mut groups = Vec::new();
        groups.extend(self.correlate_by_vulnerability(findings));
        groups.extend(self.correlate_by_asset(findings));
        groups.extend(self.detect_attack_chains(findings));
        groups
    }

    fn is_correlatable(&self, finding: &ManagedFinding) -> bool {
        // Lower ordinal = higher severity in our enum, so <= means "at least as severe"
        finding.finding.severity <= self.min_severity
            && finding.status != FindingStatus::FalsePositive
            && finding.status != FindingStatus::Fixed
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DetectionSource;
    use spectra_scanner::{Finding, VulnerabilityCategory};

    fn make_managed_finding(
        title: &str,
        severity: Severity,
        url: Option<&str>,
        category: VulnerabilityCategory,
    ) -> ManagedFinding {
        let mut f = Finding::new(title, "desc", severity, category);
        if let Some(url) = url {
            f = f.with_url(url);
        }
        ManagedFinding::new(f, DetectionSource::SqlInjectionScanner)
    }

    #[test]
    fn correlate_same_vulnerability() {
        let findings = vec![
            make_managed_finding(
                "SQL Injection",
                Severity::High,
                Some("https://a.com/search?q=1"),
                VulnerabilityCategory::Injection,
            ),
            make_managed_finding(
                "SQL Injection",
                Severity::High,
                Some("https://a.com/filter?id=1"),
                VulnerabilityCategory::Injection,
            ),
        ];

        let engine = CorrelationEngine::new();
        let groups = engine.correlate_by_vulnerability(&findings);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].findings.len(), 2);
    }

    #[test]
    fn correlate_by_asset() {
        let findings = vec![
            make_managed_finding(
                "SQL Injection",
                Severity::High,
                Some("https://example.com/search"),
                VulnerabilityCategory::Injection,
            ),
            make_managed_finding(
                "XSS",
                Severity::Medium,
                Some("https://example.com/comment"),
                VulnerabilityCategory::Xss,
            ),
        ];

        let engine = CorrelationEngine::new();
        let groups = engine.correlate_by_asset(&findings);
        assert_eq!(groups.len(), 1);
        assert!(groups[0].title.contains("example.com"));
    }

    #[test]
    fn no_correlation_different_vulns() {
        let findings = vec![
            make_managed_finding(
                "SQL Injection",
                Severity::High,
                Some("https://a.com/search"),
                VulnerabilityCategory::Injection,
            ),
            make_managed_finding(
                "XSS",
                Severity::Medium,
                Some("https://b.com/comment"),
                VulnerabilityCategory::Xss,
            ),
        ];

        let engine = CorrelationEngine::new();
        let groups = engine.correlate_by_vulnerability(&findings);
        assert!(groups.is_empty());
    }

    #[test]
    fn skip_false_positives() {
        let mut f = make_managed_finding(
            "SQL Injection",
            Severity::High,
            Some("https://a.com/search"),
            VulnerabilityCategory::Injection,
        );
        f.status = FindingStatus::FalsePositive;

        let findings = vec![f];
        let engine = CorrelationEngine::new();
        let groups = engine.correlate_by_vulnerability(&findings);
        assert!(groups.is_empty());
    }
}
