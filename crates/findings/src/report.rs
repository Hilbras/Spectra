use crate::{FindingStatus, FindingsReport, ManagedFinding};
use spectra_scanner::Severity;

/// Report generation utilities.
pub struct ReportGenerator;

impl ReportGenerator {
    /// Generates a text summary of a findings report.
    pub fn text_summary(report: &FindingsReport) -> String {
        let mut output = String::new();

        output.push_str("Findings Report\n");
        output.push_str("==============\n\n");
        output.push_str(&format!("Target ID: {}\n", report.target_id));
        output.push_str(&format!("Generated: {}\n\n", report.generated_at));

        output.push_str("Summary\n");
        output.push_str("-------\n");
        output.push_str(&format!("Total: {}\n", report.summary.total));
        output.push_str(&format!("Critical: {}\n", report.summary.critical));
        output.push_str(&format!("High: {}\n", report.summary.high));
        output.push_str(&format!("Medium: {}\n", report.summary.medium));
        output.push_str(&format!("Low: {}\n", report.summary.low));
        output.push_str(&format!("Info: {}\n\n", report.summary.info));

        output.push_str("Findings\n");
        output.push_str("--------\n");

        for finding in &report.findings {
            output.push_str(&format!(
                "[{}] {} - {}\n",
                finding.finding.severity, finding.finding.title, finding.status
            ));
            if let Some(url) = &finding.finding.affected_url {
                output.push_str(&format!("  URL: {}\n", url));
            }
            output.push_str(&format!("  {}\n\n", finding.finding.description));
        }

        output
    }

    /// Generates a JSON summary of findings grouped by severity.
    pub fn severity_breakdown(report: &FindingsReport) -> serde_json::Value {
        let mut breakdown = serde_json::Map::new();

        let severity_counts = [
            ("critical", report.summary.critical),
            ("high", report.summary.high),
            ("medium", report.summary.medium),
            ("low", report.summary.low),
            ("info", report.summary.info),
        ];

        for (level, count) in severity_counts {
            breakdown.insert(level.to_string(), serde_json::Value::Number(count.into()));
        }

        serde_json::Value::Object(breakdown)
    }

    /// Returns findings grouped by status.
    pub fn by_status(report: &FindingsReport) -> Vec<(FindingStatus, Vec<&ManagedFinding>)> {
        let statuses = [
            FindingStatus::New,
            FindingStatus::Confirmed,
            FindingStatus::Investigating,
            FindingStatus::FalsePositive,
            FindingStatus::Fixed,
            FindingStatus::Accepted,
            FindingStatus::Duplicate,
        ];

        statuses
            .iter()
            .filter_map(|status| {
                let findings: Vec<&ManagedFinding> = report
                    .findings
                    .iter()
                    .filter(|f| &f.status == status)
                    .collect();
                if findings.is_empty() {
                    None
                } else {
                    Some((status.clone(), findings))
                }
            })
            .collect()
    }

    /// Returns findings grouped by detection source.
    pub fn by_source(report: &FindingsReport) -> Vec<(String, Vec<&ManagedFinding>)> {
        let mut groups: Vec<(String, Vec<&ManagedFinding>)> = Vec::new();
        for finding in &report.findings {
            let source_name = finding.detection_source.to_string();
            if let Some(entry) = groups.iter_mut().find(|(name, _)| name == &source_name) {
                entry.1.push(finding);
            } else {
                groups.push((source_name, vec![finding]));
            }
        }
        groups
    }

    /// Returns findings by type (Vulnerability, Misconfiguration, etc).
    pub fn by_type(report: &FindingsReport) -> Vec<(String, Vec<&ManagedFinding>)> {
        let mut groups: Vec<(String, Vec<&ManagedFinding>)> = Vec::new();
        for finding in &report.findings {
            let type_name = finding.finding_type.to_string();
            if let Some(entry) = groups.iter_mut().find(|(name, _)| name == &type_name) {
                entry.1.push(finding);
            } else {
                groups.push((type_name, vec![finding]));
            }
        }
        groups
    }

    /// Returns findings above a minimum severity.
    pub fn above_severity(report: &FindingsReport, min: Severity) -> Vec<&ManagedFinding> {
        report
            .findings
            .iter()
            .filter(|f| f.finding.severity <= min)
            .collect()
    }

    /// Counts findings by category (severity + status).
    pub fn category_matrix(report: &FindingsReport) -> serde_json::Value {
        let severities = [
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
            ("info", Severity::Info),
        ];
        let statuses = [
            "new",
            "confirmed",
            "investigating",
            "false_positive",
            "fixed",
            "accepted",
            "duplicate",
        ];

        let mut matrix = serde_json::Map::new();
        for (sname, severity) in severities {
            let mut status_map = serde_json::Map::new();
            for status_name in statuses {
                let count = report
                    .findings
                    .iter()
                    .filter(|f| {
                        f.finding.severity == severity
                            && f.status.to_string().to_lowercase().replace(' ', "_") == *status_name
                    })
                    .count();
                status_map.insert(
                    status_name.to_string(),
                    serde_json::Value::Number(count.into()),
                );
            }
            matrix.insert(sname.to_string(), serde_json::Value::Object(status_map));
        }

        serde_json::Value::Object(matrix)
    }

    /// Returns the risk score (weighted sum of severities).
    pub fn risk_score(report: &FindingsReport) -> f64 {
        report
            .findings
            .iter()
            .filter(|f| {
                f.status != FindingStatus::FalsePositive && f.status != FindingStatus::Fixed
            })
            .map(|f| match f.finding.severity {
                Severity::Critical => 10.0,
                Severity::High => 7.0,
                Severity::Medium => 4.0,
                Severity::Low => 1.0,
                Severity::Info => 0.1,
            })
            .sum()
    }

    /// Returns top N most common affected hosts.
    pub fn top_hosts(report: &FindingsReport, n: usize) -> Vec<(String, usize)> {
        use std::collections::HashMap;

        let mut host_counts: HashMap<String, usize> = HashMap::new();
        for finding in &report.findings {
            if let Some(url) = &finding.finding.affected_url {
                if let Ok(parsed) = url::Url::parse(url) {
                    let host = parsed.host_str().unwrap_or("unknown").to_string();
                    *host_counts.entry(host).or_default() += 1;
                }
            }
        }

        let mut hosts: Vec<_> = host_counts.into_iter().collect();
        hosts.sort_by_key(|b| std::cmp::Reverse(b.1));
        hosts.truncate(n);
        hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DetectionSource, Severity};
    use spectra_core::Id;
    use spectra_scanner::{Finding, VulnerabilityCategory};

    fn make_report() -> FindingsReport {
        let target_id = Id::new();
        let mut report = FindingsReport::new(target_id);

        report.add_finding(ManagedFinding::new(
            Finding::new(
                "SQLi",
                "SQL injection in login",
                Severity::High,
                VulnerabilityCategory::Injection,
            )
            .with_url("https://example.com/login"),
            DetectionSource::SqlInjectionScanner,
        ));
        report.add_finding(ManagedFinding::new(
            Finding::new(
                "XSS",
                "Reflected XSS in search",
                Severity::Medium,
                VulnerabilityCategory::Xss,
            )
            .with_url("https://example.com/search"),
            DetectionSource::XssScanner,
        ));
        report.add_finding(ManagedFinding::new(
            Finding::new(
                "Dir",
                "Directory listing exposed",
                Severity::Low,
                VulnerabilityCategory::SecurityMisconfiguration,
            )
            .with_url("https://example.com/uploads"),
            DetectionSource::DirSearchScanner,
        ));

        report
    }

    #[test]
    fn text_summary_generation() {
        let report = make_report();
        let text = ReportGenerator::text_summary(&report);
        assert!(text.contains("Findings Report"));
        assert!(text.contains("SQLi"));
        assert!(text.contains("XSS"));
    }

    #[test]
    fn severity_breakdown() {
        let report = make_report();
        let breakdown = ReportGenerator::severity_breakdown(&report);
        assert_eq!(breakdown["high"], 1);
        assert_eq!(breakdown["medium"], 1);
        assert_eq!(breakdown["low"], 1);
    }

    #[test]
    fn by_status_grouping() {
        let report = make_report();
        let grouped = ReportGenerator::by_status(&report);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].0, FindingStatus::New);
        assert_eq!(grouped[0].1.len(), 3);
    }

    #[test]
    fn by_source_grouping() {
        let report = make_report();
        let grouped = ReportGenerator::by_source(&report);
        assert_eq!(grouped.len(), 3);
        assert!(grouped
            .iter()
            .any(|(name, _)| name == "SQL Injection Scanner"));
        assert!(grouped.iter().any(|(name, _)| name == "XSS Scanner"));
        assert!(grouped
            .iter()
            .any(|(name, _)| name == "Directory Search Scanner"));
    }

    #[test]
    fn by_type_grouping() {
        let report = make_report();
        let grouped = ReportGenerator::by_type(&report);
        // SQLi and XSS both map to Vulnerability, Dir maps to Misconfiguration
        assert_eq!(grouped.len(), 2);
        let vulns = grouped
            .iter()
            .find(|(name, _)| name == "Vulnerability")
            .unwrap();
        assert_eq!(vulns.1.len(), 2);
        let misconfigs = grouped
            .iter()
            .find(|(name, _)| name == "Misconfiguration")
            .unwrap();
        assert_eq!(misconfigs.1.len(), 1);
    }

    #[test]
    fn above_severity() {
        let report = make_report();
        let high_and_above = ReportGenerator::above_severity(&report, Severity::High);
        assert_eq!(high_and_above.len(), 1);
        assert_eq!(high_and_above[0].finding.title, "SQLi");

        let medium_and_above = ReportGenerator::above_severity(&report, Severity::Medium);
        assert_eq!(medium_and_above.len(), 2);
    }

    #[test]
    fn category_matrix() {
        let report = make_report();
        let matrix = ReportGenerator::category_matrix(&report);
        assert_eq!(matrix["high"]["new"], 1);
        assert_eq!(matrix["medium"]["new"], 1);
        assert_eq!(matrix["low"]["new"], 1);
    }

    #[test]
    fn risk_score() {
        let report = make_report();
        let score = ReportGenerator::risk_score(&report);
        // High(7) + Medium(4) + Low(1) = 12.0
        assert!((score - 12.0).abs() < 0.001);
    }

    #[test]
    fn risk_score_excludes_false_positives() {
        let target_id = Id::new();
        let mut report = FindingsReport::new(target_id);
        let mut f = ManagedFinding::new(
            Finding::new(
                "FP",
                "desc",
                Severity::Critical,
                VulnerabilityCategory::Injection,
            ),
            DetectionSource::SqlInjectionScanner,
        );
        f.status = FindingStatus::FalsePositive;
        report.add_finding(f);

        let score = ReportGenerator::risk_score(&report);
        assert!((score - 0.0).abs() < 0.001);
    }

    #[test]
    fn top_hosts() {
        let report = make_report();
        let hosts = ReportGenerator::top_hosts(&report, 5);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].0, "example.com");
        assert_eq!(hosts[0].1, 3);
    }

    #[test]
    fn top_hosts_limit() {
        let target_id = Id::new();
        let mut report = FindingsReport::new(target_id);

        for i in 0..5 {
            report.add_finding(ManagedFinding::new(
                Finding::new(
                    format!("Finding {}", i),
                    "desc",
                    Severity::Medium,
                    VulnerabilityCategory::Other("test".into()),
                )
                .with_url(format!("https://host{}.example.com/page", i)),
                DetectionSource::Crawler,
            ));
        }

        let hosts = ReportGenerator::top_hosts(&report, 3);
        assert_eq!(hosts.len(), 3);
    }

    #[test]
    fn empty_report() {
        let target_id = Id::new();
        let report = FindingsReport::new(target_id);
        let text = ReportGenerator::text_summary(&report);
        assert!(text.contains("Total: 0"));

        let score = ReportGenerator::risk_score(&report);
        assert!((score - 0.0).abs() < 0.001);
    }
}
