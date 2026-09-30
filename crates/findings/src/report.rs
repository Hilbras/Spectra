use crate::{FindingStatus, FindingsReport, ManagedFinding};
use spectra_scanner::Severity;

/// Report generation utilities.
pub struct ReportGenerator;

impl ReportGenerator {
    /// Generates a text summary of a findings report.
    pub fn text_summary(report: &FindingsReport) -> String {
        Self::text_summary_with_coverage(report, "Completed", &[])
    }

    /// Generates a text summary that states what the scan actually covered.
    ///
    /// `coverage_status` and `errors` are rendered above the summary rather than
    /// left to the caller, because a report that reads "Total: 0" over a scan
    /// which never reached its target is a false negative presented as a clean
    /// result — and the summary block is the part people read first, and the
    /// part most likely to be pasted into a ticket.
    ///
    /// The parameters are plain strings rather than engine types so this crate
    /// stays independent of the engine's status enum.
    pub fn text_summary_with_coverage(
        report: &FindingsReport,
        coverage_status: &str,
        errors: &[String],
    ) -> String {
        let mut output = String::new();

        if !errors.is_empty() {
            output.push_str(&format!("Scan status: {coverage_status}\n"));
            output.push_str(&format!(
                "WARNING: this scan did not complete cleanly. {} failure(s) were \
                 recorded, so the findings below are incomplete and their absence \
                 is not evidence that the target is clean.\n",
                errors.len()
            ));
            for error in errors {
                output.push_str(&format!("  - {error}\n"));
            }
            output.push('\n');
        }

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

    /// A report with no findings — what a failed scan produces, and what reads
    /// most like a clean result.
    fn make_empty_report() -> FindingsReport {
        FindingsReport::new(Id::new())
    }

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

    /// The false negative in its most quotable form: a report body reading
    /// "Total: 0" over a scan that never reached the target looks exactly like a
    /// clean result. The caveat has to be in the text, not just in a status field
    /// the reader may not look at.
    #[test]
    fn a_report_from_an_incomplete_scan_says_so_before_the_summary() {
        let report = make_empty_report();
        let errors = vec![
            "crawl: retrieved no pages from http://127.0.0.1:1/".to_string(),
            "xss: Failed to fetch target".to_string(),
        ];

        let text = ReportGenerator::text_summary_with_coverage(&report, "Failed", &errors);

        assert!(text.starts_with("Scan status: Failed"));
        assert!(
            text.contains("not evidence that the target is clean"),
            "the caveat must state the conclusion explicitly, got:\n{text}"
        );
        assert!(text.contains("xss: Failed to fetch target"));

        // The caveat must come before the counts, since the counts are what a
        // reader quotes out of a report.
        let caveat = text.find("WARNING").expect("a warning must be present");
        let summary = text.find("Summary").expect("the summary must be present");
        assert!(caveat < summary, "the warning must precede the summary");
    }

    #[test]
    fn a_clean_report_carries_no_caveat() {
        // The one result that should read as reassuring: if this started warning
        // on success, the warning would be ignored everywhere.
        let report = make_empty_report();
        let text = ReportGenerator::text_summary_with_coverage(&report, "Completed", &[]);

        assert!(!text.contains("WARNING"));
        assert!(!text.contains("Scan status"));
        assert!(text.contains("Total: 0"));
        assert!(text.starts_with("Findings Report"));
    }

    #[test]
    fn the_default_summary_is_unchanged_by_the_coverage_variant() {
        // `text_summary` delegates with no errors, so existing output must be
        // byte-identical to avoid changing reports that were already fine.
        let report = make_report();
        assert_eq!(
            ReportGenerator::text_summary(&report),
            ReportGenerator::text_summary_with_coverage(&report, "Completed", &[])
        );
    }

    #[test]
    fn a_partial_scan_is_labelled_partial_not_failed() {
        let report = make_empty_report();
        let text = ReportGenerator::text_summary_with_coverage(
            &report,
            "Partial",
            &["xss: Failed to fetch target".to_string()],
        );
        assert!(text.starts_with("Scan status: Partial"));
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
