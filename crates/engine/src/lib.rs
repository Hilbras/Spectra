use serde::{Deserialize, Serialize};
use spectra_core::Id;
use spectra_evidence::{EvidenceData, EvidenceEngine, EvidenceType};
use spectra_findings::{
    CorrelationEngine, DetectionSource, FindingsManager, InMemoryFindingsManager, ManagedFinding,
    Observation, ObservationEngine, ObservationType, ReportGenerator,
};
use spectra_network::NetworkEngine;
use spectra_scanner::{ScanResult, Scanner, ScannerConfig};
use spectra_target::{Target, TargetId};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("Engine error: {0}")]
    Generic(String),
    #[error("Scanner error: {0}")]
    Scanner(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Crawler error: {0}")]
    Crawler(String),
    #[error("Fingerprint error: {0}")]
    Fingerprint(String),
}

pub type EngineResult<T> = Result<T, EngineError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanStatus {
    Pending,
    Discovering,
    Crawling,
    Fingerprinting,
    Scanning,
    Observing,
    Verifying,
    Correlating,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Discovering => write!(f, "Discovering"),
            Self::Crawling => write!(f, "Crawling"),
            Self::Fingerprinting => write!(f, "Fingerprinting"),
            Self::Scanning => write!(f, "Scanning"),
            Self::Observing => write!(f, "Observing"),
            Self::Verifying => write!(f, "Verifying"),
            Self::Correlating => write!(f, "Correlating"),
            Self::Completed => write!(f, "Completed"),
            Self::Failed => write!(f, "Failed"),
            Self::Cancelled => write!(f, "Cancelled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPlan {
    pub target: Target,
    pub scanners: Vec<String>,
    pub max_depth: u32,
    pub max_pages: u32,
    pub timeout_secs: u64,
    pub collect_evidence: bool,
    pub record_observations: bool,
}

impl ScanPlan {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            scanners: vec!["sql_injection".into(), "xss".into(), "dir_search".into()],
            max_depth: 3,
            max_pages: 100,
            timeout_secs: 300,
            collect_evidence: true,
            record_observations: true,
        }
    }

    pub fn with_scanners(mut self, scanners: Vec<String>) -> Self {
        self.scanners = scanners;
        self
    }

    pub fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    pub fn with_max_pages(mut self, pages: u32) -> Self {
        self.max_pages = pages;
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn with_evidence(mut self, collect: bool) -> Self {
        self.collect_evidence = collect;
        self
    }

    pub fn with_observations(mut self, record: bool) -> Self {
        self.record_observations = record;
        self
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EngineMetrics {
    pub total_findings: usize,
    pub findings_by_severity: std::collections::HashMap<String, usize>,
    pub assets_discovered: usize,
    pub pages_crawled: usize,
    pub technologies_detected: usize,
    pub observations_recorded: usize,
    pub evidence_collected: usize,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub target_id: Id<TargetId>,
    pub status: ScanStatus,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub network_asset_count: usize,
    pub crawl_page_count: usize,
    pub technology_count: usize,
    pub scan_results: Vec<ScanResult>,
    pub report_summary: Option<String>,
    pub metrics: EngineMetrics,
    pub errors: Vec<String>,
}

impl ScanJob {
    pub fn new(target_id: Id<TargetId>) -> Self {
        Self {
            target_id,
            status: ScanStatus::Pending,
            started_at: None,
            completed_at: None,
            network_asset_count: 0,
            crawl_page_count: 0,
            technology_count: 0,
            scan_results: Vec::new(),
            report_summary: None,
            metrics: EngineMetrics::default(),
            errors: Vec::new(),
        }
    }

    pub fn duration_ms(&self) -> Option<u64> {
        match (&self.started_at, &self.completed_at) {
            (Some(start), Some(end)) => {
                let s = chrono::DateTime::parse_from_rfc3339(start).ok()?;
                let e = chrono::DateTime::parse_from_rfc3339(end).ok()?;
                Some((e - s).num_milliseconds() as u64)
            }
            _ => None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled
        )
    }
}

pub struct ScanEngine {
    network_engine: NetworkEngine,
    findings_manager: InMemoryFindingsManager,
    observation_engine: ObservationEngine<spectra_findings::InMemoryObservationStore>,
    evidence_engine: EvidenceEngine,
    correlation_engine: CorrelationEngine,
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanEngine {
    pub fn new() -> Self {
        Self {
            network_engine: NetworkEngine::new(),
            findings_manager: InMemoryFindingsManager::new(),
            observation_engine: ObservationEngine::new(
                spectra_findings::InMemoryObservationStore::new(),
            ),
            evidence_engine: EvidenceEngine::new(),
            correlation_engine: CorrelationEngine::new(),
        }
    }

    pub fn findings_manager(&self) -> &InMemoryFindingsManager {
        &self.findings_manager
    }

    pub fn observation_engine(
        &self,
    ) -> &ObservationEngine<spectra_findings::InMemoryObservationStore> {
        &self.observation_engine
    }

    pub fn evidence_engine(&self) -> &EvidenceEngine {
        &self.evidence_engine
    }

    pub fn correlation_engine(&self) -> &CorrelationEngine {
        &self.correlation_engine
    }

    pub async fn run_scan(&self, plan: &ScanPlan) -> EngineResult<ScanJob> {
        let mut job = ScanJob::new(plan.target.id.clone());
        job.status = ScanStatus::Discovering;
        job.started_at = Some(chrono::Utc::now().to_rfc3339());

        let start = std::time::Instant::now();

        // Phase 1: Network discovery
        let domain = plan.target.value.clone();
        let graph = self
            .network_engine
            .discover(&domain)
            .await
            .map_err(|e| EngineError::Network(e.to_string()))?;

        job.network_asset_count = graph.len();
        job.metrics.assets_discovered = graph.len();

        // Record DNS observations
        if plan.record_observations {
            for asset in graph.find_by_type(&spectra_network::AssetType::IpAddress) {
                let obs = Observation::new(
                    plan.target.id.to_string(),
                    "network-discovery",
                    ObservationType::DnsRecord,
                    serde_json::json!({
                        "host": asset.value,
                        "record_type": "A",
                    }),
                )
                .with_confidence(1.0);

                self.observation_engine
                    .record_with(obs)
                    .await
                    .map_err(|e| EngineError::Generic(e.to_string()))?;
                job.metrics.observations_recorded += 1;
            }
        }

        // Phase 2: Crawl the target
        job.status = ScanStatus::Crawling;
        let crawler_config = spectra_crawler::CrawlerConfig::default();
        let crawler = spectra_crawler::Crawler::new(crawler_config);
        let crawl_result = crawler
            .crawl(&plan.target)
            .await
            .map_err(|e| EngineError::Crawler(e.to_string()))?;

        job.metrics.pages_crawled = crawl_result.total_crawled as usize;
        job.crawl_page_count = crawl_result.total_crawled as usize;

        // Record crawl observations
        if plan.record_observations {
            for page in &crawl_result.pages {
                let obs = Observation::new(
                    plan.target.id.to_string(),
                    "crawler",
                    ObservationType::CrawlerDiscovery,
                    serde_json::json!({
                        "url": page.url,
                        "status_code": page.status_code,
                        "content_length": page.content.len(),
                        "links_found": page.links.len(),
                    }),
                )
                .with_confidence(1.0);

                self.observation_engine
                    .record_with(obs)
                    .await
                    .map_err(|e| EngineError::Generic(e.to_string()))?;
                job.metrics.observations_recorded += 1;
            }
        }

        // Phase 3: Fingerprint
        job.status = ScanStatus::Fingerprinting;
        let fp_engine = spectra_fingerprint::FingerprintEngine::new();

        if let Some(first_page) = crawl_result.pages.first() {
            let input = spectra_fingerprint::FingerprintInput {
                headers: first_page.headers.clone(),
                html: first_page.content.clone(),
                url: first_page.url.clone(),
                cookies: Vec::new(),
            };
            let fingerprint = fp_engine.fingerprint(&input);
            job.metrics.technologies_detected = fingerprint.technologies.len();
            job.technology_count = fingerprint.technologies.len();

            // Record fingerprint observations
            if plan.record_observations {
                for tech in &fingerprint.technologies {
                    let obs = Observation::new(
                        plan.target.id.to_string(),
                        "fingerprinter",
                        ObservationType::TechnologyFingerprint,
                        serde_json::json!({
                            "technology": tech.name,
                            "version": tech.version,
                            "category": tech.category,
                            "confidence": tech.confidence,
                        }),
                    )
                    .with_confidence(tech.confidence);

                    self.observation_engine
                        .record_with(obs)
                        .await
                        .map_err(|e| EngineError::Generic(e.to_string()))?;
                    job.metrics.observations_recorded += 1;
                }
            }
        }

        // Phase 4: Run scanners
        job.status = ScanStatus::Scanning;
        let scanners = self.create_scanners(&plan.scanners);

        for mut scanner in scanners {
            let config = ScannerConfig {
                name: scanner.metadata().name.clone(),
                version: scanner.metadata().version.clone(),
                ..Default::default()
            };

            scanner
                .initialize(config)
                .await
                .map_err(|e| EngineError::Scanner(e.to_string()))?;

            let result = scanner
                .scan(&plan.target)
                .await
                .map_err(|e| EngineError::Scanner(e.to_string()))?;

            for finding in &result.findings {
                let managed = ManagedFinding::new(
                    finding.clone(),
                    self.detection_source_for(&result.scanner_name),
                );
                self.findings_manager
                    .save_finding(managed)
                    .await
                    .map_err(|e| EngineError::Generic(e.to_string()))?;

                // Record scanner output observations
                if plan.record_observations {
                    let obs = Observation::new(
                        plan.target.id.to_string(),
                        &result.scanner_name,
                        ObservationType::ScannerOutput,
                        serde_json::json!({
                            "title": finding.title,
                            "severity": finding.severity,
                            "category": finding.category,
                            "affected_url": finding.affected_url,
                            "evidence_count": finding.evidence.len(),
                        }),
                    )
                    .with_confidence(0.8);

                    self.observation_engine
                        .record_with(obs)
                        .await
                        .map_err(|e| EngineError::Generic(e.to_string()))?;
                    job.metrics.observations_recorded += 1;
                }

                // Collect evidence for findings
                if plan.collect_evidence {
                    let evidence = self
                        .evidence_engine
                        .capture(
                            finding.id.clone(),
                            EvidenceType::ScannerOutput,
                            &finding.title,
                            EvidenceData::Json(serde_json::json!({
                                "title": finding.title,
                                "description": finding.description,
                                "severity": finding.severity,
                                "category": finding.category,
                                "affected_url": finding.affected_url,
                                "evidence": finding.evidence,
                            })),
                        )
                        .await
                        .map_err(|e| EngineError::Generic(e.to_string()))?;
                    job.metrics.evidence_collected += 1;
                    let _ = evidence;
                }
            }

            job.metrics.total_findings += result.findings.len();
            for finding in &result.findings {
                *job.metrics
                    .findings_by_severity
                    .entry(finding.severity.to_string())
                    .or_insert(0) += 1;
            }
            job.scan_results.push(result);

            scanner
                .cleanup()
                .await
                .map_err(|e| EngineError::Scanner(e.to_string()))?;
        }

        // Phase 5: Correlate and report
        job.status = ScanStatus::Correlating;
        let report = self
            .findings_manager
            .generate_report(&plan.target.id)
            .await
            .map_err(|e| EngineError::Generic(e.to_string()))?;

        let summary = ReportGenerator::text_summary(&report);
        job.report_summary = Some(summary);

        job.completed_at = Some(chrono::Utc::now().to_rfc3339());
        job.status = ScanStatus::Completed;
        job.metrics.scan_duration_ms = start.elapsed().as_millis() as u64;

        Ok(job)
    }

    fn create_scanners(&self, scanner_names: &[String]) -> Vec<Box<dyn Scanner>> {
        let mut scanners: Vec<Box<dyn Scanner>> = Vec::new();
        for name in scanner_names {
            match name.as_str() {
                "sql_injection" => {
                    scanners.push(Box::new(spectra_scanner::SqlInjectionScanner::new()))
                }
                "xss" => scanners.push(Box::new(spectra_scanner::XssScanner::new())),
                "dir_search" => scanners.push(Box::new(spectra_scanner::DirSearchScanner::new())),
                _ => {}
            }
        }
        scanners
    }

    fn detection_source_for(&self, scanner_name: &str) -> DetectionSource {
        match scanner_name {
            "sql_injection" => DetectionSource::SqlInjectionScanner,
            "xss" => DetectionSource::XssScanner,
            "dir_search" => DetectionSource::DirSearchScanner,
            _ => DetectionSource::Other(scanner_name.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectra_target::TargetType;

    fn test_target() -> Target {
        Target::new(
            Id::new(),
            "test-target".into(),
            TargetType::Domain,
            "example.com".into(),
        )
    }

    #[test]
    fn scan_plan_construction() {
        let target = test_target();
        let plan = ScanPlan::new(target);
        assert_eq!(plan.max_depth, 3);
        assert_eq!(plan.max_pages, 100);
        assert_eq!(plan.timeout_secs, 300);
        assert!(plan.scanners.contains(&"sql_injection".to_string()));
        assert!(plan.collect_evidence);
        assert!(plan.record_observations);
    }

    #[test]
    fn scan_plan_builder() {
        let target = test_target();
        let plan = ScanPlan::new(target)
            .with_scanners(vec!["xss".into()])
            .with_max_depth(5)
            .with_max_pages(200)
            .with_timeout(600)
            .with_evidence(false)
            .with_observations(false);

        assert_eq!(plan.scanners, vec!["xss"]);
        assert_eq!(plan.max_depth, 5);
        assert_eq!(plan.max_pages, 200);
        assert_eq!(plan.timeout_secs, 600);
        assert!(!plan.collect_evidence);
        assert!(!plan.record_observations);
    }

    #[test]
    fn scan_job_creation() {
        let target_id = Id::new();
        let job = ScanJob::new(target_id.clone());
        assert_eq!(job.status, ScanStatus::Pending);
        assert!(job.started_at.is_none());
        assert_eq!(job.metrics.total_findings, 0);
        assert!(job.errors.is_empty());
    }

    #[test]
    fn scan_job_is_terminal() {
        let job = ScanJob::new(Id::new());
        assert!(!job.is_terminal());

        let mut completed = ScanJob::new(Id::new());
        completed.status = ScanStatus::Completed;
        assert!(completed.is_terminal());

        let mut failed = ScanJob::new(Id::new());
        failed.status = ScanStatus::Failed;
        assert!(failed.is_terminal());

        let mut cancelled = ScanJob::new(Id::new());
        cancelled.status = ScanStatus::Cancelled;
        assert!(cancelled.is_terminal());
    }

    #[test]
    fn engine_creation() {
        let _engine = ScanEngine::new();
    }

    #[test]
    fn detection_source_mapping() {
        let engine = ScanEngine::new();
        assert_eq!(
            engine.detection_source_for("sql_injection"),
            DetectionSource::SqlInjectionScanner
        );
        assert_eq!(
            engine.detection_source_for("xss"),
            DetectionSource::XssScanner
        );
        assert_eq!(
            engine.detection_source_for("dir_search"),
            DetectionSource::DirSearchScanner
        );
        assert!(matches!(
            engine.detection_source_for("unknown"),
            DetectionSource::Other(_)
        ));
    }

    #[test]
    fn scan_status_variants() {
        let statuses = [
            ScanStatus::Pending,
            ScanStatus::Discovering,
            ScanStatus::Crawling,
            ScanStatus::Fingerprinting,
            ScanStatus::Scanning,
            ScanStatus::Observing,
            ScanStatus::Verifying,
            ScanStatus::Correlating,
            ScanStatus::Completed,
            ScanStatus::Failed,
            ScanStatus::Cancelled,
        ];
        assert_eq!(statuses.len(), 11);
    }

    #[test]
    fn scan_status_display() {
        assert_eq!(ScanStatus::Pending.to_string(), "Pending");
        assert_eq!(ScanStatus::Observing.to_string(), "Observing");
        assert_eq!(ScanStatus::Completed.to_string(), "Completed");
    }

    #[test]
    fn engine_metrics_default() {
        let metrics = EngineMetrics::default();
        assert_eq!(metrics.total_findings, 0);
        assert_eq!(metrics.assets_discovered, 0);
        assert_eq!(metrics.observations_recorded, 0);
        assert_eq!(metrics.evidence_collected, 0);
    }

    #[test]
    fn create_scanners_filters() {
        let engine = ScanEngine::new();
        let names = vec![
            "sql_injection".into(),
            "xss".into(),
            "unknown_scanner".into(),
        ];
        let scanners = engine.create_scanners(&names);
        assert_eq!(scanners.len(), 2);
    }
}
