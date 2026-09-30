#[cfg(test)]
mod integration_tests;
pub mod pipeline;

use serde::{Deserialize, Serialize};
use spectra_core::Id;
use spectra_events::{Event, EventBus, EventPayload, EventSource, EventType};
use spectra_evidence::{EvidenceData, EvidenceEngine, EvidenceType};
use spectra_findings::{
    CorrelationEngine, DetectionSource, FindingsManager, ManagedFinding, Observation,
    ObservationEngine, ObservationStore, ObservationType, ReportGenerator,
};
use spectra_network::NetworkEngine;
use spectra_scanner::{ScanResult, Scanner, ScannerConfig};
use spectra_target::{Target, TargetId};
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, warn};

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

/// `Copy` because it is a fieldless state enum that is passed around and
/// compared far more often than it is stored.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
    /// The scan ran to the end, but at least one stage failed, so the results
    /// are known to be incomplete.
    ///
    /// This state exists because the alternative was worse: a scan in which every
    /// request failed used to report `Completed` with zero findings, which reads
    /// in a report as "nothing to see here". For a security tool a false negative
    /// is more damaging than an error, so partial coverage is stated rather than
    /// rounded up to success.
    Partial,
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
            Self::Partial => write!(f, "Partial"),
            Self::Failed => write!(f, "Failed"),
            Self::Cancelled => write!(f, "Cancelled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPlan {
    pub target: Target,
    /// Identifies this run.
    ///
    /// Required rather than derived, because the engine attributes every
    /// observation it records to it. It used to pass `target.id` into the
    /// `scan_id` field of each observation, while `GET /scans/{id}/observations`
    /// queried by the *scan* id — so the endpoint returned an empty list for
    /// every scan, permanently, with no error to indicate why. Making the caller
    /// supply it turns that silent mismatch into a compile error.
    pub scan_id: String,
    pub scanners: Vec<String>,
    pub max_depth: u32,
    pub max_pages: u32,
    pub timeout_secs: u64,
    pub collect_evidence: bool,
    pub record_observations: bool,
}

/// The crawler configuration implied by an already-clamped plan.
///
/// A free function so the mapping is testable on its own. Inlined in
/// `run_scan_inner` it was effectively unverifiable, and it was wrong: the
/// crawler was constructed with `CrawlerConfig::default()` — depth 10, 10,000
/// pages — so `plan.max_depth` and `plan.max_pages` had no effect on anything.
fn crawler_config_for(plan: &ScanPlan) -> spectra_crawler::CrawlerConfig {
    spectra_crawler::CrawlerConfig {
        max_depth: plan.max_depth,
        max_pages: plan.max_pages,
        ..spectra_crawler::CrawlerConfig::default()
    }
}

/// The single terminal event for a finished scan.
///
/// A free function, and the only place a terminal event is chosen, so the mapping
/// can be tested directly instead of inferred from a scan that happens to end in a
/// given state. `ScanCompleted` is reserved for a target that was actually
/// assessed: publishing it for a `Partial` job tells subscribers a conclusion the
/// scan did not reach, and a subscriber has no way to check. There is no fourth
/// spelling for "finished", which is what makes the mapping exhaustible.
fn terminal_event(scan_id: &str, job: &ScanJob) -> (EventType, EventPayload) {
    match job.status {
        ScanStatus::Completed => (
            EventType::ScanCompleted,
            EventPayload::ScanCompleted {
                scan_id: scan_id.to_string(),
            },
        ),
        ScanStatus::Partial => (
            EventType::ScanPartial,
            EventPayload::ScanPartial {
                scan_id: scan_id.to_string(),
                reason: detail(job, "coverage was lost during the scan"),
            },
        ),
        _ => (
            EventType::ScanFailed,
            EventPayload::ScanFailed {
                scan_id: scan_id.to_string(),
                error: detail(job, "the scan produced no usable coverage"),
            },
        ),
    }
}

/// The recorded reasons, joined, with a fallback so the field is never empty.
///
/// An event whose `reason` is empty tells a subscriber that something went wrong
/// and nothing else. It would have to go and find the job to learn what.
fn detail(job: &ScanJob, fallback: &str) -> String {
    if job.errors.is_empty() {
        fallback.to_string()
    } else {
        job.errors.join("; ")
    }
}

/// Emits a scan lifecycle event, if a bus is attached.
///
/// Deliberately infallible and non-async. `publish` cannot fail, and a scan must
/// not be made to depend on event delivery: a subscriber that panics or a channel
/// that lags must not turn a completed scan into an error. Losing events is the
/// correct failure mode here, and `broadcast` drops them rather than blocking.
fn emit(bus: &Option<EventBus>, event_type: EventType, payload: EventPayload) {
    if let Some(bus) = bus {
        bus.publish(Event::new(event_type, EventSource::System, payload));
    }
}

/// Every scanner name this engine can run.
///
/// The single source of truth. The API validates against it so a caller is told
/// which names are valid instead of receiving a scan that silently ran fewer checks
/// than they asked for.
pub fn available_scanners() -> &'static [&'static str] {
    &[
        "sql_injection",
        "xss",
        "dir_search",
        "ssrf",
        "open_redirect",
        "path_traversal",
        "csrf",
        "xxe",
        "cors",
    ]
}

/// Log a requested scanner name that has no implementation.
///
/// The warning is not the fix. It exists so that an unresolved name is visible in
/// the logs even when the caller is not reading the scan's error list; the coverage
/// record in `run_scan_inner` is what makes it visible in the result.
fn job_warn_unresolved(name: &str) {
    warn!(
        scanner = name,
        available = ?available_scanners(),
        "requested scanner has no implementation; its vulnerability class will go unchecked"
    );
}

/// Record what the scanner selection did and did not cover.
///
/// A name with no implementation means a vulnerability class went unchecked. When
/// some scanners did run, that is *lost coverage* and the scan is `Partial`: the
/// classes that ran are honestly reported, and the ones that did not are named.
///
/// When none ran, nothing examined the target for vulnerabilities at all. That is a
/// total *coverage gap*, and the scan must be `Failed`. Reporting `Completed` with
/// zero findings over an unscanned target is the false negative the whole status
/// split exists to prevent, and it is indistinguishable from a clean result.
///
/// Requesting no scanners at all is a legitimate caller choice — the crawl and
/// fingerprint stages still produce real results — but it is not a vulnerability
/// assessment, and the report must not read as one.
///
/// A free function over `&mut ScanJob` so the decision is testable without a
/// network, a target or a running scan. The three inputs are the only facts the
/// decision depends on.
fn record_scanner_selection_coverage(job: &mut ScanJob, requested: usize, unresolved: Vec<String>) {
    let nothing_ran = requested == 0 || unresolved.len() == requested;

    for name in &unresolved {
        if nothing_ran {
            job.record_coverage_gap(
                "scanning",
                format!(
                    "no scanner ran: `{name}` has no implementation, and no other \
                     requested scanner did either"
                ),
            );
        } else {
            job.record_lost_coverage(
                "scanning",
                format!("`{name}` has no implementation; that check did not run"),
            );
        }
    }

    if requested == 0 {
        job.record_coverage_gap(
            "scanning",
            "no scanners were requested, so no vulnerability class was tested",
        );
    }
}

/// Operator-set ceilings on what a single scan may consume.
///
/// Deliberately separate from [`ScanPlan`], which is caller-supplied. A caller
/// may narrow a scan; only the operator may widen it. `POST /api/v1/scans`
/// accepts `max_depth`, `max_pages` and `timeout_secs` from the request body,
/// and before these limits were honoured the engine used
/// `CrawlerConfig::default()` — up to 10,000 pages at depth 10 with no timeout at
/// all — regardless of what the caller asked for. So the fields were decorative,
/// and the only real bound was the crawler default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLimits {
    pub max_depth: u32,
    pub max_pages: u32,
    pub timeout_secs: u64,
}

impl Default for ScanLimits {
    /// Matches `spectra_config`'s crawler and scanner defaults, so a server with
    /// no explicit configuration behaves as it did before — but now the bounds
    /// are real and overridable.
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_pages: 10_000,
            timeout_secs: 300,
        }
    }
}

impl ScanLimits {
    /// What this server permits, for a plan requesting nothing in particular.
    pub fn from_config(config: &spectra_config::Config) -> Self {
        Self {
            max_depth: config.crawler.max_depth,
            max_pages: config.crawler.max_pages,
            timeout_secs: config.scanner.default_timeout,
        }
    }

    /// Clamp `plan` into what this server allows.
    ///
    /// A zero or absent caller value means "no preference", so it takes the
    /// ceiling rather than collapsing the scan to nothing. That matters because
    /// the API treats `max_pages: Some(0)` as a real request, and honouring it
    /// literally would silently produce a scan that crawls nothing and reports
    /// no findings — the same false-negative shape Remediation 10 removed.
    pub fn clamp(&self, plan: &ScanPlan) -> ScanPlan {
        let mut clamped = plan.clone();

        clamped.max_depth = if plan.max_depth == 0 {
            self.max_depth
        } else {
            plan.max_depth.min(self.max_depth)
        };
        clamped.max_pages = if plan.max_pages == 0 {
            self.max_pages
        } else {
            plan.max_pages.min(self.max_pages)
        };
        clamped.timeout_secs = if plan.timeout_secs == 0 {
            self.timeout_secs
        } else {
            plan.timeout_secs.min(self.timeout_secs)
        };

        clamped
    }
}

impl ScanPlan {
    /// Build a plan for `scan_id` over `target`.
    pub fn new(scan_id: impl Into<String>, target: Target) -> Self {
        Self {
            target,
            scan_id: scan_id.into(),
            // Derived from `available_scanners` rather than repeated, so the default
            // and the list the API validates against cannot drift apart.
            scanners: available_scanners()
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
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
    /// Stages that produced some output but not all they should have.
    pub lost_coverage: Vec<String>,
    /// Stages that produced no output at all.
    ///
    /// Kept apart from `lost_coverage` and `errors` because the three warrant
    /// different final statuses, and inferring that from a count does not work:
    /// a crawler that failed to fetch three URLs out of two hundred still gave
    /// the scanners usable input, while a crawler that fetched nothing gave them
    /// none. Folding both into one counter would either mark good scans partial
    /// or excuse total failures. See [`ScanJob::resolve_status`].
    pub coverage_gaps: Vec<String>,
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
            lost_coverage: Vec::new(),
            coverage_gaps: Vec::new(),
        }
    }

    /// Record a failure that is reported but does not change the final status.
    ///
    /// For failures that are routine at scale — an individual URL in a crawl that
    /// otherwise succeeded. If these made every scan `Partial`, the status would
    /// stop carrying information and operators would learn to ignore it. They are
    /// still recorded, still shown in `GET /scans/{id}`, and still counted.
    pub fn record_error(&mut self, stage: &str, message: impl std::fmt::Display) {
        self.errors.push(format!("{stage}: {message}"));
    }

    /// Record a stage that produced some output but not all it should have.
    ///
    /// A scanner that could not reach the target is the canonical case: the
    /// vulnerability class it covers went unchecked, while other scanners still
    /// produced findings.
    pub fn record_lost_coverage(&mut self, stage: &str, message: impl std::fmt::Display) {
        let entry = format!("{stage}: {message}");
        self.lost_coverage.push(entry.clone());
        self.errors.push(entry);
    }

    /// Record a stage that produced no usable output whatsoever.
    pub fn record_coverage_gap(&mut self, stage: &str, message: impl std::fmt::Display) {
        let entry = format!("{stage}: {message}");
        self.coverage_gaps.push(entry.clone());
        self.lost_coverage.push(entry.clone());
        self.errors.push(entry);
    }

    /// Decide the terminal status from what the run recorded.
    ///
    /// The distinction being made is between "the orchestration finished" and
    /// "the target was analysed". Conflating them is what let a scan in which
    /// every request failed report `Completed` with zero findings — which in a
    /// findings report is indistinguishable from a clean target, and for a
    /// security tool a false negative is worse than an error.
    ///
    /// - a stage produced nothing → `Failed`: there is no result to report
    /// - a stage lost coverage → `Partial`: the findings are real but not exhaustive
    /// - nothing went wrong → `Completed`
    pub fn resolve_status(&mut self) -> ScanStatus {
        self.status = if !self.coverage_gaps.is_empty() {
            ScanStatus::Failed
        } else if !self.lost_coverage.is_empty() {
            ScanStatus::Partial
        } else {
            ScanStatus::Completed
        };
        self.status
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
            ScanStatus::Completed
                | ScanStatus::Partial
                | ScanStatus::Failed
                | ScanStatus::Cancelled
        )
    }
}

pub struct ScanEngine<F: FindingsManager, O: ObservationStore> {
    network_engine: NetworkEngine,
    findings_manager: F,
    observation_engine: ObservationEngine<O>,
    /// Shared so the HTTP layer can read the evidence the engine captures.
    ///
    /// Held as an `Arc` because the API serves `GET /findings/{id}/evidence`
    /// from this same instance. As a bare field it could only be owned by one
    /// of them, and the API's endpoints were permanently empty.
    evidence_engine: Arc<EvidenceEngine>,
    correlation_engine: CorrelationEngine,
    /// Operator ceilings applied to every plan this engine runs.
    limits: ScanLimits,
    /// Publishes scan lifecycle events.
    ///
    /// Optional, because most callers do not want them. Emitting is a side effect
    /// that must never affect a scan's outcome: a subscriber that panics, a full
    /// broadcast channel or a closed bus all have to leave the scan untouched.
    event_bus: Option<EventBus>,
}

impl Default
    for ScanEngine<
        spectra_findings::InMemoryFindingsManager,
        spectra_findings::InMemoryObservationStore,
    >
{
    fn default() -> Self {
        Self::new()
    }
}

impl
    ScanEngine<
        spectra_findings::InMemoryFindingsManager,
        spectra_findings::InMemoryObservationStore,
    >
{
    pub fn new() -> Self {
        Self {
            network_engine: NetworkEngine::new(),
            findings_manager: spectra_findings::InMemoryFindingsManager::new(),
            observation_engine: ObservationEngine::new(
                spectra_findings::InMemoryObservationStore::new(),
            ),
            evidence_engine: Arc::new(EvidenceEngine::new()),
            correlation_engine: CorrelationEngine::new(),
            limits: ScanLimits::default(),
            event_bus: None,
        }
    }
}

impl<F: FindingsManager, O: ObservationStore> ScanEngine<F, O> {
    pub fn new_with(findings_manager: F, observation_store: O) -> Self {
        Self::new_with_shared_components(
            findings_manager,
            observation_store,
            Arc::new(EvidenceEngine::new()),
        )
    }

    /// Construct the engine around components the caller also holds.
    ///
    /// The split-brain this avoids is not hypothetical: with `new_with`, the
    /// engine built its own findings manager, observation store and evidence
    /// engine, and the API built separate ones of its own. Everything the engine
    /// recorded was therefore invisible to the API, and the API's evidence and
    /// verification endpoints returned empty for every scan, forever.
    pub fn new_with_shared_components(
        findings_manager: F,
        observation_store: O,
        evidence_engine: Arc<EvidenceEngine>,
    ) -> Self {
        Self {
            network_engine: NetworkEngine::new(),
            findings_manager,
            observation_engine: ObservationEngine::new(observation_store),
            evidence_engine,
            correlation_engine: CorrelationEngine::new(),
            limits: ScanLimits::default(),
            event_bus: None,
        }
    }

    /// Publish scan lifecycle events to `bus`.
    ///
    /// The three outcomes map to three distinct event types. `Partial` is not
    /// reported as `ScanCompleted`: a scan that timed out or lost coverage found
    /// some findings and did not assess the target, and a subscriber told
    /// otherwise would act on a conclusion the scan never reached.
    pub fn with_event_bus(mut self, bus: EventBus) -> Self {
        self.event_bus = Some(bus);
        self
    }

    /// Set the operator ceilings for scans run by this engine.
    pub fn with_limits(mut self, limits: ScanLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The ceilings currently in force.
    pub fn limits(&self) -> ScanLimits {
        self.limits
    }

    pub fn findings_manager(&self) -> &F {
        &self.findings_manager
    }

    pub fn observation_engine(&self) -> &ObservationEngine<O> {
        &self.observation_engine
    }

    pub fn evidence_engine(&self) -> &EvidenceEngine {
        &self.evidence_engine
    }

    pub fn correlation_engine(&self) -> &CorrelationEngine {
        &self.correlation_engine
    }

    /// Run a scan, bounded by this engine's [`ScanLimits`].
    ///
    /// `plan` is clamped first, so a caller's `max_depth`, `max_pages` and
    /// `timeout_secs` narrow the scan but never raise it above the operator's
    /// ceilings. Any reduction is recorded on the job so it is visible in
    /// `GET /scans/{id}` rather than being applied silently.
    ///
    /// On expiry the job is returned as [`ScanStatus::Partial`] with the reason
    /// recorded — not a hang, and not a `Completed` that implies the target was
    /// fully assessed.
    pub async fn run_scan(&self, plan: &ScanPlan) -> EngineResult<ScanJob> {
        let clamped = self.limits.clamp(plan);

        let mut job = ScanJob::new(clamped.target.id.clone());
        job.status = ScanStatus::Discovering;
        job.started_at = Some(chrono::Utc::now().to_rfc3339());

        let start = std::time::Instant::now();

        // Recorded before running, so the reason survives even if the timeout
        // fires on the very first stage.
        for (label, requested, permitted) in [
            ("max_depth", plan.max_depth as u64, clamped.max_depth as u64),
            ("max_pages", plan.max_pages as u64, clamped.max_pages as u64),
            ("timeout_secs", plan.timeout_secs, clamped.timeout_secs),
        ] {
            if requested != 0 && requested > permitted {
                job.record_error(
                    "limits",
                    format!(
                        "{label} reduced from {requested} to {permitted}: \
                         the requested value exceeds this server's ceiling"
                    ),
                );
                warn!(
                    target = %clamped.target.value(),
                    label,
                    requested,
                    permitted,
                    "scan limit reduced to the server ceiling"
                );
            }
        }

        emit(
            &self.event_bus,
            EventType::ScanStarted,
            EventPayload::ScanStarted {
                scan_id: clamped.scan_id.clone(),
                target_id: clamped.target.id.to_string(),
            },
        );

        let budget = std::time::Duration::from_secs(clamped.timeout_secs);
        match tokio::time::timeout(budget, self.run_scan_inner(&clamped, &mut job)).await {
            Ok(result) => {
                if let Err(e) = result {
                    // The stages failed outright. Without this the only events a
                    // scan ever produced were started and (if it got that far)
                    // a terminal one — a crash mid-scan looked identical to a scan
                    // that was never submitted.
                    emit(
                        &self.event_bus,
                        EventType::ScanFailed,
                        EventPayload::ScanFailed {
                            scan_id: clamped.scan_id.clone(),
                            error: e.to_string(),
                        },
                    );
                    return Err(e);
                }
                Ok(job)
            }
            Err(_) => {
                error!(
                    target = %clamped.target.value(),
                    timeout_secs = clamped.timeout_secs,
                    findings = job.metrics.total_findings,
                    "scan exceeded its time budget and was stopped; results are incomplete"
                );
                job.record_lost_coverage(
                    "timeout",
                    format!(
                        "scan exceeded its {}s budget and was stopped; the target was not \
                         fully assessed and the findings below are not exhaustive",
                        clamped.timeout_secs
                    ),
                );
                job.completed_at = Some(chrono::Utc::now().to_rfc3339());
                job.metrics.scan_duration_ms = start.elapsed().as_millis() as u64;
                job.status = ScanStatus::Partial;
                // Populated here as well as on the normal path. A `Partial` scan
                // that finished its stages has a summary carrying the caveat;
                // leaving this `None` only for timeouts would make the field's
                // emptiness a signal of *how* a scan ended rather than of what the
                // user needs to know, and a UI would render it as a blank report
                // with no explanation on the field itself.
                job.report_summary = Some(format!(
                    "Scan stopped after {}s without completing.\n\n\
                     The target was NOT fully assessed. {} finding(s) recorded before \
                     the limit was reached; these are not exhaustive and the absence \
                     of further findings does not indicate their absence from the target.",
                    clamped.timeout_secs, job.metrics.total_findings
                ));
                emit(
                    &self.event_bus,
                    EventType::ScanPartial,
                    EventPayload::ScanPartial {
                        scan_id: clamped.scan_id.clone(),
                        reason: format!(
                            "stopped after the {}s budget without completing",
                            clamped.timeout_secs
                        ),
                    },
                );
                Ok(job)
            }
        }
    }

    /// The stages themselves. Kept separate so [`ScanEngine::run_scan`] can own
    /// the job across the timeout boundary and still report partial progress.
    async fn run_scan_inner(&self, plan: &ScanPlan, job: &mut ScanJob) -> EngineResult<()> {
        let start = std::time::Instant::now();

        let domain = plan.target.value.clone();
        let graph = self
            .network_engine
            .discover(&domain)
            .await
            .map_err(|e| EngineError::Network(e.to_string()))?;

        job.network_asset_count = graph.len();
        job.metrics.assets_discovered = graph.len();

        if plan.record_observations {
            for asset in graph.find_by_type(&spectra_network::AssetType::IpAddress) {
                let obs = Observation::new(
                    plan.scan_id.clone(),
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

        job.status = ScanStatus::Crawling;
        let crawler_config = crawler_config_for(plan);
        let crawler = spectra_crawler::Crawler::new(crawler_config);
        let crawl_result = crawler
            .crawl(&plan.target)
            .await
            .map_err(|e| EngineError::Crawler(e.to_string()))?;

        // The count of pages actually retrieved, not the count attempted.
        job.metrics.pages_crawled = crawl_result.total_crawled as usize;
        job.crawl_page_count = crawl_result.total_crawled as usize;

        // Crawl failures used to be invisible: the engine read only
        // `total_crawled`, which equalled `total_discovered`, so a crawl in which
        // every fetch failed reported the attempted count as the crawled count.
        for error in &crawl_result.errors {
            job.record_error("crawl", error);
        }

        // An empty crawl means every downstream stage has no input. Recording the
        // counts alone would leave a report reading "0 findings" over a target
        // that was never successfully contacted, which is the false negative this
        // status split exists to prevent.
        if crawl_result.yielded_nothing() {
            job.record_coverage_gap(
                "crawl",
                format!(
                    "retrieved no pages from {} ({} URL(s) attempted, {} failure(s)); \
                     findings from this scan are not evidence of absence",
                    plan.target.value(),
                    crawl_result.total_discovered,
                    crawl_result.error_count(),
                ),
            );
            warn!(
                scan_target = %plan.target.value(),
                attempted = crawl_result.total_discovered,
                errors = crawl_result.error_count(),
                "crawl produced no pages; scan will report no findings and they will be meaningless"
            );
        }

        if plan.record_observations {
            for page in &crawl_result.pages {
                let obs = Observation::new(
                    plan.scan_id.clone(),
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

            if plan.record_observations {
                for tech in &fingerprint.technologies {
                    let obs = Observation::new(
                        plan.scan_id.clone(),
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

        job.status = ScanStatus::Scanning;
        let (scanners, unresolved) = self.create_scanners(&plan.scanners);
        record_scanner_selection_coverage(job, plan.scanners.len(), unresolved);

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

                if plan.record_observations {
                    let obs = Observation::new(
                        plan.scan_id.clone(),
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

            // A scanner that could not reach the target still returns `Ok` with
            // an empty finding list and the reason in `errors`. That field was
            // collected and then discarded, so a scanner which failed entirely
            // was indistinguishable in the report from one that found nothing.
            // It now reaches `job.errors`, and therefore `GET /scans/{id}`.
            for error in &result.errors {
                // The scanner ran and could not do its job, so the vulnerability
                // class it covers went unchecked while the others still produced
                // findings: lost coverage, not a total gap.
                job.record_lost_coverage(&result.scanner_name, error);
                warn!(
                    scanner = %result.scanner_name,
                    error = %error,
                    "scanner reported a failure"
                );
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

        job.status = ScanStatus::Correlating;
        let report = self
            .findings_manager
            .generate_report(&plan.target.id)
            .await
            .map_err(|e| EngineError::Generic(e.to_string()))?;

        job.completed_at = Some(chrono::Utc::now().to_rfc3339());
        job.metrics.scan_duration_ms = start.elapsed().as_millis() as u64;

        // Resolved before the report is rendered, so the report can state what
        // the scan covered. Generated the other way round, the report would claim
        // "Total: 0" over a scan that never reached the target — the exact false
        // negative the status split exists to prevent, repeated in the one part
        // of the output a reader is most likely to quote.
        let status = job.resolve_status();
        let summary =
            ReportGenerator::text_summary_with_coverage(&report, &status.to_string(), &job.errors);
        job.report_summary = Some(summary);

        match status {
            ScanStatus::Failed => error!(
                target = %plan.target.value(),
                gaps = job.coverage_gaps.len(),
                "scan produced no usable coverage; its findings are not evidence of absence"
            ),
            ScanStatus::Partial => warn!(
                target = %plan.target.value(),
                errors = job.errors.len(),
                findings = job.metrics.total_findings,
                "scan finished with errors; results are incomplete"
            ),
            _ => {}
        }

        let (event_type, payload) = terminal_event(&plan.scan_id, job);
        emit(&self.event_bus, event_type, payload);

        Ok(())
    }

    /// Build the requested scanners, and name the ones that could not be built.
    ///
    /// The unresolved names are returned rather than dropped. Dropping them was a
    /// false negative: `POST /scans {"scanners": ["typo"]}` produced a scan that ran
    /// zero scanners, reported `Completed`, and rendered "Total: 0" — a clean bill
    /// of health for a target nothing had examined.
    fn create_scanners(&self, scanner_names: &[String]) -> (Vec<Box<dyn Scanner>>, Vec<String>) {
        let mut scanners: Vec<Box<dyn Scanner>> = Vec::new();
        let mut unresolved: Vec<String> = Vec::new();

        for name in scanner_names {
            match name.as_str() {
                "sql_injection" => {
                    scanners.push(Box::new(spectra_scanner::SqlInjectionScanner::new()))
                }
                "xss" => scanners.push(Box::new(spectra_scanner::XssScanner::new())),
                "dir_search" => scanners.push(Box::new(spectra_scanner::DirSearchScanner::new())),
                "ssrf" => scanners.push(Box::new(spectra_scanner::SsrfScanner::new())),
                "open_redirect" => {
                    scanners.push(Box::new(spectra_scanner::OpenRedirectScanner::new()))
                }
                "path_traversal" => {
                    scanners.push(Box::new(spectra_scanner::PathTraversalScanner::new()))
                }
                "csrf" => scanners.push(Box::new(spectra_scanner::CsrfScanner::new())),
                "xxe" => scanners.push(Box::new(spectra_scanner::XxeScanner::new())),
                "cors" => scanners.push(Box::new(spectra_scanner::CorsScanner::new())),
                other => {
                    unresolved.push(other.to_string());
                    job_warn_unresolved(other);
                }
            }
        }
        (scanners, unresolved)
    }

    fn detection_source_for(&self, scanner_name: &str) -> DetectionSource {
        match scanner_name {
            "sql_injection" => DetectionSource::SqlInjectionScanner,
            "xss" => DetectionSource::XssScanner,
            "dir_search" => DetectionSource::DirSearchScanner,
            "ssrf" => DetectionSource::SsrfScanner,
            "open_redirect" => DetectionSource::OpenRedirectScanner,
            "path_traversal" => DetectionSource::PathTraversalScanner,
            "csrf" => DetectionSource::CsrfScanner,
            "xxe" => DetectionSource::XxeScanner,
            "cors" => DetectionSource::CorsScanner,
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
        let plan = ScanPlan::new("scan-1", target);
        assert_eq!(plan.scan_id, "scan-1");
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
        let plan = ScanPlan::new("scan-1", target)
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
    fn an_unknown_scanner_name_is_reported_rather_than_dropped() {
        let engine = ScanEngine::new();

        // Resolvable names still produce scanners.
        let (built, unresolved) = engine.create_scanners(&["xss".into()]);
        assert_eq!(built.len(), 1);
        assert!(unresolved.is_empty());

        // An unknown name produces nothing, and says so. Before this was recorded,
        // the caller received a `Completed` scan with no findings and no error,
        // which is indistinguishable from a clean target.
        let (built, unresolved) = engine.create_scanners(&["typo".into()]);
        assert_eq!(built.len(), 0);
        assert_eq!(unresolved, vec!["typo".to_string()]);

        // `sqli` is a CLI-side alias translated before it reaches the engine; the
        // API does not translate, so posting it yields nothing.
        let (built, unresolved) = engine.create_scanners(&["sqli".into()]);
        assert_eq!(built.len(), 0);
        assert_eq!(unresolved, vec!["sqli".to_string()]);

        // A mix keeps the resolvable ones and names only what it could not build.
        let (built, unresolved) =
            engine.create_scanners(&["xss".into(), "typo".into(), "sql_injection".into()]);
        assert_eq!(built.len(), 2);
        assert_eq!(unresolved, vec!["typo".to_string()]);

        // Requesting none at all is not an error, but it is not a scan either.
        let (built, unresolved) = engine.create_scanners(&[]);
        assert_eq!(built.len(), 0);
        assert!(unresolved.is_empty());
    }

    /// The coverage consequence of an unresolvable scanner selection.
    ///
    /// These assert the *status*, not merely that `create_scanners` returns the
    /// right length. A test that only checked the returned count passed while the
    /// engine still reported `Completed` over a target it never scanned, which is
    /// the defect itself.
    #[test]
    fn a_scan_where_no_scanner_ran_is_failed_not_completed() {
        let mut job = ScanJob::new(Id::new());

        // The exact false negative: one unknown name, nothing else requested.
        record_scanner_selection_coverage(&mut job, 1, vec!["typo".to_string()]);

        assert_eq!(
            job.resolve_status(),
            ScanStatus::Failed,
            "a scan that tested no vulnerability class must not report Completed"
        );
        assert!(
            job.errors.iter().any(|e| e.contains("typo")),
            "the caller must be told which name failed to resolve: {:?}",
            job.errors
        );
    }

    #[test]
    fn a_scan_where_some_scanners_ran_is_partial_not_failed() {
        let mut job = ScanJob::new(Id::new());

        // Three requested, one unresolvable: the other two cover their classes.
        record_scanner_selection_coverage(&mut job, 3, vec!["typo".to_string()]);

        assert_eq!(
            job.resolve_status(),
            ScanStatus::Partial,
            "partial coverage is Partial, not Failed -- two scanners did run"
        );
        assert!(job.coverage_gaps.is_empty());
        assert_eq!(job.lost_coverage.len(), 1);
    }

    #[test]
    fn requesting_no_scanners_is_a_coverage_gap() {
        let mut job = ScanJob::new(Id::new());

        record_scanner_selection_coverage(&mut job, 0, vec![]);

        assert_eq!(
            job.resolve_status(),
            ScanStatus::Failed,
            "\"0 findings\" over a target no scanner looked at is a false negative"
        );
    }

    #[test]
    fn a_fully_resolved_selection_records_no_coverage_loss() {
        let mut job = ScanJob::new(Id::new());

        // The normal path: every requested name resolved. Nothing may be recorded,
        // or every ordinary scan would be reported Partial.
        record_scanner_selection_coverage(&mut job, 9, vec![]);

        assert_eq!(job.resolve_status(), ScanStatus::Completed);
        assert!(job.errors.is_empty());
        assert!(job.lost_coverage.is_empty());
        assert!(job.coverage_gaps.is_empty());
    }

    #[test]
    fn every_advertised_scanner_name_resolves_to_an_implementation() {
        // `available_scanners` is the list the API validates against, so an entry
        // that does not resolve would reintroduce the silent-drop defect through
        // the validation path itself.
        let engine = ScanEngine::new();
        let (built, unresolved) = engine.create_scanners(
            &available_scanners()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        );

        assert!(
            unresolved.is_empty(),
            "advertised but unimplemented: {unresolved:?}"
        );
        assert_eq!(built.len(), available_scanners().len());
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

        // This test used to assert only `scanners.len() == 2`, which *enshrined* the
        // silent drop as intended behaviour and left the caller unable to tell that
        // one of the three checks they asked for had not run. It now asserts the
        // name is reported as well.
        let (scanners, unresolved) = engine.create_scanners(&names);

        assert_eq!(scanners.len(), 2);
        assert_eq!(unresolved, vec!["unknown_scanner".to_string()]);
    }

    #[test]
    fn scan_job_lifecycle() {
        let target_id: Id<TargetId> = Id::new();
        let job = ScanJob::new(target_id);
        assert_eq!(job.status, ScanStatus::Pending);
        assert!(!job.is_terminal());

        let mut job = job;
        job.status = ScanStatus::Completed;
        assert!(job.is_terminal());

        let target_id: Id<TargetId> = Id::new();
        let mut job = ScanJob::new(target_id);
        job.status = ScanStatus::Failed;
        assert!(job.is_terminal());
    }

    #[test]
    fn partial_is_terminal() {
        // `Partial` is an end state, not a stage. Leaving it out of
        // `is_terminal` would make a finished-but-incomplete scan look like it
        // were still running, so nothing would ever clean it up.
        let mut job = ScanJob::new(Id::new());
        job.status = ScanStatus::Partial;
        assert!(job.is_terminal());
        assert_eq!(ScanStatus::Partial.to_string(), "Partial");
    }

    /// The regression this status split exists for.
    ///
    /// A scan in which the crawl retrieved nothing and every scanner failed used
    /// to finish as `Completed` with zero findings. In a findings report that is
    /// indistinguishable from a clean target, and for a security tool a false
    /// negative is worse than a visible error.
    #[test]
    fn a_scan_that_reached_nothing_is_not_reported_as_completed() {
        let mut job = ScanJob::new(Id::new());
        job.record_coverage_gap("crawl", "retrieved no pages from example.com");
        for scanner in ["xss", "sql_injection", "ssrf"] {
            job.record_lost_coverage(scanner, "Failed to fetch target");
        }

        assert_eq!(
            job.resolve_status(),
            ScanStatus::Failed,
            "a scan that analysed nothing must not claim completion"
        );
    }

    #[test]
    fn a_clean_scan_is_completed() {
        let mut job = ScanJob::new(Id::new());
        job.metrics.total_findings = 3;
        assert_eq!(job.resolve_status(), ScanStatus::Completed);
    }

    #[test]
    fn a_clean_scan_with_no_findings_is_still_completed() {
        // The counter-case that must not be broken: zero findings after a scan
        // that actually worked is the one genuinely reassuring result, and it
        // depends on there being a way to say "ran, found nothing".
        let mut job = ScanJob::new(Id::new());
        assert_eq!(job.metrics.total_findings, 0);
        assert_eq!(job.resolve_status(), ScanStatus::Completed);
    }

    #[test]
    fn lost_coverage_is_partial_not_failed() {
        let mut job = ScanJob::new(Id::new());
        job.crawl_page_count = 40;
        job.record_lost_coverage("xss", "Failed to fetch target");

        assert_eq!(
            job.resolve_status(),
            ScanStatus::Partial,
            "usable input was obtained, so this is partial coverage rather than failure"
        );
    }

    #[test]
    fn individual_crawl_failures_do_not_downgrade_the_status() {
        // A few unreachable URLs in a several-hundred-page crawl is routine.
        // If that made every scan `Partial`, the status would stop carrying
        // information and operators would learn to ignore it.
        let mut job = ScanJob::new(Id::new());
        job.crawl_page_count = 200;
        for i in 0..5 {
            job.record_error("crawl", format!("https://example.com/{i}: timeout"));
        }

        assert_eq!(job.resolve_status(), ScanStatus::Completed);
        assert_eq!(
            job.errors.len(),
            5,
            "the failures are still recorded and reported, they just do not change the status"
        );
    }

    #[test]
    fn a_coverage_gap_is_also_surfaced_as_an_error() {
        // Otherwise the reason a scan failed would live only in
        // `coverage_gaps`, and anything reporting `errors` would show an empty
        // list next to a `Failed` status.
        let mut job = ScanJob::new(Id::new());
        job.record_coverage_gap("crawl", "no pages");
        assert_eq!(job.errors, vec!["crawl: no pages".to_string()]);
        assert_eq!(job.coverage_gaps, vec!["crawl: no pages".to_string()]);
        assert_eq!(
            job.lost_coverage,
            vec!["crawl: no pages".to_string()],
            "a total gap also implies lost coverage"
        );
    }

    #[test]
    fn a_routine_error_is_recorded_without_becoming_a_coverage_claim() {
        let mut job = ScanJob::new(Id::new());
        job.record_error("crawl", "one URL timed out");
        assert_eq!(job.errors.len(), 1);
        assert!(job.lost_coverage.is_empty());
        assert!(job.coverage_gaps.is_empty());
    }

    #[test]
    fn errors_are_labelled_with_their_stage() {
        // An unlabelled error in a run with nine scanners is unactionable.
        let mut job = ScanJob::new(Id::new());
        job.record_error("xss", "Failed to fetch target: connection refused");
        assert_eq!(
            job.errors,
            vec!["xss: Failed to fetch target: connection refused".to_string()]
        );
    }

    #[test]
    fn resolving_twice_is_stable() {
        let mut job = ScanJob::new(Id::new());
        job.record_lost_coverage("xss", "boom");
        assert_eq!(job.resolve_status(), ScanStatus::Partial);
        assert_eq!(job.resolve_status(), ScanStatus::Partial);
        assert_eq!(job.errors.len(), 1, "resolving must not duplicate errors");
    }
}

#[cfg(test)]
mod scan_id_tests {
    use super::*;
    use spectra_target::{Target, TargetType};

    /// The regression: `run_scan` passed `plan.target.id` into the `scan_id`
    /// field of every observation, while `GET /scans/{id}/observations` queries
    /// by the scan id. The two could never match, so the endpoint returned an
    /// empty list for every scan with nothing indicating a fault.
    #[test]
    fn the_plan_carries_the_scan_id_separately_from_the_target() {
        let target = Target::new(
            Id::new(),
            "t".into(),
            TargetType::Domain,
            "example.com".into(),
        );
        let plan = ScanPlan::new("scan-abc", target.clone());

        assert_eq!(plan.scan_id, "scan-abc");
        assert_eq!(
            plan.target.id.to_string(),
            target.id.to_string(),
            "the target keeps its own id; the two must not be conflated"
        );
        assert_ne!(plan.scan_id, plan.target.id.to_string());
    }
}

#[cfg(test)]
mod scan_limits_tests {
    use super::*;
    use spectra_target::{Target, TargetType};

    fn plan() -> ScanPlan {
        ScanPlan::new(
            "scan-1",
            Target::new(
                Id::new(),
                "t".into(),
                TargetType::Domain,
                "example.com".into(),
            ),
        )
    }

    /// The trust boundary. A caller may narrow a scan; only the operator may
    /// widen it. Without this, honouring the request fields at all would have
    /// turned a decorative `max_pages` into a caller-controlled one — an
    /// authenticated `scanner`-role user could ask for 10 million pages.
    #[test]
    fn a_caller_cannot_exceed_the_operator_ceilings() {
        let limits = ScanLimits {
            max_depth: 3,
            max_pages: 50,
            timeout_secs: 60,
        };
        let requested = plan()
            .with_max_depth(99)
            .with_max_pages(1_000_000)
            .with_timeout(86_400);

        let clamped = limits.clamp(&requested);

        assert_eq!(clamped.max_depth, 3);
        assert_eq!(clamped.max_pages, 50);
        assert_eq!(clamped.timeout_secs, 60);
    }

    #[test]
    fn a_caller_may_narrow_a_scan() {
        let limits = ScanLimits {
            max_depth: 10,
            max_pages: 10_000,
            timeout_secs: 300,
        };
        let requested = plan().with_max_depth(1).with_max_pages(2).with_timeout(5);

        let clamped = limits.clamp(&requested);

        assert_eq!(
            (clamped.max_depth, clamped.max_pages, clamped.timeout_secs),
            (1, 2, 5),
            "a narrower request must be honoured exactly"
        );
    }

    /// A zero takes the ceiling rather than collapsing the scan to nothing.
    /// `POST /api/v1/scans` treats `max_pages: Some(0)` as a real request, and
    /// honouring it literally would produce a scan that crawls nothing and reports
    /// no findings — the false-negative shape Remediation 10 removed.
    #[test]
    fn a_zero_limit_means_no_preference_not_no_work() {
        let limits = ScanLimits {
            max_depth: 4,
            max_pages: 40,
            timeout_secs: 40,
        };
        let clamped = limits.clamp(&plan().with_max_pages(0).with_max_depth(0).with_timeout(0));

        assert_eq!(clamped.max_pages, 40);
        assert_eq!(clamped.max_depth, 4);
        assert_eq!(clamped.timeout_secs, 40);
    }

    #[test]
    fn clamping_preserves_everything_it_is_not_clamping() {
        let limits = ScanLimits::default();
        let requested = plan().with_scanners(vec!["xss".into()]);
        let clamped = limits.clamp(&requested);

        assert_eq!(clamped.scan_id, requested.scan_id);
        assert_eq!(clamped.scanners, requested.scanners);
        assert_eq!(clamped.target.id, requested.target.id);
        assert!(clamped.collect_evidence);
        assert!(clamped.record_observations);
    }

    #[test]
    fn limits_come_from_configuration() {
        // The ceilings are the operator's, so they must track config rather than
        // being hardcoded at the construction site.
        let mut config = spectra_config::Config::default();
        config.crawler.max_pages = 7;
        config.crawler.max_depth = 2;
        config.scanner.default_timeout = 11;

        let limits = ScanLimits::from_config(&config);

        assert_eq!(limits.max_pages, 7);
        assert_eq!(limits.max_depth, 2);
        assert_eq!(limits.timeout_secs, 11);
    }

    /// A scan that overruns its budget must report `Partial` with the reason, not
    /// hang and not claim to have assessed the target.
    /// The plan's limits must actually reach the crawler, not just the job record.
    /// Before this, the crawler was built with `CrawlerConfig::default()` so
    /// `max_pages: 1` still crawled up to 10,000 pages.
    #[test]
    fn the_plan_limits_reach_the_crawler() {
        let config = crawler_config_for(&plan().with_max_depth(1).with_max_pages(2));

        assert_eq!(config.max_depth, 1);
        assert_eq!(config.max_pages, 2);
    }

    /// And the ceilings must be what reaches the crawler, not the raw request.
    #[test]
    fn the_ceilings_reach_the_crawler() {
        let limits = ScanLimits {
            max_depth: 2,
            max_pages: 25,
            timeout_secs: 300,
        };
        let requested = plan().with_max_depth(50).with_max_pages(5_000);
        let clamped = limits.clamp(&requested);

        let config = crawler_config_for(&clamped);

        assert_eq!(config.max_depth, 2);
        assert_eq!(config.max_pages, 25);
    }

    /// A `CrawlerConfig` field that could be widened by a caller is a hole in
    /// the ceiling, so pin the two the plan does not cover to their defaults.
    #[test]
    fn crawler_settings_the_plan_does_not_cover_keep_their_defaults() {
        let defaults = spectra_crawler::CrawlerConfig::default();
        let config = crawler_config_for(&plan().with_max_depth(1).with_max_pages(2));

        assert_eq!(config.concurrent_requests, defaults.concurrent_requests);
        assert_eq!(config.delay_ms, defaults.delay_ms);
        assert_eq!(config.respect_robots, defaults.respect_robots);
        assert_eq!(config.user_agent, defaults.user_agent);
    }

    #[tokio::test]
    async fn a_scan_that_overruns_its_budget_stops_and_says_why() {
        let engine = ScanEngine::new().with_limits(ScanLimits {
            // One second: long enough for the first outbound request to be in
            // flight, short enough not to slow the suite.
            timeout_secs: 1,
            ..Default::default()
        });

        // A loopback port with nothing listening: the HTTP client retries with
        // backoff, so the scan cannot finish inside the budget.
        let target = Target::new(
            Id::new(),
            "dead".into(),
            TargetType::Url,
            "http://127.0.0.1:1/".into(),
        );

        let job = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            engine.run_scan(&ScanPlan::new("scan-timeout", target)),
        )
        .await
        .expect("run_scan must return rather than hang")
        .expect("a timeout is not an error");

        assert_eq!(
            job.status,
            ScanStatus::Partial,
            "an overrunning scan must not report completion"
        );
        assert!(
            job.is_terminal(),
            "an overrunning scan is finished, just incomplete"
        );
        assert!(
            job.errors.iter().any(|e| e.contains("budget")),
            "the timeout must be recorded as a reason, got: {:?}",
            job.errors
        );
        assert!(job.completed_at.is_some());
    }

    /// A timed-out scan must carry a summary explaining itself, not an empty
    /// field. Every other `Partial` outcome populates `report_summary` with the
    /// caveat; only the timeout path would leave it `None`, which a UI renders
    /// as a blank report with no reason on the field itself.
    #[tokio::test]
    async fn a_timed_out_scan_still_carries_an_explanatory_summary() {
        let engine = ScanEngine::new().with_limits(ScanLimits {
            timeout_secs: 1,
            ..Default::default()
        });

        let target = Target::new(
            Id::new(),
            "dead".into(),
            TargetType::Url,
            "http://127.0.0.1:1/".into(),
        );

        let job = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            engine.run_scan(&ScanPlan::new("scan-timeout", target)),
        )
        .await
        .expect("run_scan must return")
        .expect("a timeout is not an error");

        let summary = job
            .report_summary
            .as_deref()
            .expect("a timed-out scan must not leave the report summary empty");

        assert!(
            summary.contains("NOT fully assessed"),
            "the summary must say the target was not assessed, got: {summary}"
        );
        assert!(
            summary.contains("not exhaustive"),
            "the summary must say the findings are incomplete, got: {summary}"
        );
    }

    #[tokio::test]
    async fn the_reported_ceiling_is_recorded_on_the_job() {
        let engine = ScanEngine::new().with_limits(ScanLimits {
            max_pages: 5,
            max_depth: 1,
            timeout_secs: 1,
        });

        let target = Target::new(
            Id::new(),
            "dead".into(),
            TargetType::Url,
            "http://127.0.0.1:1/".into(),
        );
        let requested = ScanPlan::new("scan-1", target)
            .with_max_pages(1_000_000)
            .with_timeout(86_400);

        let job = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            engine.run_scan(&requested),
        )
        .await
        .expect("run_scan must return")
        .expect("a timeout is not an error");

        assert!(
            job.errors.iter().any(|e| e.contains("max_pages")),
            "a reduced limit must be visible to the caller, got: {:?}",
            job.errors
        );
        assert!(
            job.errors.iter().any(|e| e.contains("timeout_secs")),
            "a reduced timeout must be visible to the caller, got: {:?}",
            job.errors
        );
    }
}

#[cfg(test)]
mod scan_event_tests {
    use super::*;
    use spectra_events::{EventBus, EventType};
    use spectra_target::{Target, TargetType};

    /// Subscribes *before* the scan runs.
    ///
    /// `broadcast` retains events only for subscribers that existed when they were
    /// published, so a subscription taken afterwards sees nothing at all. An
    /// assertion written against a post-hoc subscription passes vacuously — a scan
    /// that published no events and a scan that published none of the type being
    /// checked look identical. Every test here therefore subscribes up front.
    fn watcher(bus: &EventBus) -> tokio::sync::broadcast::Receiver<Event> {
        bus.subscribe()
    }

    fn drain(rx: &mut tokio::sync::broadcast::Receiver<Event>) -> Vec<Event> {
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        events
    }

    fn dead_target() -> Target {
        // Loopback port 1: nothing listens, so the crawl fails. With the SSRF
        // guard bypassed elsewhere in this crate's tests, this is the
        // deterministic way to produce a scan that cannot reach its target.
        Target::new(
            Id::new(),
            "dead".into(),
            TargetType::Url,
            "http://127.0.0.1:1/".into(),
        )
    }

    /// The engine was the one component that already knew every scan transition and
    /// communicated none of it — the API reconstructed outcomes from `ScanStatus`
    /// after the fact, and nothing outside the process could observe a scan at all.
    #[tokio::test]
    async fn a_scan_publishes_its_lifecycle() {
        let bus = EventBus::new(64);
        let mut rx = watcher(&bus);
        let engine = ScanEngine::new().with_event_bus(bus.clone());

        let _ = engine
            .run_scan(&ScanPlan::new("scan-events", dead_target()))
            .await;

        let events = drain(&mut rx);
        assert!(
            events
                .iter()
                .any(|e| e.event_type == EventType::ScanStarted),
            "every scan must announce itself, got {:?}",
            events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
        );
    }

    /// The whole point of the wiring: a scan that reached nothing must not be
    /// announced as complete. Publishing `ScanCompleted` here would reintroduce
    /// the false success Remediation 10 removed from the API, on a channel that
    /// bypasses the API entirely.
    #[tokio::test]
    async fn a_scan_that_reached_nothing_is_not_announced_as_completed() {
        let bus = EventBus::new(64);
        let mut rx = watcher(&bus);
        let engine = ScanEngine::new().with_event_bus(bus.clone());

        let job = engine
            .run_scan(&ScanPlan::new("scan-partial", dead_target()))
            .await
            .expect("a scan that fails to reach its target is not an engine error");

        let events = drain(&mut rx);
        let types: Vec<_> = events.iter().map(|e| e.event_type.clone()).collect();

        assert_ne!(
            job.status,
            ScanStatus::Completed,
            "precondition: this target is unreachable, so the job is not clean"
        );
        assert!(
            !types.is_empty(),
            "precondition: the bus must have received something, or this test \
             proves nothing"
        );
        assert!(
            !types.contains(&EventType::ScanCompleted),
            "an unassessed target must never produce ScanCompleted, got {types:?}"
        );
    }

    #[tokio::test]
    async fn a_partial_scan_publishes_scan_partial_with_a_reason() {
        let bus = EventBus::new(64);
        let mut rx = watcher(&bus);
        let engine = ScanEngine::new().with_event_bus(bus.clone());

        // A timeout, because that is one of the two real routes to `Partial` and
        // the only one reachable without arranging for a scanner to fail.
        // Deliberately *not* a server whose page links to a dead port: that
        // produces a per-URL crawl error, which `record_error` treats as
        // reportable-but-not-status-changing on purpose, so the scan completes.
        let engine = engine.with_limits(ScanLimits {
            timeout_secs: 1,
            ..Default::default()
        });

        let job = engine
            .run_scan(&ScanPlan::new("scan-partial-reason", dead_target()))
            .await
            .expect("a timeout is not an engine error");

        assert_eq!(
            job.status,
            ScanStatus::Partial,
            "precondition: an overrunning scan is partial. errors: {:?}",
            job.errors
        );

        let mut partial = None;
        while let Ok(event) = rx.try_recv() {
            if let EventPayload::ScanPartial { reason, .. } = &event.payload {
                partial = Some(reason.clone());
            }
        }

        assert!(
            partial.is_some(),
            "a scan that lost coverage must publish ScanPartial, not a \
             terminal event that implies it finished"
        );
        assert!(
            !partial.unwrap().is_empty(),
            "ScanPartial carries a reason so a subscriber can act on it rather \
             than reconstruct it; an empty one tells it nothing"
        );
    }

    /// A bus is optional. Most callers do not want events, and the CLI, worker and
    /// engine's own tests all construct the engine without one.
    #[tokio::test]
    async fn a_scan_without_a_bus_still_runs() {
        let engine = ScanEngine::new();
        let job = engine
            .run_scan(&ScanPlan::new("scan-no-bus", dead_target()))
            .await
            .expect("the absence of an event bus must not affect a scan");
        assert!(job.is_terminal());
    }

    /// Exactly one terminal event per scan. Two terminal events for one scan means
    /// a subscriber is being told it finished and also that it failed.
    #[tokio::test]
    async fn a_publishes_exactly_one_terminal_event() {
        let bus = EventBus::new(64);
        let mut rx = watcher(&bus);
        let engine = ScanEngine::new().with_event_bus(bus.clone());

        let _ = engine
            .run_scan(&ScanPlan::new("scan-terminal", dead_target()))
            .await;

        let events = drain(&mut rx);
        let types: Vec<_> = events.iter().map(|e| e.event_type.clone()).collect();
        let terminal = types
            .iter()
            .filter(|t| {
                matches!(
                    t,
                    EventType::ScanCompleted | EventType::ScanPartial | EventType::ScanFailed
                )
            })
            .count();

        assert_eq!(terminal, 1, "got {types:?}");
    }
}

#[cfg(test)]
mod terminal_event_tests {
    use super::*;
    use spectra_events::EventType;

    fn job_with(status: ScanStatus, errors: Vec<&str>) -> ScanJob {
        let mut job = ScanJob::new(Id::new());
        job.status = status;
        job.errors = errors.into_iter().map(String::from).collect();
        job
    }

    /// The mapping is the whole contract. Three statuses in, three distinct event
    /// types out, and no path where an unassessed scan is announced as complete.
    #[test]
    fn each_scan_status_maps_to_its_own_event() {
        let cases = [
            (ScanStatus::Completed, EventType::ScanCompleted),
            (ScanStatus::Partial, EventType::ScanPartial),
            (ScanStatus::Failed, EventType::ScanFailed),
            (ScanStatus::Cancelled, EventType::ScanFailed),
        ];

        for (status, expected) in cases {
            let (event_type, _) = terminal_event("scan-1", &job_with(status, vec![]));
            assert_eq!(
                event_type, expected,
                "{status:?} must not be published as {expected:?}"
            );
        }
    }

    /// `Completed` means the target was assessed. If `Partial` were allowed to map
    /// here, a subscriber would be told a scan finished assessing a target it only
    /// partly reached — and there is no field on the event to check.
    #[test]
    fn only_a_clean_scan_is_announced_as_completed() {
        for status in [
            ScanStatus::Partial,
            ScanStatus::Failed,
            ScanStatus::Cancelled,
            ScanStatus::Scanning,
            ScanStatus::Discovering,
        ] {
            let (event_type, _) = terminal_event("scan-1", &job_with(status, vec![]));
            assert_ne!(
                event_type,
                EventType::ScanCompleted,
                "{status:?} is not a completed assessment and must not say it is"
            );
        }
    }

    /// The scan id must survive into the payload; it is the only correlation key a
    /// subscriber has.
    #[test]
    fn the_scan_id_reaches_the_payload() {
        let (_, payload) = terminal_event("scan-xyz", &job_with(ScanStatus::Completed, vec![]));
        assert!(matches!(
            payload,
            EventPayload::ScanCompleted { scan_id } if scan_id == "scan-xyz"
        ));
    }

    /// An empty `reason` or `error` tells a subscriber something went wrong and
    /// nothing else, leaving it to go and find the job.
    #[test]
    fn an_incomplete_outcome_always_carries_a_reason() {
        for (status, marker) in [
            (ScanStatus::Partial, "ScanPartial"),
            (ScanStatus::Failed, "ScanFailed"),
        ] {
            let (_, payload) = terminal_event("scan-1", &job_with(status, vec![]));
            let text = match payload {
                EventPayload::ScanPartial { reason, .. } => {
                    assert_eq!(marker, "ScanPartial");
                    reason
                }
                EventPayload::ScanFailed { error, .. } => {
                    assert_eq!(marker, "ScanFailed");
                    error
                }
                other => panic!("{status:?} produced {other:?}"),
            };
            assert!(!text.is_empty(), "{status:?} produced an empty reason");
        }
    }

    /// When there are recorded errors they must be carried, not replaced by the
    /// fallback. The fallback is for the case where there are none.
    #[test]
    fn recorded_errors_are_carried_into_the_event() {
        let (_, payload) = terminal_event(
            "scan-1",
            &job_with(
                ScanStatus::Partial,
                vec!["crawl: timed out", "xss: unreachable"],
            ),
        );

        match payload {
            EventPayload::ScanPartial { reason, .. } => {
                assert!(reason.contains("crawl: timed out"), "got {reason:?}");
                assert!(reason.contains("xss: unreachable"), "got {reason:?}");
            }
            other => panic!("expected ScanPartial, got {other:?}"),
        }
    }
}
