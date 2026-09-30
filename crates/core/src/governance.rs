use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum GovernanceError {
    #[error("Rate limit exceeded: {0}")]
    RateLimited(String),
    #[error("Resource limit exceeded: {0}")]
    ResourceLimited(String),
    #[error("Concurrency limit reached: {0}")]
    ConcurrencyLimited(String),
    #[error("Timeout: {0}")]
    Timeout(String),
}

pub type GovernanceResult<T> = Result<T, GovernanceError>;

/// Resource limits for different levels.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_requests_per_second: u32,
    pub max_concurrent: usize,
    pub max_queue_depth: usize,
    pub max_scan_duration_secs: u64,
    pub max_memory_bytes: u64,
    pub max_cpu_percent: f32,
    pub timeout_secs: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_requests_per_second: 100,
            max_concurrent: 10,
            max_queue_depth: 1000,
            max_scan_duration_secs: 3600,
            max_memory_bytes: 1024 * 1024 * 1024, // 1GB
            max_cpu_percent: 80.0,
            timeout_secs: 300,
        }
    }
}

/// Rate limiter with token bucket algorithm.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(max_tokens: u32, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens as f64,
            max_tokens: max_tokens as f64,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    pub fn try_consume(&mut self, tokens: u32) -> bool {
        if self.can_consume(tokens) {
            self.consume(tokens);
            true
        } else {
            false
        }
    }

    /// Whether `tokens` are available, without consuming any.
    ///
    /// Separate from [`TokenBucket::consume`] so a caller can check every limit
    /// before mutating any of them. Checking and consuming in one step is what
    /// allowed a rejected acquisition to keep what it had already taken.
    pub fn can_consume(&self, tokens: u32) -> bool {
        // Refill is time-based, so availability has to be recomputed from a
        // clone rather than read off `self.tokens`, which may be stale.
        let mut probe = self.clone();
        probe.refill();
        probe.tokens >= tokens as f64
    }

    /// Spend `tokens`, which the caller must already have checked for with
    /// [`TokenBucket::can_consume`].
    pub fn consume(&mut self, tokens: u32) {
        self.refill();
        self.tokens = (self.tokens - tokens as f64).max(0.0);
    }

    pub fn available(&self) -> f64 {
        self.tokens
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }
}

/// Concurrency limiter.
#[derive(Debug)]
pub struct ConcurrencyLimiter {
    current: usize,
    max: usize,
}

impl ConcurrencyLimiter {
    pub fn new(max: usize) -> Self {
        Self { current: 0, max }
    }

    pub fn try_acquire(&mut self) -> bool {
        if self.current < self.max {
            self.current += 1;
            true
        } else {
            false
        }
    }

    /// Take a slot, which the caller must already have found available.
    pub fn acquire(&mut self) {
        if self.current < self.max {
            self.current += 1;
        }
    }

    pub fn release(&mut self) {
        if self.current > 0 {
            self.current -= 1;
        }
    }

    pub fn available(&self) -> usize {
        self.max - self.current
    }

    pub fn current(&self) -> usize {
        self.current
    }
}

/// Resource governor for managing limits.
pub struct ResourceGovernor {
    limits: ResourceLimits,
    rate_limiter: Arc<RwLock<TokenBucket>>,
    concurrency: Arc<RwLock<ConcurrencyLimiter>>,
    queue_depth: Arc<RwLock<usize>>,
}

impl ResourceGovernor {
    pub fn new(limits: ResourceLimits) -> Self {
        let max_requests_per_second = limits.max_requests_per_second;
        let max_concurrent = limits.max_concurrent;
        let refill_rate = max_requests_per_second as f64;
        Self {
            limits,
            rate_limiter: Arc::new(RwLock::new(TokenBucket::new(
                max_requests_per_second,
                refill_rate,
            ))),
            concurrency: Arc::new(RwLock::new(ConcurrencyLimiter::new(max_concurrent))),
            queue_depth: Arc::new(RwLock::new(0)),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(ResourceLimits::default())
    }

    /// Try to acquire a request slot.
    ///
    /// Transactional: either every limit is satisfied and the state is updated,
    /// or nothing is changed and an error is returned.
    ///
    /// It previously mutated as it went, consuming a rate-limit token before
    /// checking concurrency and taking a concurrency slot before checking queue
    /// depth. Every rejection after those points leaked what it had already taken
    /// — a burst of scans against a saturated concurrency limit silently drained
    /// the token bucket, and a queue-depth rejection permanently burned a
    /// concurrency slot. The second is latent rather than live at the defaults
    /// (`max_concurrent` 10 < `max_queue_depth` 1000, so the queue check cannot
    /// fail before the concurrency check does), but it is a trap for anyone who
    /// configures the queue depth lower.
    pub async fn try_acquire(&self) -> GovernanceResult<()> {
        // Take all three locks up front so the checks are made against a single
        // consistent view rather than interleaved with other callers.
        let mut rate_limiter = self.rate_limiter.write().await;
        let mut concurrency = self.concurrency.write().await;
        let mut queue_depth = self.queue_depth.write().await;

        // Check, do not consume.
        if !rate_limiter.can_consume(1) {
            return Err(GovernanceError::RateLimited(
                "Rate limit exceeded".to_string(),
            ));
        }

        if concurrency.available() == 0 {
            return Err(GovernanceError::ConcurrencyLimited(
                "Concurrency limit reached".to_string(),
            ));
        }

        if *queue_depth >= self.limits.max_queue_depth {
            return Err(GovernanceError::ResourceLimited(
                "Queue depth limit exceeded".to_string(),
            ));
        }

        // All limits satisfied; only now is state mutated.
        rate_limiter.consume(1);
        concurrency.acquire();
        *queue_depth += 1;

        Ok(())
    }

    /// Release a request slot.
    pub async fn release(&self) {
        let mut limiter = self.concurrency.write().await;
        limiter.release();

        let mut depth = self.queue_depth.write().await;
        if *depth > 0 {
            *depth -= 1;
        }
    }

    /// Check if operation is within resource limits.
    pub async fn check_limits(&self) -> GovernanceResult<()> {
        let limiter = self.rate_limiter.read().await;
        if limiter.available() < 1.0 {
            return Err(GovernanceError::RateLimited(
                "Insufficient rate limit".to_string(),
            ));
        }

        let concurrency = self.concurrency.read().await;
        if concurrency.available() == 0 {
            return Err(GovernanceError::ConcurrencyLimited(
                "No concurrency slots available".to_string(),
            ));
        }

        let depth = self.queue_depth.read().await;
        if *depth >= self.limits.max_queue_depth {
            return Err(GovernanceError::ResourceLimited(
                "Queue is full".to_string(),
            ));
        }

        Ok(())
    }

    /// Get current stats.
    pub async fn stats(&self) -> GovernanceStats {
        let rate_limiter = self.rate_limiter.read().await;
        let concurrency = self.concurrency.read().await;
        let depth = self.queue_depth.read().await;

        GovernanceStats {
            available_rate: rate_limiter.available() as u32,
            max_rate: self.limits.max_requests_per_second,
            active_concurrency: concurrency.current(),
            max_concurrency: self.limits.max_concurrent,
            queue_depth: *depth,
            max_queue_depth: self.limits.max_queue_depth,
        }
    }
}

/// Governor stats.
#[derive(Debug, Clone)]
pub struct GovernanceStats {
    pub available_rate: u32,
    pub max_rate: u32,
    pub active_concurrency: usize,
    pub max_concurrency: usize,
    pub queue_depth: usize,
    pub max_queue_depth: usize,
}

/// Hierarchical governor for managing multiple levels.
pub struct HierarchicalGovernor {
    organization: ResourceGovernor,
    project: ResourceGovernor,
    target: ResourceGovernor,
    scan: ResourceGovernor,
    api: ResourceGovernor,
}

impl HierarchicalGovernor {
    pub fn new(
        org_limits: ResourceLimits,
        project_limits: ResourceLimits,
        target_limits: ResourceLimits,
        scan_limits: ResourceLimits,
        api_limits: ResourceLimits,
    ) -> Self {
        Self {
            organization: ResourceGovernor::new(org_limits),
            project: ResourceGovernor::new(project_limits),
            target: ResourceGovernor::new(target_limits),
            scan: ResourceGovernor::new(scan_limits),
            api: ResourceGovernor::new(api_limits),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(
            ResourceLimits::default(),
            ResourceLimits::default(),
            ResourceLimits::default(),
            ResourceLimits {
                max_concurrent: 1,
                max_scan_duration_secs: 7200,
                ..Default::default()
            },
            ResourceLimits {
                max_requests_per_second: 50,
                max_concurrent: 20,
                ..Default::default()
            },
        )
    }

    /// Try to acquire across all levels.
    pub async fn try_acquire_all(&self) -> GovernanceResult<()> {
        self.organization.try_acquire().await?;
        self.project.try_acquire().await?;
        self.target.try_acquire().await?;
        self.scan.try_acquire().await?;
        self.api.try_acquire().await?;
        Ok(())
    }

    /// Release across all levels.
    pub async fn release_all(&self) {
        self.organization.release().await;
        self.project.release().await;
        self.target.release().await;
        self.scan.release().await;
        self.api.release().await;
    }

    /// Get combined stats.
    pub async fn stats(&self) -> Vec<(String, GovernanceStats)> {
        vec![
            ("organization".to_string(), self.organization.stats().await),
            ("project".to_string(), self.project.stats().await),
            ("target".to_string(), self.target.stats().await),
            ("scan".to_string(), self.scan.stats().await),
            ("api".to_string(), self.api.stats().await),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn token_bucket_basic() {
        let mut bucket = TokenBucket::new(10, 1.0);
        assert!(bucket.try_consume(5));
        assert!(bucket.try_consume(5));
        assert!(!bucket.try_consume(1));
    }

    #[tokio::test]
    async fn token_bucket_refill() {
        let mut bucket = TokenBucket::new(10, 100.0);
        assert!(bucket.try_consume(10));
        assert!(!bucket.try_consume(1));
        // Simulate time passing
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(bucket.try_consume(1));
    }

    #[tokio::test]
    async fn concurrency_limiter_basic() {
        let mut limiter = ConcurrencyLimiter::new(2);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire());
        limiter.release();
        assert!(limiter.try_acquire());
    }

    #[tokio::test]
    async fn resource_governor_acquire_release() {
        let governor = ResourceGovernor::with_defaults();
        assert!(governor.try_acquire().await.is_ok());
        governor.release().await;
    }

    #[tokio::test]
    async fn resource_governor_stats() {
        let governor = ResourceGovernor::with_defaults();
        let stats = governor.stats().await;
        assert_eq!(stats.max_rate, 100);
        assert_eq!(stats.max_concurrency, 10);
    }

    /// A rejection for a saturated concurrency limit must not cost a rate-limit
    /// token. `try_acquire` used to consume the token first and return `Err`
    /// without refunding it, so a burst of scans against a full concurrency limit
    /// silently drained the bucket and began rejecting callers for the wrong
    /// reason.
    #[tokio::test]
    async fn a_concurrency_rejection_does_not_spend_a_rate_limit_token() {
        let governor = ResourceGovernor::new(ResourceLimits {
            max_requests_per_second: 5,
            max_concurrent: 1,
            max_queue_depth: 100,
            ..Default::default()
        });

        governor.try_acquire().await.expect("first slot");

        // Concurrency is now full, so every one of these is rejected. If any of
        // them spends a rate token, the budget below will not add up.
        for _ in 0..3 {
            assert!(
                governor.try_acquire().await.is_err(),
                "concurrency is full; this must be rejected"
            );
        }

        // With the single slot released, exactly 4 of the 5 tokens must remain.
        // A leaked token shows up as one fewer successful acquire before
        // `RateLimited` appears.
        governor.release().await;

        let mut granted = 0;
        for _ in 0..8 {
            match governor.try_acquire().await {
                Ok(()) => {
                    granted += 1;
                    // Release immediately so concurrency never binds again and the
                    // only thing under test is the token budget.
                    governor.release().await;
                }
                Err(e) => {
                    assert!(
                        matches!(e, GovernanceError::RateLimited(_)),
                        "the only limit still in the way must be the rate limit, got {e:?}"
                    );
                    break;
                }
            }
        }

        assert_eq!(
            granted, 4,
            "one token was spent by the successful acquire; the three rejections \
             must have spent none"
        );
    }

    /// The queue-depth rejection leaked a concurrency slot: it had already been
    /// taken when the queue check failed, and nothing ever released it. Unreachable
    /// at the defaults, since `max_concurrent` (10) is below `max_queue_depth`
    /// (1000), but a trap for anyone configuring a queue depth below concurrency.
    #[tokio::test]
    async fn a_queue_depth_rejection_does_not_burn_a_concurrency_slot() {
        let governor = ResourceGovernor::new(ResourceLimits {
            max_requests_per_second: 100,
            max_concurrent: 2,
            // Below max_concurrent, so the queue check is the one that binds.
            max_queue_depth: 1,
            ..Default::default()
        });

        governor.try_acquire().await.expect("first fills the queue");
        assert_eq!(
            governor.concurrency.read().await.available(),
            1,
            "the successful acquire took one of two slots"
        );

        assert!(
            governor.try_acquire().await.is_err(),
            "the second exceeds the queue depth"
        );

        // Checked without releasing first, because a slot leaked by the rejected
        // attempt is still held until someone releases. Under the previous
        // implementation this reads 0: the rejection had already taken the second
        // slot and never gave it back, permanently halving the governor's
        // capacity every time the queue filled.
        assert_eq!(
            governor.concurrency.read().await.available(),
            1,
            "the rejected attempt must not have taken a concurrency slot"
        );

        governor.release().await;
        assert_eq!(
            governor.concurrency.read().await.available(),
            2,
            "releasing the real holder must restore full concurrency"
        );
    }

    /// Repeated rejections must be idempotent. If any of them leaked state, enough
    /// of them would wedge the governor permanently — a denial of service any
    /// authenticated user could trigger by submitting scans while at capacity.
    #[tokio::test]
    async fn repeated_rejections_never_wedge_the_governor() {
        let governor = ResourceGovernor::new(ResourceLimits {
            max_requests_per_second: 1000,
            max_concurrent: 2,
            max_queue_depth: 1000,
            ..Default::default()
        });

        governor.try_acquire().await.expect("first");
        governor.try_acquire().await.expect("second");

        for _ in 0..50 {
            assert!(governor.try_acquire().await.is_err());
        }

        governor.release().await;
        governor.release().await;

        for _ in 0..2 {
            governor
                .try_acquire()
                .await
                .expect("after every holder released, the full concurrency must be back");
        }
    }

    #[tokio::test]
    async fn a_rate_limit_rejection_takes_no_slot() {
        let governor = ResourceGovernor::new(ResourceLimits {
            max_requests_per_second: 1,
            max_concurrent: 10,
            max_queue_depth: 1000,
            ..Default::default()
        });

        governor.try_acquire().await.expect("spends the only token");
        assert_eq!(
            governor.concurrency.read().await.available(),
            9,
            "the successful acquire took exactly one of ten slots"
        );

        // The bucket is empty and refills at 1/s, so the next few are rejected on
        // rate. None of them may take a concurrency slot.
        for _ in 0..5 {
            assert!(
                governor.try_acquire().await.is_err(),
                "the bucket should still be empty"
            );
        }

        assert_eq!(
            governor.concurrency.read().await.available(),
            9,
            "a rate-limited request must not consume concurrency"
        );
    }

    #[tokio::test]
    async fn hierarchical_governor_acquire() {
        let governor = HierarchicalGovernor::with_defaults();
        assert!(governor.try_acquire_all().await.is_ok());
        governor.release_all().await;
    }

    #[tokio::test]
    async fn hierarchical_governor_stats() {
        let governor = HierarchicalGovernor::with_defaults();
        let stats = governor.stats().await;
        assert_eq!(stats.len(), 5);
    }
}
