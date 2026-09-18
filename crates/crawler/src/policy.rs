use crate::CrawlerConfig;

/// Crawl policy controlling crawler behavior.
#[derive(Debug, Clone)]
pub struct CrawlPolicy {
    pub max_depth: u32,
    pub max_pages: u32,
    pub delay_ms: u64,
    pub concurrent_requests: usize,
    pub respect_robots: bool,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    pub timeout_ms: u64,
}

impl CrawlPolicy {
    /// Creates a crawl policy from crawler configuration.
    pub fn from_config(config: &CrawlerConfig) -> Self {
        Self {
            max_depth: config.max_depth,
            max_pages: config.max_pages,
            delay_ms: config.delay_ms,
            concurrent_requests: config.concurrent_requests,
            respect_robots: config.respect_robots,
            user_agent: config.user_agent.clone(),
            follow_redirects: true,
            max_redirects: 10,
            timeout_ms: 30_000,
        }
    }

    /// Creates a permissive policy for testing.
    pub fn permissive() -> Self {
        Self {
            max_depth: 100,
            max_pages: 100_000,
            delay_ms: 0,
            concurrent_requests: 50,
            respect_robots: false,
            user_agent: "Spectra-Test/0.1.0".to_string(),
            follow_redirects: true,
            max_redirects: 20,
            timeout_ms: 60_000,
        }
    }
}

impl Default for CrawlPolicy {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_pages: 10_000,
            delay_ms: 100,
            concurrent_requests: 10,
            respect_robots: true,
            user_agent: "Spectra/0.1.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
            timeout_ms: 30_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_from_config() {
        let config = CrawlerConfig {
            max_depth: 5,
            max_pages: 500,
            concurrent_requests: 5,
            delay_ms: 200,
            respect_robots: false,
            user_agent: "Test/1.0".to_string(),
        };

        let policy = CrawlPolicy::from_config(&config);
        assert_eq!(policy.max_depth, 5);
        assert_eq!(policy.max_pages, 500);
        assert_eq!(policy.concurrent_requests, 5);
        assert_eq!(policy.delay_ms, 200);
        assert!(!policy.respect_robots);
        assert_eq!(policy.user_agent, "Test/1.0");
    }

    #[test]
    fn default_policy() {
        let policy = CrawlPolicy::default();
        assert_eq!(policy.max_depth, 10);
        assert_eq!(policy.max_pages, 10_000);
        assert!(policy.respect_robots);
    }
}
