use serde::{Deserialize, Serialize};

/// Retry policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Initial delay in milliseconds.
    pub initial_delay_ms: u64,
    /// Maximum delay in milliseconds.
    pub max_delay_ms: u64,
    /// Backoff multiplier.
    pub backoff_multiplier: f64,
    /// Add jitter to delays.
    pub jitter: bool,
    /// Status codes that trigger a retry.
    pub retryable_status_codes: Vec<u16>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 100,
            max_delay_ms: 30_000,
            backoff_multiplier: 2.0,
            jitter: true,
            retryable_status_codes: vec![408, 429, 500, 502, 503, 504],
        }
    }
}

impl RetryPolicy {
    /// Creates a no-retry policy.
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Creates a conservative retry policy.
    pub fn conservative() -> Self {
        Self {
            max_retries: 5,
            initial_delay_ms: 500,
            max_delay_ms: 60_000,
            backoff_multiplier: 2.0,
            jitter: true,
            retryable_status_codes: vec![408, 429, 500, 502, 503, 504],
        }
    }

    /// Creates an aggressive retry policy.
    pub fn aggressive() -> Self {
        Self {
            max_retries: 10,
            initial_delay_ms: 50,
            max_delay_ms: 10_000,
            backoff_multiplier: 1.5,
            jitter: true,
            retryable_status_codes: vec![408, 429, 500, 502, 503, 504],
        }
    }

    /// Calculates the delay for a given attempt.
    pub fn delay_for_attempt(&self, attempt: u32) -> u64 {
        if attempt == 0 {
            return 0;
        }

        let base_delay = self.initial_delay_ms as f64;
        let multiplier = self.backoff_multiplier;
        let delay = base_delay * multiplier.powi(i32::try_from(attempt - 1).unwrap_or(0));
        let delay = delay.min(self.max_delay_ms as f64);

        if self.jitter {
            let jitter = delay * 0.1 * rand::random::<f64>();
            (delay + jitter) as u64
        } else {
            delay as u64
        }
    }

    /// Returns whether a status code should trigger a retry.
    pub fn should_retry_status(&self, status: u16) -> bool {
        self.retryable_status_codes.contains(&status)
    }

    /// Returns whether another retry is allowed.
    pub fn can_retry(&self, attempt: u32) -> bool {
        attempt < self.max_retries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.initial_delay_ms, 100);
    }

    #[test]
    fn delay_calculation() {
        let policy = RetryPolicy {
            jitter: false,
            ..Default::default()
        };
        assert_eq!(policy.delay_for_attempt(0), 0);
        assert_eq!(policy.delay_for_attempt(1), 100);
        assert_eq!(policy.delay_for_attempt(2), 200);
        assert_eq!(policy.delay_for_attempt(3), 400);
    }

    #[test]
    fn should_retry() {
        let policy = RetryPolicy::default();
        assert!(policy.should_retry_status(429));
        assert!(policy.should_retry_status(500));
        assert!(policy.should_retry_status(503));
        assert!(!policy.should_retry_status(200));
        assert!(!policy.should_retry_status(404));
    }

    #[test]
    fn can_retry() {
        let policy = RetryPolicy::default();
        assert!(policy.can_retry(0));
        assert!(policy.can_retry(1));
        assert!(policy.can_retry(2));
        assert!(!policy.can_retry(3));
    }

    #[test]
    fn no_retry_policy() {
        let policy = RetryPolicy::none();
        assert!(!policy.can_retry(0));
    }
}
