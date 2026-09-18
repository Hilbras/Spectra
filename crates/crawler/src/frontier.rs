use std::collections::{HashSet, VecDeque};
use url::Url;

/// URL frontier for managing crawl queue with deduplication.
pub struct UrlFrontier {
    _base_domain: String,
    queue: VecDeque<(String, u32)>,
    visited: HashSet<String>,
    max_size: usize,
}

impl UrlFrontier {
    pub fn new(base_url: String, max_size: usize) -> Self {
        let base_domain = Url::parse(&base_url)
            .ok()
            .and_then(|u| u.domain().map(String::from))
            .unwrap_or_default();

        let mut frontier = Self {
            _base_domain: base_domain,
            queue: VecDeque::new(),
            visited: HashSet::new(),
            max_size,
        };

        frontier.enqueue(base_url, 0);
        frontier
    }

    pub fn enqueue(&mut self, url: String, depth: u32) {
        if self.visited.len() >= self.max_size {
            return;
        }

        let normalized = normalize_url(&url);
        if self.visited.contains(&normalized) {
            return;
        }

        self.visited.insert(normalized);
        self.queue.push_back((url, depth));
    }

    pub fn dequeue(&mut self) -> Option<(String, u32)> {
        self.queue.pop_front()
    }

    pub fn can_visit(&self, url: &str) -> bool {
        let normalized = normalize_url(url);
        !self.visited.contains(&normalized)
    }

    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    pub fn visited_count(&self) -> usize {
        self.visited.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

fn normalize_url(url: &str) -> String {
    if let Ok(parsed) = Url::parse(url) {
        let mut normalized = String::new();

        let scheme = parsed.scheme();
        normalized.push_str(scheme);
        normalized.push_str("://");

        if let Some(host) = parsed.host_str() {
            normalized.push_str(&host.to_lowercase());
        }

        if let Some(port) = parsed.port() {
            normalized.push_str(&format!(":{}", port));
        }

        let path = parsed.path();
        let path = path.trim_end_matches('/');
        normalized.push_str(path);

        if let Some(query) = parsed.query() {
            normalized.push('?');
            normalized.push_str(query);
        }

        normalized
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontier_basic_operations() {
        let mut frontier = UrlFrontier::new("https://example.com".to_string(), 100);
        assert_eq!(frontier.pending(), 1);
        assert!(!frontier.is_empty());

        let (url, depth) = frontier.dequeue().unwrap();
        assert_eq!(url, "https://example.com");
        assert_eq!(depth, 0);
        assert!(frontier.is_empty());
    }

    #[test]
    fn frontier_deduplication() {
        let mut frontier = UrlFrontier::new("https://example.com".to_string(), 100);
        frontier.dequeue();

        frontier.enqueue("https://example.com/page".to_string(), 1);
        frontier.enqueue("https://example.com/page".to_string(), 2);
        frontier.enqueue("https://example.com/other".to_string(), 1);

        assert_eq!(frontier.pending(), 2);
    }

    #[test]
    fn frontier_max_size() {
        let mut frontier = UrlFrontier::new("https://example.com".to_string(), 2);
        frontier.dequeue();

        frontier.enqueue("https://example.com/a".to_string(), 1);
        frontier.enqueue("https://example.com/b".to_string(), 1);
        frontier.enqueue("https://example.com/c".to_string(), 1);

        assert_eq!(frontier.visited_count(), 2);
    }

    #[test]
    fn url_normalization() {
        assert_eq!(
            normalize_url("https://Example.COM/Page/"),
            "https://example.com/Page"
        );
        assert_eq!(
            normalize_url("https://example.com/page#fragment"),
            "https://example.com/page"
        );
        assert_eq!(
            normalize_url("https://example.com/page?key=val"),
            "https://example.com/page?key=val"
        );
    }

    #[test]
    fn can_visit_check() {
        let frontier = UrlFrontier::new("https://example.com".to_string(), 100);
        // Already in frontier (seed URL) — can't visit again
        assert!(!frontier.can_visit("https://example.com"));
        // Different URL — not yet seen
        assert!(frontier.can_visit("https://example.com/other"));
    }
}
