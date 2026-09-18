use spectra_core::{Id, Timestamp};
use spectra_target::{Target, TargetId};

/// A request to crawl a target.
#[derive(Debug, Clone)]
pub struct CrawlRequest {
    pub target_id: Id<TargetId>,
    pub start_urls: Vec<String>,
    pub max_depth: Option<u32>,
    pub max_pages: Option<u32>,
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
}

impl CrawlRequest {
    pub fn new(target: &Target) -> Self {
        let start_url = match target.target_type {
            spectra_target::TargetType::Url => target.value().to_string(),
            spectra_target::TargetType::Domain => format!("https://{}", target.value()),
            _ => format!("https://{}", target.value()),
        };

        Self {
            target_id: target.id.clone(),
            start_urls: vec![start_url],
            max_depth: None,
            max_pages: None,
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
        }
    }

    pub fn with_max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = Some(max_depth);
        self
    }

    pub fn with_max_pages(mut self, max_pages: u32) -> Self {
        self.max_pages = Some(max_pages);
        self
    }
}

/// A single crawled page.
#[derive(Debug, Clone)]
pub struct CrawledPage {
    pub url: String,
    pub status_code: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub content: String,
    pub links: Vec<String>,
    pub forms: Vec<ParsedForm>,
    pub depth: u32,
    pub crawled_at: Timestamp,
}

/// Parsed form data.
#[derive(Debug, Clone)]
pub struct ParsedForm {
    pub action: String,
    pub method: String,
    pub fields: Vec<ParsedFormField>,
}

/// A form field.
#[derive(Debug, Clone)]
pub struct ParsedFormField {
    pub name: String,
    pub field_type: String,
    pub value: Option<String>,
    pub required: bool,
}

/// Result of a crawl operation.
#[derive(Debug, Clone)]
pub struct CrawlResult {
    pub target_id: Id<TargetId>,
    pub pages: Vec<CrawledPage>,
    pub total_discovered: u32,
    pub total_crawled: u32,
    pub errors: u32,
}

impl CrawlResult {
    pub fn pages_crawled(&self) -> usize {
        self.pages.len()
    }

    pub fn pages_with_status(&self, status: u16) -> Vec<&CrawledPage> {
        self.pages
            .iter()
            .filter(|p| p.status_code == status)
            .collect()
    }

    pub fn all_urls(&self) -> Vec<&str> {
        self.pages.iter().map(|p| p.url.as_str()).collect()
    }

    pub fn all_forms(&self) -> Vec<&ParsedForm> {
        self.pages.iter().flat_map(|p| &p.forms).collect()
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_discovered == 0 {
            return 0.0;
        }
        self.total_crawled as f64 / self.total_discovered as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectra_target::{Target, TargetType};

    #[test]
    fn crawl_request_from_domain_target() {
        let target = Target::new(
            Id::new(),
            "Example".to_string(),
            TargetType::Domain,
            "example.com".to_string(),
        );

        let request = CrawlRequest::new(&target);
        assert_eq!(request.start_urls, vec!["https://example.com"]);
        assert!(request.max_depth.is_none());
    }

    #[test]
    fn crawl_request_from_url_target() {
        let target = Target::new(
            Id::new(),
            "Example Page".to_string(),
            TargetType::Url,
            "https://example.com/page".to_string(),
        );

        let request = CrawlRequest::new(&target);
        assert_eq!(request.start_urls, vec!["https://example.com/page"]);
    }

    #[test]
    fn crawl_result_operations() {
        let result = CrawlResult {
            target_id: Id::new(),
            pages: vec![
                CrawledPage {
                    url: "https://example.com".to_string(),
                    status_code: 200,
                    headers: std::collections::HashMap::new(),
                    content: "<html></html>".to_string(),
                    links: vec!["https://example.com/page".to_string()],
                    forms: Vec::new(),
                    depth: 0,
                    crawled_at: Timestamp::now(),
                },
                CrawledPage {
                    url: "https://example.com/404".to_string(),
                    status_code: 404,
                    headers: std::collections::HashMap::new(),
                    content: String::new(),
                    links: Vec::new(),
                    forms: Vec::new(),
                    depth: 1,
                    crawled_at: Timestamp::now(),
                },
            ],
            total_discovered: 10,
            total_crawled: 8,
            errors: 2,
        };

        assert_eq!(result.pages_crawled(), 2);
        assert_eq!(result.pages_with_status(200).len(), 1);
        assert_eq!(result.pages_with_status(404).len(), 1);
        assert!((result.success_rate() - 0.8).abs() < f64::EPSILON);
    }
}
