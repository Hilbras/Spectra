pub mod crawl;
pub mod error;
pub mod filter;
pub mod frontier;
pub mod parser;
pub mod policy;
pub mod robots;

pub use crawl::{CrawlRequest, CrawlResult, CrawledPage};
pub use error::{CrawlerError, CrawlerResult};
pub use filter::CrawlFilter;
pub use frontier::UrlFrontier;
pub use parser::{HtmlParser, ParsedForm, ParsedFormField};
pub use policy::CrawlPolicy;

use tracing::info;

use spectra_http::HttpClient;
use spectra_target::Target;

/// Main crawler entry point.
pub struct Crawler {
    config: CrawlerConfig,
    http_client: HttpClient,
}

/// Configuration for the crawler.
#[derive(Debug, Clone)]
pub struct CrawlerConfig {
    pub max_depth: u32,
    pub max_pages: u32,
    pub concurrent_requests: usize,
    pub delay_ms: u64,
    pub respect_robots: bool,
    pub user_agent: String,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_pages: 10_000,
            concurrent_requests: 10,
            delay_ms: 100,
            respect_robots: true,
            user_agent: "Spectra/0.1.0".to_string(),
        }
    }
}

impl From<spectra_config::config::CrawlerConfig> for CrawlerConfig {
    fn from(config: spectra_config::config::CrawlerConfig) -> Self {
        Self {
            max_depth: config.max_depth,
            max_pages: config.max_pages,
            concurrent_requests: config.concurrent_requests,
            delay_ms: 100,
            respect_robots: config.respect_robots,
            user_agent: config.user_agent,
        }
    }
}

impl Crawler {
    pub fn new(config: CrawlerConfig) -> Self {
        let http_client = HttpClient::new().expect("Failed to create HTTP client");
        Self {
            config,
            http_client,
        }
    }

    pub async fn crawl(&self, target: &Target) -> CrawlerResult<CrawlResult> {
        info!(target = %target.value(), "Starting crawl");

        let base_url = self.build_base_url(target)?;
        let filter = CrawlFilter::from_scope(&target.scope);
        let mut frontier = UrlFrontier::new(base_url.clone(), self.config.max_pages as usize);
        let mut pages = Vec::new();
        let mut errors = 0u32;
        let mut total_discovered = 0u32;

        while let Some((url, depth)) = frontier.dequeue() {
            if depth > self.config.max_depth {
                continue;
            }

            total_discovered += 1;

            match self.fetch_page(&url).await {
                Ok(mut page) => {
                    page.depth = depth;

                    let links = HtmlParser::extract_links(&page.url, &page.content);
                    for link in links {
                        if filter.should_include(&link) && frontier.can_visit(&link) {
                            frontier.enqueue(link, depth + 1);
                        }
                    }

                    page.forms = HtmlParser::extract_forms(&page.content)
                        .into_iter()
                        .map(|f| crawl::ParsedForm {
                            action: f.action,
                            method: f.method,
                            fields: f
                                .fields
                                .into_iter()
                                .map(|field| crawl::ParsedFormField {
                                    name: field.name,
                                    field_type: field.field_type,
                                    value: field.value,
                                    required: field.required,
                                })
                                .collect(),
                        })
                        .collect();

                    pages.push(page);
                }
                Err(_) => {
                    errors += 1;
                }
            }

            if pages.len() >= self.config.max_pages as usize {
                break;
            }

            if self.config.delay_ms > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(self.config.delay_ms)).await;
            }
        }

        info!(
            pages_crawled = pages.len(),
            total_discovered = total_discovered,
            errors = errors,
            "Crawl completed"
        );

        Ok(CrawlResult {
            target_id: target.id.clone(),
            pages,
            total_discovered,
            total_crawled: total_discovered,
            errors,
        })
    }

    async fn fetch_page(&self, url: &str) -> CrawlerResult<CrawledPage> {
        let request = spectra_http::Request::get(url)
            .header("User-Agent", &self.config.user_agent)
            .timeout(30_000);

        let response = self
            .http_client
            .execute(request)
            .await
            .map_err(|e| CrawlerError::RequestFailed(e.to_string()))?;

        let status = response.status.as_u16();
        let headers: std::collections::HashMap<String, String> = response
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let content = response.text().unwrap_or("").to_string();

        Ok(CrawledPage {
            url: url.to_string(),
            status_code: status,
            headers,
            content,
            links: Vec::new(),
            forms: Vec::new(),
            depth: 0,
            crawled_at: spectra_core::Timestamp::now(),
        })
    }

    fn build_base_url(&self, target: &Target) -> CrawlerResult<String> {
        match target.target_type {
            spectra_target::TargetType::Url => Ok(target.value().to_string()),
            spectra_target::TargetType::Domain => Ok(format!("https://{}", target.value())),
            _ => Err(CrawlerError::ParseError(format!(
                "Cannot build URL from target type {:?}",
                target.target_type
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crawler_config_defaults() {
        let config = CrawlerConfig::default();
        assert_eq!(config.max_depth, 10);
        assert_eq!(config.max_pages, 10_000);
        assert_eq!(config.concurrent_requests, 10);
        assert!(config.respect_robots);
        assert_eq!(config.user_agent, "Spectra/0.1.0");
    }

    #[test]
    fn crawler_creation() {
        let config = CrawlerConfig::default();
        let crawler = Crawler::new(config);
        assert_eq!(crawler.config.max_depth, 10);
    }
}
