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

use tracing::{info, warn};

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
        let mut errors: Vec<String> = Vec::new();
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
                Err(e) => {
                    // The reason used to be discarded here, leaving a bare
                    // count that could not distinguish an unreachable target
                    // from a 404 or a bug in this crawler.
                    warn!(url = %url, error = %e, "failed to fetch page");
                    errors.push(format!("{url}: {e}"));
                }
            }

            if pages.len() >= self.config.max_pages as usize {
                break;
            }

            if self.config.delay_ms > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(self.config.delay_ms)).await;
            }
        }

        if pages.is_empty() {
            // Worth a dedicated warning: downstream stages consume `pages`, so
            // an empty crawl means the whole scan has nothing to work with and
            // will report zero findings. That is a false negative, not a clean
            // result, and the operator needs to be told here rather than
            // discovering it in a report.
            warn!(
                target = %target.value(),
                attempted = total_discovered,
                "crawl produced no pages; downstream scanning will have nothing to analyse"
            );
        }

        info!(
            pages_crawled = pages.len(),
            total_discovered = total_discovered,
            errors = errors.len(),
            "Crawl completed"
        );

        // The count of pages actually retrieved, not the count attempted. These
        // were the same value, which made `success_rate()` a constant 1.0 and
        // let a wholly failed crawl report perfect success.
        let total_crawled = pages.len() as u32;

        Ok(CrawlResult {
            target_id: target.id.clone(),
            pages,
            total_discovered,
            total_crawled,
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

    /// A target pointing at a port nothing listens on.
    ///
    /// Loopback port 1 is used rather than an external host so the test needs no
    /// network: the connection is refused immediately by the kernel. The SSRF
    /// guard is applied by the API layer, not inside the crawler, so a direct
    /// call does attempt the fetch — which is what makes this observable.
    fn dead_target() -> Target {
        Target::new(
            spectra_core::Id::new(),
            "dead".into(),
            spectra_target::TargetType::Url,
            "http://127.0.0.1:1/".into(),
        )
    }

    /// A one-shot HTTP server on loopback that returns `body` for every request.
    ///
    /// Hand-rolled over `std::net` so the test needs no dev-dependency and no
    /// external service. Returns the base URL.
    fn serve_once(body: &'static str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();

        std::thread::spawn(move || {
            // Serve a bounded number of requests so the thread cannot outlive the
            // test process if the crawler retries.
            for stream in listener.incoming().take(8) {
                let Ok(mut stream) = stream else { break };
                use std::io::{Read, Write};
                let mut buffer = [0u8; 2048];
                let _ = stream.read(&mut buffer);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        format!("http://127.0.0.1:{port}/")
    }

    /// The regression: `crawl()` assigned `total_discovered` to
    /// `total_crawled`, so a crawl where every fetch failed reported a perfect
    /// success rate and a page count that had never been fetched.
    #[tokio::test]
    async fn a_crawl_where_every_fetch_fails_counts_zero_pages() {
        let crawler = Crawler::new(CrawlerConfig {
            delay_ms: 0,
            max_pages: 5,
            ..Default::default()
        });

        let result = crawler
            .crawl(&dead_target())
            .await
            .expect("crawl should complete even when every fetch fails");

        assert_eq!(result.total_discovered, 1, "the URL was attempted");
        assert_eq!(
            result.total_crawled, 0,
            "no page was retrieved, so none may be counted"
        );
        assert_eq!(result.pages.len(), 0);
        assert!(result.error_count() >= 1, "the failure must be recorded");
        assert_eq!(
            result.success_rate(),
            0.0,
            "a wholly failed crawl must not report a perfect success rate"
        );
        assert!(result.yielded_nothing());
        assert!(
            !result.errors.is_empty(),
            "the reason must be retained, not just counted"
        );
    }

    #[tokio::test]
    async fn a_successful_crawl_counts_the_pages_it_retrieved() {
        let base = serve_once("<html><body><a href=\"/other\">other</a></body></html>");
        let target = Target::new(
            spectra_core::Id::new(),
            "live".into(),
            spectra_target::TargetType::Url,
            base.clone(),
        );

        let crawler = Crawler::new(CrawlerConfig {
            delay_ms: 0,
            max_pages: 5,
            ..Default::default()
        });

        let result = crawler.crawl(&target).await.expect("crawl should complete");

        assert_eq!(
            result.total_crawled as usize,
            result.pages.len(),
            "the crawled count must equal the pages actually retrieved"
        );
        // The exact number depends on how far the frontier gets, which is not
        // what is under test here. The invariant is that the reported count is
        // the number of pages actually retrieved.
        assert!(
            result.total_crawled >= 1,
            "at least the entry page should have been retrieved"
        );
        assert!(
            result.total_crawled <= result.total_discovered,
            "cannot have retrieved more pages than were discovered"
        );
        assert!(!result.yielded_nothing());
        assert_eq!(result.error_count(), 0, "every fetch should have succeeded");
        assert_eq!(result.success_rate(), 1.0);
    }
}
