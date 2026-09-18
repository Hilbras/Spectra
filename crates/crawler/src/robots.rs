/// Parsed robots.txt directives for a domain.
#[derive(Debug, Clone, Default)]
pub struct RobotsTxt {
    pub disallowed_paths: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub crawl_delay: Option<u64>,
    pub sitemaps: Vec<String>,
}

impl RobotsTxt {
    /// Parses robots.txt content.
    pub fn parse(content: &str) -> Self {
        let mut disallowed_paths = Vec::new();
        let mut allowed_paths = Vec::new();
        let mut crawl_delay = None;
        let mut sitemaps = Vec::new();
        let mut applies_to_us = false;

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();

                match key.as_str() {
                    "user-agent" => {
                        let current_agent = value.to_lowercase();
                        applies_to_us = current_agent == "*" || current_agent.contains("spectra");
                    }
                    "disallow" if applies_to_us => {
                        if !value.is_empty() {
                            disallowed_paths.push(value);
                        }
                    }
                    "allow" if applies_to_us => {
                        if !value.is_empty() {
                            allowed_paths.push(value);
                        }
                    }
                    "crawl-delay" if applies_to_us => {
                        if let Ok(delay) = value.parse::<u64>() {
                            crawl_delay = Some(delay);
                        }
                    }
                    "sitemap" => {
                        sitemaps.push(value);
                    }
                    _ => {}
                }
            }
        }

        Self {
            disallowed_paths,
            allowed_paths,
            crawl_delay,
            sitemaps,
        }
    }

    /// Returns true if the path is allowed for crawling.
    pub fn is_allowed(&self, path: &str) -> bool {
        // Check disallowed paths
        for disallowed in &self.disallowed_paths {
            if path.starts_with(disallowed) {
                // Check if there's a more specific allow rule
                for allowed in &self.allowed_paths {
                    if path.starts_with(allowed) && allowed.len() > disallowed.len() {
                        return true;
                    }
                }
                return false;
            }
        }
        true
    }
}

/// Fetches and parses robots.txt for a domain.
pub async fn fetch_robots_txt(domain: &str) -> RobotsTxt {
    let url = format!("https://{}/robots.txt", domain);

    match reqwest::get(&url).await {
        Ok(response) => {
            if response.status().is_success() {
                match response.text().await {
                    Ok(content) => RobotsTxt::parse(&content),
                    Err(_) => RobotsTxt::default(),
                }
            } else {
                RobotsTxt::default()
            }
        }
        Err(_) => RobotsTxt::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_robots_txt() {
        let content = r#"
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /admin/public/
Crawl-delay: 5
Sitemap: https://example.com/sitemap.xml

User-agent: BadBot
Disallow: /

User-agent: Spectra
Allow: /
"#;

        let robots = RobotsTxt::parse(content);
        assert!(robots.disallowed_paths.contains(&"/admin/".to_string()));
        assert!(robots.disallowed_paths.contains(&"/private/".to_string()));
        assert!(robots.allowed_paths.contains(&"/admin/public/".to_string()));
        assert_eq!(robots.crawl_delay, Some(5));
        assert!(robots
            .sitemaps
            .contains(&"https://example.com/sitemap.xml".to_string()));
    }

    #[test]
    fn is_allowed_check() {
        let robots = RobotsTxt {
            disallowed_paths: vec!["/admin/".to_string(), "/private/".to_string()],
            allowed_paths: vec!["/admin/public/".to_string()],
            crawl_delay: None,
            sitemaps: Vec::new(),
        };

        assert!(robots.is_allowed("/"));
        assert!(robots.is_allowed("/page"));
        assert!(!robots.is_allowed("/admin/secret"));
        assert!(robots.is_allowed("/admin/public/page"));
        assert!(!robots.is_allowed("/private/data"));
    }

    #[test]
    fn parse_empty_robots() {
        let robots = RobotsTxt::parse("");
        assert!(robots.disallowed_paths.is_empty());
        assert!(robots.crawl_delay.is_none());
    }
}
