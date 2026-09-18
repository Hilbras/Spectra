use regex::Regex;
use spectra_target::Scope;

/// URL filter for controlling which URLs to crawl.
#[derive(Debug, Clone)]
pub struct CrawlFilter {
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub include_regexes: Vec<Regex>,
    pub exclude_regexes: Vec<Regex>,
    pub allowed_domains: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub allowed_extensions: Vec<String>,
    pub excluded_extensions: Vec<String>,
}

impl CrawlFilter {
    pub fn from_scope(scope: &Scope) -> Self {
        let mut allowed_domains = Vec::new();
        let mut allowed_paths = Vec::new();
        let mut excluded_paths = Vec::new();

        for rule in &scope.allowed {
            match rule.rule_type {
                spectra_target::ScopeRuleType::Allow => {
                    allowed_domains.push(rule.value.clone());
                }
                spectra_target::ScopeRuleType::Path => {
                    allowed_paths.push(rule.value.clone());
                }
                _ => {}
            }
        }

        for rule in &scope.excluded {
            match rule.rule_type {
                spectra_target::ScopeRuleType::Exclude => {
                    allowed_domains.push(format!("!{}", rule.value));
                }
                spectra_target::ScopeRuleType::Path => {
                    excluded_paths.push(rule.value.clone());
                }
                _ => {}
            }
        }

        Self {
            include_patterns: allowed_domains.clone(),
            exclude_patterns: Vec::new(),
            include_regexes: Vec::new(),
            exclude_regexes: Vec::new(),
            allowed_domains,
            allowed_paths,
            excluded_paths,
            allowed_extensions: vec![
                "html".to_string(),
                "htm".to_string(),
                "php".to_string(),
                "asp".to_string(),
                "aspx".to_string(),
                "jsp".to_string(),
                "js".to_string(),
                "json".to_string(),
                "xml".to_string(),
                "txt".to_string(),
            ],
            excluded_extensions: vec![
                "png".to_string(),
                "jpg".to_string(),
                "jpeg".to_string(),
                "gif".to_string(),
                "svg".to_string(),
                "ico".to_string(),
                "css".to_string(),
                "woff".to_string(),
                "woff2".to_string(),
                "ttf".to_string(),
                "eot".to_string(),
                "mp4".to_string(),
                "mp3".to_string(),
                "pdf".to_string(),
                "zip".to_string(),
                "tar".to_string(),
                "gz".to_string(),
            ],
        }
    }

    pub fn permissive() -> Self {
        Self {
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            include_regexes: Vec::new(),
            exclude_regexes: Vec::new(),
            allowed_domains: Vec::new(),
            allowed_paths: Vec::new(),
            excluded_paths: Vec::new(),
            allowed_extensions: Vec::new(),
            excluded_extensions: Vec::new(),
        }
    }

    pub fn should_include(&self, url: &str) -> bool {
        for re in &self.exclude_regexes {
            if re.is_match(url) {
                return false;
            }
        }

        for pattern in &self.exclude_patterns {
            if url.contains(pattern.as_str()) {
                return false;
            }
        }

        if let Ok(parsed) = url::Url::parse(url) {
            let path = parsed.path();
            for excluded in &self.excluded_paths {
                if path.starts_with(excluded) {
                    return false;
                }
            }

            if let Some(domain) = parsed.domain() {
                if !self.allowed_domains.is_empty()
                    && !self
                        .allowed_domains
                        .iter()
                        .any(|d| domain.contains(d.as_str()))
                {
                    return false;
                }
            }

            if let Some(ext) = path.rsplit('.').next() {
                if self.excluded_extensions.contains(&ext.to_string()) {
                    return false;
                }
            }
        }

        if !self.include_regexes.is_empty() {
            return self.include_regexes.iter().any(|re| re.is_match(url));
        }

        if !self.include_patterns.is_empty() {
            return self
                .include_patterns
                .iter()
                .any(|p| url.contains(p.as_str()));
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissive_filter_includes_everything() {
        let filter = CrawlFilter::permissive();
        assert!(filter.should_include("https://example.com/page"));
        assert!(filter.should_include("https://other.com/page"));
    }

    #[test]
    fn filter_excludes_extensions() {
        let filter = CrawlFilter {
            excluded_extensions: vec!["png".to_string(), "jpg".to_string(), "css".to_string()],
            ..CrawlFilter::permissive()
        };
        assert!(filter.should_include("https://example.com/page.html"));
        assert!(!filter.should_include("https://example.com/image.png"));
        assert!(!filter.should_include("https://example.com/style.css"));
    }

    #[test]
    fn filter_with_scope() {
        use spectra_target::{Scope, ScopeRule, ScopeRuleType};

        let scope = Scope {
            allowed: vec![ScopeRule {
                rule_type: ScopeRuleType::Allow,
                value: "example.com".to_string(),
                description: None,
            }],
            excluded: vec![],
            rate_limits: Default::default(),
            execution_limits: Default::default(),
        };

        let filter = CrawlFilter::from_scope(&scope);
        assert!(filter.should_include("https://example.com/page"));
        assert!(!filter.should_include("https://other.com/page"));
    }
}
