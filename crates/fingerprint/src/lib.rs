pub mod engine;
pub mod rules;

pub use engine::{FingerprintEngine, FingerprintInput};
pub use rules::{DetectionRule, RuleDatabase};

use serde::{Deserialize, Serialize};
use spectra_core::Id;
use spectra_target::TargetId;
use thiserror::Error;

/// Errors specific to fingerprinting operations.
#[derive(Debug, Error)]
pub enum FingerprintError {
    #[error("Fingerprint failed: {0}")]
    Failed(String),
    #[error("Unsupported technology: {0}")]
    UnsupportedTechnology(String),
    #[error("Network error: {0}")]
    Network(#[from] spectra_network::NetworkError),
}

/// Result type for fingerprinting operations.
pub type FingerprintResult<T> = Result<T, FingerprintError>;

/// Categories of technologies that can be detected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TechnologyCategory {
    WebServer,
    ProgrammingLanguage,
    Framework,
    Cms,
    Database,
    Cache,
    Analytics,
    Cdn,
    Dns,
    MailServer,
    Os,
    Waf,
    Other(String),
}

/// A detected technology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    pub category: TechnologyCategory,
    pub version: Option<String>,
    pub confidence: f64,
    pub detection_method: DetectionMethod,
}

/// How a technology was detected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DetectionMethod {
    HttpHeaders,
    HtmlContent,
    JavaScript,
    Cookies,
    MetaTags,
    UrlPatterns,
    ErrorMessages,
}

/// Fingerprint result for a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fingerprint {
    pub target_id: Id<TargetId>,
    pub technologies: Vec<Technology>,
    pub confidence: f64,
    pub metadata: std::collections::HashMap<String, String>,
}

impl Fingerprint {
    pub fn new(target_id: Id<TargetId>) -> Self {
        Self {
            target_id,
            technologies: Vec::new(),
            confidence: 0.0,
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn add_technology(&mut self, tech: Technology) {
        self.technologies.push(tech);
        self.recalculate_confidence();
    }

    fn recalculate_confidence(&mut self) {
        if self.technologies.is_empty() {
            self.confidence = 0.0;
            return;
        }
        let total: f64 = self.technologies.iter().map(|t| t.confidence).sum();
        self.confidence = total / self.technologies.len() as f64;
    }

    pub fn has_technology(&self, name: &str) -> bool {
        self.technologies.iter().any(|t| t.name == name)
    }

    /// Returns technologies filtered by category.
    pub fn technologies_by_category(&self, category: &TechnologyCategory) -> Vec<&Technology> {
        self.technologies
            .iter()
            .filter(|t| t.category == *category)
            .collect()
    }

    /// Returns the overall detection confidence.
    pub fn confidence(&self) -> f64 {
        self.confidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_operations() {
        let mut fp = Fingerprint::new(Id::new());
        assert_eq!(fp.technologies.len(), 0);
        assert_eq!(fp.confidence, 0.0);

        fp.add_technology(Technology {
            name: "Nginx".to_string(),
            category: TechnologyCategory::WebServer,
            version: Some("1.21.0".to_string()),
            confidence: 0.9,
            detection_method: DetectionMethod::HttpHeaders,
        });

        assert!(fp.has_technology("Nginx"));
        assert!(!fp.has_technology("Apache"));
        assert!((fp.confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn fingerprint_confidence_average() {
        let mut fp = Fingerprint::new(Id::new());

        fp.add_technology(Technology {
            name: "Nginx".to_string(),
            category: TechnologyCategory::WebServer,
            version: None,
            confidence: 0.9,
            detection_method: DetectionMethod::HttpHeaders,
        });

        fp.add_technology(Technology {
            name: "PHP".to_string(),
            category: TechnologyCategory::ProgrammingLanguage,
            version: Some("8.1".to_string()),
            confidence: 0.8,
            detection_method: DetectionMethod::HttpHeaders,
        });

        assert!((fp.confidence - 0.85).abs() < f64::EPSILON);
    }
}
