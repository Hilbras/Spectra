use serde::{Deserialize, Serialize};
use spectra_core::{Id, Metadata, Timestamp};

/// Marker type for asset identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssetId;

/// Types of assets that can be discovered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AssetType {
    Domain,
    Subdomain,
    IpAddress,
    Port,
    Service,
    WebApplication,
    Technology,
    Endpoint,
    ApiEndpoint,
    Certificate,
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain => write!(f, "domain"),
            Self::Subdomain => write!(f, "subdomain"),
            Self::IpAddress => write!(f, "ip"),
            Self::Port => write!(f, "port"),
            Self::Service => write!(f, "service"),
            Self::WebApplication => write!(f, "webapp"),
            Self::Technology => write!(f, "technology"),
            Self::Endpoint => write!(f, "endpoint"),
            Self::ApiEndpoint => write!(f, "api"),
            Self::Certificate => write!(f, "certificate"),
        }
    }
}

/// A discovered asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: Id<AssetId>,
    pub asset_type: AssetType,
    pub value: String,
    pub parent_id: Option<Id<AssetId>>,
    pub metadata: Metadata,
    pub discovered_at: Timestamp,
}

impl Asset {
    pub fn new(asset_type: AssetType, value: String) -> Self {
        Self {
            id: Id::new(),
            asset_type,
            value,
            parent_id: None,
            metadata: Metadata::new(),
            discovered_at: Timestamp::now(),
        }
    }

    pub fn with_parent(mut self, parent_id: Id<AssetId>) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// An asset discovered during discovery.
#[derive(Debug, Clone)]
pub struct DiscoveredAsset {
    pub asset: Asset,
    pub source: String,
    pub confidence: f64,
}

impl DiscoveredAsset {
    pub fn new(asset: Asset, source: impl Into<String>, confidence: f64) -> Self {
        Self {
            asset,
            source: source.into(),
            confidence,
        }
    }
}

/// Edge between assets in the graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEdge {
    pub from: Id<AssetId>,
    pub to: Id<AssetId>,
    pub relationship: AssetRelationship,
}

/// Types of relationships between assets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssetRelationship {
    ResolvesTo,
    Hosts,
    Contains,
    ConnectsTo,
    Uses,
    PartOf,
}

impl std::fmt::Display for AssetRelationship {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResolvesTo => write!(f, "resolves_to"),
            Self::Hosts => write!(f, "hosts"),
            Self::Contains => write!(f, "contains"),
            Self::ConnectsTo => write!(f, "connects_to"),
            Self::Uses => write!(f, "uses"),
            Self::PartOf => write!(f, "part_of"),
        }
    }
}

/// A graph of discovered assets and their relationships.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssetGraph {
    pub assets: Vec<Asset>,
    pub edges: Vec<AssetEdge>,
}

impl AssetGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an asset to the graph.
    pub fn add_asset(&mut self, asset: Asset) {
        self.assets.push(asset);
    }

    /// Adds an edge between two assets.
    pub fn add_edge(
        &mut self,
        from: Id<AssetId>,
        to: Id<AssetId>,
        relationship: AssetRelationship,
    ) {
        self.edges.push(AssetEdge {
            from,
            to,
            relationship,
        });
    }

    /// Finds an asset by value.
    pub fn find_by_value(&self, value: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.value == value)
    }

    /// Finds all assets of a given type.
    pub fn find_by_type(&self, asset_type: &AssetType) -> Vec<&Asset> {
        self.assets
            .iter()
            .filter(|a| a.asset_type == *asset_type)
            .collect()
    }

    /// Gets all assets that resolve to a given IP.
    pub fn find_by_ip(&self, ip: &str) -> Vec<&Asset> {
        self.assets
            .iter()
            .filter(|a| a.asset_type == AssetType::IpAddress && a.value == ip)
            .collect()
    }

    /// Gets the children of an asset.
    pub fn children(&self, parent_id: &Id<AssetId>) -> Vec<&Asset> {
        self.assets
            .iter()
            .filter(|a| a.parent_id.as_ref() == Some(parent_id))
            .collect()
    }

    /// Returns the total number of assets.
    pub fn len(&self) -> usize {
        self.assets.len()
    }

    /// Returns true if the graph has no assets.
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    /// Merges another graph into this one.
    pub fn merge(&mut self, other: AssetGraph) {
        for asset in other.assets {
            if !self.assets.iter().any(|a| a.id == asset.id) {
                self.assets.push(asset);
            }
        }
        for edge in other.edges {
            if !self
                .edges
                .iter()
                .any(|e| e.from == edge.from && e.to == edge.to)
            {
                self.edges.push(edge);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_creation() {
        let asset = Asset::new(AssetType::Domain, "example.com".to_string());
        assert_eq!(asset.asset_type, AssetType::Domain);
        assert_eq!(asset.value, "example.com");
    }

    #[test]
    fn asset_with_parent() {
        let parent = Asset::new(AssetType::Domain, "example.com".to_string());
        let parent_id = parent.id.clone();
        let child = Asset::new(AssetType::Subdomain, "www.example.com".to_string())
            .with_parent(parent_id.clone());
        assert_eq!(child.parent_id, Some(parent_id));
    }

    #[test]
    fn asset_graph_operations() {
        let mut graph = AssetGraph::new();

        let domain = Asset::new(AssetType::Domain, "example.com".to_string());
        let ip = Asset::new(AssetType::IpAddress, "93.184.216.34".to_string());
        let www = Asset::new(AssetType::Subdomain, "www.example.com".to_string())
            .with_parent(domain.id.clone());

        let domain_id = domain.id.clone();
        let ip_id = ip.id.clone();
        let www_id = www.id.clone();

        graph.add_asset(domain);
        graph.add_asset(ip);
        graph.add_asset(www);

        graph.add_edge(domain_id.clone(), ip_id, AssetRelationship::ResolvesTo);
        graph.add_edge(domain_id.clone(), www_id, AssetRelationship::Contains);

        assert_eq!(graph.len(), 3);
        assert!(graph.find_by_value("example.com").is_some());
        assert!(graph.find_by_value("nonexistent.com").is_none());
        assert_eq!(graph.find_by_type(&AssetType::Subdomain).len(), 1);
        assert_eq!(graph.children(&domain_id).len(), 1);
    }

    #[test]
    fn asset_type_display() {
        assert_eq!(AssetType::Domain.to_string(), "domain");
        assert_eq!(AssetType::IpAddress.to_string(), "ip");
        assert_eq!(AssetType::Port.to_string(), "port");
    }
}
