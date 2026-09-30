use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, info};

use crate::asset::{Asset, AssetGraph, AssetRelationship, AssetType};
use crate::dns::DnsResolver;
use crate::port::{PortInfo, PortScanner, PortState};
use crate::NetworkResult;

/// Network information about a discovered target.
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub domain: String,
    pub ip_addresses: Vec<IpAddr>,
    pub open_ports: Vec<PortInfo>,
    pub services: Vec<String>,
    pub subdomains: Vec<String>,
    pub discovery_duration_ms: u64,
}

/// Configuration for network discovery.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub dns_servers: Vec<String>,
    pub timeout_ms: u64,
    pub max_concurrent: usize,
    pub max_depth: u32,
    pub scan_common_ports: bool,
    pub discover_subdomains: bool,
    pub subdomain_list: Vec<String>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            dns_servers: Vec::new(),
            timeout_ms: 5000,
            max_concurrent: 10,
            max_depth: 2,
            scan_common_ports: true,
            discover_subdomains: true,
            subdomain_list: common_subdomains(),
        }
    }
}

/// Network discovery engine for asset enumeration.
pub struct NetworkEngine {
    dns_resolver: DnsResolver,
    port_scanner: PortScanner,
    config: DiscoveryConfig,
}

impl NetworkEngine {
    pub fn new() -> Self {
        Self {
            dns_resolver: DnsResolver::new(),
            port_scanner: PortScanner::new(),
            config: DiscoveryConfig::default(),
        }
    }

    pub fn with_config(config: DiscoveryConfig) -> Self {
        Self {
            dns_resolver: DnsResolver::with_config(config.dns_servers.clone(), config.timeout_ms),
            port_scanner: PortScanner::with_config(config.timeout_ms, 100),
            config,
        }
    }

    pub fn with_discovery_params(dns_servers: Vec<String>, timeout_ms: u64) -> Self {
        Self::with_config(DiscoveryConfig {
            dns_servers,
            timeout_ms,
            ..Default::default()
        })
    }

    pub async fn discover(&self, domain: &str) -> NetworkResult<AssetGraph> {
        info!(domain = %domain, "Starting network discovery");
        let start = Instant::now();
        let mut graph = AssetGraph::new();

        let domain_asset = Asset::new(AssetType::Domain, domain.to_string());
        let domain_id = domain_asset.id.clone();
        graph.add_asset(domain_asset);

        // Phase 1: DNS resolution
        debug!(domain = %domain, "Resolving domain");
        let ips = self.dns_resolver.resolve(domain).await?;

        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent));

        // Phase 2: Port scanning (concurrent)
        if self.config.scan_common_ports {
            let mut port_tasks = Vec::new();

            for ip in &ips {
                let ip_asset =
                    Asset::new(AssetType::IpAddress, ip.to_string()).with_parent(domain_id.clone());
                let ip_asset_id = ip_asset.id.clone();
                graph.add_asset(ip_asset);
                graph.add_edge(
                    domain_id.clone(),
                    ip_asset_id.clone(),
                    AssetRelationship::ResolvesTo,
                );

                let port_scanner = self.port_scanner.clone();
                let ip = *ip;
                let sem = semaphore.clone();

                port_tasks.push(async move {
                    let _permit = sem.acquire().await.unwrap();
                    let ports = port_scanner.scan_common_ports(ip).await;
                    (ip_asset_id, ports)
                });
            }

            let results = futures::future::join_all(port_tasks).await;

            for (ip_asset_id, ports) in results {
                for port_info in &ports {
                    if port_info.state == PortState::Open {
                        let port_value = format!("{}:{}", ip_asset_id, port_info.port);
                        let mut port_asset = Asset::new(AssetType::Port, port_value)
                            .with_parent(ip_asset_id.clone());

                        if let Some(service) = &port_info.service {
                            port_asset =
                                port_asset.with_metadata("service", serde_json::json!(service));
                        }

                        let port_id = port_asset.id.clone();
                        graph.add_edge(ip_asset_id.clone(), port_id, AssetRelationship::Hosts);
                        graph.add_asset(port_asset);
                    }
                }
            }
        } else {
            // Just add IP assets without port scanning
            for ip in &ips {
                let ip_asset =
                    Asset::new(AssetType::IpAddress, ip.to_string()).with_parent(domain_id.clone());
                let ip_asset_id = ip_asset.id.clone();
                graph.add_asset(ip_asset);
                graph.add_edge(
                    domain_id.clone(),
                    ip_asset_id,
                    AssetRelationship::ResolvesTo,
                );
            }
        }

        // Phase 3: Subdomain discovery
        if self.config.discover_subdomains {
            debug!(domain = %domain, "Discovering subdomains");
            let subdomains = self.discover_subdomains(domain).await?;
            for subdomain in subdomains {
                let sub_asset =
                    Asset::new(AssetType::Subdomain, subdomain).with_parent(domain_id.clone());
                let sub_id = sub_asset.id.clone();
                graph.add_asset(sub_asset);
                graph.add_edge(domain_id.clone(), sub_id, AssetRelationship::Contains);
            }
        }

        let duration = start.elapsed().as_millis() as u64;
        info!(
            domain = %domain,
            assets = graph.len(),
            duration_ms = duration,
            "Discovery completed"
        );

        Ok(graph)
    }

    /// Discovers subdomains by trying common prefixes.
    async fn discover_subdomains(&self, domain: &str) -> NetworkResult<Vec<String>> {
        let mut subdomains = Vec::new();
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent));

        let mut tasks = Vec::new();

        for prefix in &self.config.subdomain_list {
            let subdomain = format!("{}.{}", prefix, domain);
            let dns_resolver = self.dns_resolver.clone();
            let sem = semaphore.clone();
            let subdomain = subdomain.clone();

            tasks.push(async move {
                let _permit = sem.acquire().await.unwrap();
                match tokio::time::timeout(
                    Duration::from_millis(self.config.timeout_ms),
                    dns_resolver.resolve(&subdomain),
                )
                .await
                {
                    Ok(Ok(ips)) if !ips.is_empty() => Some(subdomain),
                    _ => None,
                }
            });
        }

        let results = futures::future::join_all(tasks).await;

        subdomains.extend(results.into_iter().flatten());

        Ok(subdomains)
    }
}

impl Default for NetworkEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns a list of common subdomain prefixes.
fn common_subdomains() -> Vec<String> {
    vec![
        "www",
        "mail",
        "ftp",
        "smtp",
        "pop",
        "imap",
        "dns",
        "ns1",
        "ns2",
        "webmail",
        "vpn",
        "admin",
        "api",
        "dev",
        "staging",
        "test",
        "beta",
        "alpha",
        "demo",
        "portal",
        "app",
        "cdn",
        "static",
        "media",
        "img",
        "images",
        "assets",
        "files",
        "download",
        "blog",
        "forum",
        "support",
        "help",
        "docs",
        "wiki",
        "shop",
        "store",
        "pay",
        "checkout",
        "billing",
        "login",
        "auth",
        "sso",
        "id",
        "db",
        "database",
        "mysql",
        "postgres",
        "redis",
        "mongo",
        "git",
        "gitlab",
        "jenkins",
        "ci",
        "cd",
        "monitor",
        "grafana",
        "kibana",
        "prometheus",
        "search",
        "elastic",
        "solr",
        "mq",
        "rabbitmq",
        "kafka",
        "nats",
        "proxy",
        "haproxy",
        "nginx",
        "apache",
        "docker",
        "k8s",
        "kubernetes",
        "rancher",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_engine_creation() {
        let _engine = NetworkEngine::new();
    }

    #[test]
    fn discovery_config_defaults() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.max_concurrent, 10);
        assert_eq!(config.max_depth, 2);
        assert!(config.scan_common_ports);
        assert!(config.discover_subdomains);
    }

    #[test]
    fn common_subdomains_list() {
        let subs = common_subdomains();
        assert!(subs.contains(&"www".to_string()));
        assert!(subs.contains(&"api".to_string()));
        assert!(subs.contains(&"admin".to_string()));
        assert!(subs.len() > 50);
    }

    #[test]
    fn network_engine_with_config() {
        let config = DiscoveryConfig {
            max_concurrent: 5,
            timeout_ms: 3000,
            ..Default::default()
        };
        let engine = NetworkEngine::with_config(config);
        assert_eq!(engine.config.max_concurrent, 5);
        assert_eq!(engine.config.timeout_ms, 3000);
    }
}
