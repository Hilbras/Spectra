use std::net::IpAddr;
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
}

/// Network discovery engine for asset enumeration.
pub struct NetworkEngine {
    dns_resolver: DnsResolver,
    port_scanner: PortScanner,
}

impl NetworkEngine {
    pub fn new() -> Self {
        Self {
            dns_resolver: DnsResolver::new(),
            port_scanner: PortScanner::new(),
        }
    }

    pub fn with_config(dns_servers: Vec<String>, timeout_ms: u64) -> Self {
        Self {
            dns_resolver: DnsResolver::with_config(dns_servers, timeout_ms),
            port_scanner: PortScanner::with_config(timeout_ms, 100),
        }
    }

    pub async fn discover(&self, domain: &str) -> NetworkResult<AssetGraph> {
        info!(domain = %domain, "Starting network discovery");
        let mut graph = AssetGraph::new();

        let domain_asset = Asset::new(AssetType::Domain, domain.to_string());
        let domain_id = domain_asset.id.clone();
        graph.add_asset(domain_asset);

        debug!(domain = %domain, "Resolving domain");
        let ips = self.dns_resolver.resolve(domain).await?;

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

            debug!(ip = %ip, "Scanning ports");
            let ports = self.port_scanner.scan_common_ports(*ip).await;
            let mut port_assets = Vec::new();

            for port_info in &ports {
                if port_info.state == PortState::Open {
                    let port_value = format!("{}:{}", ip, port_info.port);
                    let mut port_asset =
                        Asset::new(AssetType::Port, port_value).with_parent(ip_asset_id.clone());

                    if let Some(service) = &port_info.service {
                        port_asset =
                            port_asset.with_metadata("service", serde_json::json!(service));
                    }

                    let port_id = port_asset.id.clone();
                    graph.add_edge(ip_asset_id.clone(), port_id, AssetRelationship::Hosts);
                    port_assets.push(port_asset);
                }
            }

            for port_asset in &port_assets {
                graph.add_asset(port_asset.clone());
            }
        }

        debug!(domain = %domain, "Discovering subdomains");
        let subdomains = self.discover_subdomains(domain).await?;
        for subdomain in subdomains {
            let sub_asset =
                Asset::new(AssetType::Subdomain, subdomain).with_parent(domain_id.clone());
            let sub_id = sub_asset.id.clone();
            graph.add_asset(sub_asset);
            graph.add_edge(domain_id.clone(), sub_id, AssetRelationship::Contains);
        }

        info!(
            domain = %domain,
            assets = graph.len(),
            "Discovery completed"
        );

        Ok(graph)
    }

    async fn discover_subdomains(&self, domain: &str) -> NetworkResult<Vec<String>> {
        let mut subdomains = Vec::new();

        let prefixes = vec![
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
        ];

        for prefix in prefixes {
            let subdomain = format!("{}.{}", prefix, domain);
            if let Ok(ips) = self.dns_resolver.resolve(&subdomain).await {
                if !ips.is_empty() {
                    subdomains.push(subdomain);
                }
            }
        }

        Ok(subdomains)
    }
}

impl Default for NetworkEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_engine_creation() {
        let _engine = NetworkEngine::new();
    }
}
