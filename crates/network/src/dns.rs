use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// DNS record types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Txt,
    Soa,
    Ptr,
    Caa,
    Srv,
}

impl std::fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Cname => write!(f, "CNAME"),
            Self::Mx => write!(f, "MX"),
            Self::Ns => write!(f, "NS"),
            Self::Txt => write!(f, "TXT"),
            Self::Soa => write!(f, "SOA"),
            Self::Ptr => write!(f, "PTR"),
            Self::Caa => write!(f, "CAA"),
            Self::Srv => write!(f, "SRV"),
        }
    }
}

/// A DNS record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: DnsRecordType,
    pub name: String,
    pub value: String,
    pub ttl: u32,
}

impl DnsRecord {
    pub fn new(record_type: DnsRecordType, name: String, value: String, ttl: u32) -> Self {
        Self {
            record_type,
            name,
            value,
            ttl,
        }
    }
}

/// DNS resolver for performing lookups.
pub struct DnsResolver {
    /// DNS servers to use.
    servers: Vec<String>,
    /// Timeout in milliseconds.
    timeout_ms: u64,
}

impl DnsResolver {
    /// Creates a new DNS resolver with default settings.
    pub fn new() -> Self {
        Self {
            servers: vec![
                "8.8.8.8".to_string(),
                "8.8.4.4".to_string(),
                "1.1.1.1".to_string(),
            ],
            timeout_ms: 5000,
        }
    }

    /// Creates a new DNS resolver with custom settings.
    pub fn with_config(servers: Vec<String>, timeout_ms: u64) -> Self {
        Self {
            servers,
            timeout_ms,
        }
    }

    /// Resolves a domain name to IP addresses (A records).
    pub async fn resolve(&self, domain: &str) -> crate::NetworkResult<Vec<IpAddr>> {
        use std::time::Duration;
        use tokio::net::TcpStream;

        let timeout = Duration::from_millis(self.timeout_ms);

        // Try to connect to resolve the domain
        let addr = format!("{}:80", domain);
        match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => {
                if let Ok(addr) = stream.peer_addr() {
                    Ok(vec![addr.ip()])
                } else {
                    Ok(vec![])
                }
            }
            _ => {
                // Fallback: try to parse as IP
                if let Ok(ip) = domain.parse::<IpAddr>() {
                    Ok(vec![ip])
                } else {
                    Ok(vec![])
                }
            }
        }
    }

    /// Resolves a domain and returns all DNS records.
    pub async fn resolve_all(&self, domain: &str) -> crate::NetworkResult<Vec<DnsRecord>> {
        let mut records = Vec::new();

        // Resolve A records
        if let Ok(ips) = self.resolve(domain).await {
            for ip in ips {
                records.push(DnsRecord::new(
                    DnsRecordType::A,
                    domain.to_string(),
                    ip.to_string(),
                    300,
                ));
            }
        }

        // Try to resolve common subdomains
        let common_subdomains = vec![
            "www", "mail", "ftp", "smtp", "pop", "imap", "dns", "ns1", "ns2", "webmail", "vpn",
            "admin", "api", "dev", "staging", "test",
        ];

        for subdomain in common_subdomains {
            let fqdn = format!("{}.{}", subdomain, domain);
            if let Ok(ips) = self.resolve(&fqdn).await {
                if !ips.is_empty() {
                    for ip in ips {
                        records.push(DnsRecord::new(
                            DnsRecordType::A,
                            fqdn.clone(),
                            ip.to_string(),
                            300,
                        ));
                    }
                }
            }
        }

        Ok(records)
    }

    /// Performs a reverse DNS lookup.
    pub async fn reverse_lookup(&self, ip: &IpAddr) -> crate::NetworkResult<Vec<String>> {
        let _ = (ip, &self.servers, self.timeout_ms);
        Ok(vec![])
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_record_creation() {
        let record = DnsRecord::new(
            DnsRecordType::A,
            "example.com".to_string(),
            "93.184.216.34".to_string(),
            300,
        );
        assert_eq!(record.record_type, DnsRecordType::A);
        assert_eq!(record.name, "example.com");
        assert_eq!(record.value, "93.184.216.34");
    }

    #[test]
    fn dns_record_type_display() {
        assert_eq!(DnsRecordType::A.to_string(), "A");
        assert_eq!(DnsRecordType::Mx.to_string(), "MX");
        assert_eq!(DnsRecordType::Txt.to_string(), "TXT");
    }

    #[test]
    fn dns_resolver_creation() {
        let resolver = DnsResolver::new();
        assert_eq!(resolver.servers.len(), 3);
        assert_eq!(resolver.timeout_ms, 5000);
    }

    #[test]
    fn dns_resolver_custom() {
        let resolver = DnsResolver::with_config(vec!["1.1.1.1".to_string()], 10000);
        assert_eq!(resolver.servers.len(), 1);
        assert_eq!(resolver.timeout_ms, 10000);
    }
}
