use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Information about an open port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: PortProtocol,
    pub state: PortState,
    pub service: Option<String>,
    pub banner: Option<String>,
}

impl PortInfo {
    pub fn new(port: u16, state: PortState) -> Self {
        Self {
            port,
            protocol: PortProtocol::Tcp,
            state,
            service: None,
            banner: None,
        }
    }

    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    pub fn with_banner(mut self, banner: impl Into<String>) -> Self {
        self.banner = Some(banner.into());
        self
    }

    pub fn with_protocol(mut self, protocol: PortProtocol) -> Self {
        self.protocol = protocol;
        self
    }
}

/// Port protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortProtocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for PortProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

/// State of a port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Timeout,
    Unknown,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
            Self::Filtered => write!(f, "filtered"),
            Self::Timeout => write!(f, "timeout"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Common port-to-service mappings.
pub fn common_port_service(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("FTP Data"),
        21 => Some("FTP Control"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        111 => Some("RPCBind"),
        135 => Some("MSRPC"),
        139 => Some("NetBIOS"),
        143 => Some("IMAP"),
        443 => Some("HTTPS"),
        445 => Some("SMB"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1433 => Some("MSSQL"),
        1521 => Some("Oracle"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        5432 => Some("PostgreSQL"),
        5900 => Some("VNC"),
        6379 => Some("Redis"),
        8080 => Some("HTTP-Alt"),
        8443 => Some("HTTPS-Alt"),
        9200 => Some("Elasticsearch"),
        27017 => Some("MongoDB"),
        _ => None,
    }
}

/// Port scanner for discovering open ports.
pub struct PortScanner {
    /// Timeout for port connections in milliseconds.
    timeout_ms: u64,
    /// Maximum concurrent scans.
    max_concurrent: usize,
}

impl PortScanner {
    /// Creates a new port scanner.
    pub fn new() -> Self {
        Self {
            timeout_ms: 2000,
            max_concurrent: 100,
        }
    }

    /// Creates a port scanner with custom settings.
    pub fn with_config(timeout_ms: u64, max_concurrent: usize) -> Self {
        Self {
            timeout_ms,
            max_concurrent,
        }
    }

    /// Scans a single port.
    pub async fn scan_port(&self, ip: IpAddr, port: u16) -> PortInfo {
        use std::time::Duration;
        use tokio::net::TcpStream;

        let addr = format!("{}:{}", ip, port);
        let timeout = Duration::from_millis(self.timeout_ms);

        let state = match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => {
                // Connection successful - port is open
                PortState::Open
            }
            Ok(Err(_)) => {
                // Connection refused - port is closed
                PortState::Closed
            }
            Err(_) => {
                // Timeout
                PortState::Timeout
            }
        };

        let mut info = PortInfo::new(port, state);
        if let Some(service) = common_port_service(port) {
            info = info.with_service(service);
        }

        info
    }

    /// Scans a range of ports on an IP address.
    pub async fn scan_ports(&self, ip: IpAddr, start: u16, end: u16) -> Vec<PortInfo> {
        let mut results = Vec::new();
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.max_concurrent));
        let mut handles = Vec::new();

        for port in start..=end {
            let sem = semaphore.clone();
            let scanner = PortScanner {
                timeout_ms: self.timeout_ms,
                max_concurrent: 1,
            };

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                scanner.scan_port(ip, port).await
            }));
        }

        for handle in handles {
            if let Ok(info) = handle.await {
                results.push(info);
            }
        }

        // Sort by port number
        results.sort_by_key(|p| p.port);
        results
    }

    /// Scans common ports on an IP address.
    pub async fn scan_common_ports(&self, ip: IpAddr) -> Vec<PortInfo> {
        let common_ports: Vec<u16> = vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306,
            3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
        ];

        let mut results = Vec::new();
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.max_concurrent));
        let mut handles = Vec::new();

        for port in common_ports {
            let sem = semaphore.clone();
            let scanner = PortScanner {
                timeout_ms: self.timeout_ms,
                max_concurrent: 1,
            };

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                scanner.scan_port(ip, port).await
            }));
        }

        for handle in handles {
            if let Ok(info) = handle.await {
                results.push(info);
            }
        }

        // Sort by port number
        results.sort_by_key(|p| p.port);
        results
    }
}

impl Default for PortScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_info_creation() {
        let info = PortInfo::new(80, PortState::Open);
        assert_eq!(info.port, 80);
        assert_eq!(info.state, PortState::Open);
        assert_eq!(info.protocol, PortProtocol::Tcp);
    }

    #[test]
    fn port_info_with_service() {
        let info = PortInfo::new(80, PortState::Open).with_service("HTTP");
        assert_eq!(info.service, Some("HTTP".to_string()));
    }

    #[test]
    fn common_port_service_lookup() {
        assert_eq!(common_port_service(80), Some("HTTP"));
        assert_eq!(common_port_service(443), Some("HTTPS"));
        assert_eq!(common_port_service(22), Some("SSH"));
        assert_eq!(common_port_service(9999), None);
    }

    #[test]
    fn port_scanner_creation() {
        let scanner = PortScanner::new();
        assert_eq!(scanner.timeout_ms, 2000);
        assert_eq!(scanner.max_concurrent, 100);
    }

    #[test]
    fn port_state_display() {
        assert_eq!(PortState::Open.to_string(), "open");
        assert_eq!(PortState::Closed.to_string(), "closed");
        assert_eq!(PortState::Filtered.to_string(), "filtered");
    }
}
