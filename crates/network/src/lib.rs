pub mod asset;
pub mod dns;
pub mod engine;
pub mod port;

pub use asset::{Asset, AssetGraph, AssetType, DiscoveredAsset};
pub use dns::{DnsRecord, DnsRecordType, DnsResolver};
pub use engine::{NetworkEngine, NetworkInfo};
pub use port::{PortInfo, PortScanner, PortState};

use spectra_core::SpectraError;
use thiserror::Error;

/// Errors specific to network operations.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("Connection refused: {0}")]
    ConnectionRefused(String),

    #[error("Timeout after {0}ms")]
    Timeout(u64),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Network unreachable: {0}")]
    Unreachable(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("IO error: {0}")]
    Io(String),
}

impl From<NetworkError> for SpectraError {
    fn from(e: NetworkError) -> Self {
        match &e {
            NetworkError::DnsResolution(_) => Self::Network(e.to_string()),
            NetworkError::ConnectionRefused(_) => Self::Network(e.to_string()),
            NetworkError::Timeout(_) => Self::Timeout(e.to_string()),
            NetworkError::Tls(_) => Self::Network(e.to_string()),
            NetworkError::Unreachable(_) => Self::Network(e.to_string()),
            NetworkError::InvalidInput(_) => Self::Validation(e.to_string()),
            NetworkError::Io(_) => Self::Io(e.to_string()),
        }
    }
}

/// Result type for network operations.
pub type NetworkResult<T> = Result<T, NetworkError>;
