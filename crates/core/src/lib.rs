pub mod audit;
pub mod error;
pub mod governance;
pub mod id;
pub mod metadata;
pub mod recovery;
pub mod secrets;
pub mod security;
pub mod ssrf;
pub mod timestamp;

pub use error::{ErrorKind, SpectraError};
pub use id::Id;
pub use metadata::Metadata;
pub use ssrf::SSRFGuard;
pub use timestamp::Timestamp;

pub type Result<T> = std::result::Result<T, SpectraError>;
