pub mod error;
pub mod id;
pub mod metadata;
pub mod security;
pub mod timestamp;

pub use error::{ErrorKind, SpectraError};
pub use id::Id;
pub use metadata::Metadata;
pub use timestamp::Timestamp;

pub type Result<T> = std::result::Result<T, SpectraError>;
