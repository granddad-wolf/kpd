//! Storage abstraction for `kpd`: a single [`Storage`] trait plus local-filesystem,
//! WebDAV, and Dropbox backends.
//!
//! Backends move opaque bytes between a caller and a backing store and expose a
//! revision token for optimistic concurrency. Crypto never lives in this layer
//! (see `agent/adr/0003-cloud-storage-oauth-first.md`).

mod local;
mod registry;
mod webdav;

pub mod dropbox;

pub use dropbox::DropboxStorage;
pub use local::LocalStorage;
pub use registry::{from_spec, BackendSpec};
pub use webdav::WebDavStorage;

/// Errors surfaced by any [`Storage`] backend.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("not found: {0}")]
    NotFound(String),
    /// Optimistic-concurrency mismatch (the remote changed under us).
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("invalid configuration: {0}")]
    Config(String),
}

/// Metadata for optimistic concurrency. `revision` is an opaque token
/// (WebDAV ETag, Dropbox `rev`, or a SHA-256 content digest for local files).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub revision: Option<String>,
}

/// A byte-addressable backing store for a single database.
///
/// Backends are `Send + Sync` so a boxed backend can be shared across async
/// tasks. Optimistic concurrency is expressed via [`Meta::revision`]: read the
/// current revision, mutate, and pass it back as `expected_revision`.
#[async_trait::async_trait]
pub trait Storage: Send + Sync {
    /// Read the full contents of the stored database.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotFound`] when nothing is stored yet.
    async fn read(&self) -> Result<Vec<u8>, StorageError>;

    /// Write bytes to the store.
    ///
    /// If `expected_revision` is `Some`, fail with [`StorageError::Conflict`]
    /// unless it matches the current revision (optimistic concurrency). `None`
    /// means unconditional last-write-wins.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Conflict`] when `expected_revision` is `Some` and
    /// does not match the current revision.
    async fn write(&self, data: &[u8], expected_revision: Option<&str>) -> Result<Meta, StorageError>;

    /// Whether the stored database currently exists.
    async fn exists(&self) -> Result<bool, StorageError>;

    /// Return the current revision metadata.
    ///
    /// The token is opaque to callers. Backends may derive it from the stored
    /// bytes (the local backend hashes them), so this can read the file.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotFound`] when nothing is stored yet.
    async fn meta(&self) -> Result<Meta, StorageError>;
}
