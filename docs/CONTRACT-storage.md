# Contract: kpd-storage (local + cloud storage abstraction)

Single source of truth for the storage layer. Refer to `agent/PLAN.md` §4.4 and
`agent/adr/0003-cloud-storage-oauth-first.md` for context.

## File

`kpd/crates/kpd-storage/src/lib.rs` (submodules allowed, e.g. `src/local.rs`,
`src/webdav.rs`, `src/registry.rs`).

## Public API (implement exactly)

```rust
use std::path::PathBuf;

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
/// (WebDAV ETag, or `mtime_nanos-len` for local files).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub revision: Option<String>,
}

#[async_trait::async_trait]
pub trait Storage: Send + Sync {
    async fn read(&self) -> Result<Vec<u8>, StorageError>;
    /// Write bytes. If `expected_revision` is `Some`, fail with
    /// [`StorageError::Conflict`] unless it matches the current revision
    /// (optimistic concurrency). `None` means unconditional last-write-wins.
    async fn write(&self, data: &[u8], expected_revision: Option<&str>) -> Result<Meta, StorageError>;
    async fn exists(&self) -> Result<bool, StorageError>;
    async fn meta(&self) -> Result<Meta, StorageError>;
}

pub struct LocalStorage { /* private */ }
impl LocalStorage {
    pub fn new(path: impl Into<PathBuf>) -> Self;
}

pub struct WebDavStorage { /* private */ }
impl WebDavStorage {
    /// `url` is the full URL of the `.kdbx` file on the WebDAV server.
    pub fn new(
        url: impl Into<String>,
        username: Option<String>,
        password: Option<String>,
    ) -> Result<Self, StorageError>;
}

/// A backend descriptor used to construct a [`Storage`].
#[derive(Debug, Clone)]
pub enum BackendSpec {
    Local { path: PathBuf },
    WebDav { url: String, username: Option<String>, password: Option<String> },
}

/// Build a boxed backend from a spec.
pub fn from_spec(spec: BackendSpec) -> Result<Box<dyn Storage>, StorageError>;
```

## Semantics

- **LocalStorage**: `read`/`exists`/`meta` use `std::fs`. `meta().revision` is
  `Some(format!("{mtime_nanos}-{len}"))` from `fs::metadata`; missing file →
  `NotFound`. `write` must be **atomic**: write to a temp file in the same
  directory, then `fs::rename` over the target, so a crash never leaves a
  half-written database. Enforce `expected_revision` by comparing against the
  pre-write `meta()` revision.
- **WebDavStorage**: use `reqwest` (`rustls-tls`). `meta`/`read` issue a `GET`
  (or `HEAD`) and capture the `ETag` response header as the revision. `write`
  issues `PUT`; when `expected_revision` is `Some`, send an `If-Match` header and
  map HTTP **412** → `Conflict`, **404** → `NotFound`. Basic auth when
  `username`/`password` are set. Do not store the password in any `Debug`/log
  output.
- `write(_, None)` = unconditional overwrite (still returns the new `Meta`).

## Dependencies (verify versions on crates.io)

`async-trait`, `thiserror`, `reqwest` (features `rustls-tls`, no default `native-tls`),
`tokio` (for `#[tokio::test]`), `url`. No `clap`, no `serde`.

## Tests

- **LocalStorage** (in-crate, use `std::env::temp_dir` + a unique subdir, clean up
  after): round-trip write/read; revision changes after write; conflict on stale
  `expected_revision`; `NotFound` on missing file; atomic-write leaves a valid
  file (no temp remnants).
- **WebDavStorage** (no live server): factor out pure helpers so you can test
  header construction (`If-Match` present iff `expected_revision` is `Some`) and
  status→error mapping (412→Conflict, 404→NotFound). Add a `#[ignore]`d live
  integration test with env vars `WEBDAV_URL`/`WEBDAV_USER`/`WEBDAV_PASS`.

## Constraints

Edition 2021, no `unsafe`. Do NOT modify other crates, the workspace
`kpd/Cargo.toml`, the `kpd` binary, or `agent/` files. No Rust toolchain is
available in this environment — write compiling-ready code and verify `reqwest`
0.12 / `async-trait` / `tokio` APIs on docs.rs if unsure.
