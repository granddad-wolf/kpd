//! Dropbox backend, implemented over the Dropbox HTTP API (`/2/files/*`).
//!
//! `read`/`write` use the content endpoints on `content.dropboxapi.com`;
//! `exists`/`meta` use the RPC `get_metadata` endpoint on
//! `api.dropboxapi.com`. Every request carries an `Authorization: Bearer …`
//! header and a `Dropbox-API-Arg` JSON header. The access token is kept out of
//! all `Debug`/log output (this type has a manual redacted `Debug`).

use reqwest::header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};

use crate::{Meta, Storage, StorageError};

pub mod oauth;

const CONTENT_BASE: &str = "https://content.dropboxapi.com/2/files";
const RPC_BASE: &str = "https://api.dropboxapi.com/2/files";
const DROPBOX_API_ARG: HeaderName = HeaderName::from_static("dropbox-api-arg");
const OCTET_STREAM: HeaderValue = HeaderValue::from_static("application/octet-stream");

/// A database stored in Dropbox.
pub struct DropboxStorage {
    client: Client,
    access_token: String,
    remote_path: String,
}

impl DropboxStorage {
    /// Create a Dropbox backend.
    ///
    /// `access_token` is a Dropbox OAuth2 access token; `remote_path` is the
    /// full Dropbox path of the `.kdbx` file, e.g. `/vault/keepass.kdbx`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Config`] when the token is empty, the path is not
    /// an absolute, ASCII Dropbox path, or the HTTP client cannot be built.
    pub fn new(
        access_token: impl Into<String>,
        remote_path: impl Into<String>,
    ) -> Result<Self, StorageError> {
        let access_token = access_token.into();
        let remote_path = remote_path.into();

        if access_token.is_empty() {
            return Err(StorageError::Config(
                "Dropbox access token must not be empty".to_string(),
            ));
        }
        if !remote_path.starts_with('/') {
            return Err(StorageError::Config(format!(
                "Dropbox path must be absolute (start with '/'), got {remote_path:?}"
            )));
        }
        if !remote_path.is_ascii() {
            return Err(StorageError::Config(
                "Dropbox path must be ASCII so it is safe for the Dropbox-API-Arg HTTP header"
                    .to_string(),
            ));
        }

        let client = Client::builder()
            .build()
            .map_err(|e| StorageError::Config(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            client,
            access_token,
            remote_path,
        })
    }

    /// Build a POST request with `Authorization: Bearer …` applied.
    fn request(&self, url: &str) -> RequestBuilder {
        self.client
            .post(url)
            .header(AUTHORIZATION, authorization_value(&self.access_token))
    }
}

// `Debug` is implemented manually (instead of `#[derive(Debug)]`) so the access
// token is redacted and can never leak into logs or diagnostics.
impl std::fmt::Debug for DropboxStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DropboxStorage")
            .field("access_token", &"[redacted]")
            .field("remote_path", &self.remote_path)
            .finish()
    }
}

#[async_trait::async_trait]
impl Storage for DropboxStorage {
    async fn read(&self) -> Result<Vec<u8>, StorageError> {
        let request = self
            .request(&format!("{CONTENT_BASE}/download"))
            .header(DROPBOX_API_ARG, download_arg(&self.remote_path));
        let response = execute(request).await?;
        Ok(response.bytes().await.map_err(http_error)?.to_vec())
    }

    async fn write(
        &self,
        data: &[u8],
        expected_revision: Option<&str>,
    ) -> Result<Meta, StorageError> {
        let request = self
            .request(&format!("{CONTENT_BASE}/upload"))
            .header(CONTENT_TYPE, OCTET_STREAM)
            .header(
                DROPBOX_API_ARG,
                upload_arg(&self.remote_path, expected_revision),
            )
            .body(data.to_vec());
        let response = execute(request).await?;
        let body = response.bytes().await.map_err(http_error)?;
        let metadata: FileMetadata = serde_json::from_slice(&body)
            .map_err(|e| StorageError::Http(format!("invalid Dropbox upload response: {e}")))?;
        Ok(Meta {
            revision: metadata.rev,
        })
    }

    async fn exists(&self) -> Result<bool, StorageError> {
        let request = self
            .request(&format!("{RPC_BASE}/get_metadata"))
            .header(DROPBOX_API_ARG, metadata_arg(&self.remote_path));
        let response = request.send().await.map_err(http_error)?;
        if response.status().is_success() {
            return Ok(true);
        }
        let status = response.status();
        let body = response.bytes().await.map_err(http_error)?;
        if status == StatusCode::CONFLICT && is_dropbox_not_found(&body) {
            return Ok(false);
        }
        Err(classify_error(status, &body))
    }

    async fn meta(&self) -> Result<Meta, StorageError> {
        let request = self
            .request(&format!("{RPC_BASE}/get_metadata"))
            .header(DROPBOX_API_ARG, metadata_arg(&self.remote_path));
        let response = execute(request).await?;
        let body = response.bytes().await.map_err(http_error)?;
        let metadata: FileMetadata = serde_json::from_slice(&body)
            .map_err(|e| StorageError::Http(format!("invalid Dropbox metadata response: {e}")))?;
        Ok(Meta {
            revision: metadata.rev,
        })
    }
}

/// `{"path":"…"}` argument for `download` and `get_metadata`.
#[derive(Serialize)]
struct PathArg<'a> {
    path: &'a str,
}

/// The Dropbox `WriteMode` union: `overwrite` vs `update(rev)`.
#[derive(Serialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum WriteMode<'a> {
    Overwrite,
    Update { update: &'a str },
}

/// `{"path":"…","mode":…}` argument for `upload`.
#[derive(Serialize)]
struct UploadArg<'a> {
    path: &'a str,
    mode: WriteMode<'a>,
}

/// The `rev` field of a Dropbox `FileMetadata` result.
#[derive(Deserialize)]
struct FileMetadata {
    rev: Option<String>,
}

/// The `Dropbox-API-Arg` JSON for `download`.
fn download_arg(path: &str) -> String {
    serde_json::to_string(&PathArg { path }).expect("serializing a Dropbox path cannot fail")
}

/// The `Dropbox-API-Arg` JSON for `get_metadata`.
fn metadata_arg(path: &str) -> String {
    serde_json::to_string(&PathArg { path }).expect("serializing a Dropbox path cannot fail")
}

/// The `Dropbox-API-Arg` JSON for `upload`: overwrite when `expected_revision`
/// is `None`, `update(rev)` (optimistic concurrency) when `Some`.
fn upload_arg(path: &str, expected_revision: Option<&str>) -> String {
    let mode = match expected_revision {
        None => WriteMode::Overwrite,
        Some(rev) => WriteMode::Update { update: rev },
    };
    serde_json::to_string(&UploadArg { path, mode }).expect("serializing an upload arg cannot fail")
}

/// The `Authorization` header value for a bearer token.
fn authorization_value(token: &str) -> String {
    format!("Bearer {token}")
}

/// The Dropbox error kinds this backend distinguishes.
enum DropboxErrorKind {
    NotFound,
    Conflict,
}

/// Inspect a Dropbox error response body and classify the failure.
fn classify_dropbox_body(body: &[u8]) -> Option<DropboxErrorKind> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let error = value.get("error")?;
    if error.get(".tag").and_then(serde_json::Value::as_str) != Some("path") {
        return None;
    }
    let path = error.get("path")?;

    // `LookupError` (get_metadata/download): `path` is itself a tagged union.
    if path.get(".tag").and_then(serde_json::Value::as_str) == Some("not_found") {
        return Some(DropboxErrorKind::NotFound);
    }

    // `UploadWriteFailed` (upload): `path.reason` is a `WriteError` union.
    if path
        .get("reason")
        .and_then(|r| r.get(".tag"))
        .and_then(serde_json::Value::as_str)
        == Some("conflict")
    {
        return Some(DropboxErrorKind::Conflict);
    }

    None
}

/// Whether a `get_metadata` error body means `path/not_found`.
fn is_dropbox_not_found(body: &[u8]) -> bool {
    matches!(
        classify_dropbox_body(body),
        Some(DropboxErrorKind::NotFound)
    )
}

/// Map a non-success Dropbox response onto a typed [`StorageError`].
fn classify_error(status: StatusCode, body: &[u8]) -> StorageError {
    if status == StatusCode::CONFLICT {
        match classify_dropbox_body(body) {
            Some(DropboxErrorKind::Conflict) => {
                StorageError::Conflict("Dropbox revision conflict".to_string())
            }
            _ => StorageError::NotFound("Dropbox path not found (HTTP 409)".to_string()),
        }
    } else {
        http_status_error(status)
    }
}

/// Send a request and ensure a 2xx response, reading the body to classify errors.
async fn execute(request: RequestBuilder) -> Result<Response, StorageError> {
    let response = request.send().await.map_err(http_error)?;
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.bytes().await.map_err(http_error)?;
    Err(classify_error(status, &body))
}

fn http_error(e: reqwest::Error) -> StorageError {
    StorageError::Http(e.to_string())
}

fn http_status_error(status: StatusCode) -> StorageError {
    let reason = status.canonical_reason().unwrap_or("unknown");
    StorageError::Http(format!("HTTP {status} {reason}"))
}

#[cfg(test)]
mod tests {
    use super::{
        authorization_value, classify_error, download_arg, is_dropbox_not_found, metadata_arg,
        upload_arg, DropboxStorage,
    };
    use crate::{Storage, StorageError};
    use reqwest::StatusCode;

    #[test]
    fn download_arg_shape() {
        assert_eq!(
            download_arg("/vault/keepass.kdbx"),
            r#"{"path":"/vault/keepass.kdbx"}"#
        );
    }

    #[test]
    fn metadata_arg_shape() {
        assert_eq!(
            metadata_arg("/vault/keepass.kdbx"),
            r#"{"path":"/vault/keepass.kdbx"}"#
        );
    }

    #[test]
    fn upload_arg_overwrite_shape() {
        assert_eq!(
            upload_arg("/vault/keepass.kdbx", None),
            r#"{"path":"/vault/keepass.kdbx","mode":{".tag":"overwrite"}}"#
        );
    }

    #[test]
    fn upload_arg_update_shape() {
        assert_eq!(
            upload_arg("/vault/keepass.kdbx", Some("0159b15ccf0000018f46")),
            r#"{"path":"/vault/keepass.kdbx","mode":{".tag":"update","update":"0159b15ccf0000018f46"}}"#
        );
    }

    #[test]
    fn authorization_header_is_bearer() {
        assert_eq!(authorization_value("secret-token"), "Bearer secret-token");
    }

    #[test]
    fn classifies_rev_conflict_as_conflict() {
        let body = br#"{"error":{".tag":"path","path":{"reason":{".tag":"conflict","conflict":{".tag":"file"}}}}}"#;
        let err = classify_error(StatusCode::CONFLICT, body);
        assert!(matches!(err, StorageError::Conflict(_)));
    }

    #[test]
    fn classifies_not_found_409_as_not_found() {
        let body = br#"{"error":{".tag":"path","path":{".tag":"not_found"}}}"#;
        let err = classify_error(StatusCode::CONFLICT, body);
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[test]
    fn classifies_unparseable_409_as_not_found() {
        let err = classify_error(StatusCode::CONFLICT, b"not json");
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[test]
    fn classifies_other_status_as_http() {
        let err = classify_error(StatusCode::INTERNAL_SERVER_ERROR, b"");
        assert!(matches!(err, StorageError::Http(_)));
    }

    #[test]
    fn detects_not_found_error_body() {
        assert!(is_dropbox_not_found(
            br#"{"error":{".tag":"path","path":{".tag":"not_found"}}}"#
        ));
        assert!(!is_dropbox_not_found(
            br#"{"error":{".tag":"path","path":{"reason":{".tag":"conflict","conflict":{".tag":"file"}}}}}"#
        ));
    }

    #[test]
    fn debug_redacts_access_token() {
        let storage =
            DropboxStorage::new("super-secret-token", "/vault/keepass.kdbx").expect("valid config");
        let debug = format!("{storage:?}");
        assert!(!debug.contains("super-secret-token"));
        assert!(debug.contains("[redacted]"));
        assert!(debug.contains("/vault/keepass.kdbx"));
    }

    #[test]
    fn rejects_invalid_config() {
        assert!(matches!(
            DropboxStorage::new("", "/vault/keepass.kdbx"),
            Err(StorageError::Config(_))
        ));
        assert!(matches!(
            DropboxStorage::new("tok", "relative/path.kdbx"),
            Err(StorageError::Config(_))
        ));
        assert!(matches!(
            DropboxStorage::new("tok", "/vault/\u{65e5}\u{672c}\u{8a9e}.kdbx"),
            Err(StorageError::Config(_))
        ));
    }

    #[tokio::test]
    #[ignore = "requires a live Dropbox account; set DROPBOX_TOKEN and DROPBOX_PATH"]
    async fn live_dropbox_round_trip() {
        let token = std::env::var("DROPBOX_TOKEN").expect("DROPBOX_TOKEN must be set");
        let path = std::env::var("DROPBOX_PATH").expect("DROPBOX_PATH must be set");

        let storage = DropboxStorage::new(token, path).expect("valid Dropbox config");

        let data = format!(
            "kpd live test {}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        );
        let meta = storage.write(data.as_bytes(), None).await.expect("write");
        assert_eq!(storage.read().await.expect("read"), data.as_bytes());
        assert!(storage.exists().await.expect("exists"));

        // A conditional write with the fresh revision succeeds and yields a new one.
        let rev = meta.revision.clone().expect("server returned a revision");
        let meta2 = storage
            .write(b"updated", Some(rev.as_str()))
            .await
            .expect("conditional write");
        assert_ne!(meta.revision, meta2.revision);

        // A stale revision must conflict.
        let err = storage
            .write(b"nope", Some(rev.as_str()))
            .await
            .expect_err("stale write must conflict");
        assert!(matches!(err, StorageError::Conflict(_)));
    }
}
