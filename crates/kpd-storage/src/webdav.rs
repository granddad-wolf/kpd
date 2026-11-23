//! WebDAV backend, implemented over plain HTTP `GET`/`HEAD`/`PUT` with `reqwest`.

use reqwest::header::{HeaderMap, ETAG, IF_MATCH};
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode};

use crate::{Meta, Storage, StorageError};

/// Body of the exclusive write lock taken around a save.
const LOCK_BODY: &str = concat!(
    r#"<?xml version="1.0" encoding="utf-8"?>"#,
    r#"<D:lockinfo xmlns:D="DAV:">"#,
    r#"<D:lockscope><D:exclusive/></D:lockscope>"#,
    r#"<D:locktype><D:write/></D:locktype>"#,
    r#"<D:owner><D:href>kpd</D:href></D:owner>"#,
    r#"</D:lockinfo>"#,
);

/// How long a save keeps its write lock; the server drops it automatically if
/// the client disappears before the matching `UNLOCK`.
const LOCK_TIMEOUT: &str = "Second-60";

/// A database stored on a WebDAV server.
///
/// `url` is the full URL of the `.kdbx` file. Credentials, when both are
/// present, are sent as HTTP Basic auth. The password is kept out of all
/// `Debug`/log output (this type deliberately has no `Debug` implementation).
pub struct WebDavStorage {
    client: Client,
    url: String,
    username: Option<String>,
    password: Option<String>,
}

impl WebDavStorage {
    /// Create a WebDAV backend.
    ///
    /// `url` must be a valid `http`/`https` URL and must not embed credentials;
    /// pass them via `username`/`password` instead. Basic auth is applied only
    /// when both `username` and `password` are set.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Config`] when `url` is not a valid `http`/`https`
    /// URL, uses an unsupported scheme, or embeds credentials.
    pub fn new(
        url: impl Into<String>,
        username: Option<String>,
        password: Option<String>,
    ) -> Result<Self, StorageError> {
        let url = url.into();
        let parsed = url::Url::parse(&url)
            .map_err(|e| StorageError::Config(format!("invalid WebDAV URL: {e}")))?;

        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                return Err(StorageError::Config(format!(
                    "unsupported WebDAV URL scheme: {other:?} (expected http or https)"
                )));
            }
        }

        // Reject embedded userinfo so a password can never leak through a URL in
        // error text or `Debug` output; credentials must be passed separately.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(StorageError::Config(
                "WebDAV URL must not contain embedded credentials; pass username/password separately"
                    .to_string(),
            ));
        }

        let client = Client::builder()
            .connect_timeout(crate::CONNECT_TIMEOUT)
            .timeout(crate::REQUEST_TIMEOUT)
            .build()
            .map_err(|e| StorageError::Config(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            client,
            url: parsed.as_str().to_owned(),
            username,
            password,
        })
    }

    /// Build a request with Basic auth applied when both credentials are set.
    fn request(&self, method: Method) -> RequestBuilder {
        let mut builder = self.client.request(method, self.url.as_str());
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            builder = builder.basic_auth(username, Some(password));
        }
        builder
    }
}

#[async_trait::async_trait]
impl Storage for WebDavStorage {
    async fn read(&self) -> Result<Vec<u8>, StorageError> {
        let response = self.request(Method::GET).send().await.map_err(http_error)?;
        let response = ensure_success(response)?;
        Ok(response.bytes().await.map_err(http_error)?.to_vec())
    }

    async fn write(
        &self,
        data: &[u8],
        expected_revision: Option<&str>,
    ) -> Result<Meta, StorageError> {
        // Compare the revision *before* locking: some servers (Nextcloud)
        // change the `ETag` when a lock is acquired, so comparing under the
        // lock would report a spurious conflict. This check is also what
        // catches changes on servers that ignore `If-Match` (rclone).
        if let Some(expected) = expected_revision {
            let current = self.meta().await?;
            if !etag_matches(current.revision.as_deref(), expected) {
                return Err(StorageError::Conflict(format!(
                    "expected revision {expected}, found {}",
                    current.revision.as_deref().unwrap_or("none")
                )));
            }
        }

        // Hold an exclusive WebDAV lock for the PUT so no conforming writer can
        // change the resource between the check above and the write. Servers
        // without lock support fall back to preconditions below.
        let lock = self.lock_exclusive().await?;
        let result = self
            .write_locked(data, expected_revision, lock.as_deref())
            .await;
        if let Some(token) = &lock {
            // Best effort: the lock expires by itself if this fails.
            let _ = self.unlock(token).await;
        }
        result
    }

    async fn exists(&self) -> Result<bool, StorageError> {
        let response = self
            .request(Method::HEAD)
            .send()
            .await
            .map_err(http_error)?;
        match response.status() {
            status if status.is_success() => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            status => Err(http_status_error(status)),
        }
    }

    async fn meta(&self) -> Result<Meta, StorageError> {
        let response = self
            .request(Method::HEAD)
            .send()
            .await
            .map_err(http_error)?;
        let response = ensure_success(response)?;
        Ok(Meta {
            revision: etag_from_headers(response.headers()),
        })
    }
}

impl WebDavStorage {
    /// Acquire an exclusive write lock on the database.
    ///
    /// Returns `Ok(None)` when the server does not support locking (501/405),
    /// forbids it (403), or cannot lock this resource (404/409); the caller then
    /// saves with revision preconditions only. A resource already locked by
    /// another client is a [`StorageError::Conflict`].
    async fn lock_exclusive(&self) -> Result<Option<String>, StorageError> {
        let method = Method::from_bytes(b"LOCK")
            .map_err(|err| StorageError::Config(format!("invalid LOCK method: {err}")))?;
        let response = self
            .request(method)
            .header("Depth", "0")
            .header("Timeout", LOCK_TIMEOUT)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/xml; charset=utf-8",
            )
            .body(LOCK_BODY)
            .send()
            .await
            .map_err(http_error)?;

        match response.status() {
            status if status.is_success() => {
                let headers = response.headers().clone();
                let body = response.text().await.map_err(http_error)?;
                Ok(lock_token(&headers, &body))
            }
            StatusCode::LOCKED => Err(StorageError::Conflict(
                "the remote database is locked by another client".to_string(),
            )),
            StatusCode::NOT_IMPLEMENTED
            | StatusCode::METHOD_NOT_ALLOWED
            | StatusCode::FORBIDDEN
            | StatusCode::NOT_FOUND
            | StatusCode::CONFLICT => Ok(None),
            status => Err(http_status_error(status)),
        }
    }

    /// Release the write lock taken by [`Self::lock_exclusive`].
    async fn unlock(&self, token: &str) -> Result<(), StorageError> {
        let method = Method::from_bytes(b"UNLOCK")
            .map_err(|err| StorageError::Config(format!("invalid UNLOCK method: {err}")))?;
        let response = self
            .request(method)
            .header("Lock-Token", token)
            .send()
            .await
            .map_err(http_error)?;
        ensure_success(response)?;
        Ok(())
    }

    /// The locked part of [`Storage::write`]: the `PUT`, authorized by the lock
    /// token when one was acquired.
    ///
    /// Without a lock, a strong revision is still sent as `If-Match` so servers
    /// that support preconditions keep rejecting concurrent changes; weak
    /// `ETag`s cannot be used there and rely on the pre-lock HEAD check alone.
    async fn write_locked(
        &self,
        data: &[u8],
        expected_revision: Option<&str>,
        lock: Option<&str>,
    ) -> Result<Meta, StorageError> {
        let mut request = self.request(Method::PUT);
        if let Some(token) = lock {
            // The lock token authorizes this write; a locked resource answers
            // 423 to writers that do not present it. `If-Match` is deliberately
            // not sent: some servers (Nextcloud) change the ETag on lock, and
            // the pre-lock HEAD check already covered revision drift.
            request = request.header("If", format!("({token})"));
        } else if let Some(value) = if_match_value(strong_revision(expected_revision)) {
            request = request.header(IF_MATCH, value);
        }
        let response = request
            .body(data.to_vec())
            .send()
            .await
            .map_err(http_error)?;
        let response = ensure_success(response)?;
        Ok(Meta {
            revision: etag_from_headers(response.headers()),
        })
    }
}

/// The `If-Match` header value for a conditional write: `Some(revision)` iff an
/// `expected_revision` is supplied. `None` means unconditional last-write-wins.
fn if_match_value(expected_revision: Option<&str>) -> Option<String> {
    expected_revision.map(str::to_owned)
}

/// Whether an `ETag` is weak (`W/"..."`). Weak tags can never satisfy `If-Match`,
/// which requires a strong comparison.
fn is_weak_etag(etag: &str) -> bool {
    etag.trim_start().starts_with("W/")
}

/// The opaque value of an `ETag`, without the weak prefix.
fn etag_value(etag: &str) -> &str {
    let etag = etag.trim_start();
    etag.strip_prefix("W/").unwrap_or(etag)
}

/// Weak comparison of two `ETag`s (RFC 9110 §8.8.3.2): the `W/` prefix is
/// ignored. Apache `mod_dav` flips the same tag between weak (a file written
/// moments ago) and strong (the same file once it has settled), so a strict
/// string compare would report a spurious conflict between unlock and save.
fn etag_matches(current: Option<&str>, expected: &str) -> bool {
    current.is_some_and(|value| etag_value(value) == etag_value(expected))
}

/// The revision usable in an `If-Match` header: only strong `ETag`s qualify.
fn strong_revision(revision: Option<&str>) -> Option<&str> {
    revision.filter(|value| !is_weak_etag(value))
}

/// The lock token from a LOCK response, normalized to `<token>` (the syntax
/// both the `If` and `Lock-Token` request headers expect).
///
/// Most servers put it in the `Lock-Token` response header; the body's
/// `locktoken`/`href` pair is the fallback.
fn lock_token(headers: &HeaderMap, body: &str) -> Option<String> {
    let header = headers
        .get("lock-token")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let token = header.or_else(|| lock_token_from_body(body))?;
    let token = token.trim().trim_start_matches('<').trim_end_matches('>');
    (!token.is_empty()).then(|| format!("<{token}>"))
}

/// Extract the `locktoken` `href` value from a LOCK response body.
fn lock_token_from_body(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let lock_key = lower.find("locktoken")?;
    let href_key = lower[lock_key..].find("href")? + lock_key;
    let open = body[href_key..].find('>')? + href_key + 1;
    let close = body[open..].find('<')? + open;
    Some(body[open..close].to_string())
}

/// Map a non-success HTTP status onto a typed storage error when it is one we
/// distinguish: `412` → [`StorageError::Conflict`], `404` →
/// [`StorageError::NotFound`]. Returns `None` for statuses the caller should
/// treat as a generic [`StorageError::Http`] error.
fn status_to_error(status: StatusCode) -> Option<StorageError> {
    if status == StatusCode::PRECONDITION_FAILED {
        Some(StorageError::Conflict(
            "remote file changed (HTTP 412)".to_string(),
        ))
    } else if status == StatusCode::NOT_FOUND {
        Some(StorageError::NotFound(
            "remote file not found (HTTP 404)".to_string(),
        ))
    } else if status == StatusCode::LOCKED {
        Some(StorageError::Conflict(
            "the remote database is locked by another client".to_string(),
        ))
    } else {
        None
    }
}

/// Extract the `ETag` response header value, if present.
fn etag_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Map a `reqwest` failure, naming timeouts explicitly so a hung server shows
/// up as such in the TUI instead of a generic HTTP error.
fn http_error(e: reqwest::Error) -> StorageError {
    if e.is_timeout() {
        return StorageError::Http(format!(
            "request timed out (connect timeout {}s, request timeout {}s)",
            crate::CONNECT_TIMEOUT.as_secs(),
            crate::REQUEST_TIMEOUT.as_secs()
        ));
    }
    StorageError::Http(e.to_string())
}

fn http_status_error(status: StatusCode) -> StorageError {
    let reason = status.canonical_reason().unwrap_or("unknown");
    StorageError::Http(format!("HTTP {status} {reason}"))
}

/// Ensure a response is a success (2xx); otherwise map it to a typed error.
fn ensure_success(response: Response) -> Result<Response, StorageError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    if let Some(err) = status_to_error(status) {
        return Err(err);
    }
    Err(http_status_error(status))
}

#[cfg(test)]
mod tests {
    use super::{
        etag_from_headers, etag_matches, if_match_value, is_weak_etag, lock_token, status_to_error,
        strong_revision, WebDavStorage,
    };
    use crate::{Storage, StorageError};
    use reqwest::header::{HeaderMap, HeaderValue, ETAG};
    use reqwest::StatusCode;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn weak_etags_are_detected_and_excluded_from_if_match() {
        assert!(is_weak_etag("W/\"5-660e1f6b0b3af\""));
        assert!(!is_weak_etag("\"5-660e1f6b0b3af\""));

        // Weak ETags (e.g. plain Apache mod_dav) cannot be used in If-Match.
        assert_eq!(strong_revision(Some("W/\"abc\"")), None);
        assert_eq!(strong_revision(Some("\"abc\"")), Some("\"abc\""));
        assert_eq!(strong_revision(None), None);
    }

    #[test]
    fn lock_token_prefers_the_header_and_normalizes_brackets() {
        let mut headers = HeaderMap::new();
        headers.insert("lock-token", "<opaquelocktoken:abc>".parse().unwrap());
        assert_eq!(
            lock_token(&headers, ""),
            Some("<opaquelocktoken:abc>".to_string())
        );

        // Header without brackets is normalized too.
        let mut headers = HeaderMap::new();
        headers.insert("lock-token", "opaquelocktoken:def".parse().unwrap());
        assert_eq!(
            lock_token(&headers, ""),
            Some("<opaquelocktoken:def>".to_string())
        );
    }

    #[test]
    fn lock_token_falls_back_to_the_response_body() {
        let body = "<?xml version=\"1.0\"?><d:prop><d:lockdiscovery>\
                    <d:activelock><d:locktoken><d:href>opaquelocktoken:abc</d:href>\
                    </d:locktoken></d:activelock></d:lockdiscovery></d:prop>";
        assert_eq!(
            lock_token(&HeaderMap::new(), body),
            Some("<opaquelocktoken:abc>".to_string())
        );
        assert_eq!(lock_token(&HeaderMap::new(), "<no token here/>"), None);
    }

    #[test]
    fn etag_comparison_ignores_the_weak_prefix() {
        // The same tag, weak on one side and strong on the other, still matches.
        assert!(etag_matches(Some("\"733-abc\""), "W/\"733-abc\""));
        assert!(etag_matches(Some("W/\"733-abc\""), "\"733-abc\""));
        assert!(etag_matches(Some("W/\"733-abc\""), "W/\"733-abc\""));
        assert!(!etag_matches(Some("\"763-def\""), "W/\"733-abc\""));
        assert!(!etag_matches(None, "W/\"733-abc\""));
    }

    #[test]
    fn if_match_header_present_iff_expected_revision_is_some() {
        assert_eq!(if_match_value(None), None);
        assert_eq!(
            if_match_value(Some("W/\"etag-1\"")),
            Some("W/\"etag-1\"".to_string())
        );
    }

    #[test]
    fn maps_precondition_failed_to_conflict() {
        let err = status_to_error(StatusCode::PRECONDITION_FAILED)
            .expect("412 must map to a typed error");
        assert!(matches!(err, StorageError::Conflict(_)));
    }

    #[test]
    fn maps_not_found_to_not_found() {
        let err = status_to_error(StatusCode::NOT_FOUND).expect("404 must map to a typed error");
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[test]
    fn success_and_other_statuses_map_to_none() {
        assert!(status_to_error(StatusCode::OK).is_none());
        assert!(status_to_error(StatusCode::CREATED).is_none());
        assert!(status_to_error(StatusCode::INTERNAL_SERVER_ERROR).is_none());
    }

    #[test]
    fn extracts_etag_from_headers() {
        let mut headers = HeaderMap::new();
        assert_eq!(etag_from_headers(&headers), None);

        headers.insert(ETAG, HeaderValue::from_static("\"abc123\""));
        assert_eq!(etag_from_headers(&headers), Some("\"abc123\"".to_string()));
    }

    #[tokio::test]
    #[ignore = "requires a live WebDAV server; set WEBDAV_URL (and optionally WEBDAV_USER/WEBDAV_PASS)"]
    async fn live_webdav_round_trip() {
        let url = std::env::var("WEBDAV_URL").expect("WEBDAV_URL must be set");
        let user = std::env::var("WEBDAV_USER").ok();
        let pass = std::env::var("WEBDAV_PASS").ok();

        let storage = WebDavStorage::new(url, user, pass).expect("valid WebDAV config");

        let data = format!(
            "kpd live test {}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        );
        let meta = storage.write(data.as_bytes(), None).await.expect("write");
        assert_eq!(storage.read().await.expect("read"), data.as_bytes());

        // A conditional write with the fresh revision succeeds and yields a new one.
        let rev = meta.revision.clone().expect("server returned an ETag");
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
