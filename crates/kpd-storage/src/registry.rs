//! Backend registry: descriptors and the [`from_spec`] constructor.

use std::path::PathBuf;

use crate::{DropboxStorage, LocalStorage, Storage, StorageError, WebDavStorage};

/// A backend descriptor used to construct a [`Storage`].
#[derive(Clone)]
pub enum BackendSpec {
    Local {
        path: PathBuf,
    },
    WebDav {
        url: String,
        username: Option<String>,
        password: Option<String>,
    },
    Dropbox {
        access_token: String,
        path: String,
    },
}

// `Debug` is implemented manually (instead of `#[derive(Debug)]`) so the WebDAV
// password and the Dropbox access token are redacted and can never leak into
// logs or diagnostics.
impl std::fmt::Debug for BackendSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local { path } => f.debug_struct("Local").field("path", path).finish(),
            Self::WebDav {
                url,
                username,
                password,
            } => f
                .debug_struct("WebDav")
                .field("url", url)
                .field("username", username)
                .field("password", &password.as_ref().map(|_| "[redacted]"))
                .finish(),
            Self::Dropbox { path, .. } => f
                .debug_struct("Dropbox")
                .field("access_token", &"[redacted]")
                .field("path", path)
                .finish(),
        }
    }
}

/// Build a boxed backend from a spec.
///
/// # Errors
///
/// Returns [`StorageError::Config`] when a [`BackendSpec::WebDav`] spec has an
/// invalid or unsupported URL, or when a [`BackendSpec::Dropbox`] spec has an
/// empty token or a non-absolute/non-ASCII path.
pub fn from_spec(spec: BackendSpec) -> Result<Box<dyn Storage>, StorageError> {
    match spec {
        BackendSpec::Local { path } => Ok(Box::new(LocalStorage::new(path))),
        BackendSpec::WebDav {
            url,
            username,
            password,
        } => Ok(Box::new(WebDavStorage::new(url, username, password)?)),
        BackendSpec::Dropbox { access_token, path } => {
            Ok(Box::new(DropboxStorage::new(access_token, path)?))
        }
    }
}
