//! Terminal UI for `kpd` (ratatui + crossterm).
//!
//! Read-only MVP: unlock a KDBX database with a masked master password, browse
//! the group tree and entries, search across all groups, copy secrets to the
//! clipboard with auto-clear, and lock/quit.
//!
//! Module layout:
//!
//! - [`state`] — pure, terminal-independent state machine (selection,
//!   navigation, search, detail data, lock/unlock). Unit-tested without a TTY.
//! - [`app`] — runtime glue: key handling, the unlock buffer, clipboard-guard
//!   ownership, and the transient status message.
//! - [`ui`] — ratatui rendering for each screen.
//! - [`run`] — terminal lifecycle (raw mode, alternate screen, panic hook) and
//!   the `event::poll`-driven event loop.

#![forbid(unsafe_code)]

mod app;
mod run;
mod state;
mod ui;

use std::path::PathBuf;
use std::time::Duration;

pub use kpd_storage::BackendSpec;
pub use run::run;

/// Errors surfaced while running the interactive UI.
#[derive(Debug, thiserror::Error)]
pub enum TuiError {
    #[error("terminal error: {0}")]
    Terminal(String),
    #[error(transparent)]
    Kdbx(#[from] kpd_kdbx::KdbxError),
    #[error(transparent)]
    Clipboard(#[from] kpd_clipboard::ClipboardError),
}

/// Where the database lives: a local file, or a cloud backend addressed by a
/// [`BackendSpec`].
///
/// Cloud locations are opened and saved through [`kpd_storage::Storage`], so
/// the TUI works the same way against a local file, WebDAV, or Dropbox. The
/// cloud path fetches the encrypted bytes on unlock and uploads the re-encrypted
/// bytes on save, using the remote revision for optimistic concurrency.
#[derive(Debug, Clone)]
pub enum DbLocation {
    Local(PathBuf),
    Cloud(BackendSpec),
}

impl DbLocation {
    /// Human-readable location for the unlock screen and status bar.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Local(path) => path.display().to_string(),
            Self::Cloud(BackendSpec::Local { path }) => path.display().to_string(),
            Self::Cloud(BackendSpec::WebDav { url, .. }) => url.clone(),
            Self::Cloud(BackendSpec::Dropbox { path, .. }) => format!("dropbox:{path}"),
        }
    }

    /// Short label for the status bar: the file name, or the last path
    /// segment of a cloud URL.
    #[must_use]
    pub fn short_label(&self) -> String {
        match self {
            Self::Local(path) | Self::Cloud(BackendSpec::Local { path }) => short_name(path),
            Self::Cloud(BackendSpec::WebDav { url, .. }) => {
                let path = url.split(['?', '#']).next().unwrap_or(url);
                path.rsplit('/')
                    .find(|segment| !segment.is_empty())
                    .unwrap_or(path)
                    .to_string()
            }
            Self::Cloud(BackendSpec::Dropbox { path, .. }) => {
                short_name(std::path::Path::new(path))
            }
        }
    }

    /// Whether saving goes through a [`Storage`](kpd_storage::Storage) backend
    /// instead of the local-file save path.
    #[must_use]
    pub fn is_cloud(&self) -> bool {
        matches!(self, Self::Cloud(_))
    }
}

/// The final component of a path, falling back to the full path.
fn short_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Configuration for one `kpd-tui` run.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub location: DbLocation,
    pub key_file: Option<PathBuf>,
    /// Clipboard auto-clear timeout for copied secrets.
    pub clipboard_timeout: Duration,
}

impl AppConfig {
    /// Defaults: a local database, no key file, 30-second clipboard timeout.
    pub fn new(db_path: impl Into<PathBuf>) -> Self {
        Self {
            location: DbLocation::Local(db_path.into()),
            key_file: None,
            clipboard_timeout: Duration::from_secs(30),
        }
    }

    /// The same defaults, but the database is opened from and saved to a cloud
    /// backend described by `spec`.
    pub fn cloud(spec: BackendSpec) -> Self {
        Self {
            location: DbLocation::Cloud(spec),
            key_file: None,
            clipboard_timeout: Duration::from_secs(30),
        }
    }

    /// Attach a key file to the database key.
    pub fn with_key_file(mut self, key_file: impl Into<PathBuf>) -> Self {
        self.key_file = Some(key_file.into());
        self
    }
}
