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

/// Configuration for one `kpd-tui` run.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub db_path: PathBuf,
    pub key_file: Option<PathBuf>,
    /// Clipboard auto-clear timeout for copied secrets.
    pub clipboard_timeout: Duration,
}

impl AppConfig {
    /// Defaults: no key file, 30-second clipboard timeout.
    pub fn new(db_path: impl Into<PathBuf>) -> Self {
        Self {
            db_path: db_path.into(),
            key_file: None,
            clipboard_timeout: Duration::from_secs(30),
        }
    }
}
