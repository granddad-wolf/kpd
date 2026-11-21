# Contract: kpd-tui (read-only MVP UI)

Single source of truth for the terminal UI crate. Refer to
`agent/SPEC-read-only-mvp.md` for the exact behavior and keybindings.

## File & module

`kpd/crates/kpd-tui/src/lib.rs` (you may add submodules under `src/`).

## Public API (implement exactly)

```rust
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum TuiError {
    #[error("terminal error: {0}")]
    Terminal(String),
    #[error(transparent)]
    Kdbx(#[from] kpd_kdbx::KdbxError),
    #[error(transparent)]
    Clipboard(#[from] kpd_clipboard::ClipboardError),
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub db_path: PathBuf,
    pub key_file: Option<PathBuf>,
    /// Clipboard auto-clear timeout for copied secrets.
    pub clipboard_timeout: Duration,
}

impl AppConfig {
    /// Defaults: no key file, 30-second clipboard timeout.
    pub fn new(db_path: impl Into<PathBuf>) -> Self;
}

/// Run the interactive TUI: unlock (masked password entry) -> main view
/// (group tree + entry list + detail) -> search/copy -> lock/quit.
pub fn run(config: AppConfig) -> Result<(), TuiError>;
```

## Behavior requirements

1. **Terminal lifecycle**: enable crossterm raw mode and the alternate screen on
   entry; restore them on exit AND via a panic hook, so a crash never leaves the
   user's terminal broken. Process `crossterm::event::Event` (Key, Resize) in a
   simple loop; no busy-wait (use `event::poll` with a small timeout).

2. **Unlock screen**: masked master-password input (echo `*` or nothing; never
   the real characters). Enter = attempt `kpd_kdbx::open(&config.db_path,
   &CompositeKey)`; wrong key shows the error inline and stays on the unlock
   screen; Esc = quit. Use `config.key_file` if present when building the
   `CompositeKey`.

3. **Main view**:
   - Left pane: group tree (from `Database::root`, recursive).
   - Right pane: entries of the selected group (title + username).
   - On `Enter`: an entry **detail** view (title, username, password masked as
     `••••` until revealed, URL, notes, custom fields, attachment names).
   - Bottom: status bar (locked/unlocked state, db path, entry count).

4. **Search**: `Ctrl+F` enters a search prompt; filtering uses
   `Database::search(query)` across all groups. Results shown in the right pane
   (with group path). Esc clears the filter.

5. **Copy**: `Ctrl+C` copies the focused entry's password (or the focused field
   in detail view) via `kpd_clipboard::copy_autoclear(text, config.clipboard_timeout)`,
   and shows a short confirmation + remaining time hint in the status bar. Keep
   the returned `ClipboardGuard` alive; drop it on next copy.

6. **Lock/Quit**: `L` drops the in-memory `Database` and returns to the unlock
   screen (re-prompt). `Q` quits from the main view; `Esc` quits from the unlock
   screen.

7. **Keybindings** (match SPEC): `↑`/`↓`/`Tab` navigate, `Enter` open detail,
   `Ctrl+F` search, `Ctrl+C` copy, `L` lock, `Q` quit.

## Secrets & hygiene

- Never write the master password or entry passwords to disk, logs, or `Debug`.
- Reuse `kpd_core::db::Entry.password` (`secrecy::SecretString`) and
  `secrecy::ExposeSecret` only where the plaintext is needed (clipboard copy,
  reveal). Do not clone secret strings into plain `String`s except for the
  clipboard call.

## Dependencies (add to `kpd/crates/kpd-tui/Cargo.toml`)

- `ratatui` and `crossterm` — verify current versions on https://crates.io and
  use caret requirements (both are 0.x: use the current minor).
- `thiserror` (2.x), plus path deps: `kpd-core`, `kpd-kdbx`, `kpd-crypto`,
  `kpd-clipboard`.
- No `tokio`/async for the MVP. No `clap` (the binary parses args itself).

## Definition of done

- `cargo build`-clean, clippy-clean idiomatic code, no `unsafe`.
- Unit-test the pure parts (e.g. a small model of the app state / selection
  navigation) without a terminal where feasible; keep anything needing a real TTY
  out of the always-run suite.
- Do NOT modify other crates, the workspace `kpd/Cargo.toml`, or `agent/` files.
