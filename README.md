# kpd — KeePass-compatible TUI password manager

`kpd` (working title) is a terminal password manager that reads and writes
KeePass 2.x `.kdbx` (KDBX4) databases, built in Rust with `ratatui`.

> **Status: pre-alpha.** The read-only MVP (open / unlock / browse / search /
> copy), guarded writes, TUI editing, the WASM plugin system and cloud storage
> (WebDAV / Dropbox, CLI and in-TUI) are implemented. Saves back up the previous
> file, round-trip verify, and write atomically. Keep a separate copy of any
> production database until you have validated it with your own KeePass clients.

## Features

Implemented:

- Read KDBX4 (KeePass 2.x) databases; KDBX3 / KDB best-effort, with a KDBX
  4.0 → 4.1 upgrade on save.
- Terminal UI: open / lock, group tree, entry list, search, copy to clipboard.
- TUI create / edit / delete for entries and groups.
- Auto-clearing clipboard for copied secrets (conditional clear).
- Guarded write backend (`DbHandle::save`: backup + round-trip verify + atomic replace).
- Storage trait with local + WebDAV + Dropbox backends (optimistic concurrency).
- Open and save directly against cloud storage from the TUI (`kpd open --webdav`
  / `--dropbox`), with revision-conflict detection.
- WASM plugin system (capability-gated, empty-WASI sandbox, fuel/memory limits)
  with a `P` plugin picker in the TUI and a `kpd plugin` CLI.

Planned:

- Google Drive / OneDrive / S3 backends.
- Conflict resolution beyond "refuse and reload".

## Usage

```sh
# Local database
kpd open ~/vault.kdbx

# Cloud database: fetched on unlock, uploaded on save (Ctrl+S)
KPD_WEBDAV_USER=me KPD_WEBDAV_PASS=secret \
  kpd open --webdav https://dav.example.com/vault.kdbx
KPD_DROPBOX_TOKEN=... kpd open --dropbox /vault.kdbx --keyfile ~/vault.key
```

Secrets are read from the environment, never from argv. In the TUI, `Ctrl+S`
saves; for a cloud database the save carries the revision the session opened at,
so a concurrent remote change surfaces as a conflict instead of being
overwritten.

## Building

Prerequisites: Rust stable (via `rustup`), on Ubuntu 24 LTS or similar.

```sh
cargo build --release
./target/release/kpd --help
```

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit   # cargo install cargo-audit
```

## Repository split

- **Public repo (this):** source, releases, CI.
- **Private repo:** agent files — plans, ADRs, research, and internal issues.

## License

Dual-licensed under **Apache-2.0 OR MIT**. See `LICENSE-APACHE` and `LICENSE-MIT`.
