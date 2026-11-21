# kpd — KeePass-compatible TUI password manager

`kpd` (working title) is a terminal password manager that reads and writes
KeePass 2.x `.kdbx` (KDBX4) databases, built in Rust with `ratatui`.

> **Status: pre-alpha — code-complete, not yet compiled.** The read-only MVP
> (open / unlock / browse / search / copy) and the guarded write backend are
> implemented; TUI edit screens and the plugin/cloud systems are next. There is
> no Rust toolchain in the generation environment, so this has not been
> `cargo build`-verified — see the agent repo's runbook. **Do not open production
> databases with write enabled until the write path has passed round-trip tests
> against real KeePass files.**

## Features

Implemented (code-complete, pending first compile):

- Read KDBX4 (KeePass 2.x) databases; KDBX3 / KDB best-effort.
- Terminal UI: open / lock, group tree, entry list, search, copy to clipboard.
- Auto-clearing clipboard for copied secrets (conditional clear).
- Guarded write backend (`DbHandle::save`: backup + round-trip verify + atomic replace).
- Storage trait with local + WebDAV backends (optimistic concurrency).

Planned:

- TUI create/edit/delete entries and groups (Phase 3b).
- Plugin system (WASM via `wasmtime`, capability-gated).
- Cloud backends (Dropbox / Google Drive / OneDrive, S3).

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
