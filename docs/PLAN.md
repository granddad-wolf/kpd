# KeePass-compatible TUI Password Manager — Project Plan

> Working title: **`kpd`** (rename before first public release).
> Status: v0.1 draft — architecture + team + roadmap. Author: DSH `lead` agent team.

---

## 1. Goal

A terminal (TUI) password manager that is **file-compatible with classic KeePass
(KeePass 2.x, `.kdbx` / KDBX4 format)**, built in Rust with `ratatui`, featuring:

1. A **plugin system** (users can add plugins).
2. **Out-of-the-box cloud storage** for the password database.
3. Development on **Ubuntu 24 LTS**, tracked in **two GitHub repos**:
   - **Public** — distribution: source, releases, docs, CI.
   - **Private** — agent files: plans, prompts, research, decisions, internal issues.

---

## 2. Non-negotiable security principles

These are firm requirements, not preferences, for a password manager:

- **Never roll our own crypto.** KDBX4 uses AES-256 / ChaCha20, Argon2d (and
  AES-KDF), HMAC-SHA256 header authentication, and GZip-compressed XML. We rely on
  the `keepass` crate and audited primitives (`argon2`, `aes-gcm`/`chacha20poly1305`,
  `sha2`, `hmac`).
- **Secrets are zeroized.** Use `zeroize` / `secrecy` for master keys, entry
  passwords, and any decrypted buffers. No `String` copies of secrets lying around.
- **No plaintext DB on disk.** Decrypted content lives in memory only; when flushed
  to disk it is re-encrypted to KDBX.
- **Master password entry is non-echoing** (crossterm raw mode), and clipboard
  copies **auto-clear** after a configurable timeout.
- **Plugins are hostile by default.** A plugin sandbox is mandatory (see §5).
- **Every merge/save is backup-friendly.** Write support is experimental upstream;
  we round-trip-test against real KeePass files and refuse to overwrite without a
  `.bak` (see §4.3).

---

## 3. Architecture — Cargo workspace

```
kpd/
├── Cargo.toml                 # [workspace] members
├── crates/
│   ├── kpd/                   # binary: entrypoint, CLI parsing, wiring
│   ├── kpd-tui/               # ratatui + crossterm UI: screens, widgets, keybindings
│   ├── kpd-core/              # domain model: Database, Group, Entry, Attachment, History
│   ├── kpd-kdbx/              # KDBX (de)serialization wrapper over `keepass` crate
│   ├── kpd-crypto/            # key derivation, secret handling, zeroize helpers
│   ├── kpd-storage/           # Storage trait + backends (local, WebDAV, S3, …)
│   ├── kpd-plugin-api/        # host <-> plugin interface (WIT bindings if WASM)
│   ├── kpd-plugin-runtime/    # plugin loader + sandbox (wasmtime, etc.)
│   └── kpd-clipboard/         # platform clipboard + auto-clear (Linux: arboard/x11-clipboard)
├── plugins/
│   └── example-hello/         # reference plugin
├── .github/workflows/         # CI: build, test, clippy, audit, release
└── docs/
```

Dependency boundaries (enforced by `cargo deny` / review):

- `kpd-tui` → `kpd-core`, `kpd-kdbx`, `kpd-storage`, `kpd-clipboard`
- `kpd-core` → `kpd-crypto` (and exposes the data model to plugins)
- `kpd-kdbx` → `kpd-core`, `kpd-crypto`, `keepass`
- `kpd-plugin-runtime` → `kpd-plugin-api` only (plugins never touch `kpd-kdbx` raw crypto)

Key crate choices:

| Concern | Crate | Notes |
|---|---|---|
| TUI | `ratatui` + `crossterm` | User-selected. |
| KDBX parsing | `keepass` (or `foldpass-keepass-rs` fork) | KDB/KDBX3/KDBX4 read; **experimental** KDBX4 write. |
| Key derivation | `argon2`, `aes-kdf` (if needed) | Argon2id for new DBs; Argon2d/AES-KDF for legacy compat. |
| Encryption | `aes`, `chacha20`, `twofish` | Per KDBX4 cipher suite. |
| Secret hygiene | `zeroize`, `secrecy` | No `Debug`/`Clone` on secret types where avoidable. |
| Clipboard | `arboard` (or `x11-clipboard`) | Auto-clear timer. |
| Plugin sandbox | `wasmtime` + `wit-bindgen` (proposed) | See §5. |
| Async (TUI + network) | `tokio` | Needed for cloud backends; keep TUI on a render loop. |
| Config | `serde` + `toml` | `~/.config/kpd/config.toml`. |
| Testing | `cargo nextest`, `proptest`, `insta` | Round-trip + property tests. |
| Security CI | `cargo audit`, `cargo deny`, `cargo geiger` | Block merge on `cargo audit` findings. |

---

## 4. Core decisions & risks

### 4.1 KDBX compatibility scope
- **Read**: KDBX4 (primary), KDBX3 (best effort), KDB (legacy, read-only).
- **Write**: KDBX4, via the `keepass` crate's `save_kdbx4` feature — **guarded**.
- Fields to preserve: entries, groups, titles, usernames, passwords, URLs, notes,
  custom string fields, attachments (binary), group/entry icons, timestamps,
  history (KDBX4 has entry history), tags.

### 4.2 Write-path risk (highest project risk)
Upstream KDBX4 writing is **experimental and lossy**. Strategy options:
1. **(Recommended start)** Read-only MVP + read/write via `keepass` crate, but gate
   saves behind: `.bak` auto-backup, round-trip diff tests, and a "report lost
   fields" check.
2. **Improve the crate** — contribute a non-lossy writer upstream or maintain our own
   fork in the private repo (the `foldpass-keepass-rs` precedent exists).
3. **Read-only first release** — ship viewing/copying/search first; add editing after
   the write path is proven.

### 4.3 Backup discipline
Every save writes `name.kdbx.bak` (previous version) before overwrite, and supports
configurable rolling backups. A "what fields would be lost?" diff is shown before
confirming any save while write is still experimental.

### 4.4 Cloud storage
`kpd-storage` defines a single trait:

```rust
#[async_trait]
trait Storage {
    async fn read(&self) -> Result<Bytes, StorageError>;
    async fn write(&self, data: &[u8]) -> Result<(), StorageError>;
    async fn exists(&self) -> Result<bool, StorageError>;
    async fn metadata(&self) -> Result<Meta, StorageError>; // etag / rev for conflict detection
}
```

Backends (priority order):
1. **Local filesystem** (always; the baseline).
2. **WebDAV** (covers Nextcloud, ownCloud, and many NAS) — simplest remote.
3. **S3-compatible** (MinIO, R2, AWS).
4. **Dropbox / Google Drive / OneDrive** via their HTTP APIs (OAuth + refresh tokens).

Sync = storage read → merge (KeePass-style, last-write-wins with conflict prompt) →
storage write. Crypto is **never** in the storage layer.

---

## 5. Plugin system

Rust has **no stable ABI**, so native `.so` plugins are fragile. Options:

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **WASM (`wasmtime`) + WIT** | Sandboxed, safe, cross-platform, hostile-plugin-friendly | More plumbing; host API must be designed | **Recommended** |
| Native `.so` via `abi_stable` | Full speed, direct Rust | No sandbox; ABI coupling | Secondary |
| Scripting (`rhai`/`lua`) | Simple, embedded | Weak typing, limited power | Optional extra |

**Proposal:** WASM plugins via `wasmtime`, with a `wit-bindgen` host API exposing a
*read-only, filtered* view of the database (e.g. "give me entries matching query")
plus plugin lifecycle + config + logging. Plugins **never** receive the master key or
raw KDBX bytes; they talk through a capability-gated API. A `kpd-plugin-api` crate
defines the contract; `kpd-plugin-runtime` loads and sandboxes plugins from a
`plugins/` dir (manifest declares name, version, permissions, entrypoint).

Plugin permissions to start: `entry.read`, `entry.search`, `clipboard.write`,
`http.fetch` (optional, off by default). Each is declared in the manifest and shown
to the user at first load (like a browser extension prompt).

---

## 6. Team / agent roster

Roles are realized as DSH subagents orchestrated by `lead` (me):

| Role | Responsibility | Deliverables |
|---|---|---|
| **Lead / Architect** (me) | Plan, integration, final review, decisions | PLAN.md, ADRs, release checklist |
| **Security & Crypto** | KDF, cipher wrappers, secret hygiene, threat review | `kpd-crypto`, security review docs |
| **Core / Domain** | Data model, search, CRUD, history | `kpd-core` |
| **KDBX Format** | `keepass` wrapper, round-trip tests, lossy-write mitigation | `kpd-kdbx` + test fixtures |
| **TUI / UX** | ratatui screens, keybindings, clipboard UX | `kpd-tui`, `kpd-clipboard` |
| **Plugin Runtime** | WIT contract, wasmtime host, sample plugin | `kpd-plugin-api`, `kpd-plugin-runtime` |
| **Storage / Cloud** | Storage trait + backends | `kpd-storage` |
| **CI / Packaging** | GitHub Actions, releases, cargo-release, cross-build | `.github/workflows`, release docs |
| **QA / Test** | property tests, KDBX round-trip, clippy/audit gates | test suites, fixtures, CI gates |

Coordination model: `lead` decomposes work, dispatches parallel subagents where
independent, runs a dedicated **reviewer** pass before any merge to `main`.

---

## 7. Roadmap / milestones

### Phase 0 — Environment & repos (0.5 day)
- Install rustup (stable) on Ubuntu 24 LTS; VSCode `rust-analyzer`, `cargo nextest`.
- Create public + private GitHub repos; branch protection; pre-commit hooks
  (rustfmt, clippy, `git-secrets`).

### Phase 1 — Spike: read a real `.kdbx` (1–2 days)
- Workspace scaffolding; `kpd-kdbx` opens a real KeePass file, prints group/entry
  tree. Proves the crypto chain end-to-end.

### Phase 2 — Read-only MVP (1–2 weeks)
- Open/unlock/lock DB; list + search entries; show details; copy password to
  clipboard with auto-clear; config file.

### Phase 3 — Write/edit (1–2 weeks, highest risk)
- Add/edit/delete entries & groups; save via `keepass` crate with `.bak` + loss
  report; heavy round-trip testing against real KeePass.

### Phase 4 — Plugin system (1–2 weeks)
- WASM host + WIT API + manifest + permission prompt + example plugin.

### Phase 5 — Cloud storage (1–2 weeks)
- `Storage` trait; local + WebDAV first, then S3, then OAuth backends.

### Phase 6 — Hardening & release (1+ week)
- `cargo audit`/`deny` clean, fuzzing on the parser boundary, clipboard/secret audit,
  man page, first GitHub release (crates.io + prebuilt binaries).

---

## 8. Decisions (locked — 2026-11-17)

1. **Plugin runtime**: WASM via `wasmtime` + `wit-bindgen`, capability-gated host API.
2. **Write strategy**: read-only MVP first, then guarded writes (`.bak` + loss report).
3. **Cloud priority**: OAuth providers first (Dropbox / Google Drive / OneDrive),
   then WebDAV, then S3-compatible. (OAuth needs app registration + refresh-token
   handling; WebDAV is a cheap fast-follow.)
4. **License**: dual **Apache-2.0 OR MIT**. No fork of KeePass itself; the `keepass`
   crate is consumed as a *dependency* (its source is not copied into our repo), so
   the dual license is compatible. `.kdbx` is a file *format*, not GPL code — format
   compatibility does not impose GPL on an independent implementation.
5. **Project name**: `kpd` is a working placeholder; final name TBD.

See `agent/adr/` for the rationale behind each decision.

## 9. Progress log

- **2026-11-17 — read-only MVP code-complete.** Implemented and reviewed:
  `kpd-crypto` (CompositeKey + zeroize), `kpd-core` (domain model + search),
  `kpd-kdbx` (`keepass` 0.17 wrapper, API verified against docs.rs),
  `kpd-clipboard` (arboard + conditional auto-clear), `kpd-tui` (unlock/browse/
  detail/search/copy/lock), the `kpd` binary, and CI. Not yet compiled (no Rust
  toolchain in the generation environment) — first `cargo build` on Ubuntu 24 LTS
  is the immediate next step (see `agent/RUNBOOK-linux-build.md`). Write/edit
  support, the plugin system, and cloud storage remain (Phases 3b/4/5).
- **2026-11-17 — storage + write backend complete.** `kpd-storage` (`Storage`
  trait + local/WebDAV backends + registry, atomic + optimistic-concurrency) and
  Phase 3a `kpd-kdbx::DbHandle` + guarded `save` (serialize off-target → `.bak` →
  in-memory round-trip verify → atomic replace → lossy-field warning) implemented
  and reviewed.
- **2026-11-17 — Phase 3 complete (read-write).** `DbHandle` mutation methods
  (`add_entry`/`set_entry_field`/`delete_entry`/`add_group`/`delete_group`, with
  history + tombstones + root guard) and the TUI edit/add/delete/save flow (App
  owns `DbHandle` + session key; prompt state machine; save with lossy-field
  warning + confirmation) implemented and reviewed. The app now opens → browses →
  edits → saves end-to-end (still uncompiled). Remaining: WASM plugin system,
  cloud OAuth backends, hardening/release.
- **2026-11-18 — Phase 4a plugin system complete.** `kpd-plugin-api` (WIT
  capability contract), `kpd-plugin-runtime` (wasmtime 50 component loader with
  capability-gated `Host` impls, `StoreLimits` + fuel, no WASI), and a sample
  plugin (`plugins/example`, `cdylib` → `wasm32-wasip2`) implemented and
  reviewed. Workspace MSRV raised to 1.97 (wasmtime requirement). Remaining:
  TUI plugin integration/manifest (4b), cloud OAuth backends, hardening/release.
- **2026-11-18 — hardening pass.** `kpd/SECURITY.md`, `agent/THREAT-MODEL.md`
  (assets/boundaries/threats + residual risks), `kpd/RELEASING.md`, private-repo
  `.gitignore`, and staged-build guidance in the runbook. Remaining: cloud OAuth
  backends (blocked on provider choice), TUI plugin menu, and code hardening
  (cargo-deny, `MemoryProtection`/`mlock`).
- **2026-11-18 — Dropbox backend (Phase 5, first OAuth provider).**
  `kpd-storage::DropboxStorage` implements the `Storage` trait (download/upload/
  get_metadata with `Dropbox-API-Arg` + Bearer auth; `update(rev)` optimistic
  concurrency → `Conflict`; 409 → `NotFound`) plus RFC 7636 PKCE helpers.
  Implemented and reviewed. Remaining: wire cloud storage into the `kpd` binary,
  TUI plugin menu, and code hardening.
- **2026-11-18 — cloud CLI wired.** `kpd cloud fetch/push <webdav|dropbox> …`
  subcommands connect the `Storage` backends to the binary (secrets via env vars,
  `tokio` runtime via `block_on`). Cloud storage is now usable end-to-end via
  fetch → open → edit → push. Remaining: transparent cloud-in-TUI (open/save
  against a cloud URL), TUI plugin menu, code hardening.
- **2026-11-18 — consistency audit + fix.** A cross-crate audit confirmed all 7
  internal dependency edges are consistent, and found one definite
  compile-blocking bug: `DatabaseKey::with_keyfile` returns
  `Result<_, DatabaseKeyError>` with no `From` impl for `KdbxError`. Fixed by
  mapping it to `KdbxError::Parse`. Also fixed a stale MSRV comment.
