# Contract: DropboxStorage (first cloud OAuth backend)

Extends `kpd-storage` with a Dropbox backend implementing the existing
`Storage` trait. **Decision note:** Dropbox is implemented first as the concrete
OAuth provider (simplest HTTP API, most common cloud for password vaults);
Google Drive and OneDrive follow the same `Storage` trait later. This is a
reasonable default pending a different provider choice from the author.

## File

Add `kpd/crates/kpd-storage/src/dropbox.rs` (+ re-export from `lib.rs`; a small
`dropbox/oauth.rs` submodule for the PKCE helpers).

## Public API

```rust
pub struct DropboxStorage { /* private: reqwest::Client, access_token, remote_path */ }

impl DropboxStorage {
    /// `access_token` is a Dropbox OAuth2 access token; `remote_path` is the
    /// full Dropbox path of the `.kdbx` file, e.g. "/vault/keepass.kdbx".
    pub fn new(access_token: impl Into<String>, remote_path: impl Into<String>)
        -> Result<Self, StorageError>;
}

#[async_trait::async_trait]
impl Storage for DropboxStorage { /* read / write / exists / meta */ }
```

`DropboxStorage` must have a manual redacted `Debug` (never print the token).
It must also be constructible via the existing `BackendSpec`/`from_spec`
(add a `BackendSpec::Dropbox { access_token, path }` variant).

## HTTP semantics (Dropbox API)

Base URLs: `https://content.dropboxapi.com/2/files/…` (content) and
`https://api.dropboxapi.com/2/files/…` (RPC).

- `read()` → `POST https://content.dropboxapi.com/2/files/download` with header
  `Dropbox-API-Arg: {"path":"<remote_path>"}` and `Authorization: Bearer <token>`.
  Response body = file bytes. 409 → `NotFound`; other non-2xx → `Http`.
- `write(data, expected_revision)` → `POST …/2/files/upload` with
  `Content-Type: application/octet-stream`, body = data, and `Dropbox-API-Arg`:
  - `{"path":"<remote_path>","mode":{".tag":"overwrite"}}` when `expected_revision` is `None`;
  - `{"path":"<remote_path>","mode":{".tag":"update","update":"<rev>"}}` when `Some(rev)` (optimistic concurrency).
  A rev mismatch → `Conflict`; 409 → `NotFound`.
- `exists()` → `POST https://api.dropboxapi.com/2/files/get_metadata` with
  `Dropbox-API-Arg: {"path":"<remote_path>"}`. 200 → `true`; 409 `path/not_found` → `false`.
- `meta()` → same `get_metadata`; `revision = Some(rev)` from the response JSON.

## OAuth2 PKCE helpers (pure, testable) — `dropbox::oauth`

RFC 7636:

```rust
pub fn generate_code_verifier() -> Result<String, StorageError>; // 32 random bytes -> base64url, no pad (43 chars)
pub fn code_challenge(verifier: &str) -> String;                  // base64url(sha256(verifier)), no pad
pub fn authorize_url(client_id: &str, code_challenge: &str) -> String;
pub fn token_request_body(client_id: &str, code: &str, verifier: &str) -> String; // form-encoded, for POST /oauth2/token
```

Token endpoint: `https://api.dropboxapi.com/oauth2/token`. The interactive
browser-open + code-paste + token exchange is a follow-up CLI (out of scope).

## Dependencies (add to `kpd-storage/Cargo.toml`, verify on crates.io)

`sha2` (0.10.x), `base64` (0.22.x), `getrandom` (0.2.x or 0.3.x — verify),
`serde` (1.x) + `serde_json` (1.x). `reqwest`/`thiserror`/`url` already present.

## Tests (pure, no live server)

- Header/JSON construction: `Dropbox-API-Arg` shape for download, upload
  (overwrite vs update(rev)), get_metadata; `Authorization: Bearer …`.
- PKCE: verifier length/charset; `code_challenge` equals a **known** base64url
  (sha256) vector; `token_request_body` contains the right form fields.
- Error mapping: 409 → NotFound, rev-conflict → Conflict, other → Http.
- `#[ignore]` live round-trip test using `DROPBOX_TOKEN` + `DROPBOX_PATH`.

## Constraints

No `unsafe`; the access token must never appear in `Debug`/logs/errors. Do NOT
modify other crates, the workspace `kpd/Cargo.toml`, the `kpd` binary, or
`agent/` files. No Rust toolchain here — write compiling-ready code and verify
the `reqwest`/`serde_json`/`base64` APIs on docs.rs.
