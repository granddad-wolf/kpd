# Contract: kpd read-only MVP crate APIs

Single source of truth for the foundational crates. Implement **exactly** these
public APIs so the crates compose. Internals are yours; the public surface and
module paths must match. Refer to `agent/SPEC-read-only-mvp.md` for behavior.

> Conventions: edition 2021, rust-version 1.75, **no `unsafe`**. Use `thiserror`
> for error enums. Never log or `Debug`-print secret material.

---

## `kpd-crypto`

File: `kpd/crates/kpd-crypto/src/lib.rs`

```rust
pub use zeroize::Zeroizing;

/// Composite key: master password and/or key-file path. Secret material is
/// zeroized on drop. `Debug` must redact the password.
#[derive(Default)]
pub struct CompositeKey {
    password: Option<Zeroizing<String>>,
    key_file_path: Option<std::path::PathBuf>,
}

impl CompositeKey {
    /// Empty key (neither password nor key file).
    pub fn new() -> Self;

    /// Build with a master password (zeroized internally).
    pub fn with_password(mut self, password: impl Into<String>) -> Self;

    /// Build with a key-file path.
    pub fn with_key_file_path(mut self, path: impl Into<std::path::PathBuf>) -> Self;

    pub fn password(&self) -> Option<&str>;
    pub fn key_file_path(&self) -> Option<&std::path::Path>;

    /// `true` when neither a password nor a key file is set.
    pub fn is_empty(&self) -> bool;
}

impl std::fmt::Debug for CompositeKey { /* redacted: `<CompositeKey password=[redacted] ...>` */ }
```

Notes: do **not** derive `Clone` on `CompositeKey` (a password manager must not
duplicate key material casually). Add unit tests for `is_empty` and redacted
`Debug`.

---

## `kpd-core`

Files: `kpd/crates/kpd-core/src/lib.rs` (`pub mod db;`) and
`kpd/crates/kpd-core/src/db.rs`.

```rust
// lib.rs
pub mod db;
pub use db::{Attachment, CustomField, Database, Entry, EntryRef, Group, Times};

// db.rs
use chrono::{DateTime, Utc};
use secrecy::SecretString;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct Database {
    pub root: Group,
    /// KDBX `DatabaseName`, if set.
    pub name: Option<String>,
    /// KDBX `Generator` field, if set.
    pub generator: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Group {
    pub uuid: Uuid,
    pub name: String,
    pub notes: Option<String>,
    pub entries: Vec<Entry>,
    pub children: Vec<Group>,
    pub times: Times,
}

#[derive(Debug, Clone, Default)]
pub struct Entry {
    pub uuid: Uuid,
    pub title: String,
    pub username: String,
    pub password: SecretString,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// Custom string fields other than the standard ones above.
    pub custom_fields: Vec<CustomField>,
    pub attachments: Vec<Attachment>,
    pub times: Times,
    /// Previous versions (KDBX4 entry history), oldest first.
    pub history: Vec<Entry>,
}

#[derive(Debug, Clone)]
pub struct CustomField {
    pub key: String,
    pub value: SecretString,
    pub protected: bool,
}

#[derive(Debug, Clone)]
pub struct Attachment {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Times {
    pub creation: Option<DateTime<Utc>>,
    pub last_modification: Option<DateTime<Utc>>,
    pub last_access: Option<DateTime<Utc>>,
    pub expiry: Option<DateTime<Utc>>,
}

/// Locator for an entry plus the group path leading to it (root-first).
#[derive(Debug, Clone)]
pub struct EntryRef {
    pub group_path: Vec<String>,
    pub entry_uuid: Uuid,
}

impl Database {
    /// Case-insensitive substring match across title, username, url, and notes.
    /// Empty query returns `all_entries()`.
    pub fn search(&self, query: &str) -> Vec<EntryRef>;

    /// Every entry with its group path (root-first, root name excluded).
    pub fn all_entries(&self) -> Vec<EntryRef>;

    pub fn entry(&self, uuid: Uuid) -> Option<&Entry>;

    pub fn group_by_uuid(&self, uuid: Uuid) -> Option<&Group>;
}
```

`SecretString` redacts on `Debug`, so deriving `Debug` on `Entry` is safe.
Add unit tests for `search` (case-insensitive) and `all_entries` on a hand-built
in-memory `Database`.

---

## `kpd-kdbx`

File: `kpd/crates/kpd-kdbx/src/lib.rs`. **Only this crate depends on `keepass`.**

```rust
use std::path::Path;

use kpd_core::db::Database;
use kpd_crypto::CompositeKey;

#[derive(Debug, thiserror::Error)]
pub enum KdbxError {
    #[error("database file not found: {0}")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("wrong master password, key file, or corrupt database")]
    WrongCredentials,
    #[error("unsupported or corrupt KDBX data: {0}")]
    Parse(String),
}

/// Open and decrypt a KDBX database into the `kpd-core` domain model.
pub fn open(path: &Path, key: &CompositeKey) -> Result<Database, KdbxError>;
```

Requirements:

- Use the `keepass` crate (`Database::open`, `DatabaseKey`) to decrypt/parse, then
  map its types into `kpd-core` types. Isolate the mapping in a module such as
  `src/import.rs`.
- Map the `keepass` entry field map (`Title`, `UserName`, `Password`, `URL`,
  `Notes`) into `Entry`'s named fields; map remaining fields into
  `custom_fields`. Preserve `protected` state.
- Map binaries/attachments and entry history into `Entry.attachments` /
  `Entry.history`.
- **Verify the exact `keepass` API on `https://docs.rs/keepass/latest/keepass/`
  before coding** (the exact `Database::open` signature, `DatabaseKey` builder,
  `Group`/`Entry`/`Value` field shapes differ across versions). Do not guess.
- Distinguish `DatabaseOpenError` wrong-credentials cases from parse/IO errors so
  `KdbxError::WrongCredentials` is returned for bad keys.
- Add one integration-style test that opens a checked-in fixture `.kdbx`
  (place it at `kpd/crates/kpd-kdbx/tests/fixtures/` and document how it was
  generated in a README there — do **not** commit any real user database).

---

## `kpd-clipboard`

File: `kpd/crates/kpd-clipboard/src/lib.rs`. Depends on `arboard`.

```rust
use std::time::Duration;

use secrecy::SecretString;

#[derive(Debug, thiserror::Error)]
pub enum ClipboardError {
    #[error("clipboard unavailable: {0}")]
    Unavailable(String),
    #[error("failed to write clipboard: {0}")]
    Set(String),
}

/// Copy `text` to the clipboard and auto-clear it after `timeout`.
pub fn copy_autoclear(text: SecretString, timeout: Duration) -> Result<ClipboardGuard, ClipboardError>;

#[derive(Debug)]
pub struct ClipboardGuard { /* private */ }

impl ClipboardGuard {
    /// Clear immediately (also cancels the scheduled auto-clear).
    pub fn clear_now(&mut self);
    /// Consume the guard to cancel the scheduled auto-clear, leaving the text.
    pub fn cancel(self);
}
```

Requirements:

- Spawn a thread that sleeps `timeout`, then clears the clipboard **only if it
  still equals our text** (avoid clobbering something the user copied later).
- Use an `Arc<AtomicBool>` (or similar) so `cancel()`/`clear_now()` and the
  timer thread agree; no busy-wait.
- Ensure the secret text is zeroized when the guard drops.
