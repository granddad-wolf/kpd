# ADR-0005: Write path — keepass Database as source of truth + guarded save

- **Status**: accepted (design). Implementation is Phase 3a/3b.
- **Date**: 2026-11-17
- **Input**: `agent/RESEARCH-keepass-save.md` (verified against `keepass` 0.17.0 tag).

## Context

`keepass` 0.17.0 writes **KDBX 4.1 only** (`save_kdbx4` feature; KDB/KDBX2/3 and
KDBX4.0 are rejected with `UnsupportedVersion`). Save re-serializes the inner XML
from the in-memory typed model, so any field the model doesn't carry is silently
dropped (documented lossy field: KeePassXC `<PreviousParentGroup>`). Our own
`kpd-core` model is a *deliberately reduced* projection (named fields + custom
fields + attachments + history + times), so routing writes through `kpd-core`
would drop far more than the crate already does.

## Decisions

1. **Source of truth for writes = `keepass::Database`.** `kpd-core::Database`
   remains a **read-only projection** for display/search. `kpd-kdbx` keeps the
   parsed `keepass::Database` alive in a handle; mutations and `save` operate on
   it directly. No `kpd-core -> keepass` round-trip for writes.
2. **Save format = KDBX 4.1 only.** Saving a database whose version is not KDB4(1)
   is a hard refusal (`KdbxError::UnsupportedForWrite`), never a silent conversion.
3. **The composite key is re-supplied at save time and never cached.** The handle
   stores no key material. `save` rebuilds a `keepass::DatabaseKey` from the
   `CompositeKey` argument (fresh salt/seed each save — ciphertext changes every
   time by design).
4. **Guarded save recipe** (matches ADR-0002): serialize off-target → optional
   `.bak` backup → in-memory round-trip verify → atomic replace → lossy-field
   warning surfaced to the user before write.
5. **KDF/cipher policy:** re-saving an existing database preserves its original
   config (carried over by `Database::open`). For **new** databases (Phase 3b) use
   `Argon2id` with strong parameters (≥64 MiB, tuned iterations), not the crate's
   weak `Argon2d / 50 iter / 1 MiB` default.

## Phase 3a public API (implementation contract for `kpd-kdbx`)

Add to `kpd/crates/kpd-kdbx/src/lib.rs` (the existing read-only `open` and
`KdbxError` stay; one variant is added):

```rust
#[derive(Debug, thiserror::Error)]
pub enum KdbxError {
    // ...existing NotFound, Io, WrongCredentials, Parse...
    #[error("this database format cannot be written (only KDBX 4.1 is supported for saving)")]
    UnsupportedForWrite,
}

#[derive(Debug, Clone)]
pub struct SaveOptions {
    /// Write a `.bak` backup of the previous file before overwriting (default true).
    pub backup: bool,
    /// Use a timestamped suffix instead of the fixed `.bak` (default false).
    pub timestamped_backup: bool,
}

impl Default for SaveOptions { /* backup: true, timestamped_backup: false */ }

#[derive(Debug, Clone)]
pub struct SaveReport {
    pub bytes_written: usize,
    /// The round-trip re-open compared equal to the in-memory database.
    pub round_trip_ok: bool,
    pub backup_path: Option<std::path::PathBuf>,
    /// Human-readable warnings (e.g. the lossy-field caveat) to show the user.
    pub warnings: Vec<String>,
}

/// A handle that owns the decrypted `keepass::Database` for the write path.
pub struct DbHandle { /* private */ }

impl DbHandle {
    pub fn open(path: &Path, key: &CompositeKey) -> Result<Self, KdbxError>;
    /// Read-only projection for display/search.
    pub fn view(&self) -> kpd_core::db::Database;
    /// Guarded save per the recipe above.
    pub fn save(&self, key: &CompositeKey, opts: &SaveOptions) -> Result<SaveReport, KdbxError>;
}
```

Requirements for `save`:

1. `keepass` dependency becomes `keepass = { version = "0.17", features = ["save_kdbx4"] }`.
2. Serialize off-target: `inner.save(&mut Vec::new(), build_database_key(key)?)`.
3. Backup (if `opts.backup` and source exists): copy source → `source.kdbx.bak`
   (or `source.<UTC-timestamp>.bak` when `timestamped_backup`).
4. Round-trip verify: re-open the in-memory bytes via `Database::open(&mut
   Cursor::new(&bytes), build_database_key(key)?)` and compare with `inner`
   (`keepass::Database` implements `PartialEq`/`Eq`). Set `round_trip_ok`; do not
   write if verify fails.
5. Atomic replace: write to a temp file in the same directory, `fsync`, rename
   over the target, then `fsync` the parent directory.
6. Always include the lossy-field warning in `SaveReport.warnings` (extension /
   un-modeled XML fields such as KeePassXC `PreviousParentGroup` may be dropped).
7. Map `DatabaseSaveError` → `KdbxError`: `Io`→`Io`, `UnsupportedVersion`→
   `UnsupportedForWrite`, `Key`/`Cryptography`/`Serialization`/`Random`→`Parse(msg)`.

## Consequences / open questions

- Phase 3b: mutation methods on `DbHandle` (`add_entry`, `update_entry_field`,
  `delete_entry`, `add_group`, …) + the TUI edit screens, driven by the same
  handle. New-DB creation uses `DatabaseConfig` with strong Argon2id params.
- Needs a real KeePass/KeePassXC fixture corpus + diff harness to enumerate
  lossy fields before any write is allowed (ADR-0002 gate).
- Upstream secret buffers on the save path are not zeroized (#391); track as a
  hardening item, not a correctness blocker.
