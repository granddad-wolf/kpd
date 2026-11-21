# Research note: `keepass` 0.17.0 save/write path (Phase 3)

Status: research only. No code changed.
Sources: docs.rs (keepass 0.17.0), the `v0.17.0` tag of
[`sseemayer/keepass-rs`](https://github.com/sseemayer/keepass-rs) (commit
`26cb076aa5cbbe36e175326dfdaf5a19799c4085`), and GitHub issues/PRs.

---

## (a) Verified save API + feature flag

### Feature flag

- **`save_kdbx4`** gates the entire write path. In `Cargo.toml` it is declared as
  an empty feature (`save_kdbx4 = []`) — it enables no extra dependencies, it only
  turns on `#[cfg(feature = "save_kdbx4")]` code:
  - `src/db/mod.rs`: `mod save;` + `pub use crate::db::save::DatabaseSaveError;`
  - `src/format/kdbx4/mod.rs`: `mod dump;` + `pub(crate) use ...::dump_kdbx4;`
  - `src/format/mod.rs`: `mod io;`
  - `src/config.rs`: `dump`/`get_iv_size`/`get_key_size`/`seed_size`/`get_kdf_and_seed`/`to_variant_dictionary`
  - `src/format/xml_db/mod.rs`: `to_xml` and `KeePassFile::db_to_xml`
- Source: [`src/db/mod.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/db/mod.rs),
  [`Cargo.toml.orig`](https://docs.rs/crate/keepass/0.17.0/source/Cargo.toml.orig),
  feature list at <https://docs.rs/crate/keepass/0.17.0/features>.
- **Not in the default docs.rs build.** The rustdoc `Database` page at
  <https://docs.rs/keepass/0.17.0/keepass/db/struct.Database.html> lists no `save`
  method — the method only exists when `save_kdbx4` is enabled. `kpd` must add
  `keepass = { version = "0.17.0", features = ["save_kdbx4"] }` and confirm the
  method exists in its own build (it is verified present at the `v0.17.0` tag).

### Method

Exact signature (`src/db/save.rs`, tag `v0.17.0`):

```rust
impl Database {
    /// Saves the database to the given destination, using the provided key for encryption.
    pub fn save(
        &self,
        destination: &mut dyn std::io::Write,
        key: DatabaseKey,
    ) -> Result<(), DatabaseSaveError>
}
```

Notes:
- Takes `&self` (not `&mut self`) — the write reads the DB and builds fresh keys/seeds.
- Writes to any `&mut dyn std::io::Write` (file, `Vec<u8>`, temp file, …). This is
  what makes the temp-file + atomic-rename recipe (below) natural.
- `key: DatabaseKey` is passed **by value** (it implements `Zeroize`/`Drop`; it is
  consumed and its elements are read via `get_key_elements()`).
- Source: [`src/db/save.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/db/save.rs).

`Database::save` only handles `DatabaseVersion::KDB4(_)`; KDB / KDBX2 / KDBX3 map
to `DatabaseSaveError::UnsupportedVersion`. `dump_kdbx4` additionally rejects any
minor version other than `1` (`DatabaseVersion::KDB4(1)`), so **only KDBX 4.1 is
writable** — KDBX4.0 as well as all older formats are read-only for save purposes.

---

## (b) KDBX version + KDF/cipher for NEW databases, and configurability

Saving always produces **KDBX 4.1** (`DatabaseVersion::KDB4(1)`);
`KDBX4_CURRENT_MINOR_VERSION = 1` in [`src/format/mod.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/format/mod.rs).

`Database::new()` uses `DatabaseConfig::default()`
([`src/config.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/config.rs)):

| Setting | Default |
|---|---|
| `version` | `KDB4(1)` → KDBX 4.1 |
| `outer_cipher_config` | `AES256` (AES-256-CBC) |
| `compression_config` | `GZip` |
| `inner_cipher_config` | `ChaCha20` (protected-value stream) |
| `kdf_config` | `Argon2` (Argon2**d**, *not* Argon2id) — `iterations: 50`, `memory: 1024*1024` bytes (1 MiB), `parallelism: 4`, `version: Version13` |
| `public_custom_data` | `None` |

All of these are configurable through `DatabaseConfig` (a `#[non_exhaustive]`
struct) via `Database::with_config(config)`:

- Outer cipher: `AES256` | `Twofish` | `ChaCha20`.
- Inner cipher: `Plain` | `Salsa20` | `ChaCha20`.
- Compression: `None` | `GZip`.
- KDF: `Aes { rounds }` | `Argon2 { iterations, memory, parallelism, version }` |
  `Argon2id { iterations, memory, parallelism, version }` (`memory` is in bytes;
  the crate converts to KiB for the Argon2 backend).

Two nuances worth flagging for `kpd`:
1. The default KDF is **Argon2d**, matching KeePass's own default; Argon2id is
   available but must be chosen explicitly.
2. The shipped defaults are **weak** for a 2026 password manager (Argon2d with 50
   iterations / 1 MiB). For *new* databases `kpd` should set stronger params
   explicitly. For *existing* databases, the `Database.config` carried over from
   `Database::open` preserves the file's original KDF/cipher, and re-saving reuses
   those (a fresh salt is drawn — see below).

---

## (c) What `DatabaseKey` does during save

`dump_kdbx4`
([`src/format/kdbx4/dump.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/format/kdbx4/dump.rs))
does **not** reuse any stored key. On every save it generates fresh randomness:

- 32-byte `master_seed`, a new outer `IV`, a new inner-stream key, and a new KDF
  seed (salt) via `getrandom`.
- `composite_key = SHA256( key_elements )`, where `key_elements` come from the
  supplied `DatabaseKey` (SHA-256 of the password and/or keyfile data).
- `transformed_key = kdf.transform_key(composite_key)` (using the fresh KDF seed).
- `master_key = SHA256( master_seed || transformed_key )`; HMAC key =
  `SHA512( master_seed || transformed_key || HMAC_KEY_END )`.

Consequences:
- **The key must be re-supplied on every save** — it is a required argument and the
  `Database` never retains it. A new salt/seed each time means the ciphertext
  changes on every save even when content + password are identical.
- With the `challenge_response` feature, the key is first challenged against the
  fresh KDF seed (`db_key.perform_challenge(&kdf_seed)`) before extracting elements.

---

## (d) "Rewrites XML from scratch" — still true, and lossy fields

Still true. Save fully re-serializes the inner XML from the in-memory typed model:

`crate::format::xml_db::to_xml(db, &mut inner_cipher)` →
`KeePassFile::db_to_xml` → `quick_xml::se::to_string_with_root("KeePassFile", &kdbx)`.

The original `<KeePassFile>` XML is not preserved; any element the parser does not
map onto a struct field is silently dropped on save.

The typed model covers the standard KDBX4 schema: `Meta` (including
`MemoryProtection` and `custom_data`), `Group`/`Entry` (incl. `Times`, `AutoType`,
`History`, per-item `CustomData`), custom icons, binary attachments, and
`DeletedObjects`. Attachments, custom icons, and history are round-tripped (see the
crate's own `test_attachments`, `test_icons`, and the attachment-ID renumbering in
`with_dense_attachment_ids`).

**Documented lossy field:** `<PreviousParentGroup>` on `Group`/`Entry` — a
KeePassXC 2.7.x undo/restore element. It is parsed (so KeePassXC files open) but is
*not* plumbed into the in-memory model and is *not* written back, so re-saving a DB
in which an entry/group was moved in KeePassXC drops the undo hint. See open PR
[#319](https://github.com/sseemayer/keepass-rs/pull/319).

General rule for `kpd`: treat "un-modeled / vendor-extension fields may be lost" as
a standing risk, and surface a warning before saving any file whose XML contains
elements `kpd` does not round-trip.

---

## (e) Creating a NEW database programmatically

Yes — this is the same builder API already used in `kpd` tests:

```rust
use keepass::{Database, DatabaseKey, db::{fields, Value, EntryMut, GroupMut}};

let mut db = Database::new();            // or Database::with_config(cfg)
let mut root: GroupMut = db.root_mut();
let mut entry: EntryMut = root.add_entry();
entry.set_unprotected(fields::TITLE, "My Entry");
entry.set_protected(fields::PASSWORD, "hunter2");
// entry.add_attachment(...) etc.

let mut buf = Vec::new();
db.save(&mut buf, DatabaseKey::new().with_password("master"))?;
```

No metadata is *strictly required*: `Database::new()` sets `meta: Meta::default()`
(all optional fields `None`, empty `custom_data`), and the crate's own round-trip
test saves a bare `Database::new()` and reopens it equal. For KeePass interop,
`kpd` should at minimum set:

- `meta.generator = Some("kpd ...")` (the writing program, per KeePass convention);
- `meta.database_name = Some(...)`.

Optional-but-relevant:
- `meta.memory_protection` is `None` by default → no `<MemoryProtection>` element is
  written. `MemoryProtection::default()` (protects password) is *not* auto-attached;
  set `meta.memory_protection = Some(MemoryProtection::default())` if `kpd` wants the
  KeePass password-protection convention.
- Recycle bin is just a group referenced by `meta.recyclebin_uuid`; save does not
  create one. `kpd` should manage `recyclebin_enabled`/`recyclebin_uuid` itself.
- `Meta` field inventory: [`src/db/types/meta.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/db/types/meta.rs).

---

## (f) Error type

`keepass::db::DatabaseSaveError` (re-exported; `#[non_exhaustive]`, `thiserror`):

| Variant | Wraps | Relevance to `kpd` |
|---|---|---|
| `Io` | `std::io::Error` | disk/FS failures during the guarded write |
| `Serialization` | `quick_xml::SeError` | XML serialization failure |
| `Key` | `crate::key::DatabaseKeyError` | missing/empty/invalid key components |
| `Cryptography` | `crate::crypt::CryptographyError` | cipher/KDF failure |
| `Random` | `getrandom::Error` | entropy source failure |
| `UnsupportedVersion` | (unit) | **trying to save KDB / KDBX2 / KDBX3 / KDBX4.0** — must be handled as a hard refusal, not a silent conversion |

Source: [`src/db/save.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/db/save.rs).

---

## (g) Known issues / gotchas (GitHub)

- **#218 / #219 (fixed, 2024):** HMAC block-stream chunking corrupted large DBs.
  Chunking removed; the block stream is written in one pass. No action needed beyond
  round-trip testing.
- **#357 (fixed):** AES-KDF UUID interop — save now emits the KDBX3 AES-KDF UUID
  (`KDF_AES_KDBX3`) for cross-tool compatibility (comment in `config.rs`).
- **#374 (fixed):** removing an attachment left an ID gap; on save the inner-header
  attachments were written by position, so later attachments desynced. Fixed by
  `with_dense_attachment_ids` auto-renumbering on save. `kpd` should still call
  `Database::remove_unused_attachments()` after deletions.
- **#367 / #302 (fixed):** `DeletedObject` `<DeletionTime>` now serializes with the
  schema name; tombstones without a timestamp are omitted (avoids strict clients like
  KeePassium rejecting the file). Note the warning in #367: a file already damaged by
  the old writer may have lost deletion timestamps permanently.
- **#319 (open):** `<PreviousParentGroup>` (KeePassXC) is read but not round-tripped
  → lossy field (see §d).
- **#392 (open, read side):** some tools emit `<String>`/`<Binary>` after
  `<Times>`/`<AutoType>`; quick-xml needs `overlapped-lists`. Affects *reading* such
  files, not writing, but relevant if `kpd` edits those files.
- **#391 (open, security):** intermediate secret buffers on the open *and save* paths
  (key elements, decrypted payload, XML, cipher/stream keys) are plain `Vec<u8>` and
  are not zeroized before drop. Relevant to `kpd`'s memory-hardening goals; not a
  write-correctness issue.

---

## (b2) Guarded-write recipe for `kpd`

Consistent with [ADR-0002](adr/0002-read-only-first-guarded-writes.md):

1. **Serialize off-target.** Call `db.save(&mut Vec::new(), key)` (or a temp file in
   the same directory), never straight into the live `.kdbx`.
2. **Backup first.** Copy the current `.kdbx` → `.kdbx.bak` (optionally timestamped)
   and confirm it opens with the current key before proceeding.
3. **Round-trip verify in memory.** Re-open the freshly written bytes with the same
   key via `Database::parse(&bytes, key)` and compare against the in-memory
   `Database` (`Database` implements `PartialEq`/`Eq`). This catches
   serialization/encryption regressions before touching disk.
4. **Atomic replace.** Write the verified bytes to a temp file, `fsync`, then rename
   over the target (and `fsync` the parent directory on Unix).
5. **Lossy-field warning + confirmation.** Because save rebuilds XML from the typed
   model, surface a pre-save warning that un-modeled/extension fields (e.g.
   KeePassXC `PreviousParentGroup`) may be dropped, and require explicit user
   confirmation (ADR-0002 gate).
6. **Key hygiene.** Re-derive `DatabaseKey` from user input at save time; don't cache
   the composite key. `DatabaseKey` zeroizes on drop; the surrounding buffers are not
   zeroized upstream (#391) — be mindful of copies in `kpd`.

---

## (c2) Risks + open questions for Phase 3

1. **Format coverage mismatch.** `kpd` reads KDB/KDBX3/KDBX4, but `save` only writes
   KDBX4.1 (and even KDBX4.0 is rejected). `kpd` must refuse to save older formats
   rather than silently convert/drop them.
2. **Lossy round-trip.** Extension/un-modeled XML fields are dropped on save. Needs a
   corpus of real KeePass + KeePassXC fixtures and a diff harness (ADR-0002) to
   enumerate what `kpd` would lose before any write is allowed.
3. **Weak new-DB defaults.** The crate's `Argon2d / 50 iter / 1 MiB` default is below
   modern guidance; `kpd` should pick stronger KDF params for new DBs while preserving
   existing files' params on re-save.
4. **Memory zeroization gaps (#391).** Secrets linger in plain buffers on the save
   path; decide whether `kpd` accepts this upstream limitation or mitigates.
5. **Open questions.** (a) Confirm `save`/`DatabaseSaveError` resolve in `kpd`'s own
   build after enabling `save_kdbx4` (docs.rs doesn't show them). (b) Verify history
   (`EntryTrack`), custom-data, and protected-field round-tripping against real
   KeePass files, not just the crate's self-round-trip tests. (c) Decide XML
   protected-vs-unprotected policy for custom data / notes / new fields `kpd` writes.
