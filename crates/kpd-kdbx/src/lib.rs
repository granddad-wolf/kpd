//! KDBX decryption, parsing, and guarded writing, wrapping the `keepass` crate.
//!
//! Reads expose a read-only `kpd-core` projection; writes operate on the
//! decrypted `keepass::Database` kept alive in [`DbHandle`] and follow the
//! guarded-save recipe from ADR-0005.

use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use keepass::db::{
    fields, Database as KpDatabase, DatabaseOpenError, DatabaseSaveError, EntryId, GroupId,
};
use keepass::DatabaseKey;
use uuid::Uuid;

use kpd_core::db::Database;
use kpd_crypto::CompositeKey;

mod import;

/// Errors produced while opening or saving a KDBX database.
#[derive(Debug, thiserror::Error)]
pub enum KdbxError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("wrong master password, key file, or corrupt database")]
    WrongCredentials,
    #[error("unsupported or corrupt KDBX data: {0}")]
    Parse(String),
    #[error("this database format cannot be written (only KDBX 4.1 is supported for saving)")]
    UnsupportedForWrite,
    #[error(
        "this database was opened from memory and is not backed by a file; serialize it instead"
    )]
    NotFileBacked,
    #[error("the root group cannot be deleted")]
    CannotDeleteRoot,
}

/// A single editable field of an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryField {
    Title,
    UserName,
    Password,
    Url,
    Notes,
    /// A custom string field, stored protected by default.
    Custom(String),
}

/// Options controlling a guarded [`DbHandle::save`].
#[derive(Debug, Clone)]
pub struct SaveOptions {
    /// Write a `.bak` backup of the previous file before overwriting (default true).
    pub backup: bool,
    /// Use a timestamped suffix instead of the fixed `.bak` (default false).
    pub timestamped_backup: bool,
}

impl Default for SaveOptions {
    fn default() -> Self {
        Self {
            backup: true,
            timestamped_backup: false,
        }
    }
}

/// Outcome of a guarded save.
#[derive(Debug, Clone)]
pub struct SaveReport {
    /// Number of encrypted bytes written to the target file.
    pub bytes_written: usize,
    /// The round-trip re-open compared equal to the in-memory database.
    pub round_trip_ok: bool,
    /// Path of the `.bak` backup written, if any.
    pub backup_path: Option<PathBuf>,
    /// Human-readable warnings (e.g. the lossy-field caveat) to show the user.
    pub warnings: Vec<String>,
}

/// Standing caveat surfaced on every save: `keepass` re-serializes the inner
/// XML from its typed model, so any XML element the parser does not carry (such
/// as KeePassXC's `<PreviousParentGroup>`) is dropped.
const LOSSY_FIELD_WARNING: &str = "\
saving re-serializes the database from the in-memory model; un-modeled or \
vendor-extension XML fields (e.g. KeePassXC <PreviousParentGroup>) may be dropped";

/// A handle that owns the decrypted `keepass::Database` for the write path.
pub struct DbHandle {
    inner: KpDatabase,
    /// The file the database was opened from, for the guarded file save.
    /// `None` for a handle created by [`DbHandle::open_bytes`], which is
    /// serialized by the caller (e.g. to upload it to cloud storage).
    path: Option<PathBuf>,
}

impl DbHandle {
    /// Open and decrypt the KDBX database at `path`, keeping the parsed
    /// `keepass::Database` alive for later writes.
    ///
    /// # Errors
    ///
    /// Mirrors [`open`]: [`KdbxError::NotFound`] when `path` is missing,
    /// [`KdbxError::Io`] on read failures, [`KdbxError::WrongCredentials`] when
    /// the key does not decrypt the file, and [`KdbxError::Parse`] for corrupt
    /// or unsupported data.
    pub fn open(path: &Path, key: &CompositeKey) -> Result<Self, KdbxError> {
        let mut file = open_database_file(path)?;
        let db_key = build_database_key(key)?;

        let db = KpDatabase::open(&mut file, db_key).map_err(map_open_error)?;

        Ok(DbHandle {
            inner: db,
            path: Some(path.to_path_buf()),
        })
    }

    /// Open and decrypt a KDBX database from memory.
    ///
    /// The handle is not backed by a file: [`DbHandle::save`] returns
    /// [`KdbxError::NotFileBacked`], and the caller is expected to push
    /// [`DbHandle::serialize`] output wherever it came from (e.g. cloud
    /// storage). This is what the TUI uses for remote databases.
    ///
    /// # Errors
    ///
    /// Mirrors [`DbHandle::open`] except that there is no [`KdbxError::NotFound`]
    /// case: [`KdbxError::WrongCredentials`] when the key does not decrypt the
    /// bytes, and [`KdbxError::Parse`] for corrupt or unsupported data.
    pub fn open_bytes(bytes: &[u8], key: &CompositeKey) -> Result<Self, KdbxError> {
        let db = KpDatabase::open(&mut Cursor::new(bytes), build_database_key(key)?)
            .map_err(map_open_error)?;

        Ok(DbHandle {
            inner: db,
            path: None,
        })
    }

    /// The file backing this handle, if it was opened from one.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Read-only projection of the database for display/search.
    pub fn view(&self) -> Database {
        import::convert(&self.inner)
    }

    /// The database file-format version, e.g. `"KDBX4.0"` or `"KDBX4.1"`.
    pub fn version(&self) -> String {
        self.inner.config.version.to_string()
    }

    /// Whether the in-memory database is KDBX 4.1 — the only format the writer
    /// produces. KDBX 4.0 (and older) databases read fine but must be upgraded
    /// before they can be saved.
    pub fn is_kdbx41(&self) -> bool {
        matches!(
            self.inner.config.version,
            keepass::config::DatabaseVersion::KDB4(1)
        )
    }

    /// Upgrade the in-memory database to KDBX 4.1 so it can be saved. Cipher and
    /// KDF settings are preserved; only the file-format version changes. The
    /// original file is preserved by the `.bak` backup on save.
    pub fn upgrade_to_kdbx41(&mut self) {
        self.inner.config.version = keepass::config::DatabaseVersion::KDB4(1);
    }

    /// Serialize the in-memory database to KDBX 4.1 bytes.
    ///
    /// The bytes are round-trip verified before they are returned: a fresh
    /// in-memory database is re-opened from them and compared with `self`, so a
    /// caller that writes them (a file or a cloud backend) never persists data
    /// this writer cannot read back.
    ///
    /// # Errors
    ///
    /// Returns [`KdbxError::UnsupportedForWrite`] for databases that are not
    /// KDBX 4.1, and [`KdbxError::Parse`] on serialization or round-trip
    /// verification failures.
    pub fn serialize(&self, key: &CompositeKey) -> Result<Vec<u8>, KdbxError> {
        // 1. Serialize off-target; never write straight into the live file.
        let mut bytes = Vec::new();
        self.inner
            .save(&mut bytes, build_database_key(key)?)
            .map_err(map_save_error)?;

        // 2. Round-trip verify: re-open the freshly written bytes in memory and
        //    compare against the in-memory database. Abort without returning
        //    bytes if they do not round-trip.
        let reopened = KpDatabase::open(&mut Cursor::new(&bytes), build_database_key(key)?)
            .map_err(|err| KdbxError::Parse(format!("round-trip re-open failed: {err}")))?;
        if reopened != self.inner {
            return Err(KdbxError::Parse(
                "round-trip verification failed: the re-opened database differs from the in-memory database"
                    .to_string(),
            ));
        }

        Ok(bytes)
    }

    /// Guarded save per the ADR-0005 recipe.
    ///
    /// # Errors
    ///
    /// Returns [`KdbxError::NotFileBacked`] when the handle was created by
    /// [`DbHandle::open_bytes`], [`KdbxError::UnsupportedForWrite`] for
    /// databases that are not KDBX 4.1, [`KdbxError::Io`] on filesystem
    /// failures, and [`KdbxError::Parse`] on serialization or round-trip
    /// verification failures.
    pub fn save(&self, key: &CompositeKey, opts: &SaveOptions) -> Result<SaveReport, KdbxError> {
        let Some(path) = self.path.as_deref() else {
            return Err(KdbxError::NotFileBacked);
        };

        // 1–2. Serialize and round-trip verify before anything touches the disk.
        let bytes = self.serialize(key)?;

        // 3. Optional backup of the previous file, taken before anything is replaced.
        let backup_path = if opts.backup {
            backup_previous(path, opts.timestamped_backup)?
        } else {
            None
        };

        // 4. Atomic replace: temp file in the same directory, fsync, rename
        //    over the target, then fsync the parent directory (on Unix).
        write_atomically(path, &bytes)?;

        // 5. Always surface the lossy-field warning to the caller.
        Ok(SaveReport {
            bytes_written: bytes.len(),
            round_trip_ok: true,
            backup_path,
            warnings: vec![LOSSY_FIELD_WARNING.to_string()],
        })
    }

    /// Add an entry under `parent_uuid`; returns the new entry's UUID.
    ///
    /// # Errors
    ///
    /// Returns [`KdbxError::NotFound`] when `parent_uuid` does not name an
    /// existing group.
    pub fn add_entry(
        &mut self,
        parent_uuid: Uuid,
        title: &str,
        username: &str,
        password: &str,
    ) -> Result<Uuid, KdbxError> {
        let gid = GroupId::from_uuid(parent_uuid);
        let mut parent = self
            .inner
            .group_mut(gid)
            .ok_or_else(|| KdbxError::NotFound(format!("group not found: {parent_uuid}")))?;

        let mut entry = parent.add_entry();
        entry.set_unprotected(fields::TITLE, title);
        entry.set_unprotected(fields::USERNAME, username);
        entry.set_protected(fields::PASSWORD, password);

        Ok(entry.id().uuid())
    }

    /// Set one field of an entry (recorded in history).
    ///
    /// `Password` and [`EntryField::Custom`] values are stored protected; the
    /// other fields are stored unprotected.
    ///
    /// # Errors
    ///
    /// Returns [`KdbxError::NotFound`] when `entry_uuid` does not name an
    /// existing entry.
    pub fn set_entry_field(
        &mut self,
        entry_uuid: Uuid,
        field: EntryField,
        value: &str,
    ) -> Result<(), KdbxError> {
        let eid = EntryId::from_uuid(entry_uuid);
        let mut entry = self
            .inner
            .entry_mut(eid)
            .ok_or_else(|| KdbxError::NotFound(format!("entry not found: {entry_uuid}")))?;

        entry.edit_tracking(|tracked| match field {
            EntryField::Title => tracked.set_unprotected(fields::TITLE, value),
            EntryField::UserName => tracked.set_unprotected(fields::USERNAME, value),
            EntryField::Password => tracked.set_protected(fields::PASSWORD, value),
            EntryField::Url => tracked.set_unprotected(fields::URL, value),
            EntryField::Notes => tracked.set_unprotected(fields::NOTES, value),
            EntryField::Custom(key) => tracked.set_protected(key, value),
        });

        Ok(())
    }

    /// Hard-delete an entry (records a `deleted_objects` tombstone).
    ///
    /// # Errors
    ///
    /// Returns [`KdbxError::NotFound`] when `entry_uuid` does not name an
    /// existing entry.
    pub fn delete_entry(&mut self, entry_uuid: Uuid) -> Result<(), KdbxError> {
        let eid = EntryId::from_uuid(entry_uuid);
        let mut entry = self
            .inner
            .entry_mut(eid)
            .ok_or_else(|| KdbxError::NotFound(format!("entry not found: {entry_uuid}")))?;

        entry.track_changes().remove();
        Ok(())
    }

    /// Add a child group under `parent_uuid`; returns the new group's UUID.
    ///
    /// # Errors
    ///
    /// Returns [`KdbxError::NotFound`] when `parent_uuid` does not name an
    /// existing group.
    pub fn add_group(&mut self, parent_uuid: Uuid, name: &str) -> Result<Uuid, KdbxError> {
        let gid = GroupId::from_uuid(parent_uuid);
        let mut parent = self
            .inner
            .group_mut(gid)
            .ok_or_else(|| KdbxError::NotFound(format!("group not found: {parent_uuid}")))?;

        let mut group = parent.add_group();
        group.name = name.to_string();

        Ok(group.id().uuid())
    }

    /// Hard-delete a group and its descendants (root refused).
    ///
    /// # Errors
    ///
    /// Returns [`KdbxError::CannotDeleteRoot`] when `group_uuid` names the root
    /// group, and [`KdbxError::NotFound`] when it does not name any group.
    pub fn delete_group(&mut self, group_uuid: Uuid) -> Result<(), KdbxError> {
        let gid = GroupId::from_uuid(group_uuid);

        if gid == self.inner.root().id() {
            return Err(KdbxError::CannotDeleteRoot);
        }

        let mut group = self
            .inner
            .group_mut(gid)
            .ok_or_else(|| KdbxError::NotFound(format!("group not found: {group_uuid}")))?;

        group
            .track_changes()
            .remove()
            .map_err(|_| KdbxError::CannotDeleteRoot)?;
        Ok(())
    }
}

/// Open and decrypt a KDBX database into the `kpd-core` domain model.
///
/// This is a convenience wrapper around [`DbHandle::open`] that immediately
/// drops the `keepass::Database` after projecting it, and is therefore
/// read-only.
///
/// # Errors
///
/// Returns [`KdbxError::NotFound`] when `path` does not exist,
/// [`KdbxError::Io`] when the database file or an associated key file cannot be
/// read, [`KdbxError::WrongCredentials`] when the password/key file does not
/// decrypt the database, and [`KdbxError::Parse`] for unsupported or corrupt
/// KDBX data.
pub fn open(path: &Path, key: &CompositeKey) -> Result<Database, KdbxError> {
    DbHandle::open(path, key).map(|handle| handle.view())
}

fn open_database_file(path: &Path) -> Result<File, KdbxError> {
    File::open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            KdbxError::NotFound(path.display().to_string())
        } else {
            KdbxError::Io(err)
        }
    })
}

fn build_database_key(key: &CompositeKey) -> Result<DatabaseKey, KdbxError> {
    let mut db_key = DatabaseKey::new();

    if let Some(password) = key.password() {
        db_key = db_key.with_password(password);
    }

    if let Some(keyfile_path) = key.key_file_path() {
        let mut keyfile = File::open(keyfile_path)?;
        db_key = db_key
            .with_keyfile(&mut keyfile)
            .map_err(|e| KdbxError::Parse(format!("invalid key file: {e}")))?;
    }

    Ok(db_key)
}

/// Map a `keepass` open error onto our public error type.
///
/// `Key` and `Cryptography` failures both mean the supplied credentials did not
/// decrypt the database (or the data is corrupted in a way that is
/// indistinguishable from a wrong key at this layer), so both map to
/// [`KdbxError::WrongCredentials`]. Everything else that is not I/O is a format
/// problem and maps to [`KdbxError::Parse`].
fn map_open_error(err: DatabaseOpenError) -> KdbxError {
    use DatabaseOpenError::{Cryptography, Io, Key};

    match err {
        Io(e) => KdbxError::Io(e),
        Key(_) | Cryptography(_) => KdbxError::WrongCredentials,
        other => KdbxError::Parse(other.to_string()),
    }
}

/// Map a `keepass` save error onto our public error type.
///
/// `UnsupportedVersion` means the database is KDB/KDBX2/KDBX3/KDBX4.0 and must
/// be refused, never silently converted; every other non-I/O failure (`Key`,
/// `Cryptography`, `Serialization`, `Random`, and any future variant) is a
/// serialization/format problem and maps to [`KdbxError::Parse`].
fn map_save_error(err: DatabaseSaveError) -> KdbxError {
    match err {
        DatabaseSaveError::Io(e) => KdbxError::Io(e),
        DatabaseSaveError::UnsupportedVersion => KdbxError::UnsupportedForWrite,
        other => KdbxError::Parse(other.to_string()),
    }
}

/// Copy the current database file to a `.bak` sibling, returning the backup
/// path. `timestamped` appends a UTC timestamp before the `.bak` suffix. When
/// the source file no longer exists, no backup is made.
fn backup_previous(path: &Path, timestamped: bool) -> Result<Option<PathBuf>, KdbxError> {
    if !path.exists() {
        return Ok(None);
    }

    let mut name = path.as_os_str().to_os_string();
    if timestamped {
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        name.push(format!(".{stamp}.bak"));
    } else {
        name.push(".bak");
    }
    let backup = PathBuf::from(name);

    fs::copy(path, &backup).map_err(KdbxError::Io)?;
    Ok(Some(backup))
}

/// Write `bytes` to a temp file in `path`'s directory, fsync it, rename it over
/// `path`, and fsync the parent directory on Unix. The temp file is removed on
/// failure.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), KdbxError> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        KdbxError::Parse(format!(
            "cannot determine the file name of {}",
            path.display()
        ))
    })?;

    // `create_new` makes the temp-file create atomic; the retry loop tolerates
    // stale leftovers from a previous crashed run.
    let mut temp_path = None;
    for attempt in 0..100u32 {
        let candidate = dir.join(format!(
            ".{}.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            attempt
        ));

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                // Write and fsync; on any failure, remove the temp file so an
                // error or crash never leaves a stray partial file behind.
                let write_result = file.write_all(bytes).and_then(|()| file.sync_all());
                drop(file);
                if let Err(e) = write_result {
                    let _ = fs::remove_file(&candidate);
                    return Err(KdbxError::Io(e));
                }
                temp_path = Some(candidate);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(KdbxError::Io(e)),
        }
    }

    let temp_path = temp_path.ok_or_else(|| {
        KdbxError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not create a unique temporary file next to the target",
        ))
    })?;

    if let Err(e) = fs::rename(&temp_path, path).and_then(|()| sync_parent_dir(dir)) {
        let _ = fs::remove_file(&temp_path);
        return Err(KdbxError::Io(e));
    }

    Ok(())
}

/// fsync the parent directory so the rename itself is durable.
#[cfg(unix)]
fn sync_parent_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// On non-Unix platforms directory fsync is not available; the rename is still
/// performed (and the file itself was already fsynced).
#[cfg(not(unix))]
fn sync_parent_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::fields;
    use secrecy::ExposeSecret;

    const PASSWORD: &str = "correct horse battery staple";

    /// An in-memory database with one entry, built with the crate's builders
    /// (no real KeePass binary fixture needed).
    fn sample_db() -> KpDatabase {
        let mut db = KpDatabase::new();
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "Example");
            entry.set_unprotected(fields::USERNAME, "alice");
            entry.set_protected(fields::PASSWORD, "hunter2");
        }
        db
    }

    /// A unique path in the system temp dir for a throwaway `.kdbx`.
    fn unique_temp_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "kpd-kdbx-{}-{}-{}.kdbx",
            tag,
            std::process::id(),
            nanos
        ))
    }

    /// Removes every tracked file on drop, so temp files are cleaned up even if
    /// an assertion fails.
    struct TempFiles(Vec<PathBuf>);

    impl TempFiles {
        fn track(&mut self, path: impl Into<PathBuf>) -> PathBuf {
            let path = path.into();
            self.0.push(path.clone());
            path
        }
    }

    impl Drop for TempFiles {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = fs::remove_file(path);
            }
        }
    }

    #[test]
    fn save_round_trips_creates_backup_and_warns() {
        let mut cleanup = TempFiles(Vec::new());
        let path = cleanup.track(unique_temp_path("roundtrip"));
        let key = CompositeKey::new().with_password(PASSWORD);

        // Seed an on-disk file for `DbHandle::open` to load.
        {
            let db = sample_db();
            let mut file = File::create(&path).expect("create seed file");
            db.save(&mut file, build_database_key(&key).expect("seed key"))
                .expect("seed save");
        }

        let handle = DbHandle::open(&path, &key).expect("open handle");

        // Content is visible through the read-only projection.
        let view = handle.view();
        assert_eq!(view.root.entries.len(), 1);
        assert_eq!(view.root.entries[0].title, "Example");
        assert_eq!(view.root.entries[0].password.expose_secret(), "hunter2");

        let report = handle
            .save(&key, &SaveOptions::default())
            .expect("guarded save");

        assert!(report.round_trip_ok);
        assert!(report.bytes_written > 0);

        // A fixed `.bak` backup was written next to the target.
        let backup = report.backup_path.expect("a .bak backup path");
        cleanup.track(backup.clone());
        assert!(backup.exists());

        // The lossy-field warning is always present.
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("PreviousParentGroup")));

        // The file on disk still opens to the same content.
        let reopened = DbHandle::open(&path, &key).expect("reopen after save");
        let reopened_view = reopened.view();
        assert_eq!(reopened_view.root.entries.len(), 1);
        assert_eq!(reopened_view.root.entries[0].title, "Example");
        assert_eq!(
            reopened_view.root.entries[0].password.expose_secret(),
            "hunter2"
        );
    }

    #[test]
    fn save_timestamped_backup_uses_a_timestamped_name() {
        let mut cleanup = TempFiles(Vec::new());
        let path = cleanup.track(unique_temp_path("timestamped"));
        let key = CompositeKey::new().with_password(PASSWORD);

        {
            let db = sample_db();
            let mut file = File::create(&path).expect("create seed file");
            db.save(&mut file, build_database_key(&key).expect("seed key"))
                .expect("seed save");
        }

        let handle = DbHandle::open(&path, &key).expect("open handle");

        let report = handle
            .save(
                &key,
                &SaveOptions {
                    backup: true,
                    timestamped_backup: true,
                },
            )
            .expect("timestamped save");

        assert!(report.round_trip_ok);

        let backup = report.backup_path.expect("a timestamped backup path");
        cleanup.track(backup.clone());
        assert!(backup.exists());

        // It is not the fixed `.bak` sibling, and it still ends in `.bak`.
        let fixed = PathBuf::from(format!("{}.bak", path.display()));
        assert_ne!(backup, fixed);
        assert!(backup
            .file_name()
            .expect("backup file name")
            .to_string_lossy()
            .ends_with(".bak"));
    }

    /// Seed a throwaway `.kdbx` from [`sample_db`] on disk and return its path
    /// and the key used to encrypt it.
    fn seed_file(cleanup: &mut TempFiles, tag: &str) -> (PathBuf, CompositeKey) {
        let path = cleanup.track(unique_temp_path(tag));
        let key = CompositeKey::new().with_password(PASSWORD);
        let db = sample_db();
        let mut file = File::create(&path).expect("create seed file");
        db.save(&mut file, build_database_key(&key).expect("seed key"))
            .expect("seed save");
        (path, key)
    }

    #[test]
    fn add_entry_returns_uuid_and_entry_appears_protected() {
        let mut cleanup = TempFiles(Vec::new());
        let (path, key) = seed_file(&mut cleanup, "add-entry");
        let mut handle = DbHandle::open(&path, &key).expect("open handle");

        let root_uuid = handle.view().root.uuid;
        let new_uuid = handle
            .add_entry(root_uuid, "New Site", "bob", "s3cret")
            .expect("add entry");

        let view = handle.view();
        assert_eq!(view.root.entries.len(), 2);
        let added = view
            .root
            .entries
            .iter()
            .find(|entry| entry.uuid == new_uuid)
            .expect("added entry present");
        assert_eq!(added.title, "New Site");
        assert_eq!(added.username, "bob");
        assert_eq!(added.password.expose_secret(), "s3cret");

        // The read-only projection does not surface protection for the standard
        // fields, so check the keepass entry directly.
        let kp_entry = handle
            .inner
            .entry(EntryId::from_uuid(new_uuid))
            .expect("keepass entry present");
        assert!(kp_entry.fields[fields::PASSWORD].is_protected());
        assert!(!kp_entry.fields[fields::TITLE].is_protected());
        assert!(!kp_entry.fields[fields::USERNAME].is_protected());
    }

    #[test]
    fn set_entry_field_updates_title_and_records_history() {
        let mut cleanup = TempFiles(Vec::new());
        let (path, key) = seed_file(&mut cleanup, "set-field");
        let mut handle = DbHandle::open(&path, &key).expect("open handle");

        let entry_uuid = handle.view().root.entries[0].uuid;

        handle
            .set_entry_field(entry_uuid, EntryField::Title, "Renamed")
            .expect("set field");

        let view = handle.view();
        let entry = view
            .root
            .entries
            .iter()
            .find(|entry| entry.uuid == entry_uuid)
            .expect("entry present");
        assert_eq!(entry.title, "Renamed");
        // `edit_tracking` snapshots the pre-edit entry ("Example") into history.
        assert_eq!(entry.history.len(), 1);
        assert_eq!(entry.history[0].title, "Example");
        // The tracked edit also bumps `last_modification`.
        assert!(entry.times.last_modification.is_some());
    }

    #[test]
    fn set_entry_field_maps_protection_by_field_type() {
        let mut cleanup = TempFiles(Vec::new());
        let (path, key) = seed_file(&mut cleanup, "field-protection");
        let mut handle = DbHandle::open(&path, &key).expect("open handle");

        let entry_uuid = handle.view().root.entries[0].uuid;

        handle
            .set_entry_field(entry_uuid, EntryField::UserName, "carol")
            .expect("set username");
        handle
            .set_entry_field(entry_uuid, EntryField::Password, "new-pass")
            .expect("set password");
        handle
            .set_entry_field(entry_uuid, EntryField::Url, "https://x.example")
            .expect("set url");
        handle
            .set_entry_field(entry_uuid, EntryField::Notes, "a note")
            .expect("set notes");
        handle
            .set_entry_field(
                entry_uuid,
                EntryField::Custom("TOTP Seed".to_string()),
                "secret",
            )
            .expect("set custom");

        let view = handle.view();
        let entry = view
            .root
            .entries
            .iter()
            .find(|entry| entry.uuid == entry_uuid)
            .expect("entry present");
        assert_eq!(entry.username, "carol");
        assert_eq!(entry.password.expose_secret(), "new-pass");
        assert_eq!(entry.url.as_deref(), Some("https://x.example"));
        assert_eq!(entry.notes.as_deref(), Some("a note"));

        let totp = entry
            .custom_fields
            .iter()
            .find(|field| field.key == "TOTP Seed")
            .expect("custom field present");
        assert!(totp.protected);
        assert_eq!(totp.value.expose_secret(), "secret");

        // Standard fields keep the `Password`/`Custom`-protected rule at the
        // keepass layer too.
        let kp_entry = handle
            .inner
            .entry(EntryId::from_uuid(entry_uuid))
            .expect("keepass entry present");
        assert!(!kp_entry.fields[fields::USERNAME].is_protected());
        assert!(kp_entry.fields[fields::PASSWORD].is_protected());
        assert!(!kp_entry.fields[fields::URL].is_protected());
        assert!(!kp_entry.fields[fields::NOTES].is_protected());
        assert!(kp_entry.fields["TOTP Seed"].is_protected());
    }

    #[test]
    fn delete_entry_removes_it_and_records_tombstone() {
        let mut cleanup = TempFiles(Vec::new());
        let (path, key) = seed_file(&mut cleanup, "delete-entry");
        let mut handle = DbHandle::open(&path, &key).expect("open handle");

        let entry_uuid = handle.view().root.entries[0].uuid;

        handle.delete_entry(entry_uuid).expect("delete entry");

        let view = handle.view();
        assert!(view.root.entries.is_empty());
        assert!(view.entry(entry_uuid).is_none());
        assert!(handle.inner.deleted_objects.contains_key(&entry_uuid));
    }

    #[test]
    fn add_group_nests_under_parent() {
        let mut cleanup = TempFiles(Vec::new());
        let (path, key) = seed_file(&mut cleanup, "add-group");
        let mut handle = DbHandle::open(&path, &key).expect("open handle");

        let root_uuid = handle.view().root.uuid;
        let child_uuid = handle.add_group(root_uuid, "Child").expect("add child");
        let grandchild_uuid = handle
            .add_group(child_uuid, "Grandchild")
            .expect("add grandchild");

        let view = handle.view();
        assert_eq!(view.root.children.len(), 1);

        let child = &view.root.children[0];
        assert_eq!(child.uuid, child_uuid);
        assert_eq!(child.name, "Child");
        assert_eq!(child.children.len(), 1);
        assert_eq!(child.children[0].uuid, grandchild_uuid);
        assert_eq!(child.children[0].name, "Grandchild");
    }

    #[test]
    fn delete_group_removes_subtree() {
        let mut cleanup = TempFiles(Vec::new());
        let (path, key) = seed_file(&mut cleanup, "delete-group");
        let mut handle = DbHandle::open(&path, &key).expect("open handle");

        let root_uuid = handle.view().root.uuid;
        let child_uuid = handle.add_group(root_uuid, "Child").expect("add child");
        let child_entry_uuid = handle
            .add_entry(child_uuid, "In child", "bob", "pw")
            .expect("add entry in child");

        handle.delete_group(child_uuid).expect("delete group");

        let view = handle.view();
        assert!(view.root.children.is_empty());
        assert!(view.group_by_uuid(child_uuid).is_none());
        // The entry that lived inside the deleted subtree is gone, but the
        // seed entry still lives under the root.
        assert!(view.entry(child_entry_uuid).is_none());
        assert_eq!(view.all_entries().len(), 1);
        assert_eq!(view.all_entries()[0].entry_uuid, view.root.entries[0].uuid);
    }

    #[test]
    fn delete_group_refuses_root() {
        let mut cleanup = TempFiles(Vec::new());
        let (path, key) = seed_file(&mut cleanup, "delete-root");
        let mut handle = DbHandle::open(&path, &key).expect("open handle");

        let root_uuid = handle.view().root.uuid;
        let err = handle
            .delete_group(root_uuid)
            .expect_err("root deletion refused");
        assert!(matches!(err, KdbxError::CannotDeleteRoot));

        // The database is untouched.
        let view = handle.view();
        assert_eq!(view.root.entries.len(), 1);
        assert_eq!(view.root.entries[0].title, "Example");
    }

    #[test]
    fn mutations_return_not_found_for_missing_ids() {
        let mut cleanup = TempFiles(Vec::new());
        let (path, key) = seed_file(&mut cleanup, "not-found");
        let mut handle = DbHandle::open(&path, &key).expect("open handle");

        let bogus = Uuid::new_v4();

        assert!(matches!(
            handle.add_entry(bogus, "t", "u", "p"),
            Err(KdbxError::NotFound(_))
        ));
        assert!(matches!(
            handle.set_entry_field(bogus, EntryField::Title, "x"),
            Err(KdbxError::NotFound(_))
        ));
        assert!(matches!(
            handle.delete_entry(bogus),
            Err(KdbxError::NotFound(_))
        ));
        assert!(matches!(
            handle.add_group(bogus, "g"),
            Err(KdbxError::NotFound(_))
        ));
        assert!(matches!(
            handle.delete_group(bogus),
            Err(KdbxError::NotFound(_))
        ));
    }

    #[test]
    fn open_bytes_round_trips_and_serialize_reproduces_content() {
        let mut cleanup = TempFiles(Vec::new());
        let (path, key) = seed_file(&mut cleanup, "open-bytes");

        let original = fs::read(&path).expect("read seed file");
        let mut handle = DbHandle::open_bytes(&original, &key).expect("open from bytes");

        // The memory-backed handle has no path and refuses a file save.
        assert_eq!(handle.path(), None);
        assert!(matches!(
            handle.save(&key, &SaveOptions::default()),
            Err(KdbxError::NotFileBacked)
        ));

        // Mutate, serialize, and re-open the serialized bytes.
        let root_uuid = handle.view().root.uuid;
        handle
            .add_entry(root_uuid, "Cloud Entry", "carol", "pa55")
            .expect("add entry");
        let bytes = handle.serialize(&key).expect("serialize");
        assert!(!bytes.is_empty());

        let reopened = DbHandle::open_bytes(&bytes, &key).expect("reopen serialized bytes");
        let view = reopened.view();
        assert_eq!(view.root.entries.len(), 2);
        assert!(view
            .root
            .entries
            .iter()
            .any(|entry| entry.title == "Cloud Entry"));

        // Serialized bytes are a real KDBX file: they open through the
        // file-backed path too.
        let serialized_path = cleanup.track(unique_temp_path("serialized"));
        fs::write(&serialized_path, &bytes).expect("write serialized");
        let handle = DbHandle::open(&serialized_path, &key).expect("open serialized file");
        assert_eq!(handle.view().root.entries.len(), 2);
    }

    #[test]
    fn serialize_refuses_to_write_with_a_wrong_key() {
        let key = CompositeKey::new().with_password(PASSWORD);
        let wrong = CompositeKey::new().with_password("not the password");

        let mut bytes = Vec::new();
        sample_db()
            .save(&mut bytes, build_database_key(&key).expect("key"))
            .expect("save sample");

        assert!(matches!(
            DbHandle::open_bytes(&bytes, &wrong),
            Err(KdbxError::WrongCredentials)
        ));
    }
}
