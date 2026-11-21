//! Local filesystem backend.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::{Meta, Storage, StorageError};

/// A database stored as a plain file on the local filesystem.
///
/// Writes are atomic: the new bytes are written to a temporary file in the same
/// directory and then `rename`d over the target, so a crash can never leave a
/// half-written database. Writes also hold an exclusive advisory lock on a
/// sibling `.<name>.lock` file across the revision check *and* the rename, so
/// concurrent kpd writers cannot both pass the check and clobber each other.
/// The lock is advisory: writers that do not take it (other tools, or file
/// systems that ignore locks) are not serialized.
///
/// `revision` is the SHA-256 of the file's contents (`sha256-<hex>`), so any
/// byte change is observable regardless of file length or filesystem timestamp
/// granularity; computing it therefore reads the file.
pub struct LocalStorage {
    path: PathBuf,
}

impl LocalStorage {
    /// Create a backend rooted at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait::async_trait]
impl Storage for LocalStorage {
    async fn read(&self) -> Result<Vec<u8>, StorageError> {
        fs::read(&self.path).map_err(|e| map_io_error(&self.path, e))
    }

    async fn write(
        &self,
        data: &[u8],
        expected_revision: Option<&str>,
    ) -> Result<Meta, StorageError> {
        // Serialize the whole check-and-rename with other kpd writers: without
        // the lock two conditional writers could both read the same revision and
        // then overwrite each other (a lost update). The guard is released when
        // it drops at the end of this function.
        let _lock = acquire_write_lock(&self.path)?;

        // Optimistic-concurrency check against the pre-write revision. A missing
        // file has revision `None`, so any `Some(expected)` conflicts.
        if let Some(expected) = expected_revision {
            let current = match current_revision(&self.path)? {
                Some(rev) => rev,
                None => {
                    return Err(StorageError::Conflict(format!(
                        "expected revision {expected}, but the file does not exist"
                    )));
                }
            };
            if current.as_str() != expected {
                return Err(StorageError::Conflict(format!(
                    "expected revision {expected}, found {current}"
                )));
            }
        }

        write_atomic(&self.path, data)
    }

    async fn exists(&self) -> Result<bool, StorageError> {
        match fs::metadata(&self.path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    async fn meta(&self) -> Result<Meta, StorageError> {
        let data = fs::read(&self.path).map_err(|e| map_io_error(&self.path, e))?;
        Ok(Meta {
            revision: Some(revision_for(&data)),
        })
    }
}

/// Map an I/O error to [`StorageError`], turning `NotFound` into [`StorageError::NotFound`].
fn map_io_error(path: &Path, err: std::io::Error) -> StorageError {
    if err.kind() == std::io::ErrorKind::NotFound {
        StorageError::NotFound(path.display().to_string())
    } else {
        StorageError::Io(err)
    }
}

/// Current revision string, or `None` when the file does not exist.
///
/// Derived from the file's contents (not its metadata), so a rewrite that keeps
/// the same length is still detectable.
fn current_revision(path: &Path) -> Result<Option<String>, StorageError> {
    match fs::read(path) {
        Ok(data) => Ok(Some(revision_for(&data))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StorageError::Io(e)),
    }
}

/// The opaque revision token for `data`: `sha256-<lowercase hex digest>`.
///
/// Content-derived so every byte change produces a new token, including
/// same-length rewrites within one filesystem-timestamp tick.
fn revision_for(data: &[u8]) -> String {
    format!("sha256-{:x}", Sha256::digest(data))
}

/// An exclusive advisory lock guarding one database's read-check-rename window.
///
/// The underlying lock file is a stable sibling path, so renaming the database
/// itself never invalidates the lock. Dropping the guard unlocks and closes it.
struct WriteLock {
    file: fs::File,
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        // Closing the handle would release the lock too; unlocking explicitly
        // makes the intent clear. There is no useful error to report here.
        let _ = self.file.unlock();
    }
}

/// The sibling file used as the lock target for `path`: `.<name>.lock`.
fn lock_path(path: &Path) -> PathBuf {
    let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("kpd");
    path.with_file_name(format!(".{base}.lock"))
}

/// Block until the exclusive write lock for `path` is held.
///
/// The lock file is created on demand and intentionally left in place: removing
/// it on unlock would let a later writer create a fresh inode and bypass a
/// waiter still holding the old one.
fn acquire_write_lock(path: &Path) -> Result<WriteLock, StorageError> {
    let lock_path = lock_path(path);
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(StorageError::Io)?;
    file.lock().map_err(StorageError::Io)?;
    Ok(WriteLock { file })
}

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Write `data` to `path` atomically: temp file in the same directory, `sync_all`,
/// then `rename` over the target.
fn write_atomic(path: &Path, data: &[u8]) -> Result<Meta, StorageError> {
    let tmp = temp_path(path);

    let result = (|| -> Result<(), StorageError> {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(data)?;
        // Flush to the device before the rename so a crash after rename cannot
        // surface a file whose contents were never persisted.
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // The token describes the bytes this call wrote, so it can be handed back
    // as `expected_revision` without re-reading the file.
    Ok(Meta {
        revision: Some(revision_for(data)),
    })
}

/// A unique temporary path in the same directory as `path`.
fn temp_path(path: &Path) -> PathBuf {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("kpd");
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(".{base}.tmp-{pid}-{nanos}-{seq}"))
}

#[cfg(test)]
mod tests {
    use super::LocalStorage;
    use crate::{Storage, StorageError};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A unique, self-cleaning temp directory per test.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let unique = format!(
                "kpd-storage-{name}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock after epoch")
                    .as_nanos()
            );
            let dir = std::env::temp_dir().join(unique);
            fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn dir_entries(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .expect("read temp dir")
            .map(|e| {
                e.expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    #[tokio::test]
    async fn round_trip_write_then_read() {
        let dir = TempDir::new("roundtrip");
        let storage = LocalStorage::new(dir.file("db.kdbx"));

        let data = b"kpd database bytes".to_vec();
        let meta = storage.write(&data, None).await.expect("write");
        assert!(meta.revision.is_some());

        assert_eq!(storage.read().await.expect("read"), data);
        assert!(storage.exists().await.expect("exists"));
        assert_eq!(
            meta.revision.as_deref(),
            storage.meta().await.expect("meta").revision.as_deref()
        );
    }

    #[tokio::test]
    async fn revision_changes_after_write() {
        let dir = TempDir::new("revision-change");
        let storage = LocalStorage::new(dir.file("db.kdbx"));

        // Same length on purpose: a content-derived revision must still change.
        let first = storage.write(b"aaaa", None).await.expect("first write");
        let second = storage.write(b"bbbb", None).await.expect("second write");

        assert_ne!(first.revision, second.revision);
        assert_eq!(
            second.revision.as_deref(),
            storage.meta().await.expect("meta").revision.as_deref()
        );
    }

    #[tokio::test]
    async fn revision_is_a_content_digest() {
        let dir = TempDir::new("revision-format");
        let storage = LocalStorage::new(dir.file("db.kdbx"));

        let data = b"hello world";
        let meta = storage.write(data, None).await.expect("write");
        let rev = meta.revision.expect("revision present");

        // `sha256-` followed by 64 lowercase hex digits, stable across reads.
        let hex = rev.strip_prefix("sha256-").expect("sha256- prefix");
        assert_eq!(hex.len(), 64);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(rev, super::revision_for(data));
        assert_eq!(
            Some(rev.as_str()),
            storage.meta().await.expect("meta").revision.as_deref()
        );
    }

    #[tokio::test]
    async fn write_conflicts_on_stale_revision() {
        let dir = TempDir::new("conflict");
        let storage = LocalStorage::new(dir.file("db.kdbx"));

        let meta = storage
            .write(b"original", None)
            .await
            .expect("initial write");
        let stale = meta.revision.expect("revision present");

        // A concurrent, unconditional writer changes the file out from under us.
        // The payload is the same length as the original on purpose: this is the
        // regression case where a metadata-only revision could miss the change.
        storage
            .write(b"changed!", None)
            .await
            .expect("concurrent write");

        let err = storage
            .write(b"mine", Some(stale.as_str()))
            .await
            .expect_err("stale revision must conflict");
        assert!(matches!(err, StorageError::Conflict(_)));

        // The failed conditional write must not have clobbered the change.
        assert_eq!(storage.read().await.expect("read"), b"changed!");
    }

    #[tokio::test]
    async fn write_with_expected_revision_on_missing_file_conflicts() {
        let dir = TempDir::new("conflict-missing");
        let storage = LocalStorage::new(dir.file("db.kdbx"));

        let err = storage
            .write(b"data", Some("some-revision"))
            .await
            .expect_err("missing file with expected revision must conflict");
        assert!(matches!(err, StorageError::Conflict(_)));
    }

    #[tokio::test]
    async fn missing_file_is_not_found() {
        let dir = TempDir::new("not-found");
        let storage = LocalStorage::new(dir.file("missing.kdbx"));

        assert!(!storage.exists().await.expect("exists"));
        assert!(matches!(
            storage.read().await.expect_err("read"),
            StorageError::NotFound(_)
        ));
        assert!(matches!(
            storage.meta().await.expect_err("meta"),
            StorageError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn atomic_write_leaves_no_temp_remnants() {
        let dir = TempDir::new("atomic");
        let path = dir.file("db.kdbx");
        let storage = LocalStorage::new(&path);

        storage.write(b"atomic payload", None).await.expect("write");

        assert_eq!(fs::read(&path).expect("read back"), b"atomic payload");

        let mut names = dir_entries(dir.path());
        names.sort();
        assert_eq!(
            names,
            vec![".db.kdbx.lock".to_string(), "db.kdbx".to_string()]
        );
    }

    #[tokio::test]
    async fn failed_write_leaves_no_temp_remnants() {
        let dir = TempDir::new("atomic-fail");
        let storage = LocalStorage::new(dir.file("db.kdbx"));

        storage.write(b"v1", None).await.expect("first write");
        let rev = storage
            .meta()
            .await
            .expect("meta")
            .revision
            .expect("revision");
        storage.write(b"v2", None).await.expect("second write");

        // A stale revision conflicts and must not leave a temp file behind.
        assert!(matches!(
            storage.write(b"v3", Some(rev.as_str())).await,
            Err(StorageError::Conflict(_))
        ));

        let mut names = dir_entries(dir.path());
        names.sort();
        assert_eq!(
            names,
            vec![".db.kdbx.lock".to_string(), "db.kdbx".to_string()]
        );
    }

    /// Concurrent conditional writers must serialize: exactly one wins, and the
    /// rest observe a conflict instead of silently overwriting the winner.
    #[test]
    fn concurrent_conditional_writes_have_one_winner() {
        use std::sync::{Arc, Barrier};

        const WRITERS: usize = 8;

        let dir = TempDir::new("concurrent");
        let path = dir.file("db.kdbx");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build runtime");

        let initial = runtime
            .block_on(LocalStorage::new(&path).write(b"initial", None))
            .expect("initial write");
        let revision = initial.revision.expect("revision present");

        let barrier = Arc::new(Barrier::new(WRITERS));
        let handles: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let path = path.clone();
                let revision = revision.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .build()
                        .expect("build runtime");
                    let storage = LocalStorage::new(path);
                    // Line every writer up so they race on the lock together.
                    barrier.wait();
                    runtime.block_on(storage.write(
                        format!("writer-{writer}").as_bytes(),
                        Some(revision.as_str()),
                    ))
                })
            })
            .collect();

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("writer thread"))
            .collect();

        let winners = results.iter().filter(|result| result.is_ok()).count();
        assert_eq!(winners, 1, "exactly one conditional write may win");
        assert!(
            results
                .iter()
                .filter(|result| result.is_err())
                .all(|result| matches!(result, Err(StorageError::Conflict(_)))),
            "losers must conflict: {results:?}"
        );

        // The stored bytes and the reported revision belong to the single winner.
        let contents = runtime
            .block_on(LocalStorage::new(&path).read())
            .expect("read back");
        assert!(contents.starts_with(b"writer-"));
        let winner = results
            .iter()
            .find_map(|result| result.as_ref().ok())
            .expect("one winner");
        assert_eq!(
            runtime
                .block_on(LocalStorage::new(&path).meta())
                .expect("meta")
                .revision
                .as_deref(),
            winner.revision.as_deref()
        );
    }
}
