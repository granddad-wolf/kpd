//! Live `WebDAV` integration test (ignored by default).
//!
//! Point it at a scratch `WebDAV` resource whose contents you do not mind
//! rewriting, then run:
//!
//! ```sh
//! WEBDAV_URL=http://127.0.0.1:8098/vault.kdbx \
//! WEBDAV_USER=kpd WEBDAV_PASS=dav-test-pw \
//!   cargo test -p kpd-storage --test webdav_live -- --ignored --nocapture
//! ```
//!
//! It overwrites the resource with its own current bytes, so it is safe for a
//! throwaway test file but not for a real database. Keep it as a single test:
//! `WebDAV` locks are exclusive, so parallel runs against one resource would
//! collide with 423 Locked.

use kpd_storage::{Storage, StorageError, WebDavStorage};

fn storage() -> WebDavStorage {
    let url = std::env::var("WEBDAV_URL").expect("WEBDAV_URL must be set");
    let user = std::env::var("WEBDAV_USER").ok();
    let pass = std::env::var("WEBDAV_PASS").ok();
    WebDavStorage::new(url, user, pass).expect("valid WebDAV URL")
}

#[tokio::test]
#[ignore = "requires WEBDAV_URL (+ WEBDAV_USER/WEBDAV_PASS) pointing at a scratch file"]
async fn conditional_write_round_trips_and_rejects_a_stale_revision() {
    let storage = storage();

    // The TUI reads the revision before downloading the bytes, so pin that
    // order here: a conditional write with the revision captured before the
    // read must succeed.
    let revision = storage.meta().await.expect("read remote metadata").revision;
    let original = storage.read().await.expect("read the remote file");
    println!("revision at unlock: {revision:?}");

    let meta = storage
        .write(&original, revision.as_deref())
        .await
        .expect("conditional write with the current revision");
    println!("revision after write: {:?}", meta.revision);

    // The pre-write revision is now stale: the next write must be refused.
    let err = storage
        .write(&original, revision.as_deref())
        .await
        .expect_err("a stale revision must be refused");
    println!("stale write error: {err}");
    assert!(matches!(err, StorageError::Conflict(_)), "{err:?}");

    // An unconditional write is still allowed.
    storage
        .write(&original, None)
        .await
        .expect("unconditional write");
}
