//! End-to-end write round-trip against a real KeePass database.
//!
//! Opens a **copy** of `KPD_TEST_DB`, adds an entry, performs a guarded save,
//! and verifies the result by reopening it. The source database is never
//! modified.
//!
//! The saved file is left at `<temp>/kpd-write-test.kdbx` (and its `.bak`) so
//! you can confirm another KeePass-compatible tool still opens it.

use std::path::PathBuf;

use kpd_crypto::CompositeKey;
use kpd_kdbx::{DbHandle, SaveOptions};

fn temp_db_path() -> PathBuf {
    std::env::temp_dir().join("kpd-write-test.kdbx")
}

#[test]
#[ignore = "requires KPD_TEST_DB + KPD_TEST_PASSWORD; operates on a temp copy"]
fn write_round_trip_on_real_database() {
    let src = std::env::var("KPD_TEST_DB").expect("KPD_TEST_DB must point to a real .kdbx");
    let password = std::env::var("KPD_TEST_PASSWORD").expect("KPD_TEST_PASSWORD must be set");
    let key = CompositeKey::new().with_password(password);

    // Fresh copy so the source is never modified.
    let db_path = temp_db_path();
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(db_path.with_extension("kdbx.bak"));
    std::fs::copy(&src, &db_path).expect("copy the source database");

    let mut handle = DbHandle::open(&db_path, &key).expect("open the copied database");

    // The crate's writer only produces KDBX 4.1. Upgrade 4.0 (and older) in
    // memory; the original 4.0 file is preserved by the `.bak` backup on save.
    if !handle.is_kdbx41() {
        eprintln!(
            "note: database is {}; upgrading to KDBX 4.1 on save",
            handle.version()
        );
        handle.upgrade_to_kdbx41();
    }

    // Add a marker entry under the root group.
    let root_uuid = handle.view().root.uuid;
    let marker = format!("kpd-write-test-{}", std::process::id());
    let new_uuid = handle
        .add_entry(root_uuid, &marker, "kpd", "s3cret")
        .expect("add an entry");

    let report = handle
        .save(&key, &SaveOptions::default())
        .expect("guarded save should succeed after upgrading to KDBX 4.1");

    assert!(
        report.round_trip_ok,
        "in-memory round-trip verification failed"
    );
    let backup = report.backup_path.expect("a .bak backup");
    assert!(backup.exists(), "the .bak backup should exist");

    // Reopen the saved copy and confirm the marker survived.
    let reopened = DbHandle::open(&db_path, &key).expect("reopen the saved database");
    assert!(
        reopened.view().entry(new_uuid).is_some(),
        "the new entry should survive the write round-trip"
    );

    // The backup must also be a valid database.
    let _ = DbHandle::open(&backup, &key).expect("the .bak backup should open");

    eprintln!("write round-trip OK — saved {} bytes", report.bytes_written);
    eprintln!("  saved db: {}", db_path.display());
    eprintln!("  backup:   {}", backup.display());
    eprintln!("Open the saved db with KeePass/KeePassXC to confirm interop.");
}
