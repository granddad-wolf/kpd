//! Integration test that opens a real `.kdbx` fixture with a password.
//!
//! This test is `#[ignore]`d because it needs a real KeePass database, which we
//! do not commit to the repository. See `tests/fixtures/README.md` for how to
//! obtain one and how to run this test.

use std::path::Path;

use kpd_crypto::CompositeKey;
use kpd_kdbx::open;

#[test]
#[ignore]
fn opens_a_real_kdbx_fixture() {
    let db_path = std::env::var("KPD_TEST_DB").expect("KPD_TEST_DB must point to a .kdbx file");
    let password = std::env::var("KPD_TEST_PASSWORD")
        .expect("KPD_TEST_PASSWORD must hold the master password");

    let key = CompositeKey::new().with_password(password);
    let database = open(Path::new(&db_path), &key).expect("fixture should open");

    assert!(!database.root.children.is_empty() || !database.root.entries.is_empty());
}
