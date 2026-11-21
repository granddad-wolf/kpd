# KDBX test fixtures

This directory is where a real KeePass `.kdbx` file can be dropped so the
ignored integration test `tests/open_fixture.rs` can open a genuine database.

**Do not commit a real user database.** Only commit KeePass databases that were
created *specifically* as test fixtures, from non-sensitive placeholder data.

## How to create a fixture (on a Linux box)

Any KeePass 2.x `.kdbx` (KDBX 3.1 or 4.x) works. For example, with KeePassXC:

```sh
keepassxc-cli db-create --set-password \
    -p "correct-horse-battery-staple" \
    tests/fixtures/test.kdbx
```

Or copy a database created with KeePass on Windows into this directory.

The fixture must be decryptable with a password only (no key file) for the
default test, since the test sets `KPD_TEST_PASSWORD`.

## Running the ignored test

```sh
KPD_TEST_DB=tests/fixtures/test.kdbx \
KPD_TEST_PASSWORD=correct-horse-battery-staple \
    cargo test --test open_fixture -- --ignored
```

- `KPD_TEST_DB` — path to the `.kdbx` fixture (absolute or relative to the
  `kpd-kdbx` crate root).
- `KPD_TEST_PASSWORD` — the master password for that fixture.
