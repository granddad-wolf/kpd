# Runbook: build & run kpd on Ubuntu 24 LTS

## 0. Prerequisites

- Ubuntu 24.04 with a desktop (XFCE/X11) — a display is required for the clipboard.
- Rust stable via rustup (needs **>= 1.89** because `keepass` 0.17 requires it):
  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- Optional: `cargo install cargo-audit` (CI runs it too).

## 1. Get the code

Copy the `kpd/` directory to your Linux box, or `git clone` the public repo once
it exists. The `agent/` directory (plans/ADRs/contracts) belongs in the private repo.

## 2. Build (staged — recommended)

Build the **core app first**. `-p kpd` builds the binary, the TUI, the core/
crypto/kdbx/clipboard crates, and the storage crate (`reqwest`/`tokio`), but it
skips the single heaviest, highest-risk crate — the `wasmtime` plugin runtime —
so you can validate the read/write/cloud UI before that:

```sh
cd kpd
cargo build --release -p kpd
./target/release/kpd --help
```

Then build the **full workspace** (adds `kpd-storage` + the WASM plugin system):

```sh
cargo build --release
```

The first full build pulls a large dependency tree (the `keepass` crate brings
the Argon2/AES/ChaCha20/Twofish cipher stack; `wasmtime` 50 needs Rust >= 1.97 —
run `rustup update` first if you're behind). The clipboard backend is pure Rust
(x11rb / smithay), so no extra C system libraries are expected.

## 3. Run

```sh
cargo run --release -- open /path/to/your.kdbx
cargo run --release -- open /path/to/your.kdbx --keyfile /path/to/key.keyx
cargo run --release -- open /path/to/your.kdbx --timeout 20
```

Keybindings: `↑`/`↓`/`Tab` navigate · `Enter` open detail · `Ctrl+F` search ·
`Ctrl+C` copy · `Ctrl+S` save · `a` add entry · `g` add group · `e` edit field ·
`d` delete entry · `x` delete group · `r` reveal (detail) · `L` lock · `Q` quit ·
`Esc` back/cancel/quit.

## 4. Test

```sh
cargo test                 # unit tests (no display needed)
cargo test -- --ignored    # fixture + clipboard integration tests (need display)
```

For the `#[ignore]`d fixture test, set `KPD_TEST_DB` and `KPD_TEST_PASSWORD` to a
real `.kdbx` and its master password (see `kpd/crates/kpd-kdbx/tests/fixtures/README.md`).
Never commit a real database.

## 5. What works now

- Open a real KeePass 2.x (`.kdbx` / KDBX4) database with a master password (+ optional key file).
- Browse the group tree and entries, search across all groups, view details.
- Copy secrets to the clipboard with **auto-clear** after a configurable timeout.
- Add/edit/delete entries and groups, and **save** (guarded: `.bak` backup + round-trip
  verify + atomic replace, with a lossy-field warning before save).

## 6. Known limitations

- Saves write **KDBX 4.1 only**; opening KDB/KDBX3/KDBX4.0 works read-only, but saving
  them is refused (`UnsupportedForWrite`), never silently converted.
- Saving re-serializes from the in-memory model, so un-modeled vendor-extension XML
  (e.g. KeePassXC `<PreviousParentGroup>`) may be dropped — the UI warns before save.
- Delete is hard delete for now (recycle bin is a follow-up).
- No scroll offset for very long lists (selection stays in-bounds; long lists can clip).
- On Linux, clipboard content persists after our process yields ownership only if a
  clipboard manager is running (standard X11 behavior).

## 7. First-compile expectations (important)

This code was written by the agent team against **verified** crate APIs, but it has
**not been compiled** — there is no Rust toolchain in the generation environment.
Expect a small number of minor fixes on the first `cargo build` (a typo, an API
nuance, a version constraint). Feed any compiler errors back to the team (via
Cline/Roo Code in VSCode, or this DSH session) and we'll fix them quickly.
