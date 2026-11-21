# Releasing kpd

Checklist for cutting a release (once the first build/test passes on Linux).

## 0. Preconditions

- [ ] `cargo build -p kpd` and `cargo test` pass on Ubuntu 24 LTS.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` is clean.
- [ ] `cargo audit` clean (CI gate).
- [ ] `cargo fmt --all -- --check` clean.
- [ ] KDBX round-trip test against real KeePass 2.x and KeePassXC files passes.

## 1. Before tagging

- [ ] Bump `version` in the workspace `[workspace.package]` (single source).
- [ ] Update `CHANGELOG.md` (add one once a release exists).
- [ ] Confirm `repository` and `authors` in the workspace `Cargo.toml` are current.
- [ ] Confirm `rust-version` matches the lowest toolchain you actually support.
- [ ] Confirm the dual `Apache-2.0 OR MIT` license is declared in every crate
      (`license.workspace = true`) and both `LICENSE-APACHE`/`LICENSE-MIT` are
      present at the repo root.
- [ ] Review the threat model (`agent/THREAT-MODEL.md`) residual risks and note
      any that changed.

## 2. Build & publish

```sh
cargo publish --dry-run -p kpd-core -p kpd-crypto -p kpd-kdbx -p kpd-clipboard \
  -p kpd-storage -p kpd-tui -p kpd-plugin-api -p kpd-plugin-runtime
# then, for each crate in dependency order:
cargo publish -p <crate>
```

## 3. Binaries

Build release binaries for target platforms (at minimum Linux x86_64):

```sh
cargo build --release -p kpd
# optional: cross-compile / musl for a portable static binary
```

Attach the built `kpd` binary + checksums to the GitHub release.

## 4. Post-release

- [ ] Tag `v<version>` and create a GitHub release with notes.
- [ ] Push the public repo; confirm CI (fmt/clippy/test/audit) is green on the tag.
