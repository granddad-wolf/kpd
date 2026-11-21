# ADR-0004: Dual Apache-2.0 / MIT license

- **Status**: accepted
- **Date**: 2026-11-17

## Context

The author wants the project under **Apache-2.0 and MIT** (dual), and does **not**
want to fork KeePass itself — this is a new, independent application.

## Decision

SPDX identifier: `Apache-2.0 OR MIT`. Consume `keepass-rs` (and all third-party
crates) as *dependencies only*; do not copy their source into our repository.
Verify each dependency's license at adoption time (`cargo deny` gate).

## Consequences

- File-format compatibility with KeePass is fine: `.kdbx` is a file format, not
  GPL code. An independent implementation does not inherit KeePass's GPLv2+.
- If we later vendor a fork of any dependency, its license headers must be
  preserved and reviewed.
- `cargo deny` runs in CI to keep the license posture clean.
