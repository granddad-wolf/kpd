# ADR-0002: Read-only first, then guarded writes

- **Status**: accepted
- **Date**: 2026-11-17

## Context

Upstream `keepass-rs` KDBX4 writing is **experimental and lossy** — the inner XML
is rebuilt from parsed objects, so fields the parser does not model can be lost.

## Decision

Ship **read-only first**: open / unlock / lock, list, search, view, and copy to
clipboard. Add editing later, gated by:

1. automatic `.bak` backup before every overwrite;
2. a "fields that would be lost" report;
3. round-trip diff tests against real KeePass fixtures;
4. explicit user confirmation before any save.

## Consequences

- v1 is useful and safe immediately.
- The highest-risk work (correct writes) is de-risked incrementally.
- Requires building a corpus of real KeePass test databases.
