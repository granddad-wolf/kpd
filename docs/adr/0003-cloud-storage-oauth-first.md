# ADR-0003: Cloud storage abstraction, OAuth providers first

- **Status**: accepted
- **Date**: 2026-11-17

## Context

The database must be storable in cloud services "out of the box". Sync must be
safe — no silent overwrite of a concurrently changed file.

## Decision

Define a single async `Storage` trait (`read` / `write` / `exists` / `metadata`
with a revision/etag). Implement the local filesystem backend always. Ship the
**OAuth providers first** (Dropbox, Google Drive, OneDrive), then WebDAV, then
S3-compatible.

Sync flow = `storage.read()` → merge with conflict prompt → `storage.write()`.
Crypto never lives in the storage layer.

## Consequences

- OAuth requires app registration, redirect/refresh-token handling, and protected
  token storage.
- A pluggable backend registry keeps later providers purely additive.
