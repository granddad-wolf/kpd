# ADR-0001: WASM plugin runtime

- **Status**: accepted
- **Date**: 2026-11-17

## Context

The app must support third-party plugins. Rust has no stable ABI, so native
`.so` plugins are fragile across toolchain versions and cannot be safely
sandboxed. A password manager must treat plugins as potentially hostile.

## Decision

Use **WebAssembly** via **`wasmtime`** + **`wit-bindgen`**. Plugins are `.wasm`
modules loaded from a `plugins/` directory. They interact only through a
capability-gated host API and never receive the master key, raw database bytes,
or unredacted secrets.

## Consequences

- Sandboxed, cross-platform, safe against hostile plugins.
- More plumbing: the host API surface must be designed and versioned (WIT).
- Plugin authors target `wasm32-wasip1` (or wasi-preview2 via WIT).
