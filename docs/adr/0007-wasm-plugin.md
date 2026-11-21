# ADR-0007: WASM plugin system — component model + capability-gated WIT

- **Status**: accepted (design). Implementation is Phase 4a.
- **Date**: 2026-11-18
- **Input**: `agent/RESEARCH-wasm-plugin.md` (verified 2026-11-18), ADR-0001.

## Context

ADR-0001 chose `wasmtime` + `wit-bindgen` for a sandboxed, hostile-plugin-safe
plugin system. Research confirmed: `wasmtime` **50.0.2** (MSRV 1.97), `wit-bindgen`
**0.63.0**, `cargo-component` deprecated; the recommended path is the **Component
Model**, where the `.wit` `world` is the capability contract and WASI is opt-in
(a plugin has no fs/network unless we link it).

## Decisions

1. **Component Model.** The WIT `world` in `kpd-plugin-api/wit/world.wit` defines
   exactly the host interfaces a plugin may import (one interface = one capability)
   plus a single `export run(command, args) -> string`. Guests build with
   `cargo build --target wasm32-wasip2` (rustc emits the component directly); the
   host uses `wasmtime::component::bindgen!`.
2. **Capabilities.** Three host interfaces: `entries` (`list-entries` →
   `list<entry-summary>`), `clipboard` (`copy`), `logging` (`log`, always on).
   The host enforces `entries.read` and `clipboard.write` at runtime from a
   permission set; ungranted calls return an empty list / `false` respectively.
3. **No secrets cross the boundary.** `entry-summary` is `{uuid, title, username}`
   only — never passwords, notes, or raw DB bytes. The master key is never passed
   to a plugin.
4. **Resource bounds.** `StoreLimits` (max memory) + fuel (or epoch) so a hostile
   plugin cannot exhaust CPU/memory. No WASI is ever linked.
5. **MSRV raised to 1.97** (wasmtime 50 requires it). The build box uses rustup
   stable; `rustup update` suffices if behind.

## WIT world (source of truth: `kpd/crates/kpd-plugin-api/wit/world.wit`)

```wit
package kpd:plugin@0.1.0;

interface entries {
    record entry-summary {
        uuid: string,
        title: string,
        username: string,
    }
    list-entries: func(query: string) -> list<entry-summary>;
}

interface clipboard {
    copy: func(text: string) -> bool;
}

interface logging {
    log: func(message: string);
}

world plugin {
    import entries;
    import clipboard;
    import logging;
    export run: func(command: string, args: list<string>) -> string;
}
```

## Phase 4a public API (`kpd-plugin-runtime`)

```rust
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission { EntriesRead, ClipboardWrite }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySummary { pub uuid: String, pub title: String, pub username: String }

#[derive(Debug, Clone)]
pub struct Limits { pub max_memory_bytes: usize, pub fuel: u64 }
impl Default for Limits { /* 16 MiB, 10_000_000 */ }

#[derive(Debug, Default)]
pub struct RunContext {
    pub entries: Vec<EntrySummary>,  // filtered view the host provides
    pub copied: Vec<String>,         // out: clipboard.copy text
    pub logs: Vec<String>,           // out: logging.log messages
}

#[derive(Debug, thiserror::Error)]
pub enum PluginError { /* Load, Instantiate, Trap, Capability, Limit, ... */ }

pub struct PluginRuntime { /* Engine */ }
impl PluginRuntime {
    pub fn new() -> Self;
    pub fn load(&self, path: &Path, permissions: &[Permission], limits: Limits)
        -> Result<Plugin, PluginError>;
}

pub struct Plugin { /* component instance + Store<HostState> */ }
impl Plugin {
    pub fn run(&mut self, command: &str, args: &[String], ctx: &mut RunContext)
        -> Result<String, PluginError>;
}
```

`kpd-plugin-api` is a light crate owning the `.wit`; `kpd-plugin-runtime` depends
on `wasmtime = "50.0.2"` and holds the `bindgen!` host bindings + the `Host`
trait impls (capability-gated). A sample plugin lives in `kpd/plugins/example/`
(built with `wit-bindgen = "0.63.0"` → `wasm32-wasip2`).

## Consequences

- End-to-end run of a real `.wasm` requires compiling the sample plugin on the
  Linux box (documented commands in `plugins/example/README.md`). The permission
  model is unit-tested purely; the wasm loader is best-effort compiling-ready.
- Phase 4b: TUI plugin menu/commands, a `plugin.toml` manifest parser, and richer
  capabilities (secrets behind an explicit `entries.read-secrets` grant).
