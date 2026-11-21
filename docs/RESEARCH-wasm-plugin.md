# Research: Sandboxed WASM Plugin System for `kpd`

**Status:** Research only — no code was modified.
**Date:** 2026-11-18
**Context:** ADR-0001 selected `wasmtime` + `wit-bindgen`, capability-gated, hostile-plugin-safe. Plugins must receive a *filtered, capability-gated* view of entries (never the master key or raw DB bytes) and must have **no filesystem/network by default**.

All versions below were verified against crates.io / docs.rs / docs.wasmtime.dev / component-model.bytecodealliance.org on 2026-11-18.

---

## Version snapshot (verified 2026-11-18)

| Crate / tool | Latest stable | `rust-version` (MSRV) | Notes |
|---|---|---|---|
| `wasmtime` | **50.0.2** (2026-11-16) | **1.97.0** | `51.0.0-rc.1` prerelease exists. `48.0.9` (MSRV 1.95.0) is a backport published the same day. |
| `wasmtime-wasi` | **50.0.2** | 1.97.0 | Default features `p1,p2,p3`. WASI is a *separate* crate from `wasmtime`. |
| `wit-bindgen` | **0.63.0** (2026-10-14) | *(none declared)* | 0.61.x declared 1.85.0; 0.62/0.63 declare none. |
| `wasm-tools` | **1.263.0** (2026-10-30) | **1.88.0** | Single CLI binary `wasm-tools`. |
| `cargo-component` | 0.21.1 (2025-03-18) | *(none)* | **Deprecated.** Last published ~20 months ago. |

**crates.io quirk to be aware of:** crates.io reports `newest_version` = `48.0.9` for wasmtime. That field is literally "most recently *published*", not "highest". The *highest stable* is `50.0.2` (`max_stable_version` / `default_version`). Use `50.0.2`.

---

## 1. wasmtime version + MSRV + minimal embedding API

**Latest stable: `wasmtime = "50.0.2"`, MSRV `rust-version = "1.97.0"`.**

`wasmtime` splits its API into two halves:

- **Core Wasm** API at the crate root: `Engine`, `Module`, `Store<T>`, `Linker<T>`, `Instance`, `Func`, `TypedFunc<Params, Results>`, `Memory`.
- **Component Model** API under `wasmtime::component`: `Component`, `component::Linker`, `component::Instance`, `component::Func`, `component::TypedFunc`, plus the `wasmtime::component::bindgen!` macro.

Minimal core-module load-and-call sequence for an export `(i32, i32) -> i32`:

```rust
use wasmtime::*;

fn main() -> Result<()> {
    // 1. Global compilation environment (one per process).
    let engine = Engine::default();

    // 2. Compile the module (from .wasm bytes or a file).
    let module = Module::from_file(&engine, "plugin.wasm")?;
    //    ...or Module::new(&engine, &wasm_bytes)?;

    // 3. Per-instance state container. `T` is arbitrary host state.
    let mut store = Store::new(&engine, ());

    // 4. (Optional) Linker for injecting host functions by name.
    let mut linker = Linker::new(&engine);
    linker.func_wrap("host", "list_entries", |caller: Caller<'_, ()>, ptr: i32, len: i32| {
        // see §5 for reading strings through caller.get_export("memory")
    })?;

    // 5. Instantiate: resolve imports, run `start` if present.
    let instance = linker.instantiate(&mut store, &module)?;
    //    ...or, with no imports: Instance::new(&mut store, &module, &[])?

    // 6. Get a typed handle and call it. Params/Results are Rust tuples.
    let add: TypedFunc<(i32, i32), i32> =
        instance.get_typed_func(&mut store, "add")?;
    let result: i32 = add.call(&mut store, (20, 22))?; // 42
    Ok(())
}
```

Key signatures (from `docs.rs/wasmtime/50.0.2`):

- `Engine::default() -> Engine`
- `Module::from_file(&Engine, impl AsRef<Path>) -> Result<Module>` / `Module::new(&Engine, &[u8]) -> Result<Module>` (the `wat` feature, on by default, also accepts `.wat` text)
- `Store::new(&Engine, T) -> Store<T>` (also `Store::default()`)
- `Linker::new(&Engine) -> Linker<T>`
- `Linker::func_wrap(&mut self, module: &str, name: &str, impl IntoFunc<T, Params, Args>) -> Result<&mut Self>` — the host callback gets `Caller<'_, T>` as an optional first argument, then typed params.
- `Linker::instantiate(&self, store: impl AsContextMut<Data=T>, &Module) -> Result<Instance>`
- `Instance::get_typed_func<Params, Results>(&mut store, name) -> Result<TypedFunc<Params, Results>>`
- `TypedFunc::call(&mut store, Params) -> Result<Results>`

`(i32, i32) -> i32` maps to `TypedFunc<(i32, i32), i32>` and `call(&mut store, (a, b))`. Single values use the bare type (`TypedFunc<i32, i32>`); zero-arg/zero-result use `()`.

---

## 2. Component model vs core module — pragmatic 2026 recommendation

**Recommendation: use the Component Model (`WIT` + `wit-bindgen` + wasmtime component support) for the capability-gated plugin ABI.** It is the stronger fit for a security-sensitive host, and it is what the official tooling now defaults to.

| Dimension | Component Model (WIT) | Core modules + `Linker` |
|---|---|---|
| Capability surface | **Structural.** The `.wit` `world` *is* the contract: an `import` interface = an explicitly granted capability. The host `Linker` only wires what it chooses. | Ad-hoc: module imports are just string names `("mod","func")`; you manually match them. No static contract. |
| Typed data | `string`, `list<T>`, `record`, `variant`, `resource`, `result` handled **automatically** by wit-bindgen. | You hand-roll ptr+len encoding and ABI (see §5). |
| Hostile-plugin safety | Typed ABI + canonical ABI means a mismatched/trick call is a trap, not UB. `resource` types give *opaque handles* (e.g. a filtered entry handle) so the plugin never sees raw memory it shouldn't. | Correct but more foot-guns: every string/array crossing is a manual bounds check against `Memory`. |
| Toolchain surface | `.wit` file + `wit_bindgen::generate!` (guest) + `wasmtime::component::bindgen!` (host). No separate component-wrapping step when targeting `wasm32-wasip2`. | No `.wit`, no wit-bindgen, no wasm-tools. Just `Linker` + typed funcs + `Memory`. |
| Cross-language plugins later | Easy (C, JS via jco, Python, etc.). | Each language re-implements your raw ABI by hand. |
| WASI requirement | Built to `wasm32-wasip2` target. WASI is *not* auto-linked into your world — only interfaces you declare are importable. | `wasm32-unknown-unknown` or `wasm32-wasip1` core module. |
| Official push | **Components are the default path.** `component-model` is now a *default* wasmtime feature; `cargo-component` is deprecated in favor of native `cargo build --target wasm32-wasip2` + wit-bindgen. | Still fully supported (the "hello world" and "memory" examples are core modules). |

**Tradeoffs for a small, security-sensitive host:**

- **Component model cost:** one extra concept (`.wit`), one extra dependency (`wit-bindgen` on the guest; the host uses wasmtime's built-in `component::bindgen!`), and a `wasm32-wasip2` toolchain target. The "world = capability contract" property and automatic typed `string`/`list`/`resource` marshalling are worth it for a KeePass entry API, which is inherently structured (title, username, password, url, notes, custom fields, timestamps).
- **Core-module alternative:** viable for a *minimal* MVP because it is lower-dependency and the security property ("no fs/net unless the `Linker` provides it") holds **identically**. But you take on the ptr+len ABI and lose the static capability contract. If you expect any non-trivial structured entry data or future non-Rust plugins, components win quickly.

The Bytecode Alliance's own "Application with Plugins" example (docs.wasmtime.dev/wasip2-plugins.html) is exactly this pattern — a host that loads `.wasm` components, with an *empty* `host` interface to demonstrate a plugin that can call nothing.

---

## 3. wit-bindgen current workflow

**Current tooling:** the `wit_bindgen::generate!` **proc-macro** (not the old `wit-bindgen` CLI binary; that binary moved to the separate `wit-bindgen-cli` crate). `cargo-component` is deprecated.

The guest-side (plugin) recipe, straight from component-model.bytecodealliance.org:

1. Add the target: `rustup target add wasm32-wasip2`
2. `Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
wit-bindgen = "0.63.0"
```

3. `wit/world.wit` (see §6 for the kpd-specific world).
4. `src/lib.rs`:

```rust
mod bindings {
    wit_bindgen::generate!({
        // path optional; defaults to top-level `wit/` directory
        path: "wit/world.wit",
    });
    // `export!` wires the Guest impl into the component's exports
    use super::Plugin;
    export!(Plugin);
}

struct Plugin;

impl bindings::exports::<...>::Guest for Plugin {
    // implement each function declared in the world's `export` interface
}
```

5. Build — rustc emits the component **directly**, no `wasm-tools` needed:

```sh
cargo build --target wasm32-wasip2 --release
# -> target/wasm32-wasip2/release/<name>.wasm  (a *component*, ~16K in release)
```

6. Inspect / validate:

```sh
wasm-tools component wit target/wasm32-wasip2/release/adder.wasm   # print embedded WIT
wasm-tools validate target/wasm32-wasip2/release/adder.wasm
```

**Host-side bindings** (embedder): use wasmtime's own macro, which runs wit-bindgen under the hood:

```rust
use wasmtime::component::bindgen;   // re-exported macro
bindgen!("plugin");                  // reads wit/world.wit, generates `Plugin`
```

The generated `Plugin` type has `Plugin::instantiate(&mut store, &component, &linker)` and `call_<fn>(&mut store, args)` methods (hyphens become underscores, prefixed `call_`).

**`wasm-tools component new` is only needed when you have a *core* module** (e.g. built for `wasm32-unknown-unknown`) and want to wrap it in a component with a WIT adapter (or a non-Rust/legacy guest). With `wit_bindgen::generate!` + `--target wasm32-wasip2`, you never call it.

**Targets:** `wasm32-wasip1` ⇒ core Wasm module (WASI P1); `wasm32-wasip2` ⇒ **component** (WASI P2). For components you must use `wasm32-wasip2`. (`wasm32-unknown-unknown` is core-only, no WASI.)

---

## 4. Capability sandboxing (no fs/network by default)

**Confirmed: WASI is optional and opt-in.**

- The `wasmtime` crate "does **not** natively provide support for WASI" (docs.rs/wasmtime/50.0.2, "WASI" section). WASI lives in the separate `wasmtime-wasi` crate, and it only becomes reachable when you explicitly add it to a `Linker` (e.g. `wasmtime_wasi::add_to_linker` / the component `WasiCtx` + `wasmtime_wasi::bindgen!`).
- If you **never add WASI**, a plugin has **zero** filesystem/network/socket/clock/random access. The only things it can call are (a) its own code and (b) host functions *you* define in the `Linker`.
- For **core modules**: instantiate with a `Linker` that contains *only* your functions (`host_list_entries`, `host_clipboard_write`, …). Any other import (including a hostile plugin trying to import `wasi_snapshot_preview1` names) simply **fails to instantiate** (`UnknownImportError`). You can additionally call `linker.define_unknown_imports_as_traps(&module)` to make unknown imports trap deterministically instead of failing setup.
- For **components**: the capability surface is the `.wit` `world`. A guest component can only `import` interfaces declared in its own world, and the host `component::Linker` provides only those. Do **not** include any `wasi:*` interface in your world, and the component has no OS access at all.

```rust
// core-module path: only these names exist; nothing else resolves
let mut linker: Linker<Host> = Linker::new(&engine);
linker.func_wrap("host", "list_entries",  list_entries_impl)?;
linker.func_wrap("host", "clipboard_write", clipboard_write_impl)?;
// NO wasmtime_wasi::add_to_linker(...) => no fs, no net, no clock
let instance = linker.instantiate(&mut store, &module)?;
```

Security note for a password manager: even "no WASI" doesn't bound *time* or *memory* of a hostile plugin. Add `StoreLimits` (max memory/instances), and CPU bounds via `Config::consume_fuel(true)` + `store.set_fuel(...)` (deterministic) or `Config::epoch_interruption(true)` + `Engine::increment_epoch()` (timer-based), so a plugin cannot hang or exhaust the host.

---

## 5. String / `Vec<u8>` / structured data across the boundary

**Core modules — manual ptr+len via linear memory:**

There is no string type in core Wasm. You pass `(ptr: i32, len: i32)` and read/write guest memory through the exported `Memory`:

```rust
let memory: Memory = instance.get_memory(&mut store, "memory").unwrap();

// Read a guest string at (ptr,len): copy bytes out of guest linear memory
let bytes = &memory.data(&store)[ptr as usize .. ptr as usize + len as usize];
let s = std::str::from_utf8(bytes)?;

// Write into guest memory (guest must have allocated room, or use its allocator export)
let buf = memory.data_mut(&mut store);
buf[ptr as usize .. ptr as usize + data.len()].copy_from_slice(data);
```

- `Memory::data(&store) -> &[u8]` and `Memory::data_mut(&mut store) -> &mut [u8]` give direct slices; `Memory::data_size`, `Memory::size`, `Memory::grow` are also available. Out-of-bounds accesses **trap** (a `Result::Err`).
- Structured data ⇒ serialize yourself (e.g. JSON, postcard, a hand-rolled byte layout) into the shared buffer, then pass ptr+len. wit-bindgen's generated *guests* already do this internally via a `realloc` export; if you write the guest in raw Rust you must export your own allocator (`malloc`/`free`) or reserve a scratch buffer.
- Host functions injected via `Linker::func_wrap` receive ptr+len and get the memory through `caller.get_export("memory").and_then(Extern::into_memory)`.

**Component model — automatic:**

wit-bindgen maps `string`, `list<u8>`, `list<T>`, `record`, `variant`, `enum`, `result`, and `resource` to typed Rust and handles the canonical-ABI encoding (ptr+len lifting/lowering) for you. Guest and host both see plain `String`, `Vec<u8>`, `Vec<T>`, `struct`, `enum`, `Result<_, _>`. No manual memory handling. For "filtered entries" you can model an entry as a `record` and a `list<entry>` result, or expose a `resource` handle per entry so the plugin never touches a serialized buffer at all.

---

## 6. Minimal end-to-end example (component model — recommended)

A plugin that exports one function and a host that loads and calls it.

### Plugin crate (guest)

`plugin/Cargo.toml`:

```toml
[package]
name = "kpd-plugin-demo"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wit-bindgen = "0.63.0"
```

`plugin/wit/world.wit`:

```wit
package kpd:demo@0.1.0;

/// The ONLY host functions a plugin may call = the capability grants.
/// (No wasi:fs, wasi:sockets, etc. => no filesystem or network.)
interface host {
    list-entries: func() -> list<string>;
    clipboard-write: func(text: string) -> bool;
}

world plugin {
    import host;
    export run: func(x: s32, y: s32) -> s32;
}
```

`plugin/src/lib.rs`:

```rust
mod bindings {
    wit_bindgen::generate!({ path: "wit/world.wit" });
    use super::Plugin;
    export!(Plugin);
}

struct Plugin;

impl bindings::exports::kpd::demo::run::Guest for Plugin {
    fn run(x: i32, y: i32) -> i32 {
        // plugin may call only `host` capabilities declared above
        let names = bindings::kpd::demo::host::list_entries();
        let _ok = bindings::kpd::demo::host::clipboard_write(&format!("{x}+{y}={}", x + y));
        let _ = names;
        x + y
    }
}
```

Build:

```sh
cd plugin
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
# -> target/wasm32-wasip2/release/kpd_plugin_demo.wasm
```

### Host crate (embedder)

`host/Cargo.toml`:

```toml
[package]
name = "kpd-host-demo"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
wasmtime = "50.0.2"   # component-model, async, cranelift, wat are DEFAULT features
```

`host/src/main.rs`:

```rust
use anyhow::Result;
use wasmtime::component::{bindgen, Component, Linker};
use wasmtime::{Engine, Store};

// Reads the `plugin` world from the WIT and generates the `Plugin`
// host-binding type plus a `Host` trait for each imported interface.
bindgen!({
    path: "../plugin/wit/world.wit",
    world: "plugin",
});

// Your store data type: filtered-entry DB, clipboard sink, etc.
struct HostState;

// Provide the `host` interface. These are the ONLY functions a plugin can
// call — there is no WASI, filesystem, or network wired up.
impl kpd::demo::host::Host for HostState {
    fn list_entries(&mut self) -> Vec<String> {
        // Return FILTERED entries (titles/uuids), never secrets or raw DB bytes.
        Vec::new()
    }
    fn clipboard_write(&mut self, text: String) -> bool {
        let _ = text; // hand off to the TUI clipboard abstraction
        true
    }
}

fn main() -> Result<()> {
    let engine = Engine::default();

    // Component capability linker. `root()` registers the store data type
    // (`HostState`) as the provider of the world's imported interfaces,
    // and nothing else is reachable.
    let mut linker: Linker<HostState> = Linker::new(&engine);
    linker.root();

    let component = Component::from_file(
        &engine,
        "../plugin/target/wasm32-wasip2/release/kpd_plugin_demo.wasm",
    )?;
    let mut store = Store::new(&engine, HostState);
    let plugin = Plugin::instantiate(&mut store, &component, &linker)?;

    let sum = plugin.call_run(&mut store, 20, 22)?; // 42
    println!("plugin returned {sum}");
    Ok(())
}
```

Host-side wiring note: `wasmtime::component::bindgen!` generates a `Host` trait per *imported* interface (here `kpd::demo::host::Host`; the exact path follows the WIT package/interface names — browse it with `cargo doc` or `WASMTIME_DEBUG_BINDGEN=1`). You `impl` that trait for the `Store<T>` data type and call `component::Linker::root()` to register it. The wasmtime `wasip2-plugins` example shows the same `bindgen!` + `Component::from_file` + `Store::new` + `Plugin::instantiate` + `call_*` sequence — with an *empty* host interface, the `Linker` is passed straight through with nothing registered, proving zero capability by default.

### Core-module alternative (smallest possible, no WIT/wit-bindgen/wasm-tools)

Plugin built for `wasm32-unknown-unknown` (or `wasm32-wasip1`) exporting `#[no_mangle] pub extern "C" fn add(x: i32, y: i32) -> i32`, then:

```rust
use wasmtime::*;
let engine = Engine::default();
let module = Module::from_file(&engine, "plugin.wasm")?;
let mut store = Store::new(&engine, ());
let mut linker = Linker::new(&engine);
linker.func_wrap("host", "clipboard_write", |s: &str| { /* ... */ })?; // note: no WASI added
let instance = linker.instantiate(&mut store, &module)?;
let add: TypedFunc<(i32, i32), i32> = instance.get_typed_func(&mut store, "add")?;
let sum = add.call(&mut store, (20, 22))?;
```

This is the absolute minimum dependency set (`wasmtime` only), with the same no-fs/no-net guarantee (no `wasmtime-wasi`), at the cost of a hand-rolled ptr+len ABI for strings/lists.

---

## 7. Gotchas

1. **`component-model`, `async`, `cranelift`, `wat`, `wit-parser` are now DEFAULT wasmtime features** (verified in the 50.0.2 manifest). You do **not** need to add `features = ["component-model"]`; older tutorials telling you to enable it are stale. The *non*-default ones you might touch: `component-model-bytes`, `memory-protection-keys`, `call-hook`, `all-arch`, `winch`.
2. **MSRV is a real constraint.** wasmtime 50.0.2 requires **Rust 1.97.0**; the 49.x line needs 1.96, 48.x needs 1.95. `wasm-tools` 1.263.0 needs 1.88.0. Pin your toolchain or choose the wasmtime minor matching your MSRV. (`wit-bindgen` 0.63 declares no MSRV; 0.61.x declared 1.85.0.)
3. **`cargo-component` is deprecated.** Do not adopt it. The current flow is: native `cargo build --target wasm32-wasip2` + `wit_bindgen::generate!` (guest) + `wasmtime::component::bindgen!` (host) + `wasm-tools` only for inspection/validation. The component-model docs carry an explicit "cargo-component is in the process of being deprecated" warning.
4. **`wit-bindgen` crate ≠ CLI.** The `wit-bindgen` crate is the macro/runtime (no binary). The standalone CLI lives in the `wit-bindgen-cli` crate if you ever want `--generate` from the command line. The old `wit_bindgen::generate!` macro remains the supported path.
5. **Target matters: `wasm32-wasip2` for components, not `wasm32-wasip1`.** `wasm32-wasip1` produces a *core* module; `wasm32-wasip2` produces a *component*. For the component path you must add the `wasm32-wasip2` target. `wasm32-wasip1` is *not* sufficient for wit-bindgen components (it's fine for the core-module path, as is `wasm32-unknown-unknown`).
6. **`wasm-tools component new` is only for wrapping an existing core module into a component.** With `wit_bindgen::generate!` + `wasm32-wasip2`, rustc emits the component directly — no extra step. Don't add `component new` unless you're porting a legacy core-module plugin.
7. **WASI is opt-in and separate.** `wasmtime` has no WASI; `wasmtime-wasi` (`add_to_linker` / `WasiCtx`) must be explicitly added to a `Linker` for fs/net to exist. Omitting it = capability-free by construction. (Note `wasmtime-wasi` default features are `p1,p2,p3` in 50.x — the *crate* ships them, but they're inert until you link them.)
8. **A "no WASI" plugin can still burn CPU/memory.** For a hostile-plugin-safe host, also set `StoreLimits` and fuel/epoch interruption (see §4). The sandbox prevents *ambient* access, not resource exhaustion.
9. **Component `store` is per-plugin and single-owner.** Keep one `Store<HostState>` per instantiated plugin; the generated `Plugin` type and its `call_*` methods borrow `&mut Store`. Don't share a `Store` across concurrently-running plugins; use `Linker`/`Engine` (shareable) for shared state.
10. **`bindgen!` macro name differs by side.** Guest: `wit_bindgen::generate!` + generated `export!`. Host: `wasmtime::component::bindgen!` (which shells out to wit-bindgen). Don't confuse them — the host does *not* use `wit_bindgen::generate!` unless you deliberately generate host bindings through wit-bindgen directly.

---

## Primary sources

- https://crates.io/crates/wasmtime (50.0.2, rust-version 1.97.0, feature list) and https://docs.rs/wasmtime/50.0.2/wasmtime/
- https://docs.rs/wasmtime/50.0.2/wasmtime/struct.Linker.html (func_wrap / instantiate / define_unknown_imports_as_traps)
- https://crates.io/crates/wit-bindgen (0.63.0), https://crates.io/crates/wasm-tools (1.263.0), https://crates.io/crates/cargo-component (0.21.1, stale)
- https://docs.wasmtime.dev/ (intro), /examples-hello-world.html, /examples-memory.html, /wasip2-plugins.html
- https://component-model.bytecodealliance.org/language-support/building-a-simple-component/rust.html (native wasm32-wasip2 + wit-bindgen workflow, cargo-component deprecation warning)
