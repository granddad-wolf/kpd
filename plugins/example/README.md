# `kpd-plugin-example`

A minimal example plugin for `kpd`'s sandboxed WASM plugin system (Phase 4a).
It is a **standalone crate** (deliberately *not* a member of the `kpd` Cargo
workspace) and implements the guest side of the `plugin` world defined in
`kpd/crates/kpd-plugin-api/wit/world.wit`.

## Commands

| Command          | Behavior                                                          |
|------------------|-------------------------------------------------------------------|
| `count`          | Returns the number of entries (`list-entries("")` = all).         |
| `search <query>` | Returns `title (username)` lines matching `<query>` (empty = all).|
| `copy <text>`    | Calls `clipboard.copy(<text>)` and returns `true` / `false`.      |
| *(anything else)*| Returns usage text.                                               |

It also demonstrates `logging.log`, which is always available (no grant needed).

## Manifest

`kpd_plugin_example.toml` declares the capabilities the plugin uses:

```toml
capabilities = ["entries.read", "clipboard.write"]
```

The host requires a manifest next to the component (`<name>.wasm` ←
`<name>.toml`). The TUI shows a consent prompt listing these capabilities
before it runs the plugin; the CLI refuses to run without a manifest.

## Install

Copy the manifest together with the component, keeping the stems equal:

```sh
mkdir -p ~/.config/kpd/plugins
cp target/wasm32-wasip2/release/kpd_plugin_example.wasm \
   kpd_plugin_example.toml ~/.config/kpd/plugins/
```

## Build

Run these commands **from this directory** (`kpd/plugins/example`):

```sh
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```

Output (a WebAssembly *component*, emitted directly by rustc — no
`wasm-tools component new` step needed):

```
target/wasm32-wasip2/release/kpd_plugin_example.wasm
```

Optional inspection / validation:

```sh
wasm-tools component wit target/wasm32-wasip2/release/kpd_plugin_example.wasm
wasm-tools validate target/wasm32-wasip2/release/kpd_plugin_example.wasm
```

## How it works

- `Cargo.toml` sets `[lib] crate-type = ["cdylib"]` and depends on
  `wit-bindgen = "0.63.0"`.
- `src/lib.rs` calls `wit_bindgen::generate!({ path: "../../crates/kpd-plugin-api/wit/world.wit" })`
  (the path is relative to this crate's `Cargo.toml`), implements the generated
  top-level `Guest` trait (`fn run(command: String, args: Vec<String>) -> String`),
  and wires it up with `export!(Plugin)`.
- The `wasm32-wasip2` target makes rustc emit a component directly.
