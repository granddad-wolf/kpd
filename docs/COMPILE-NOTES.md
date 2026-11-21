# First-compile notes (Ubuntu 24 LTS)

The codebase is code-complete and has passed a cross-crate consistency audit.
One definite compile-blocker was already found and **fixed** (`with_keyfile`
error conversion in `kpd-kdbx`). These notes cover the remaining areas most
likely to need a one-line tweak on the first `cargo build`.

## Staged build (recommended)

```sh
cd ~/kpd
cargo build --release -p kpd     # core app (skips wasmtime plugin runtime)
cargo build --release            # full workspace (storage + plugins)
```

## Already fixed (no action needed)

- `kpd-kdbx`: `DatabaseKey::with_keyfile(...)?` now maps its
  `DatabaseKeyError` → `KdbxError::Parse` (previously no `From` impl).

## Likely needs a tweak — each is a one-liner

1. **wasmtime component bindgen names** (`kpd-plugin-runtime`) — the generated
   `bindings::Plugin`, `bindings::kpd::plugin::{entries,clipboard,logging}::Host`,
   and `call_run` follow the documented pattern but are the kind of thing that
   only fails at macro-expansion. If they don't resolve:
   ```sh
   WASMTIME_DEBUG_BINDGEN=1 cargo build -p kpd-plugin-runtime
   ```
   …dumps the real generated names; adjust the paths to match. Fallback for the
   `add_to_linker` call if the compiler asks:
   `bindings::Plugin::add_to_linker::<_, wasmtime::component::HasSelf<_>>(&mut linker, |s: &mut HostState| s)`.

2. **Guest `Guest` trait path** (`plugins/example/src/lib.rs`) — top-level
   `export run` generates a top-level `Guest` trait (`impl bindings::Guest`). If
   that doesn't resolve, try `impl bindings::exports::kpd::plugin::run::Guest`.

3. **ratatui `areas` destructuring** (`kpd-tui/src/ui.rs`) — ratatui 0.30
   `Layout::areas` returns `[Rect; N]`, so `let [a, b, c] = …areas(…)` works. If
   it returns `Rc<[Rect]>` on the resolved version, replace with:
   ```rust
   let r = Layout::vertical([…]).areas(frame.area());
   // use r[0], r[1], r[2]
   ```

4. **keepass 0.17 signatures** — all verified against the 0.17.0 source (see
   `agent/RESEARCH-keepass-save.md` and `agent/RESEARCH-keepass-mutation.md`).
   If any mismatch appears, check those files for the exact signatures.

## How to report back

Paste the full `cargo build` error output (with the crate + line) into this
session (or into Cline/Roo Code pointed at the DeepSeek API), and the team will
patch it. Do `cargo build -p kpd` first and report those errors before the full
workspace build, so we fix the core app before the wasmtime surface.
