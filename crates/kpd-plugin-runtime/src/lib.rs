//! # `kpd-plugin-runtime`
//!
//! The host-side loader for `kpd`'s sandboxed, hostile-plugin-safe WASM plugin
//! system (Phase 4a, see ADR-0007). It compiles a WebAssembly *component* and
//! exposes a capability-gated, resource-bounded `run` entry point.
//!
//! ## Sandbox model
//!
//! * **Capability-gated by construction.** The WIT `world plugin`
//!   (`kpd-plugin-api/wit/world.wit`) declares exactly three imported host
//!   interfaces — `entries`, `clipboard`, `logging` — and one exported `run`
//!   function. The `component::Linker` wires only those interfaces, and **no
//!   WASI is ever linked**, so a plugin has no filesystem, network, socket,
//!   clock, or environment access.
//! * **Runtime permission checks.** `entries.list-entries` returns an empty
//!   list unless the plugin holds [`Permission::EntriesRead`];
//!   `clipboard.copy` returns `false` unless it holds
//!   [`Permission::ClipboardWrite`]; `logging.log` is always allowed. No
//!   secret (passwords, notes, raw DB bytes, the master key) ever crosses the
//!   boundary.
//! * **Resource bounds.** [`StoreLimits`] caps linear-memory growth, and a
//!   deterministic fuel budget is reset before every call, so a hostile plugin
//!   cannot exhaust memory or hang the host.
//!
//! ## Naming note
//!
//! The generated host bindings (kept in the private `mod bindings`) follow the
//! WIT package/interface names: the `Host` traits live at
//! `kpd::plugin::{entries,clipboard,logging}::Host`, and the world struct is
//! `Plugin` (the world name in `UpperCamelCase`) with the generated
//! `add_to_linker`, `instantiate`, and `call_run` methods.

use std::path::Path;

use wasmtime::component::{Component, HasSelf};
use wasmtime::{Engine, Store, StoreLimits, StoreLimitsBuilder};

use wasmtime::component::ResourceTable;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// Generated host bindings for the `plugin` world.
///
/// The `bindgen!` path is resolved relative to this crate's `Cargo.toml`
/// (`kpd/crates/kpd-plugin-runtime/`), so one `..` reaches the sibling
/// `kpd-plugin-api` crate.
mod bindings {
    wasmtime::component::bindgen!({
        path: "../kpd-plugin-api/wit/world.wit",
        world: "plugin",
    });
}

/// A capability a plugin may be granted.
///
/// One variant per gated host interface. The host checks these at load time
/// and enforces them on every call (see the `Host` trait implementations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Allow reading the filtered entry list via `entries.list-entries`.
    EntriesRead,
    /// Allow writing to the host clipboard via `clipboard.copy`.
    ClipboardWrite,
}

/// A filtered, secret-free view of a single entry.
///
/// This deliberately mirrors the WIT `entry-summary` record (`uuid`, `title`,
/// `username`) and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySummary {
    pub uuid: String,
    pub title: String,
    pub username: String,
}

/// Resource bounds applied to a plugin.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum guest linear-memory, in bytes.
    pub max_memory_bytes: usize,
    /// Fuel (deterministic CPU budget) reset before each `run` call.
    pub fuel: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 16 * 1024 * 1024, // 16 MiB
            fuel: 10_000_000,
        }
    }
}

/// Per-run inputs and outputs.
///
/// `entries` is the filtered view the host exposes to the plugin; `copied` and
/// `logs` collect the plugin's clipboard writes and log lines, respectively.
#[derive(Debug, Default)]
pub struct RunContext {
    /// The filtered view of entries the host provides to the plugin.
    pub entries: Vec<EntrySummary>,
    /// Populated with the text of every *granted* `clipboard.copy`.
    pub copied: Vec<String>,
    /// Populated with every `logging.log` message.
    pub logs: Vec<String>,
}

/// Errors surfaced by the plugin runtime.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// The wasmtime engine could not be configured.
    #[error("failed to configure the wasmtime engine: {0}")]
    Engine(#[source] wasmtime::Error),

    /// The plugin component could not be compiled.
    #[error("failed to compile the plugin component: {0}")]
    Load(#[source] wasmtime::Error),

    /// The plugin component could not be instantiated.
    #[error("failed to instantiate the plugin component: {0}")]
    Instantiate(#[source] wasmtime::Error),

    /// The plugin trapped during execution (or exceeded its fuel budget).
    #[error("plugin execution trapped: {0}")]
    Trap(#[source] wasmtime::Error),

    /// A resource limit was exceeded or could not be applied.
    #[error("resource limit was exceeded or could not be applied: {0}")]
    Limit(#[source] wasmtime::Error),
}

/// The process-wide compilation environment, shared across plugin instances.
pub struct PluginRuntime {
    engine: Engine,
}

impl PluginRuntime {
    /// Create a runtime with fuel-based CPU accounting enabled.
    ///
    /// `Engine::new` is technically fallible, but with this fixed, known-good
    /// configuration it cannot fail; use [`PluginRuntime::try_new`] if you want
    /// the error surfaced instead of an assertion.
    pub fn new() -> Self {
        Self::try_new().expect("wasmtime engine config is statically valid")
    }

    /// Fallible constructor; [`PluginRuntime::new`] unwraps this.
    pub fn try_new() -> Result<Self, PluginError> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(PluginError::Engine)?;
        Ok(Self { engine })
    }

    /// Compile and instantiate a plugin component with the given capabilities
    /// and resource bounds.
    ///
    /// `permissions` is copied into the per-plugin store and enforced on every
    /// subsequent call; `limits` bounds memory (via [`StoreLimits`]) and CPU
    /// (via fuel).
    pub fn load(
        &self,
        path: &Path,
        permissions: &[Permission],
        limits: Limits,
    ) -> Result<Plugin, PluginError> {
        let component = Component::from_file(&self.engine, path).map_err(PluginError::Load)?;

        // One linker: WASI (empty context) + the world's capability interfaces.
        let mut linker = wasmtime::component::Linker::<HostState>::new(&self.engine);

        // Satisfy the WASI P2 imports a Rust wasm32-wasip2 component links into
        // itself, with an EMPTY WasiCtx: no filesystem, no network, no env, no
        // args (only io/poll, clocks, random are reachable).
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)
            .map_err(PluginError::Instantiate)?;

        // The capability contract: only the world's three imported interfaces.
        bindings::Plugin::add_to_linker::<_, HasSelf<_>>(
            &mut linker,
            |state: &mut HostState| state,
        )
        .map_err(PluginError::Instantiate)?;

        // Max-memory limiter, plus a deterministic trap on grow failure.
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits.max_memory_bytes)
            .trap_on_grow_failure(true)
            .build();

        let mut store = Store::new(
            &self.engine,
            HostState {
                permissions: permissions.to_vec(),
                entries: Vec::new(),
                copied: Vec::new(),
                logs: Vec::new(),
                limits: store_limits,
                wasi: WasiCtxBuilder::new().build(),
                table: ResourceTable::new(),
            },
        );
        store.limiter(|state: &mut HostState| &mut state.limits);

        // The store starts at 0 fuel under `consume_fuel`; give instantiation a
        // budget too (run() re-sets it per call).
        store.set_fuel(limits.fuel).map_err(PluginError::Limit)?;

        let instance = bindings::Plugin::instantiate(&mut store, &component, &linker)
            .map_err(PluginError::Instantiate)?;

        Ok(Plugin {
            store,
            instance,
            limits,
        })
    }
}

/// A loaded, instantiated plugin: its `Store` state plus the component handle.
pub struct Plugin {
    store: Store<HostState>,
    instance: bindings::Plugin,
    limits: Limits,
}

impl Plugin {
    /// Run a command against the plugin, wiring `ctx` into and out of the store.
    ///
    /// The entries and sinks are moved out of `ctx` into the store (via
    /// `std::mem::take`, leaving `ctx` empty), fuel is reset, the guest's `run`
    /// export is called, and then the clipboard/log sinks are moved back into
    /// `ctx.copied` / `ctx.logs`. `ctx.entries` is consumed (the plugin cannot
    /// mutate it) and left empty.
    pub fn run(
        &mut self,
        command: &str,
        args: &[String],
        ctx: &mut RunContext,
    ) -> Result<String, PluginError> {
        let RunContext {
            entries,
            copied,
            logs,
        } = std::mem::take(ctx);

        {
            let state = self.store.data_mut();
            state.entries = entries;
            state.copied = copied;
            state.logs = logs;
        }

        // Fresh, deterministic CPU budget for this call.
        self.store
            .set_fuel(self.limits.fuel)
            .map_err(PluginError::Limit)?;

        let result = self
            .instance
            .call_run(&mut self.store, command, args)
            .map_err(PluginError::Trap)?;

        let state = self.store.data_mut();
        ctx.copied = std::mem::take(&mut state.copied);
        ctx.logs = std::mem::take(&mut state.logs);

        Ok(result)
    }
}

/// Per-plugin host state held inside the `Store`.
struct HostState {
    permissions: Vec<Permission>,
    entries: Vec<EntrySummary>,
    copied: Vec<String>,
    logs: Vec<String>,
    limits: StoreLimits,
    wasi: WasiCtx,
    table: ResourceTable,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

/// `entries` interface: a filtered, capability-gated list of summaries.
impl bindings::kpd::plugin::entries::Host for HostState {
    fn list_entries(&mut self, query: String) -> Vec<bindings::kpd::plugin::entries::EntrySummary> {
        if !permits(&self.permissions, Permission::EntriesRead) {
            return Vec::new();
        }
        self.entries
            .iter()
            .filter(|entry| matches_query(entry, &query))
            .map(|entry| bindings::kpd::plugin::entries::EntrySummary {
                uuid: entry.uuid.clone(),
                title: entry.title.clone(),
                username: entry.username.clone(),
            })
            .collect()
    }
}

/// `clipboard` interface: appends text to the copied sink when granted.
impl bindings::kpd::plugin::clipboard::Host for HostState {
    fn copy(&mut self, text: String) -> bool {
        if !permits(&self.permissions, Permission::ClipboardWrite) {
            return false;
        }
        self.copied.push(text);
        true
    }
}

/// `logging` interface: always allowed.
impl bindings::kpd::plugin::logging::Host for HostState {
    fn log(&mut self, message: String) {
        self.logs.push(message);
    }
}

/// True if `permissions` contains `needed`.
fn permits(permissions: &[Permission], needed: Permission) -> bool {
    permissions.contains(&needed)
}

/// Case-insensitive substring match on `title` or `username`.
///
/// An empty `query` matches every entry (mirroring the WIT contract's
/// "empty query = all").
fn matches_query(entry: &EntrySummary, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let query = query.to_lowercase();
    entry.title.to_lowercase().contains(&query) || entry.username.to_lowercase().contains(&query)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(uuid: &str, title: &str, username: &str) -> EntrySummary {
        EntrySummary {
            uuid: uuid.to_string(),
            title: title.to_string(),
            username: username.to_string(),
        }
    }

    #[test]
    fn permits_returns_true_for_granted_permission() {
        let permissions = [Permission::EntriesRead, Permission::ClipboardWrite];
        assert!(permits(&permissions, Permission::EntriesRead));
        assert!(permits(&permissions, Permission::ClipboardWrite));
    }

    #[test]
    fn permits_returns_false_for_ungranted_permission() {
        let permissions = [Permission::EntriesRead];
        assert!(!permits(&permissions, Permission::ClipboardWrite));
        assert!(!permits(&[], Permission::EntriesRead));
        assert!(!permits(&[], Permission::ClipboardWrite));
    }

    #[test]
    fn matches_query_empty_matches_everything() {
        let e = entry("u1", "GitHub", "alice@example.com");
        assert!(matches_query(&e, ""));
    }

    #[test]
    fn matches_query_is_case_insensitive_substring_on_title() {
        let e = entry("u1", "GitHub", "alice@example.com");
        assert!(matches_query(&e, "git"));
        assert!(matches_query(&e, "GITHUB"));
        assert!(matches_query(&e, "hub"));
        assert!(!matches_query(&e, "gitlab"));
    }

    #[test]
    fn matches_query_is_case_insensitive_substring_on_username() {
        let e = entry("u1", "GitHub", "alice@example.com");
        assert!(matches_query(&e, "ALICE"));
        assert!(matches_query(&e, "example.com"));
        assert!(!matches_query(&e, "bob"));
    }
}
