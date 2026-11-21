//! # `kpd-plugin-api`
//!
//! The WebAssembly host↔plugin contract for `kpd`, expressed in
//! [WIT](https://component-model.bytecodealliance.org/design/wit.html) (the
//! Component Model interface-definition language).
//!
//! This crate **owns** the contract file `wit/world.wit` and documents it. It
//! deliberately carries **no** runtime dependencies — in particular no
//! `wasmtime` and no `wit-bindgen` — so both the host loader
//! (`kpd-plugin-runtime`, which reads the WIT via
//! `wasmtime::component::bindgen!`) and guest plugins (which read it via
//! `wit_bindgen::generate!`) can point at the `.wit` file by path without
//! taking a Cargo dependency on this crate.
//!
//! ## The `plugin` world
//!
//! The file `wit/world.wit` defines one world, `plugin`:
//!
//! ```wit
//! package kpd:plugin@0.1.0;
//!
//! world plugin {
//!     import entries;    // entries.list-entries(query) -> list<entry-summary>
//!     import clipboard;  // clipboard.copy(text) -> bool
//!     import logging;    // logging.log(message)
//!     export run: func(command: string, args: list<string>) -> string;
//! }
//! ```
//!
//! A plugin may *import* exactly those three host interfaces and *export* the
//! single `run` entry point. That WIT world **is** the entire capability
//! surface: one imported interface == one capability, and nothing else is
//! reachable.
//!
//! ## Capability model
//!
//! | Interface   | Function        | Capability                                   | Gating on the host                   |
//! |-------------|-----------------|----------------------------------------------|--------------------------------------|
//! | `entries`   | `list-entries`  | Read filtered entry summaries.               | Requires the `entries.read` grant; otherwise returns an empty list. |
//! | `clipboard` | `copy`          | Copy text to the host clipboard.             | Requires the `clipboard.write` grant; otherwise returns `false`. |
//! | `logging`   | `log`           | Append a message to the host log.            | Always allowed.                      |
//!
//! ## Secrets never cross the boundary
//!
//! The `entry-summary` record carries only `uuid`, `title`, and `username`.
//! Passwords, notes, custom fields, and raw database bytes are
//! never exposed, and the master key is never passed to a plugin.
//!
//! ## No ambient access
//!
//! The world imports no `wasi:*` interface, so a plugin has no filesystem,
//! network, socket, clock, or environment access unless the host explicitly
//! links those interfaces (the `kpd` host does not).
