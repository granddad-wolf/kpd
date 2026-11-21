//! A minimal example plugin for `kpd`, demonstrating the `plugin` world.
//!
//! It implements the guest side of `kpd-plugin-api/wit/world.wit`: it imports
//! the `entries` / `clipboard` / `logging` host interfaces and exports a single
//! `run(command, args) -> string` entry point.
//!
//! Commands:
//!   * `count`               -> number of entries (empty query = all)
//!   * `search <query>`      -> `title (username)` lines matching the query
//!   * `copy <text>`         -> `clipboard.copy(text)`, reported as "true"/"false"
//!   * anything else         -> usage text


mod bindings {
    wit_bindgen::generate!({
        path: "../../crates/kpd-plugin-api/wit/world.wit",
    });

    use super::Plugin;
    export!(Plugin);
}

struct Plugin;

impl bindings::Guest for Plugin {
    fn run(command: String, args: Vec<String>) -> String {
        match command.as_str() {
            "count" => {
                // Empty query = all entries (per the WIT contract).
                let entries = bindings::kpd::plugin::entries::list_entries("");
                entries.len().to_string()
            }
            "search" => {
                let query = args.join(" ");
                let entries = bindings::kpd::plugin::entries::list_entries(&query);
                entries
                    .iter()
                    .map(|entry| format!("{} ({})", entry.title, entry.username))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            "copy" => {
                let text = args.join(" ");
                let copied = bindings::kpd::plugin::clipboard::copy(&text);
                // Note: `logging` is always available, so demonstrate it too.
                bindings::kpd::plugin::logging::log(&format!("copy({text}) -> {copied}"));
                copied.to_string()
            }
            _ => usage(),
        }
    }
}

fn usage() -> String {
    let mut out = String::new();
    out.push_str("usage:\n");
    out.push_str("  count           number of entries\n");
    out.push_str("  search <query>  list matching 'title (username)' lines\n");
    out.push_str("  copy <text>     copy text to the host clipboard\n");
    out
}
