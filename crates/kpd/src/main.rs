use std::path::PathBuf;
use std::time::Duration;

use kpd_crypto::CompositeKey;
use kpd_plugin_runtime::{EntrySummary, Limits, PluginRuntime, RunContext};
use kpd_storage::{from_spec, BackendSpec, Storage};
use kpd_tui::{run, AppConfig};

enum Action {
    Run(AppConfig),
    Cloud(CloudCommand),
    Plugin(PluginCommand),
    Version,
    Help,
}

enum CloudCommand {
    Fetch {
        backend: Box<dyn Storage>,
        out: PathBuf,
    },
    Push {
        backend: Box<dyn Storage>,
        from: PathBuf,
    },
}

struct PluginCommand {
    wasm: PathBuf,
    command: String,
    args: Vec<String>,
    db: Option<PathBuf>,
    password_env: String,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Ok(Action::Run(config)) => {
            if let Err(err) = run(config) {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Cloud(command)) => {
            if let Err(err) = run_cloud(command) {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Plugin(command)) => {
            if let Err(err) = run_plugin(command) {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Version) => println!("kpd {}", env!("CARGO_PKG_VERSION")),
        Ok(Action::Help) => print_help(),
        Err(msg) => {
            eprintln!("error: {msg}\n");
            print_help();
            std::process::exit(2);
        }
    }
}

fn parse(args: &[String]) -> Result<Action, String> {
    if args.is_empty() {
        return Err("missing command".to_string());
    }
    match args[0].as_str() {
        "--version" | "-V" => Ok(Action::Version),
        "--help" | "-h" => Ok(Action::Help),
        "open" => parse_open(&args[1..]),
        "cloud" => parse_cloud(&args[1..]),
        "plugin" => parse_plugin(&args[1..]),
        other => Err(format!("unknown command or flag: {other}")),
    }
}

fn parse_open(args: &[String]) -> Result<Action, String> {
    // Usage:
    //   kpd open <path>            [--keyfile <path>] [--timeout <secs>]
    //   kpd open --webdav <url>    [--keyfile <path>] [--timeout <secs>]
    //   kpd open --dropbox <path>  [--keyfile <path>] [--timeout <secs>]
    let mut local: Option<PathBuf> = None;
    let mut cloud: Option<BackendSpec> = None;
    let mut key_file = None;
    let mut timeout = Duration::from_secs(30);

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--keyfile" | "-k" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| format!("{} requires a value", args[i - 1]))?;
                key_file = Some(PathBuf::from(value));
            }
            "--timeout" | "-t" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| format!("{} requires a value", args[i - 1]))?;
                let secs = value
                    .parse::<u64>()
                    .map_err(|_| "timeout must be a non-negative integer (seconds)".to_string())?;
                timeout = Duration::from_secs(secs);
            }
            "--webdav" => {
                i += 1;
                let url = args
                    .get(i)
                    .ok_or_else(|| "--webdav requires a URL".to_string())?;
                cloud = Some(cloud_spec("webdav", url)?);
            }
            "--dropbox" => {
                i += 1;
                let path = args
                    .get(i)
                    .ok_or_else(|| "--dropbox requires a remote path".to_string())?;
                cloud = Some(cloud_spec("dropbox", path)?);
            }
            other if other.starts_with('-') => return Err(format!("unknown option: {other}")),
            other => {
                if local.replace(PathBuf::from(other)).is_some() {
                    return Err("only one database path may be given".to_string());
                }
            }
        }
        i += 1;
    }

    let config = match (local, cloud) {
        (Some(path), None) => {
            let mut config = AppConfig::new(path);
            config.key_file = key_file;
            config.clipboard_timeout = timeout;
            config
        }
        (None, Some(spec)) => {
            let mut config = AppConfig::cloud(spec);
            config.key_file = key_file;
            config.clipboard_timeout = timeout;
            config
        }
        (None, None) => {
            return Err(
                "`open` requires a database path or a cloud backend (--webdav/--dropbox)"
                    .to_string(),
            )
        }
        (Some(_), Some(_)) => {
            return Err("choose either a local path or a cloud backend, not both".to_string())
        }
    };

    Ok(Action::Run(config))
}

fn parse_cloud(args: &[String]) -> Result<Action, String> {
    if args.is_empty() {
        return Err("`cloud` requires `fetch` or `push`".to_string());
    }
    match args[0].as_str() {
        "fetch" => parse_cloud_fetch(&args[1..]),
        "push" => parse_cloud_push(&args[1..]),
        other => Err(format!(
            "unknown cloud command: {other} (expected fetch | push)"
        )),
    }
}

fn parse_cloud_fetch(args: &[String]) -> Result<Action, String> {
    if args.len() < 3 {
        return Err("usage: kpd cloud fetch <webdav|dropbox> <url|path> <out>".to_string());
    }
    let backend = cloud_backend(&args[0], &args[1])?;
    let out = PathBuf::from(&args[2]);
    Ok(Action::Cloud(CloudCommand::Fetch { backend, out }))
}

fn parse_cloud_push(args: &[String]) -> Result<Action, String> {
    if args.len() < 3 {
        return Err("usage: kpd cloud push <webdav|dropbox> <url|path> <from>".to_string());
    }
    let backend = cloud_backend(&args[0], &args[1])?;
    let from = PathBuf::from(&args[2]);
    Ok(Action::Cloud(CloudCommand::Push { backend, from }))
}

/// Build the backend descriptor for a kind + location. Secrets come from
/// environment variables so they never appear on the command line or in argv.
fn cloud_spec(kind: &str, location: &str) -> Result<BackendSpec, String> {
    Ok(match kind {
        "webdav" => BackendSpec::WebDav {
            url: location.to_string(),
            username: std::env::var("KPD_WEBDAV_USER").ok(),
            password: std::env::var("KPD_WEBDAV_PASS").ok(),
        },
        "dropbox" => BackendSpec::Dropbox {
            access_token: std::env::var("KPD_DROPBOX_TOKEN")
                .map_err(|_| "KPD_DROPBOX_TOKEN environment variable must be set".to_string())?,
            path: location.to_string(),
        },
        other => {
            return Err(format!(
                "unknown backend kind: {other} (expected webdav | dropbox)"
            ));
        }
    })
}

/// Build a boxed `Storage` backend from a kind + location.
fn cloud_backend(kind: &str, location: &str) -> Result<Box<dyn Storage>, String> {
    from_spec(cloud_spec(kind, location)?).map_err(|e| e.to_string())
}

fn run_cloud(command: CloudCommand) -> Result<(), String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        match command {
            CloudCommand::Fetch { backend, out } => {
                let data = backend.read().await.map_err(|e| e.to_string())?;
                std::fs::write(&out, &data).map_err(|e| format!("write {}: {e}", out.display()))?;
                eprintln!("fetched {} bytes -> {}", data.len(), out.display());
                Ok(())
            }
            CloudCommand::Push { backend, from } => {
                let data =
                    std::fs::read(&from).map_err(|e| format!("read {}: {e}", from.display()))?;
                let meta = backend
                    .write(&data, None)
                    .await
                    .map_err(|e| e.to_string())?;
                let rev = meta.revision.unwrap_or_default();
                eprintln!("pushed {} bytes (revision: {rev})", data.len());
                Ok(())
            }
        }
    })
}

fn parse_plugin(args: &[String]) -> Result<Action, String> {
    let mut db = None;
    let mut password_env = "KPD_DB_PASSWORD".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--db requires a path".to_string())?;
                db = Some(PathBuf::from(value));
            }
            "--password-env" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--password-env requires a variable name".to_string())?;
                password_env = value.clone();
            }
            _ => break,
        }
        i += 1;
    }

    let rest = &args[i..];
    if rest.len() < 2 {
        return Err(
            "usage: kpd plugin [--db <path>] [--password-env <VAR>] <wasm> <command> [args...]"
                .to_string(),
        );
    }

    Ok(Action::Plugin(PluginCommand {
        wasm: PathBuf::from(&rest[0]),
        command: rest[1].clone(),
        args: rest[2..].to_vec(),
        db,
        password_env,
    }))
}

/// Run a plugin against the (optional) database entry list.
///
/// With `--db`, the master password is read from the environment variable named
/// by `--password-env` (default `KPD_DB_PASSWORD`) so it never appears on argv.
fn run_plugin(command: PluginCommand) -> Result<(), String> {
    let entries = match &command.db {
        Some(db_path) => {
            let password = std::env::var(&command.password_env).map_err(|_| {
                format!(
                    "set {} to the database master password (or omit --db to run without entries)",
                    command.password_env
                )
            })?;
            let key = CompositeKey::new().with_password(password);
            let db = kpd_kdbx::open(db_path, &key).map_err(|err| err.to_string())?;
            db.all_entries()
                .into_iter()
                .filter_map(|entry_ref| {
                    db.entry(entry_ref.entry_uuid).map(|entry| EntrySummary {
                        uuid: entry.uuid.to_string(),
                        title: entry.title.clone(),
                        username: entry.username.clone(),
                    })
                })
                .collect()
        }
        None => Vec::new(),
    };

    let manifest = kpd_plugin_runtime::PluginManifest::load(&command.wasm)
        .map_err(|err| format!("plugin manifest: {err}"))?;
    let runtime = PluginRuntime::new();
    let mut plugin = runtime
        .load(&command.wasm, &manifest.capabilities, Limits::default())
        .map_err(|err| format!("load plugin: {err}"))?;

    let mut ctx = RunContext {
        entries,
        ..Default::default()
    };
    let result = plugin
        .run(&command.command, &command.args, &mut ctx)
        .map_err(|err| format!("run plugin: {err}"))?;

    println!("{result}");
    for line in &ctx.logs {
        eprintln!("log: {line}");
    }
    for text in &ctx.copied {
        eprintln!("copied: {text}");
    }
    Ok(())
}

fn print_help() {
    println!(
        "kpd {} — KeePass-compatible TUI password manager\n\n\
         USAGE:\n\
         \x20   kpd open <path> [--keyfile <path>] [--timeout <secs>]\n\
         \x20   kpd open --webdav <url> [--keyfile <path>] [--timeout <secs>]\n\
         \x20   kpd open --dropbox <path> [--keyfile <path>] [--timeout <secs>]\n\
         \x20   kpd cloud fetch <webdav|dropbox> <url|path> <out>\n\
         \x20   kpd cloud push <webdav|dropbox> <url|path> <from>\n\
         \x20   kpd plugin [--db <path>] [--password-env <VAR>] <wasm> <command> [args...]\n\
         \x20   kpd --version\n\
         \x20   kpd --help\n\n\
         OPTIONS (open):\n\
         \x20   -k, --keyfile <path>   Key file for the composite key\n\
         \x20   -t, --timeout <secs>   Clipboard auto-clear timeout (default 30)\n\
         \x20   --webdav <url>         Open/save the database on a WebDAV server\n\
         \x20   --dropbox <path>       Open/save the database in Dropbox\n\n\
         CLOUD ENV VARS (secrets are read from the environment, never argv):\n\
         \x20   KPD_WEBDAV_USER / KPD_WEBDAV_PASS   WebDAV basic-auth credentials\n\
         \x20   KPD_DROPBOX_TOKEN                    Dropbox OAuth2 access token\n\n\
         PLUGIN ENV VARS:\n\
         \x20   KPD_DB_PASSWORD   Master password for `plugin --db` (default variable)\n\n\
         PLUGIN MANIFESTS:\n\
         \x20   A plugin must ship <name>.toml next to the .wasm, declaring\n\
         \x20   capabilities = [\"entries.read\", \"clipboard.write\"].\n\n\
         FLAGS:\n\
         \x20   -V, --version   Print version\n\
         \x20   -h, --help      Print help",
        env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::{cloud_backend, parse, Action};
    use kpd_storage::BackendSpec;
    use kpd_tui::DbLocation;

    #[test]
    fn cloud_fetch_requires_three_args() {
        let args: Vec<String> = ["cloud", "fetch", "webdav", "https://x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(parse(&args).is_err());
    }

    #[test]
    fn cloud_unknown_subcommand_is_an_error() {
        let args: Vec<String> = ["cloud", "sync"].iter().map(|s| s.to_string()).collect();
        assert!(parse(&args).is_err());
    }

    #[test]
    fn dropbox_backend_requires_token_env() {
        // Ensure the token is not set for this test.
        std::env::remove_var("KPD_DROPBOX_TOKEN");
        assert!(cloud_backend("dropbox", "/vault/keepass.kdbx").is_err());
    }

    #[test]
    fn unknown_backend_kind_is_an_error() {
        assert!(cloud_backend("s3", "/vault/keepass.kdbx").is_err());
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn open_parses_into_run_action() {
        match parse(&args(&["open", "/tmp/db.kdbx"])) {
            Ok(Action::Run(config)) => {
                assert!(matches!(config.location, DbLocation::Local(_)));
            }
            _ => panic!("expected a Run action"),
        }
    }

    #[test]
    fn open_webdav_parses_into_a_cloud_run() {
        match parse(&args(&[
            "open",
            "--webdav",
            "https://dav.example.com/db.kdbx",
        ])) {
            Ok(Action::Run(config)) => match config.location {
                DbLocation::Cloud(BackendSpec::WebDav { url, .. }) => {
                    assert_eq!(url, "https://dav.example.com/db.kdbx");
                }
                other => panic!("expected a WebDAV cloud location, got {other:?}"),
            },
            _ => panic!("expected a Run action"),
        }
    }

    #[test]
    fn open_accepts_options_around_the_cloud_backend() {
        match parse(&args(&[
            "open",
            "--timeout",
            "5",
            "--webdav",
            "https://dav.example.com/db.kdbx",
            "--keyfile",
            "/tmp/db.key",
        ])) {
            Ok(Action::Run(config)) => {
                assert_eq!(config.clipboard_timeout, std::time::Duration::from_secs(5));
                assert_eq!(
                    config.key_file.as_deref(),
                    Some(std::path::Path::new("/tmp/db.key"))
                );
                assert!(config.location.is_cloud());
            }
            _ => panic!("expected a Run action"),
        }
    }

    #[test]
    fn open_requires_a_path_or_a_cloud_backend() {
        assert!(parse(&args(&["open"])).is_err());
        assert!(parse(&args(&["open", "--webdav"])).is_err());
        assert!(parse(&args(&["open", "--nonsense"])).is_err());
    }

    #[test]
    fn open_rejects_a_local_path_and_a_cloud_backend_together() {
        let parsed = parse(&args(&[
            "open",
            "/tmp/db.kdbx",
            "--webdav",
            "https://dav.example.com/db.kdbx",
        ]));
        assert!(parsed.is_err());
    }

    #[test]
    fn plugin_parses_into_plugin_action() {
        let args: Vec<String> = ["plugin", "p.wasm", "count"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(matches!(parse(&args), Ok(Action::Plugin(_))));
    }

    #[test]
    fn plugin_requires_wasm_and_command() {
        let args: Vec<String> = ["plugin", "p.wasm"].iter().map(|s| s.to_string()).collect();
        assert!(parse(&args).is_err());
    }
}
