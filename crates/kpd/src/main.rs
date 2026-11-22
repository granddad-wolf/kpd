use std::path::PathBuf;
use std::time::Duration;

use kpd_crypto::CompositeKey;
use kpd_plugin_runtime::{EntrySummary, Limits, Permission, PluginRuntime, RunContext};
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
    if args.is_empty() {
        return Err("`open` requires a database path".to_string());
    }

    let db_path = PathBuf::from(&args[0]);
    let mut key_file = None;
    let mut timeout = Duration::from_secs(30);

    let mut i = 1;
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
            other => return Err(format!("unknown option: {other}")),
        }
        i += 1;
    }

    Ok(Action::Run(AppConfig {
        db_path,
        key_file,
        clipboard_timeout: timeout,
    }))
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

/// Build a boxed `Storage` backend from a kind + location. Secrets come from
/// environment variables so they never appear on the command line.
fn cloud_backend(kind: &str, location: &str) -> Result<Box<dyn Storage>, String> {
    let spec = match kind {
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
    };
    from_spec(spec).map_err(|e| e.to_string())
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

    let runtime = PluginRuntime::new();
    let permissions = [Permission::EntriesRead, Permission::ClipboardWrite];
    let mut plugin = runtime
        .load(&command.wasm, &permissions, Limits::default())
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
         \x20   kpd cloud fetch <webdav|dropbox> <url|path> <out>\n\
         \x20   kpd cloud push <webdav|dropbox> <url|path> <from>\n\
         \x20   kpd plugin [--db <path>] [--password-env <VAR>] <wasm> <command> [args...]\n\
         \x20   kpd --version\n\
         \x20   kpd --help\n\n\
         OPTIONS (open):\n\
         \x20   -k, --keyfile <path>   Key file for the composite key\n\
         \x20   -t, --timeout <secs>   Clipboard auto-clear timeout (default 30)\n\n\
         CLOUD ENV VARS (secrets are read from the environment, never argv):\n\
         \x20   KPD_WEBDAV_USER / KPD_WEBDAV_PASS   WebDAV basic-auth credentials\n\
         \x20   KPD_DROPBOX_TOKEN                    Dropbox OAuth2 access token\n\n\
         PLUGIN ENV VARS:\n\
         \x20   KPD_DB_PASSWORD   Master password for `plugin --db` (default variable)\n\n\
         FLAGS:\n\
         \x20   -V, --version   Print version\n\
         \x20   -h, --help      Print help",
        env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::{cloud_backend, parse, Action};

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

    #[test]
    fn open_parses_into_run_action() {
        let args: Vec<String> = ["open", "/tmp/db.kdbx"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(matches!(parse(&args), Ok(Action::Run(_))));
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
