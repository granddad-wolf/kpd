use std::path::PathBuf;
use kpd_plugin_runtime::{Limits, Permission, PluginRuntime, RunContext};

fn sample_plugin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../plugins/example/target/wasm32-wasip2/release/kpd_plugin_example.wasm")
}

#[test]
#[ignore = "requires the sample plugin built for wasm32-wasip2"]
fn runs_the_sample_plugin_with_capabilities() {
    let path = sample_plugin_path();
    assert!(path.exists(), "build the sample plugin first");
    let runtime = PluginRuntime::new();
    let mut plugin = runtime
        .load(&path, &[Permission::EntriesRead, Permission::ClipboardWrite], Limits::default())
        .expect("load plugin");
    let mut ctx = RunContext::default();
    assert_eq!(plugin.run("copy", &["hello".to_string()], &mut ctx).expect("run copy"), "true");
    assert_eq!(ctx.copied, vec!["hello".to_string()]);
    assert!(ctx.logs.iter().any(|l| l.contains("copy(hello) -> true")));
    let mut ctx = RunContext::default();
    assert_eq!(plugin.run("count", &[], &mut ctx).expect("run count"), "0");
}

#[test]
#[ignore = "requires the sample plugin built for wasm32-wasip2"]
fn denies_ungranted_capabilities() {
    let path = sample_plugin_path();
    assert!(path.exists(), "build the sample plugin first");
    let runtime = PluginRuntime::new();
    let mut plugin = runtime.load(&path, &[], Limits::default()).expect("load plugin");
    let mut ctx = RunContext::default();
    assert_eq!(plugin.run("copy", &["hello".to_string()], &mut ctx).expect("run copy"), "false");
    assert!(ctx.copied.is_empty());
}
