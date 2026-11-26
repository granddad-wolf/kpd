//! `plugin.toml` capability manifests.
//!
//! A plugin ships a manifest next to its component: `foo.wasm` is described by
//! `foo.toml`. The manifest declares the capabilities the plugin wants:
//!
//! ```toml
//! name = "kpd_plugin_example"
//! version = "0.1.0"
//! description = "Count, search, and copy demo plugin"
//! capabilities = ["entries.read", "clipboard.write"]
//! ```
//!
//! The TUI shows this declaration in a consent prompt before running a plugin;
//! the CLI refuses to run one without a manifest. The manifest is a
//! *declaration*, not the sandbox itself: the host still only links — and
//! enforces — the capabilities in [`PluginManifest::capabilities`].

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Permission;

/// A plugin manifest that could not be loaded or parsed.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// No `<name>.toml` next to the component.
    #[error("missing plugin manifest: {0} (a plugin must ship <name>.toml next to the .wasm)")]
    NotFound(PathBuf),
    /// The manifest exists but could not be read.
    #[error("cannot read plugin manifest {path}: {message}")]
    Io { path: PathBuf, message: String },
    /// The manifest is not valid TOML or is missing required fields.
    #[error("invalid plugin manifest {path}: {message}")]
    Invalid { path: PathBuf, message: String },
    /// A capability name the host does not know.
    #[error("unknown capability {capability:?} in {path} (known: entries.read, clipboard.write)")]
    UnknownCapability { path: PathBuf, capability: String },
}

/// A parsed `plugin.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManifest {
    /// Plugin display name.
    pub name: String,
    /// Optional version string.
    pub version: Option<String>,
    /// Optional one-line description shown in the consent prompt.
    pub description: Option<String>,
    /// Capabilities the plugin asks for (deduplicated, in manifest order).
    pub capabilities: Vec<Permission>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    capabilities: Vec<String>,
}

impl PluginManifest {
    /// The manifest path for a component: `foo.wasm` → `foo.toml`.
    #[must_use]
    pub fn path_for(wasm: &Path) -> PathBuf {
        wasm.with_extension("toml")
    }

    /// Load and validate the manifest that belongs to `wasm`.
    ///
    /// # Errors
    ///
    /// [`ManifestError::NotFound`] when the manifest is missing,
    /// [`ManifestError::Io`] when it cannot be read, and
    /// [`ManifestError::Invalid`] / [`ManifestError::UnknownCapability`] when
    /// it does not parse or names a capability the host does not implement.
    pub fn load(wasm: &Path) -> Result<Self, ManifestError> {
        let path = Self::path_for(wasm);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(ManifestError::NotFound(path));
            }
            Err(err) => {
                return Err(ManifestError::Io {
                    path,
                    message: err.to_string(),
                });
            }
        };
        Self::parse(&path, &text)
    }

    /// Parse manifest text that came from `path`.
    ///
    /// # Errors
    ///
    /// See [`Self::load`].
    pub fn parse(path: &Path, text: &str) -> Result<Self, ManifestError> {
        let raw: RawManifest = toml::from_str(text).map_err(|err| ManifestError::Invalid {
            path: path.to_path_buf(),
            message: err.to_string(),
        })?;

        let name = raw.name.trim();
        if name.is_empty() {
            return Err(ManifestError::Invalid {
                path: path.to_path_buf(),
                message: "name must not be empty".to_string(),
            });
        }

        let mut capabilities: Vec<Permission> = Vec::new();
        for capability in raw.capabilities {
            let permission = Permission::from_id(&capability).ok_or_else(|| {
                ManifestError::UnknownCapability {
                    path: path.to_path_buf(),
                    capability,
                }
            })?;
            if !capabilities.contains(&permission) {
                capabilities.push(permission);
            }
        }

        Ok(Self {
            name: name.to_string(),
            version: raw.version,
            description: raw.description,
            capabilities,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ManifestError, PluginManifest};
    use crate::Permission;
    use std::path::Path;

    fn parse(text: &str) -> Result<PluginManifest, ManifestError> {
        PluginManifest::parse(Path::new("/tmp/demo.toml"), text)
    }

    #[test]
    fn parses_a_full_manifest() {
        let manifest = parse(
            r#"
name = "demo"
version = "1.2.3"
description = "does a thing"
capabilities = ["entries.read", "clipboard.write"]
"#,
        )
        .expect("valid manifest");

        assert_eq!(manifest.name, "demo");
        assert_eq!(manifest.version.as_deref(), Some("1.2.3"));
        assert_eq!(manifest.description.as_deref(), Some("does a thing"));
        assert_eq!(
            manifest.capabilities,
            vec![Permission::EntriesRead, Permission::ClipboardWrite]
        );
    }

    #[test]
    fn capabilities_are_optional_and_deduplicated() {
        let manifest =
            parse("name = \"demo\"\ncapabilities = [\"entries.read\", \"entries.read\"]\n")
                .expect("valid manifest");
        assert_eq!(manifest.capabilities, vec![Permission::EntriesRead]);

        let manifest = parse("name = \"demo\"\n").expect("valid manifest");
        assert_eq!(manifest.capabilities, Vec::<Permission>::new());
    }

    #[test]
    fn unknown_capability_is_rejected() {
        let err = parse("name = \"demo\"\ncapabilities = [\"network\"]\n")
            .expect_err("unknown capability must fail");
        assert!(
            matches!(err, ManifestError::UnknownCapability { .. }),
            "{err}"
        );
    }

    #[test]
    fn unknown_fields_and_missing_name_are_rejected() {
        assert!(matches!(
            parse("name = \"demo\"\npermissions = []\n"),
            Err(ManifestError::Invalid { .. })
        ));
        assert!(matches!(
            parse("capabilities = []\n"),
            Err(ManifestError::Invalid { .. })
        ));
        assert!(matches!(
            parse("name = \"  \"\n"),
            Err(ManifestError::Invalid { .. })
        ));
    }

    #[test]
    fn missing_manifest_reports_the_expected_path() {
        let err = PluginManifest::load(Path::new("/nonexistent/demo.wasm"))
            .expect_err("missing manifest must fail");
        match err {
            ManifestError::NotFound(path) => {
                assert_eq!(path, Path::new("/nonexistent/demo.toml"));
            }
            other => panic!("expected NotFound, got {other}"),
        }
    }

    #[test]
    fn manifest_path_is_the_component_stem_with_toml() {
        assert_eq!(
            PluginManifest::path_for(Path::new("/plugins/demo.wasm")),
            Path::new("/plugins/demo.toml")
        );
    }
}
