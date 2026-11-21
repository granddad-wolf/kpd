//! Key derivation and secret hygiene: composite keys and zeroized secrets.
//!
//! This crate owns the [`CompositeKey`] used to unlock a KeePass database. The
//! master password is wrapped in [`Zeroizing`] so it is zeroized from memory on
//! drop, the type deliberately does not implement `Clone`, and its `Debug`
//! implementation redacts the password.
//!
//! Argon2/AES-KDF derivation for the read path is performed by the `keepass`
//! crate via `kpd-kdbx`; no derivation lives here yet.

pub use zeroize::Zeroizing;

/// Composite key: master password and/or key-file path.
///
/// Secret material is zeroized on drop via [`Zeroizing`]. `Debug` redacts the
/// password. Intentionally not `Clone`: a password manager must not casually
/// duplicate key material.
#[derive(Default)]
pub struct CompositeKey {
    password: Option<Zeroizing<String>>,
    key_file_path: Option<std::path::PathBuf>,
}

impl CompositeKey {
    /// Empty key (neither password nor key file).
    pub fn new() -> Self {
        Self::default()
    }

    /// Build with a master password (zeroized internally).
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(Zeroizing::new(password.into()));
        self
    }

    /// Build with a key-file path.
    pub fn with_key_file_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.key_file_path = Some(path.into());
        self
    }

    /// The master password, if set.
    pub fn password(&self) -> Option<&str> {
        self.password.as_ref().map(|p| p.as_str())
    }

    /// The key-file path, if set.
    pub fn key_file_path(&self) -> Option<&std::path::Path> {
        self.key_file_path.as_deref()
    }

    /// `true` when neither a password nor a key file is set.
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.key_file_path.is_none()
    }
}

impl std::fmt::Debug for CompositeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeKey")
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("key_file_path", &self.key_file_path)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_empty_by_default() {
        assert!(CompositeKey::new().is_empty());
        assert!(CompositeKey::default().is_empty());
    }

    #[test]
    fn is_empty_false_when_password_set() {
        let key = CompositeKey::new().with_password("hunter2");
        assert!(!key.is_empty());
        assert_eq!(key.password(), Some("hunter2"));
        assert!(key.key_file_path().is_none());
    }

    #[test]
    fn is_empty_false_when_key_file_set() {
        let key = CompositeKey::new().with_key_file_path("key.keyx");
        assert!(!key.is_empty());
        assert!(key.password().is_none());
        assert_eq!(key.key_file_path(), Some(std::path::Path::new("key.keyx")));
    }

    #[test]
    fn is_empty_false_when_both_set() {
        let key = CompositeKey::new()
            .with_password("hunter2")
            .with_key_file_path("key.keyx");
        assert!(!key.is_empty());
    }

    // An empty string is still "a password set", so `is_empty` must be false.
    #[test]
    fn is_empty_false_when_empty_string_password_set() {
        let key = CompositeKey::new().with_password("");
        assert!(!key.is_empty());
        assert_eq!(key.password(), Some(""));
    }

    #[test]
    fn debug_redacts_password() {
        const SECRET: &str = "super-secret-password-123";
        let key = CompositeKey::new().with_password(SECRET);
        let debug = format!("{key:?}");
        assert!(!debug.contains(SECRET));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn debug_keeps_key_file_path() {
        let key = CompositeKey::new().with_key_file_path("key.keyx");
        let debug = format!("{key:?}");
        assert!(debug.contains("key.keyx"));
    }
}
