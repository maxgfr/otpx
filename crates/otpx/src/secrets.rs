//! Small secrets of this device: the cached vault key, quick-unlock material and sync
//! tokens. In the OS keychain (macOS Keychain, Secret Service on Linux), or in
//! `secrets.json` (0600) in the config directory when the keychain is off
//! (`OTPX_KEYCHAIN=0`, headless machines, tests).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Once;

use anyhow::Context as _;
use zeroize::Zeroizing;

use crate::paths;

/// Keychain service name.
const SERVICE: &str = "otpx";

/// Where secrets go.
pub struct Secrets {
    scope: String,
    file: Option<PathBuf>,
}

fn keychain_wanted() -> bool {
    !matches!(
        std::env::var("OTPX_KEYCHAIN").as_deref(),
        Ok("0" | "off" | "false" | "no")
    )
}

fn init_store() -> bool {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        #[cfg(target_os = "macos")]
        let store = apple_native_keyring_store::keychain::Store::new()
            .map(|s| s as std::sync::Arc<keyring_core::CredentialStore>);
        #[cfg(all(unix, not(target_os = "macos")))]
        let store = dbus_secret_service_keyring_store::Store::new()
            .map(|s| s as std::sync::Arc<keyring_core::CredentialStore>);
        #[cfg(not(unix))]
        let store: keyring_core::Result<std::sync::Arc<keyring_core::CredentialStore>> =
            Err(keyring_core::Error::NoDefaultStore);
        if let Ok(s) = store {
            keyring_core::set_default_store(s);
        }
    });
    keyring_core::get_default_store().is_some()
}

impl Secrets {
    /// Secrets of the config directory `dir` (items are scoped to it, so two config
    /// directories never share a key).
    pub fn new(dir: &Path) -> Secrets {
        let canon = dir.canonicalize().unwrap_or_else(|_| dir.to_owned());
        let digest = <sha2::Sha256 as sha2::Digest>::digest(canon.to_string_lossy().as_bytes());
        let scope = data_encoding::HEXLOWER.encode(&digest[..6]);
        let file = if keychain_wanted() && init_store() {
            None
        } else {
            Some(dir.join("secrets.json"))
        };
        Secrets { scope, file }
    }

    /// `keychain` or `file`.
    pub fn backend(&self) -> &'static str {
        if self.file.is_some() {
            "file"
        } else {
            "keychain"
        }
    }

    fn user(&self, name: &str) -> String {
        format!("{}:{name}", self.scope)
    }

    fn read_file(path: &Path) -> anyhow::Result<BTreeMap<String, String>> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                paths::check_private(path)?;
                serde_json::from_str(&s).with_context(|| format!("reading {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// The secret `name`, if set.
    pub fn get(&self, name: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        if let Some(path) = &self.file {
            let map = Secrets::read_file(path)?;
            return Ok(match map.get(name) {
                Some(v) => Some(Zeroizing::new(
                    data_encoding::BASE64
                        .decode(v.as_bytes())
                        .context("secrets.json")?,
                )),
                None => None,
            });
        }
        let entry = keyring_core::Entry::new(SERVICE, &self.user(name)).context("keychain")?;
        match entry.get_secret() {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::Error::new(e).context("reading the keychain")),
        }
    }

    /// Sets the secret `name`.
    pub fn set(&self, name: &str, value: &[u8]) -> anyhow::Result<()> {
        if let Some(path) = &self.file {
            let mut map = Secrets::read_file(path)?;
            map.insert(name.to_owned(), data_encoding::BASE64.encode(value));
            let s = Zeroizing::new(serde_json::to_string_pretty(&map).expect("map serializes"));
            return paths::write_private(path, s.as_bytes());
        }
        keyring_core::Entry::new(SERVICE, &self.user(name))
            .and_then(|e| e.set_secret(value))
            .context("writing the keychain")
    }

    /// Removes the secret `name` (no error when absent).
    pub fn delete(&self, name: &str) -> anyhow::Result<()> {
        if let Some(path) = &self.file {
            let mut map = Secrets::read_file(path)?;
            if map.remove(name).is_some() {
                let s = serde_json::to_string_pretty(&map).expect("map serializes");
                paths::write_private(path, s.as_bytes())?;
            }
            return Ok(());
        }
        match keyring_core::Entry::new(SERVICE, &self.user(name))
            .and_then(|e| e.delete_credential())
        {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow::Error::new(e).context("writing the keychain")),
        }
    }
}
