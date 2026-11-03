//! `config.json` in the config directory: this device's settings. Never synced (the vault
//! carries what all devices share).

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use crate::paths;

/// How long an unlock lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnlockMode {
    /// The key stays in the OS keychain for `ttl_secs` after `otpx unlock`.
    #[default]
    KeychainTtl,
    /// The key stays in the OS keychain until `otpx lock`.
    KeychainPersistent,
    /// Every command asks (nothing is cached).
    AlwaysAsk,
}

impl UnlockMode {
    /// Parses a mode name.
    pub fn parse(s: &str) -> Option<UnlockMode> {
        Some(match s {
            "keychain-ttl" | "ttl" => UnlockMode::KeychainTtl,
            "keychain-persistent" | "persistent" => UnlockMode::KeychainPersistent,
            "always-ask" | "always" | "ask" => UnlockMode::AlwaysAsk,
            _ => return None,
        })
    }

    /// Name as written in the config.
    pub fn as_str(self) -> &'static str {
        match self {
            UnlockMode::KeychainTtl => "keychain-ttl",
            UnlockMode::KeychainPersistent => "keychain-persistent",
            UnlockMode::AlwaysAsk => "always-ask",
        }
    }
}

/// A place the vault syncs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RemoteKind {
    /// A file in a (private) GitHub repository, through the Contents API.
    Github {
        /// `owner/name`.
        repo: String,
        /// Path of the vault in the repository.
        path: String,
        /// Branch (empty: the default branch).
        #[serde(default)]
        branch: String,
    },
    /// A file of a secret gist.
    Gist {
        /// Gist id.
        id: String,
        /// File name in the gist.
        file: String,
    },
    /// A folder (iCloud Drive, Dropbox, Syncthing, a USB key…).
    Folder {
        /// The folder; the vault is `vault.otpx` inside.
        path: PathBuf,
    },
}

/// A configured remote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remote {
    /// Short name (`github`, `gist`, `icloud`…).
    pub name: String,
    /// Where.
    #[serde(flatten)]
    pub kind: RemoteKind,
    /// Last successful sync (ms).
    #[serde(default)]
    pub last_sync: u64,
    /// The vault key id this remote held after the last sync: a re-key endorsed only by an
    /// older key cannot be a concurrent one any more.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub seen_key: String,
}

impl Remote {
    /// One-line description.
    pub fn describe(&self) -> String {
        match &self.kind {
            RemoteKind::Github { repo, path, branch } => {
                let b = if branch.is_empty() {
                    String::new()
                } else {
                    format!("@{branch}")
                };
                format!("github {repo}{b}:{path}")
            }
            RemoteKind::Gist { id, file } => format!("gist {id}/{file}"),
            RemoteKind::Folder { path } => format!("folder {}", path.display()),
        }
    }

    /// Whether it needs a token.
    pub fn needs_token(&self) -> bool {
        !matches!(self.kind, RemoteKind::Folder { .. })
    }
}

/// Device-local quick unlock.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quick {
    /// Touch ID releases the key kept in the keychain (macOS).
    #[serde(default)]
    pub touchid: bool,
    /// A PIN opens `pin.json` (with a device secret kept in the keychain).
    #[serde(default)]
    pub pin: bool,
}

/// Wrong PINs before the PIN is erased.
pub const PIN_ATTEMPTS: u32 = 5;

/// The config file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Random id of this device, written in the stamps of its changes.
    pub device_id: String,
    /// Human name of this device (hostname by default).
    #[serde(default)]
    pub device_name: String,
    /// How unlocking is cached.
    #[serde(default)]
    pub unlock_mode: UnlockMode,
    /// Session length for [`UnlockMode::KeychainTtl`].
    #[serde(default = "default_ttl")]
    pub unlock_ttl_secs: u64,
    /// Quick unlock.
    #[serde(default)]
    pub quick: Quick,
    /// Sync targets.
    #[serde(default)]
    pub remotes: Vec<Remote>,
    /// Sync after each change (best effort).
    #[serde(default = "yes")]
    pub auto_sync: bool,
    /// Base URL of share links.
    #[serde(default)]
    pub web_base: String,
    /// The user wrote the recovery code down (`otpx recovery --confirm`).
    #[serde(default)]
    pub recovery_confirmed: bool,
}

fn default_ttl() -> u64 {
    15 * 60
}

fn yes() -> bool {
    true
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().trim_end_matches(".local").to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "this device".to_owned())
}

impl Config {
    fn fresh() -> anyhow::Result<Config> {
        Ok(Config {
            device_id: otpx_core::model::random_id(6)?,
            device_name: hostname(),
            unlock_mode: UnlockMode::default(),
            unlock_ttl_secs: default_ttl(),
            quick: Quick::default(),
            remotes: Vec::new(),
            auto_sync: true,
            web_base: String::new(),
            recovery_confirmed: false,
        })
    }

    /// Path of the file in `dir`.
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("config.json")
    }

    /// Loads the config of `dir`, or a fresh one (not written until [`Config::save`]).
    pub fn load(dir: &Path) -> anyhow::Result<Config> {
        let p = Config::path(dir);
        match std::fs::read_to_string(&p) {
            Ok(s) => serde_json::from_str(&s).with_context(|| format!("reading {}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::fresh(),
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    /// Writes the config (0600).
    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        let mut s = serde_json::to_string_pretty(self).expect("config serializes");
        s.push('\n');
        paths::write_private(&Config::path(dir), s.as_bytes())
    }

    /// The remote named `name`.
    pub fn remote(&self, name: &str) -> Option<&Remote> {
        self.remotes.iter().find(|r| r.name == name)
    }

    /// Base URL of share links.
    pub fn web_base(&self) -> String {
        if self.web_base.is_empty() {
            otpx_core::share::DEFAULT_BASE.to_owned()
        } else {
            self.web_base.clone()
        }
    }
}
