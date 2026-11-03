//! A folder remote: `vault.otpx` in a directory another tool syncs (iCloud Drive,
//! Dropbox, Syncthing, a USB key). The version is a hash of the content.

use std::path::{Path, PathBuf};

use super::{Backend, PushError, Version};
use crate::{exit, fail, paths};

/// A folder remote.
pub struct Folder {
    file: PathBuf,
}

impl Folder {
    /// The remote at `dir`.
    pub fn new(dir: &Path) -> Folder {
        Folder {
            file: dir.join("vault.otpx"),
        }
    }
}

fn version(content: &str) -> Version {
    let d = <sha2::Sha256 as sha2::Digest>::digest(content.as_bytes());
    data_encoding::HEXLOWER.encode(&d)
}

impl Backend for Folder {
    fn fetch(&self) -> anyhow::Result<Option<(String, Version)>> {
        match std::fs::read_to_string(&self.file) {
            Ok(s) => {
                let v = version(&s);
                Ok(Some((s, v)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let dir = self.file.parent().unwrap_or(Path::new("."));
                if !dir.is_dir() {
                    return Err(fail(
                        exit::NETWORK,
                        format!("{} is not reachable (unmounted?)", dir.display()),
                    ));
                }
                Ok(None)
            }
            Err(e) => Err(fail(exit::NETWORK, format!("{}: {e}", self.file.display()))),
        }
    }

    fn push(
        &self,
        content: &str,
        base: Option<&Version>,
        _message: &str,
    ) -> Result<Version, PushError> {
        let current = self.fetch()?;
        if current.as_ref().map(|c| &c.1) != base {
            return Err(PushError::Conflict);
        }
        paths::write_private(&self.file, content.as_bytes())?;
        Ok(version(content))
    }
}
