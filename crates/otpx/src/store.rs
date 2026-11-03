//! The vault file on disk (`<data dir>/vault.otpx`) and its snapshots.
//!
//! Every write keeps the previous file in `backups/` (the last [`KEEP`]), so no change,
//! import or sync can lose what was there before.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use otpx_core::vault::VaultFile;

use crate::{exit, fail, paths};

/// Snapshots kept.
pub const KEEP: usize = 50;

/// Paths of a data directory.
#[derive(Debug, Clone)]
pub struct Store {
    /// Data directory.
    pub dir: PathBuf,
}

/// An exclusive lock on the vault, released on drop.
pub struct Lock {
    _file: std::fs::File,
}

impl Store {
    /// The vault file.
    pub fn vault(&self) -> PathBuf {
        self.dir.join("vault.otpx")
    }

    /// The snapshot directory.
    pub fn backups(&self) -> PathBuf {
        self.dir.join("backups")
    }

    /// Whether a vault exists.
    pub fn exists(&self) -> bool {
        self.vault().is_file()
    }

    /// Takes the lock (waits for another otpx writing the vault).
    pub fn lock(&self) -> anyhow::Result<Lock> {
        paths::make_private_dir(&self.dir)?;
        let p = self.dir.join("vault.lock");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&p)
            .with_context(|| format!("opening {}", p.display()))?;
        f.lock()
            .with_context(|| format!("locking {}", p.display()))?;
        Ok(Lock { _file: f })
    }

    /// Reads the vault file.
    pub fn read(&self) -> anyhow::Result<Option<(VaultFile, String)>> {
        let p = self.vault();
        match std::fs::read_to_string(&p) {
            Ok(s) => {
                paths::check_private(&p)?;
                let f = VaultFile::parse(&s)
                    .map_err(|e| fail(exit::ERROR, format!("{}: {e}", p.display())))?;
                Ok(Some((f, s)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    /// Writes the vault file, first keeping the current one as a snapshot. Unchanged
    /// content is not rewritten.
    pub fn write(&self, json: &str, now_ms: u64) -> anyhow::Result<()> {
        let p = self.vault();
        if let Ok(old) = std::fs::read_to_string(&p) {
            if old == json {
                return Ok(());
            }
            let b = self.backups();
            paths::make_private_dir(&b)?;
            paths::write_private(&b.join(format!("vault-{now_ms}.otpx")), old.as_bytes())?;
            self.prune()?;
        }
        paths::write_private(&p, json.as_bytes())
    }

    /// Snapshots, newest first: `(path, time ms)`.
    pub fn snapshots(&self) -> anyhow::Result<Vec<(PathBuf, u64)>> {
        let mut v: Vec<(PathBuf, u64)> = match std::fs::read_dir(self.backups()) {
            Ok(rd) => rd
                .filter_map(Result::ok)
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let t = name
                        .strip_prefix("vault-")?
                        .strip_suffix(".otpx")?
                        .parse()
                        .ok()?;
                    Some((e.path(), t))
                })
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).context("listing snapshots"),
        };
        v.sort_by_key(|s| std::cmp::Reverse(s.1));
        Ok(v)
    }

    fn prune(&self) -> anyhow::Result<()> {
        for (p, _) in self.snapshots()?.into_iter().skip(KEEP) {
            let _ = std::fs::remove_file(p);
        }
        Ok(())
    }
}

/// Reads a vault file given on the command line.
pub fn read_vault_file(path: &Path) -> anyhow::Result<VaultFile> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    VaultFile::parse(&s).map_err(|e| fail(exit::USAGE, format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_are_kept_and_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store {
            dir: dir.path().to_owned(),
        };
        s.write("v0", 0).unwrap();
        for i in 1..=(KEEP as u64 + 5) {
            s.write(&format!("v{i}"), i).unwrap();
        }
        s.write(&format!("v{}", KEEP + 5), 999).unwrap();
        let snaps = s.snapshots().unwrap();
        assert_eq!(snaps.len(), KEEP);
        assert_eq!(
            std::fs::read_to_string(&snaps[0].0).unwrap(),
            format!("v{}", KEEP + 4)
        );
        let _l = s.lock().unwrap();
    }
}
