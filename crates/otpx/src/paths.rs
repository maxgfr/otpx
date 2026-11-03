//! Directories and private files.
//!
//! Config (`config.json`, quick-unlock data): `--config-dir`, `$OTPX_CONFIG_DIR`,
//! `$XDG_CONFIG_HOME/otpx`, `~/.config/otpx`. Data (the vault and its snapshots):
//! `--data-dir`, `$OTPX_DATA_DIR`, `$XDG_DATA_HOME/otpx`, `~/.local/share/otpx`. Same on
//! macOS, so the paths are easy to find and to back up. Directories are 0700, files 0600.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

use crate::{exit, fail};

fn resolve(
    explicit: Option<OsString>,
    xdg: Option<OsString>,
    home: Option<OsString>,
    sub: &[&str],
) -> Option<PathBuf> {
    let set = |v: Option<OsString>| v.filter(|s| !s.is_empty()).map(PathBuf::from);
    set(explicit)
        .or_else(|| set(xdg).map(|x| x.join("otpx")))
        .or_else(|| {
            set(home).map(|h| {
                let mut p = h;
                for s in sub {
                    p = p.join(s);
                }
                p.join("otpx")
            })
        })
}

/// The config directory.
pub fn config_dir(flag: Option<&Path>) -> anyhow::Result<PathBuf> {
    resolve(
        flag.map(|p| p.as_os_str().to_owned()),
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
        &[".config"],
    )
    .ok_or_else(|| {
        fail(
            exit::ERROR,
            "no config directory: set OTPX_CONFIG_DIR or HOME",
        )
    })
}

/// The data directory.
pub fn data_dir(flag: Option<&Path>) -> anyhow::Result<PathBuf> {
    resolve(
        flag.map(|p| p.as_os_str().to_owned()),
        std::env::var_os("XDG_DATA_HOME"),
        std::env::var_os("HOME"),
        &[".local", "share"],
    )
    .ok_or_else(|| fail(exit::ERROR, "no data directory: set OTPX_DATA_DIR or HOME"))
}

/// Creates `dir` (and parents) readable by the owner only.
pub fn make_private_dir(dir: &Path) -> anyhow::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(())
}

/// Writes `bytes` to `path` atomically (temporary file, fsync, rename), mode 0600.
pub fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    make_private_dir(dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)
            .and_then(|()| f.sync_all())
            .with_context(|| format!("writing {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Writes a shared file (an export the user asked for): atomic, mode 0600 too, since every
/// export holds secrets.
pub fn write_export(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !dir.is_dir() {
        return Err(fail(
            exit::USAGE,
            format!("{} is not a directory", dir.display()),
        ));
    }
    let tmp = dir.join(format!(".otpx-export.{}.tmp", std::process::id()));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)
            .and_then(|()| f.sync_all())
            .with_context(|| format!("writing {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Refuses a file or directory others can read.
#[cfg(unix)]
pub fn check_private(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        let fix = if meta.is_dir() {
            "chmod 700"
        } else {
            "chmod 600"
        };
        return Err(fail(
            exit::ERROR,
            format!(
                "{} is readable by other users (mode {mode:o}); run `{fix} {}`",
                path.display(),
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Refuses a file or directory others can read.
#[cfg(not(unix))]
pub fn check_private(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_order() {
        let r = |e: Option<&str>, x: Option<&str>, h: Option<&str>| {
            resolve(
                e.map(Into::into),
                x.map(Into::into),
                h.map(Into::into),
                &[".config"],
            )
        };
        assert_eq!(
            r(Some("/a"), Some("/x"), Some("/h")),
            Some(PathBuf::from("/a"))
        );
        assert_eq!(
            r(Some(""), Some("/x"), Some("/h")),
            Some(PathBuf::from("/x/otpx"))
        );
        assert_eq!(
            r(None, None, Some("/h")),
            Some(PathBuf::from("/h/.config/otpx"))
        );
        assert_eq!(r(None, None, None), None);
    }

    #[test]
    fn private_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub").join("f");
        write_private(&p, b"one").unwrap();
        write_private(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        check_private(&p).unwrap();
        check_private(p.parent().unwrap()).unwrap();
    }
}
