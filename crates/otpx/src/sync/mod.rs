//! Syncing the vault file with remotes.
//!
//! Each remote holds the same encrypted file. A sync fetches it, merges it entry by entry
//! with the local vault (both sides keep their changes, see `otpx_core::merge`), and
//! writes the result back only if the remote did not change meanwhile (GitHub: the blob
//! sha; gist: the revision; folder: a hash), retrying otherwise.

pub mod folder;
pub mod github;

use std::time::Duration;

use otpx_core::vault::VaultFile;
use serde_json::json;

use crate::config::{Remote, RemoteKind};
use crate::session::Session;
use crate::{Ctx, core_failure, exit, fail, now_ms};

/// A version of the remote file (blob sha, gist revision, content hash).
pub type Version = String;

/// What a push can run into.
pub enum PushError {
    /// The remote changed since it was read.
    Conflict,
    /// The write landed but replaced a version written meanwhile (gists have no conditional
    /// write): that version's content, to merge and push again.
    Overwrote(String),
    /// Anything else.
    Other(anyhow::Error),
}

impl From<anyhow::Error> for PushError {
    fn from(e: anyhow::Error) -> PushError {
        PushError::Other(e)
    }
}

/// A place holding the vault file.
pub trait Backend {
    /// The file and its version, or `None` when there is none yet.
    fn fetch(&self) -> anyhow::Result<Option<(String, Version)>>;
    /// Writes the file if the remote is still at `base` (`None`: must not exist yet).
    fn push(
        &self,
        content: &str,
        base: Option<&Version>,
        message: &str,
    ) -> Result<Version, PushError>;
}

/// The token of a remote (keychain), or from the environment.
pub fn token(ctx: &Ctx, remote: &Remote) -> anyhow::Result<String> {
    if let Some(t) = ctx.secrets().get(&format!("remote:{}", remote.name))? {
        return Ok(String::from_utf8_lossy(&t).into_owned());
    }
    for var in ["OTPX_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(t) = std::env::var(var)
            && !t.trim().is_empty()
        {
            return Ok(t.trim().to_owned());
        }
    }
    Err(fail(
        exit::NETWORK,
        format!(
            "no token for remote {:?}: run `otpx sync setup` again or set OTPX_GITHUB_TOKEN",
            remote.name
        ),
    ))
}

/// The backend of a remote.
pub fn backend(ctx: &Ctx, remote: &Remote) -> anyhow::Result<Box<dyn Backend>> {
    let token = if remote.needs_token() {
        token(ctx, remote)?
    } else {
        String::new()
    };
    Ok(backend_with(remote, token))
}

/// The backend of a remote with a given token (a device link's, before it is stored).
pub fn backend_with(remote: &Remote, token: String) -> Box<dyn Backend> {
    match &remote.kind {
        RemoteKind::Github { repo, path, branch } => {
            Box::new(github::Repo::new(token, repo, path, branch))
        }
        RemoteKind::Gist { id, file } => Box::new(github::Gist::new(token, id, file)),
        RemoteKind::Folder { path } => Box::new(folder::Folder::new(path)),
    }
}
/// What one sync did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Both sides were the same.
    UpToDate,
    /// Local changes went up.
    Pushed,
    /// Remote changes came down.
    Pulled,
    /// Both.
    Merged,
}

impl Outcome {
    /// Human name.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::UpToDate => "up to date",
            Outcome::Pushed => "pushed",
            Outcome::Pulled => "pulled",
            Outcome::Merged => "merged",
        }
    }
}

fn parse_remote(content: &str, s: &Session) -> anyhow::Result<VaultFile> {
    let file = VaultFile::parse(content).map_err(|e| {
        fail(
            exit::CONFLICT,
            format!("the remote file is not an otpx vault: {e}"),
        )
    })?;
    if file.id != s.vault.id {
        return Err(fail(
            exit::CONFLICT,
            "the remote holds another vault (use another path, or `otpx sync setup … --replace-local` on a new device)",
        ));
    }
    Ok(file)
}

/// Merges a remote copy into `s`; returns whether it brought something and whether the remote
/// needs the merged result.
fn merge_remote(ctx: &Ctx, s: &mut Session, file: &VaultFile) -> anyhow::Result<(bool, bool)> {
    use otpx_core::vault::Trust;
    let before = (s.vault.data.clone(), s.vault.keyring.clone());
    match file.trust(&s.vault) {
        Trust::Same => {
            let other = file.unlock_dek(s.vault.dek()).map_err(|_| {
                fail(
                    exit::CONFLICT,
                    "the remote vault does not open with this vault's key: it was modified",
                )
            })?;
            let change = s.vault.absorb(&other, now_ms()).map_err(core_failure)?;
            crate::session::note_keyring(ctx, change);
            let differs = s.vault.data != other.data || s.vault.keyring != other.keyring;
            Ok((
                before.0 != s.vault.data || before.1 != s.vault.keyring,
                differs,
            ))
        }
        // An old copy under a key this vault rotated away from (stale, or replayed): replace it.
        Trust::Stale => Ok((false, true)),
        t @ (Trust::Endorsed | Trust::Concurrent) => {
            crate::session::rekey(ctx, s, file, t == Trust::Concurrent)?;
            let other = file.unlock_dek(s.vault.dek()).ok();
            let differs =
                other.is_none_or(|o| s.vault.data != o.data || s.vault.keyring != o.keyring);
            Ok((true, differs))
        }
        Trust::Untrusted => Err(fail(
            exit::CONFLICT,
            "the remote vault was re-keyed by something this device cannot verify (a tampered remote?): nothing was merged or sent",
        )),
    }
}

/// Syncs `s` with one backend.
pub fn sync_one(ctx: &Ctx, backend: &dyn Backend, s: &mut Session) -> anyhow::Result<Outcome> {
    let device = ctx.config().device_name;
    let mut pulled = false;
    for attempt in 0..6 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(200 * attempt));
        }
        let remote = backend.fetch()?;
        let base = match &remote {
            Some((content, version)) => {
                let file = parse_remote(content, s)?;
                let (brought, differs) = merge_remote(ctx, s, &file)?;
                pulled |= brought;
                if !differs {
                    return Ok(if pulled {
                        Outcome::Pulled
                    } else {
                        Outcome::UpToDate
                    });
                }
                Some(version.clone())
            }
            None => None,
        };
        let json = s.vault.seal().map_err(core_failure)?.to_json();
        let msg = format!("otpx: sync from {device}");
        match backend.push(&json, base.as_ref(), &msg) {
            Ok(_) => {
                return Ok(if pulled {
                    Outcome::Merged
                } else {
                    Outcome::Pushed
                });
            }
            Err(PushError::Conflict) => continue,
            Err(PushError::Overwrote(lost)) => {
                // Merge the version our write replaced, then write again.
                let file = parse_remote(&lost, s)?;
                pulled |= merge_remote(ctx, s, &file)?.0;
            }
            Err(PushError::Other(e)) => return Err(e),
        }
    }
    Err(fail(
        exit::CONFLICT,
        "the remote kept changing during the sync; try again",
    ))
}

/// Syncs with every remote (or the one named), saving locally after.
pub fn sync_all(
    ctx: &Ctx,
    s: &mut Session,
    only: Option<&str>,
) -> anyhow::Result<Vec<(String, Outcome)>> {
    let cfg = ctx.config();
    let remotes: Vec<Remote> = cfg
        .remotes
        .iter()
        .filter(|r| only.is_none_or(|n| r.name == n))
        .cloned()
        .collect();
    if remotes.is_empty() {
        return Err(fail(
            exit::NOT_FOUND,
            match only {
                Some(n) => format!("no remote named {n:?} (see `otpx sync ls`)"),
                None => {
                    "no remote: `otpx sync setup github --repo you/otpx-vault` (or gist, folder)"
                        .into()
                }
            },
        ));
    }
    let mut done = Vec::new();
    let mut errors = Vec::new();
    for r in &remotes {
        let res = backend(ctx, r).and_then(|b| sync_one(ctx, b.as_ref(), s));
        match res {
            Ok(o) => {
                ctx.ui
                    .emit("synced", json!({ "remote": r.name, "result": o.as_str() }));
                ctx.ui.note(&format!("{}: {}", r.name, o.as_str()));
                let name = r.name.clone();
                ctx.update_config(|c| {
                    if let Some(x) = c.remotes.iter_mut().find(|x| x.name == name) {
                        x.last_sync = now_ms();
                    }
                })?;
                done.push((r.name.clone(), o));
            }
            Err(e) => errors.push((r.name.clone(), e)),
        }
    }
    crate::session::write_local(ctx, s)?;
    if let Some((name, e)) = errors.into_iter().next() {
        let code = e
            .downcast_ref::<crate::Failure>()
            .map_or(exit::NETWORK, |f| f.code);
        return Err(fail(code, format!("{name}: {e:#}")));
    }
    Ok(done)
}

/// A shared HTTP agent: 30 s timeouts, statuses returned rather than turned into errors.
pub fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(concat!("otpx/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}
