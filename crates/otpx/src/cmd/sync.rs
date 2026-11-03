//! `otpx sync`: run a sync, list remotes, set them up.

use std::path::PathBuf;
use std::process::ExitCode;

use otpx_core::vault::VaultFile;
use serde_json::json;

use crate::config::{Remote, RemoteKind};
use crate::session::{self, read_secret};
use crate::sync::{self, Backend, github};
use crate::{Ctx, exit, fail, human_duration, now_ms, ui};

/// `otpx sync`.
#[derive(Debug, clap::Args)]
#[command(after_long_help = "\
Examples:
  otpx sync setup github --repo you/otpx-vault      # private repo; versions kept by git
  otpx sync setup gist                              # a new secret gist
  otpx sync setup folder ~/Library/Mobile\\ Documents/com~apple~CloudDocs/otpx
  otpx sync                                         # sync with every remote now

GitHub token: a fine-grained personal access token limited to the vault repository,
with \"Contents: read and write\" (gists: \"Gists: read and write\"). Create it at
https://github.com/settings/personal-access-tokens/new. The token stays in the keychain.

On a new device, the same `otpx sync setup …` fetches the vault (then `otpx unlock`),
or open a link from `otpx link` made on a device that already syncs.")]
pub struct SyncArgs {
    #[command(subcommand)]
    cmd: Option<SyncCmd>,
    /// Only this remote
    #[arg(long)]
    remote: Option<String>,
}

#[derive(Debug, clap::Subcommand)]
enum SyncCmd {
    /// List remotes
    Ls,
    /// Add a remote (and sync with it, or fetch the vault on a new device)
    Setup(SetupArgs),
    /// Remove a remote (its copy stays where it is)
    Remove {
        /// Remote name
        name: String,
    },
}

#[derive(Debug, clap::Args)]
struct SetupArgs {
    #[command(subcommand)]
    kind: SetupKind,
    /// Name of the remote (default: its kind)
    #[arg(long, global = true)]
    name: Option<String>,
    /// Read the token from stdin
    #[arg(long, global = true)]
    token_stdin: bool,
    /// Use the token of the GitHub CLI (`gh auth token`; broad scopes: prefer a fine-grained one)
    #[arg(long, global = true)]
    gh: bool,
    /// On a new device whose vault differs from the remote one: replace the local vault
    #[arg(long, global = true)]
    replace_local: bool,
}

#[derive(Debug, clap::Subcommand)]
enum SetupKind {
    /// A file in a private GitHub repository
    Github {
        /// owner/name
        #[arg(long)]
        repo: String,
        /// Path in the repository
        #[arg(long, default_value = "vault.otpx")]
        path: String,
        /// Branch (default: the repository's default branch)
        #[arg(long, default_value = "")]
        branch: String,
        /// Create the private repository with the GitHub CLI if it does not exist
        #[arg(long)]
        create: bool,
    },
    /// A file in a secret gist (a new one unless --id)
    Gist {
        /// Existing gist id
        #[arg(long)]
        id: Option<String>,
        /// File name in the gist
        #[arg(long, default_value = "vault.otpx")]
        file: String,
    },
    /// A folder synced by another tool (iCloud Drive, Dropbox, Syncthing…)
    Folder {
        /// The folder
        path: PathBuf,
    },
}

/// Runs `otpx sync …`.
pub fn run(a: SyncArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    match a.cmd {
        None => {
            let mut s = session::open(ctx)?;
            let done = sync::sync_all(ctx, &mut s, a.remote.as_deref())?;
            ctx.ui.say(&format!(
                "Synced with {} remote(s); {} account(s).",
                done.len(),
                s.vault.data.entries.len()
            ));
            Ok(ExitCode::SUCCESS)
        }
        Some(SyncCmd::Ls) => {
            let cfg = ctx.config();
            for r in &cfg.remotes {
                ctx.ui.emit(
                    "remote",
                    json!({ "name": r.name, "target": r.describe(), "last_sync": r.last_sync }),
                );
                let when = if r.last_sync == 0 {
                    "never".into()
                } else {
                    format!(
                        "{} ago",
                        human_duration(now_ms().saturating_sub(r.last_sync) / 1000)
                    )
                };
                ctx.ui.say(&format!(
                    "{:<10} {}  (last sync: {when})",
                    r.name,
                    ui::clean(&r.describe())
                ));
            }
            if cfg.remotes.is_empty() {
                ctx.ui.note("No remote. See `otpx sync --help`.");
            }
            Ok(ExitCode::SUCCESS)
        }
        Some(SyncCmd::Remove { name }) => {
            if ctx.config().remote(&name).is_none() {
                return Err(fail(exit::NOT_FOUND, format!("no remote {name:?}")));
            }
            ctx.update_config(|c| c.remotes.retain(|r| r.name != name))?;
            ctx.secrets().delete(&format!("remote:{name}"))?;
            ctx.ui.emit("remote_removed", json!({ "name": name }));
            ctx.ui
                .say(&format!("Removed {name} (its copy is untouched)."));
            Ok(ExitCode::SUCCESS)
        }
        Some(SyncCmd::Setup(s)) => setup(s, ctx),
    }
}

fn get_token(ctx: &Ctx, a: &SetupArgs) -> anyhow::Result<String> {
    if a.token_stdin {
        return Ok(read_secret("", true)?.trim().to_owned());
    }
    if a.gh {
        let out = std::process::Command::new("gh")
            .args(["auth", "token"])
            .output()
            .map_err(|_| fail(exit::USAGE, "the GitHub CLI (gh) is not installed"))?;
        let t = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if t.is_empty() {
            return Err(fail(
                exit::AUTH,
                "`gh auth token` printed nothing: run `gh auth login`",
            ));
        }
        ctx.ui.warn("using the GitHub CLI token: it can reach all your repositories; a fine-grained token limited to the vault repository is safer");
        return Ok(t);
    }
    if let Ok(t) = std::env::var("OTPX_GITHUB_TOKEN")
        && !t.trim().is_empty()
    {
        return Ok(t.trim().to_owned());
    }
    if ui::interactive() {
        ctx.ui.note("A fine-grained token limited to the vault repository (Contents: read and write), or with Gists: read and write:");
        ctx.ui
            .note("  https://github.com/settings/personal-access-tokens/new");
        let t = read_secret("GitHub token: ", false)?;
        return Ok(t.trim().to_owned());
    }
    Err(fail(
        exit::USAGE,
        "a GitHub token is needed: --token-stdin, --gh or OTPX_GITHUB_TOKEN",
    ))
}

fn setup(a: SetupArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let (default_name, kind, token) = match &a.kind {
        SetupKind::Github {
            repo,
            path,
            branch,
            create,
        } => {
            if !repo.contains('/') {
                return Err(fail(exit::USAGE, "--repo is owner/name"));
            }
            let token = get_token(ctx, &a)?;
            if *create {
                let exists = github::Repo::new(token.clone(), repo, path, branch)
                    .check()
                    .is_ok();
                if !exists {
                    let st = std::process::Command::new("gh")
                        .args([
                            "repo",
                            "create",
                            repo,
                            "--private",
                            "--description",
                            "otpx vault (encrypted)",
                        ])
                        .status()
                        .map_err(|_| fail(exit::USAGE, "--create needs the GitHub CLI (gh)"))?;
                    if !st.success() {
                        return Err(fail(
                            exit::NETWORK,
                            format!("`gh repo create {repo}` failed"),
                        ));
                    }
                }
            }
            let private = github::Repo::new(token.clone(), repo, path, branch).check()?;
            if !private {
                ctx.ui.warn(&format!("{repo} is public: the vault is encrypted, but a private repository hides even its existence and history"));
            }
            (
                "github",
                RemoteKind::Github {
                    repo: repo.clone(),
                    path: path.clone(),
                    branch: branch.clone(),
                },
                Some(token),
            )
        }
        SetupKind::Gist { id, file } => {
            let token = get_token(ctx, &a)?;
            let id = match id {
                Some(i) => i.clone(),
                None => {
                    // A placeholder file: the first sync replaces it with the vault.
                    let id = github::Gist::create(
                        &token,
                        &format!("{file}.README"),
                        "otpx vault: the encrypted vault is the other file of this gist.\n",
                    )?;
                    ctx.ui.note(&format!("Created the secret gist {id}."));
                    id
                }
            };
            (
                "gist",
                RemoteKind::Gist {
                    id,
                    file: file.clone(),
                },
                Some(token),
            )
        }
        SetupKind::Folder { path } => {
            if !path.is_dir() {
                std::fs::create_dir_all(path)
                    .map_err(|e| fail(exit::USAGE, format!("{}: {e}", path.display())))?;
            }
            let path = path.canonicalize()?;
            ("folder", RemoteKind::Folder { path }, None)
        }
    };
    let name = a.name.clone().unwrap_or_else(|| default_name.to_owned());
    let remote = Remote {
        name: name.clone(),
        kind,
        last_sync: 0,
        seen_key: String::new(),
    };
    if let Some(t) = &token {
        ctx.secrets().set(&format!("remote:{name}"), t.as_bytes())?;
    }
    let backend = sync::backend(ctx, &remote)?;
    attach(ctx, &remote, backend.as_ref(), a.replace_local)?;
    ctx.update_config(|c| {
        c.remotes.retain(|r| r.name != name);
        c.remotes.push(Remote {
            last_sync: now_ms(),
            ..remote.clone()
        });
    })?;
    ctx.ui.emit(
        "remote_added",
        json!({ "name": name, "target": remote.describe() }),
    );
    Ok(ExitCode::SUCCESS)
}

/// First contact with a remote: push the local vault, merge, or fetch it on a new device.
pub fn attach(
    ctx: &Ctx,
    remote: &Remote,
    backend: &dyn Backend,
    replace_local: bool,
) -> anyhow::Result<()> {
    let local = ctx.store.read()?;
    let fetched = backend.fetch()?;
    match (local, fetched) {
        (None, None) => Err(fail(
            exit::NOT_FOUND,
            "no vault here nor on the remote: run `otpx init` first",
        )),
        (None, Some((content, _))) => {
            let file = VaultFile::parse(&content).map_err(|e| {
                fail(
                    exit::CONFLICT,
                    format!("the remote file is not an otpx vault: {e}"),
                )
            })?;
            ctx.store.write(&file.to_json(), now_ms())?;
            ctx.ui.say(&format!(
                "Fetched your vault from {}. Unlock it with `otpx unlock`.",
                remote.describe()
            ));
            Ok(())
        }
        (Some((lf, _)), Some((content, _))) if replace_local => {
            let file = VaultFile::parse(&content).map_err(|e| {
                fail(
                    exit::CONFLICT,
                    format!("the remote file is not an otpx vault: {e}"),
                )
            })?;
            if file.id != lf.id {
                ctx.store.write(&file.to_json(), now_ms())?;
                session::forget(ctx)?;
                ctx.ui.say("Replaced the local vault with the remote one (the old one is in `otpx backup ls`). Unlock with `otpx unlock`.");
                return Ok(());
            }
            sync_with(ctx, backend, remote)
        }
        (Some(_), _) => sync_with(ctx, backend, remote),
    }
}

fn sync_with(ctx: &Ctx, backend: &dyn Backend, remote: &Remote) -> anyhow::Result<()> {
    let mut s = session::open(ctx)?;
    let o = sync::sync_one(ctx, backend, &mut s, &remote.seen_key)?;
    session::write_local(ctx, &mut s)?;
    ctx.ui.say(&format!(
        "{} is set up ({}).",
        remote.describe(),
        o.as_str()
    ));
    Ok(())
}
