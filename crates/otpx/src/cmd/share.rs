//! Sharing: encrypted links, age files, device setup links, receiving them.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use otpx_core::share::{self, Share};
use serde_json::json;

use super::{entry_json, resolve};
use crate::config::Remote;
use crate::session::{self, read_secret};
use crate::{Ctx, core_failure, exit, fail, now_ms, parse_duration, ui};

/// `otpx share`.
#[derive(Debug, clap::Args)]
pub struct ShareArgs {
    #[command(subcommand)]
    cmd: ShareCmd,
}

#[derive(Debug, clap::Subcommand)]
enum ShareCmd {
    /// An encrypted link (the key is in the #fragment, never sent to any server)
    Link {
        /// Accounts to share
        #[arg(required = true)]
        queries: Vec<String>,
        /// Refuse to open after this long (e.g. 10m, 1d; 0 for never)
        #[arg(long, default_value = "1d")]
        expires: String,
        /// Also require a passphrase (asked here; send it another way)
        #[arg(long)]
        passphrase: bool,
        /// Read the passphrase from stdin
        #[arg(long)]
        passphrase_stdin: bool,
        /// Show the link as a QR code too
        #[arg(long)]
        qr: bool,
    },
    /// An age file for someone's public key (`otpx id` on their side)
    Age {
        /// Accounts to share
        #[arg(required = true)]
        queries: Vec<String>,
        /// Recipient public key (age1…), repeatable
        #[arg(long = "to", required = true)]
        to: Vec<String>,
        /// Output file (default: stdout, ASCII-armored)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// The account's QR code, to scan with any authenticator app
    Qr {
        /// Account
        query: String,
    },
}

/// Shares accounts.
pub fn share(a: ShareArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    match a.cmd {
        ShareCmd::Link {
            queries,
            expires,
            passphrase,
            passphrase_stdin,
            qr,
        } => {
            let s = session::open(ctx)?;
            let entries = pick(&s.vault.data, &queries)?;
            let secs = parse_duration(&expires)?;
            let exp = if secs == 0 { 0 } else { now_ms() + secs * 1000 };
            let pass = if passphrase_stdin {
                Some(read_secret("", true)?)
            } else if passphrase {
                Some(super::vault::new_password(false, "passphrase")?)
            } else {
                None
            };
            let link = share::create_link(
                &ctx.config().web_base(),
                &Share::accounts(&entries, exp),
                pass.as_deref().map(|p| p.as_str()),
            )
            .map_err(core_failure)?;
            ctx.ui.emit("share_link", json!({ "link": link, "expires": exp, "passphrase": pass.is_some(), "count": entries.len() }));
            if !ctx.ui.is_json() {
                if qr {
                    println!("{}", otpx_core::qr::terminal(&link).map_err(core_failure)?);
                }
                println!("{link}");
                ctx.ui.note(&format!(
                    "Anyone with this link{} can add {} account(s) until it expires{}. Send it over a private channel.",
                    if pass.is_some() { " and the passphrase" } else { "" },
                    entries.len(),
                    if exp == 0 { " (never)".into() } else { format!(" (in {expires})") },
                ));
            }
        }
        ShareCmd::Age { queries, to, out } => {
            let s = session::open(ctx)?;
            let entries = pick(&s.vault.data, &queries)?;
            let recips: Vec<&str> = to.iter().map(String::as_str).collect();
            let armored =
                share::age_encrypt(&recips, &Share::accounts(&entries, 0)).map_err(core_failure)?;
            match out {
                Some(p) => {
                    crate::paths::write_export(&p, armored.as_bytes())?;
                    ctx.ui
                        .emit("share_age", json!({ "path": p, "count": entries.len() }));
                    ctx.ui.say(&format!(
                        "Wrote {} for {} recipient(s): they open it with `otpx receive {}`.",
                        p.display(),
                        to.len(),
                        p.display()
                    ));
                }
                None => print!("{armored}"),
            }
        }
        ShareCmd::Qr { query } => {
            return super::io::qr(super::io::QrArgs { query, svg: None }, ctx);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn pick(data: &otpx_core::VaultData, queries: &[String]) -> anyhow::Result<Vec<otpx_core::Entry>> {
    let mut v: Vec<otpx_core::Entry> = Vec::new();
    for q in queries {
        let e = resolve(data, q)?;
        if !v.iter().any(|x| x.id == e.id) {
            v.push(e.clone());
        }
    }
    Ok(v)
}

/// `otpx receive`.
#[derive(Debug, clap::Args)]
pub struct ReceiveArgs {
    /// A share link, an age file, or `-` for stdin
    input: String,
    /// Read the passphrase from stdin
    #[arg(long)]
    passphrase_stdin: bool,
    /// Add without asking
    #[arg(short, long)]
    yes: bool,
}

/// Opens a share.
pub fn receive(a: ReceiveArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let raw = if a.input == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else if std::path::Path::new(&a.input).is_file() {
        std::fs::read_to_string(&a.input)?
    } else {
        a.input.clone()
    };
    let trimmed = raw.trim();
    let shared =
        if trimmed.starts_with("-----BEGIN AGE") || trimmed.starts_with("age-encryption.org/") {
            let s = session::open(ctx)?;
            share::age_decrypt(&s.vault.data.identities, trimmed.as_bytes(), now_ms())
                .map_err(core_failure)?
        } else {
            let pass = if share::link_needs_passphrase(trimmed) {
                Some(read_secret("Passphrase: ", a.passphrase_stdin)?)
            } else {
                None
            };
            share::open_link(trimmed, pass.as_deref().map(|p| p.as_str()), now_ms()).map_err(
                |e| match e {
                    otpx_core::Error::Decrypt => fail(
                        exit::AUTH,
                        "this link does not open (wrong passphrase, or a truncated link)",
                    ),
                    e => core_failure(e),
                },
            )?
        };
    if let Some(device) = &shared.device {
        return receive_device(ctx, device);
    }
    for e in &shared.entries {
        ctx.ui.emit("shared", entry_json(e));
        ctx.ui.note(&format!("  {}", ui::clean(&e.label())));
    }
    if !a.yes
        && !ctx
            .ui
            .confirm(&format!("Add these {} account(s)", shared.entries.len()))?
    {
        return Err(fail(exit::USAGE, "cancelled"));
    }
    let mut s = session::open(ctx)?;
    let device = ctx.config().device_id;
    let mut added = 0;
    for e in shared.entries.iter().cloned() {
        if s.vault
            .data
            .add_unique(e, now_ms(), &device)
            .map_err(core_failure)?
        {
            added += 1;
        }
    }
    if added > 0 {
        session::save(ctx, &mut s)?;
    }
    ctx.ui.emit(
        "received",
        json!({ "added": added, "count": shared.entries.len() }),
    );
    let dup = shared.entries.len() - added;
    ctx.ui.say(&format!(
        "Added {added} account(s){}.",
        if dup > 0 {
            format!(", {dup} already there")
        } else {
            String::new()
        }
    ));
    Ok(ExitCode::SUCCESS)
}

/// The device setup carried by `otpx link`.
#[derive(serde::Serialize, serde::Deserialize)]
struct DeviceSetup {
    remotes: Vec<Remote>,
    tokens: Vec<(String, String)>,
}

fn receive_device(ctx: &Ctx, device: &serde_json::Value) -> anyhow::Result<ExitCode> {
    let setup: DeviceSetup = serde_json::from_value(device.clone())
        .map_err(|e| fail(exit::USAGE, format!("device setup: {e}")))?;
    for (name, token) in &setup.tokens {
        ctx.secrets()
            .set(&format!("remote:{name}"), token.as_bytes())?;
    }
    let names: Vec<String> = setup.remotes.iter().map(|r| r.name.clone()).collect();
    ctx.update_config(|c| {
        for r in &setup.remotes {
            c.remotes.retain(|x| x.name != r.name);
            c.remotes.push(Remote {
                last_sync: 0,
                ..r.clone()
            });
        }
    })?;
    ctx.ui.emit("device_setup", json!({ "remotes": names }));
    ctx.ui.say(&format!(
        "Set up {} remote(s): {}.",
        names.len(),
        names.join(", ")
    ));
    if let Some(r) = setup.remotes.first() {
        let backend = crate::sync::backend(ctx, r)?;
        super::sync::attach(ctx, r, backend.as_ref(), false)?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Prints the age public key, creating the identity on first use.
pub fn id(ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let mut s = session::open(ctx)?;
    if s.vault.data.identities.is_empty() {
        s.vault.data.identities.push(share::new_identity(now_ms()));
        session::save(ctx, &mut s)?;
    }
    let public = s
        .vault
        .data
        .primary_identity()
        .map(|i| i.public.clone())
        .unwrap_or_default();
    ctx.ui.emit("identity", json!({ "public": public }));
    if ctx.ui.is_json() {
        return Ok(ExitCode::SUCCESS);
    }
    println!("{public}");
    ctx.ui.note(
        "Give this key to people who share accounts with you (`otpx share age … --to <key>`).",
    );
    Ok(ExitCode::SUCCESS)
}

/// `otpx link`.
#[derive(Debug, clap::Args)]
pub struct LinkArgs {
    /// Refuse to open after this long
    #[arg(long, default_value = "15m")]
    expires: String,
    /// Read the passphrase from stdin
    #[arg(long)]
    passphrase_stdin: bool,
    /// Show the link as a QR code too
    #[arg(long)]
    qr: bool,
}

/// Makes a device setup link (remotes and tokens, passphrase required).
pub fn link(a: LinkArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let cfg = ctx.config();
    if cfg.remotes.is_empty() {
        return Err(fail(
            exit::NOT_FOUND,
            "no remote to hand over: `otpx sync setup …` first",
        ));
    }
    let mut tokens = Vec::new();
    for r in cfg.remotes.iter().filter(|r| r.needs_token()) {
        tokens.push((r.name.clone(), crate::sync::token(ctx, r)?));
    }
    let folders = cfg.remotes.iter().any(|r| !r.needs_token());
    let setup = DeviceSetup {
        remotes: cfg.remotes.clone(),
        tokens,
    };
    let pass = read_secret(
        "Passphrase for the link (tell it to yourself on the other device): ",
        a.passphrase_stdin,
    )?;
    if pass.chars().count() < 6 {
        return Err(fail(
            exit::USAGE,
            "use a passphrase of 6 characters or more: the link carries your sync tokens",
        ));
    }
    let secs = parse_duration(&a.expires)?.max(60);
    let share = Share {
        v: 1,
        entries: Vec::new(),
        device: Some(serde_json::to_value(&setup)?),
        expires: now_ms() + secs * 1000,
        note: String::new(),
    };
    let link = share::create_link(&cfg.web_base(), &share, Some(&pass)).map_err(core_failure)?;
    ctx.ui.emit("device_link", json!({ "link": link }));
    if !ctx.ui.is_json() {
        if a.qr {
            println!("{}", otpx_core::qr::terminal(&link).map_err(core_failure)?);
        }
        println!("{link}");
        ctx.ui.note(&format!("On the new device: `otpx receive '<link>'` (or open it in the web app), then `otpx unlock`. Valid {}.", a.expires));
        if folders {
            ctx.ui.note("Folder remotes are copied as paths: they work only if the folder exists at the same place there.");
        }
    }
    Ok(ExitCode::SUCCESS)
}
