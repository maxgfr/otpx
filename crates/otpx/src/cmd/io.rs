//! Import, export, QR codes and snapshots.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use otpx_core::formats::{self, ExportFormat, Format};
use otpx_core::model::Entry;
use serde_json::json;

use super::{entry_json, resolve};
use crate::session::{self, read_secret};
use crate::{Ctx, core_failure, exit, fail, now_ms, ui};

/// `otpx import`.
#[derive(Debug, clap::Args)]
#[command(after_long_help = "\
Where to get the files:
  Google Authenticator   ⋮ > Transfer accounts > Export: screenshot each QR code, then
                         `otpx import shot1.png shot2.png` (or `otpx import --screen` on a Mac
                         while the phone is mirrored, or scan them in the web app)
  Microsoft Authenticator  no export: re-add each account from its site's QR code
                         (`otpx add --screen`), or on a rooted Android copy
                         /data/data/com.azure.authenticator/databases/PhoneFactor and import it
  Aegis                  Settings > Import & Export > Export (plain or encrypted)
  2FAS                   Settings > 2FAS Backup > Export (.2fas, with or without password)
  andOTP                 Backups > Backup (plain .json or encrypted .json.aes)
  Bitwarden              Tools > Export vault > .json (not encrypted)
  totp-cli               ~/.config/totp-cli/credentials
  anything else          a text file of otpauth:// URIs, or a CSV with a header")]
pub struct ImportArgs {
    /// Files to read (`-` for stdin); QR images and transfer screenshots work too
    files: Vec<PathBuf>,
    /// Force the format (auto, uris, aegis, 2fas, andotp, bitwarden, totp-cli, csv, otpx, image, microsoft)
    #[arg(long, default_value = "auto")]
    format: String,
    /// Read the backup's password from stdin
    #[arg(long)]
    password_stdin: bool,
    /// Select a QR code on the screen (macOS)
    #[arg(long)]
    screen: bool,
    /// Show what would be imported, change nothing
    #[arg(long)]
    dry_run: bool,
}

/// Imports accounts.
pub fn import(a: ImportArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let forced = Format::parse(&a.format)
        .ok_or_else(|| fail(exit::USAGE, format!("unknown format {:?}", a.format)))?;
    let mut inputs: Vec<(String, Vec<u8>, Option<PathBuf>)> = Vec::new();
    for p in &a.files {
        if p.as_os_str() == "-" {
            let mut b = Vec::new();
            std::io::stdin().read_to_end(&mut b)?;
            inputs.push(("stdin".into(), b, None));
        } else {
            let b =
                std::fs::read(p).map_err(|e| fail(exit::USAGE, format!("{}: {e}", p.display())))?;
            inputs.push((p.display().to_string(), b, Some(p.clone())));
        }
    }
    if a.screen {
        inputs.push(("screen".into(), super::entries::capture_screen()?, None));
    }
    if inputs.is_empty() {
        return Err(fail(
            exit::USAGE,
            "nothing to import: give files (see `otpx import --help`) or --screen",
        ));
    }
    let mut password: Option<zeroize::Zeroizing<String>> = if a.password_stdin {
        Some(read_secret("", true)?)
    } else {
        None
    };
    let mut found: Vec<Entry> = Vec::new();
    let mut batches: Vec<(i32, i32)> = Vec::new();
    for (name, bytes, path) in &inputs {
        let fmt = if forced == Format::Auto {
            formats::detect(bytes)
        } else {
            forced
        };
        let got = if fmt == Format::MsAuth {
            let p = path.clone().ok_or_else(|| {
                fail(
                    exit::USAGE,
                    "the Microsoft Authenticator database must be a file",
                )
            })?;
            formats::msauth::import_path(&p).map_err(core_failure)?
        } else {
            match formats::import(bytes, fmt, password.as_deref().map(|s| s.as_str())) {
                Err(otpx_core::Error::NeedsPassword(what))
                    if password.is_none() && ui::interactive() =>
                {
                    let pw = read_secret(&format!("Password of the {what} backup: "), false)?;
                    let r = formats::import(bytes, fmt, Some(&pw));
                    password = Some(pw);
                    r
                }
                r => r,
            }
            .map_err(|e| match e {
                otpx_core::Error::NeedsPassword(w) => fail(
                    exit::AUTH,
                    format!("{name}: the {w} backup is encrypted: pass --password-stdin"),
                ),
                e => fail(crate::code_of_core(&e), format!("{name}: {e}")),
            })?
        };
        for s in &got.skipped {
            ctx.ui.warn(&format!("{name}: skipped {}", ui::clean(s)));
        }
        ctx.ui.note(&format!(
            "{name}: {} account(s) ({})",
            got.entries.len(),
            got.format
        ));
        batches.extend(got.batches.iter().copied());
        found.extend(got.entries);
    }
    let check = formats::Imported {
        batches,
        ..Default::default()
    };
    let missing = check.missing_batches();
    if !missing.is_empty() {
        let list: Vec<String> = missing.iter().map(|i| (i + 1).to_string()).collect();
        ctx.ui.warn(&format!(
            "Google transfer: QR code(s) {} of {} not imported yet",
            list.join(", "),
            check.batches.iter().map(|b| b.1).max().unwrap_or(0)
        ));
    }
    if a.dry_run {
        for e in &found {
            ctx.ui.emit("found", entry_json(e));
            ctx.ui.say(&format!("  {}", ui::clean(&e.label())));
        }
        return Ok(ExitCode::SUCCESS);
    }
    let mut s = session::open(ctx)?;
    let device = ctx.config().device_id;
    let (mut added, mut dup) = (0usize, 0usize);
    for e in found {
        let label = e.label();
        if s.vault
            .data
            .add_unique(e, now_ms(), &device)
            .map_err(core_failure)?
        {
            added += 1;
            ctx.ui.emit("added", json!({ "label": label }));
        } else {
            dup += 1;
        }
    }
    if added > 0 {
        session::save(ctx, &mut s)?;
    }
    ctx.ui
        .emit("imported", json!({ "added": added, "duplicates": dup }));
    ctx.ui.say(&format!(
        "Imported {added} account(s){}.",
        if dup > 0 {
            format!(", {dup} already there")
        } else {
            String::new()
        }
    ));
    Ok(ExitCode::SUCCESS)
}

/// `otpx export`.
#[derive(Debug, clap::Args)]
pub struct ExportArgs {
    /// uris, google, aegis, 2fas, andotp, bitwarden, csv, paper (printable), otpx (the encrypted vault)
    #[arg(short, long)]
    format: String,
    /// Output file (required unless --stdout or --qr)
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Write to stdout (every format but otpx and aegis --encrypt holds secrets in clear)
    #[arg(long)]
    stdout: bool,
    /// Show QR codes in the terminal one after the other (google, uris)
    #[arg(long)]
    qr: bool,
    /// Encrypt (aegis) with a password read from the terminal, or stdin with --password-stdin
    #[arg(long)]
    encrypt: bool,
    /// Read the export password from stdin
    #[arg(long)]
    password_stdin: bool,
    /// Only accounts matching these queries
    queries: Vec<String>,
}

/// Exports accounts.
pub fn export(a: ExportArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let s = session::open(ctx)?;
    if a.format == "otpx" {
        let json = s.vault.seal().map_err(core_failure)?.to_json();
        return write_out(ctx, &a, json.as_bytes(), "otpx", s.vault.data.entries.len());
    }
    let fmt = ExportFormat::parse(&a.format).ok_or_else(|| {
        let names: Vec<&str> = ExportFormat::ALL.iter().map(|(n, _, _)| *n).collect();
        fail(
            exit::USAGE,
            format!("unknown format {:?} ({}, otpx)", a.format, names.join(", ")),
        )
    })?;
    let mut entries: Vec<Entry> = if a.queries.is_empty() {
        s.vault.data.entries.clone()
    } else {
        let mut v = Vec::new();
        for q in &a.queries {
            v.push(resolve(&s.vault.data, q)?.clone());
        }
        v
    };
    entries.sort_by_key(|x| x.label().to_lowercase());
    if fmt == ExportFormat::Google {
        for l in formats::google::not_exportable(&entries) {
            ctx.ui.warn(&format!("{} cannot go to Google Authenticator (Steam, or a period other than 30 s): left out", ui::clean(&l)));
        }
    }
    if a.qr {
        let codes: Vec<String> = match fmt {
            ExportFormat::Google => formats::google::export(&entries).map_err(core_failure)?,
            ExportFormat::Uris => entries.iter().map(otpx_core::uri::to_uri).collect(),
            _ => return Err(fail(exit::USAGE, "--qr works with --format google or uris")),
        };
        return show_qr_sequence(ctx, &codes);
    }
    let password = if a.encrypt {
        if fmt != ExportFormat::Aegis {
            return Err(fail(
                exit::USAGE,
                "--encrypt is for --format aegis (use --format otpx for the vault itself)",
            ));
        }
        Some(super::vault::new_password(
            a.password_stdin,
            "export password",
        )?)
    } else {
        None
    };
    let body = if fmt == ExportFormat::Paper {
        formats::paper::export(&entries, None, now_ms()).map_err(core_failure)?
    } else {
        formats::export(
            &entries,
            fmt,
            password.as_deref().map(|s| s.as_str()),
            now_ms(),
        )
        .map_err(core_failure)?
    };
    write_out(ctx, &a, body.as_bytes(), &a.format, entries.len())
}

fn write_out(
    ctx: &Ctx,
    a: &ExportArgs,
    bytes: &[u8],
    fmt: &str,
    n: usize,
) -> anyhow::Result<ExitCode> {
    match (&a.out, a.stdout) {
        (Some(p), _) => {
            crate::paths::write_export(p, bytes)?;
            ctx.ui
                .emit("exported", json!({ "format": fmt, "path": p, "count": n }));
            ctx.ui.say(&format!(
                "Exported {n} account(s) to {} ({fmt}).",
                p.display()
            ));
            if fmt != "otpx" && !a.encrypt {
                ctx.ui
                    .note("This file holds your secrets in clear: delete it once used.");
            }
        }
        (None, true) => {
            use std::io::Write;
            std::io::stdout().write_all(bytes)?;
        }
        (None, false) => {
            return Err(fail(
                exit::USAGE,
                "pass --out FILE (or --stdout, or --qr for google/uris)",
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn show_qr_sequence(ctx: &Ctx, codes: &[String]) -> anyhow::Result<ExitCode> {
    if !ui::interactive() {
        return Err(fail(exit::USAGE, "--qr needs a terminal"));
    }
    for (i, c) in codes.iter().enumerate() {
        print!("\x1b[2J\x1b[H");
        println!(
            "QR code {} of {} — scan it with the phone, then press Enter",
            i + 1,
            codes.len()
        );
        println!("{}", otpx_core::qr::terminal(c).map_err(core_failure)?);
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
    }
    print!("\x1b[2J\x1b[H");
    ctx.ui.say(&format!("Shown {} QR code(s).", codes.len()));
    Ok(ExitCode::SUCCESS)
}

/// `otpx qr`.
#[derive(Debug, clap::Args)]
pub struct QrArgs {
    /// Account
    pub query: String,
    /// Write an SVG image instead
    #[arg(long, value_name = "PATH")]
    pub svg: Option<PathBuf>,
}

/// Shows an account's QR code.
pub fn qr(a: QrArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let s = session::open(ctx)?;
    let e = resolve(&s.vault.data, &a.query)?;
    let uri = otpx_core::uri::to_uri(e);
    if let Some(p) = &a.svg {
        crate::paths::write_export(
            p,
            otpx_core::qr::svg(&uri).map_err(core_failure)?.as_bytes(),
        )?;
        ctx.ui.emit("qr", json!({ "path": p }));
        ctx.ui.say(&format!(
            "Wrote {} (it holds the secret: delete it once scanned).",
            p.display()
        ));
        return Ok(ExitCode::SUCCESS);
    }
    if ctx.ui.is_json() {
        return Err(fail(
            exit::USAGE,
            "a QR code is for a screen: pass --svg PATH with --json",
        ));
    }
    println!("{}", otpx_core::qr::terminal(&uri).map_err(core_failure)?);
    println!("{}", ui::clean(&e.label()));
    Ok(ExitCode::SUCCESS)
}

/// `otpx backup`.
#[derive(Debug, clap::Args)]
pub struct BackupArgs {
    #[command(subcommand)]
    cmd: Option<BackupCmd>,
}

#[derive(Debug, clap::Subcommand)]
enum BackupCmd {
    /// List snapshots (newest first)
    Ls,
    /// Bring the vault back to a snapshot (the change syncs like any other)
    Restore {
        /// Snapshot number from `otpx backup ls` (1 = newest) or a path
        which: String,
        /// Only restore accounts matching this query
        #[arg(long)]
        only: Option<String>,
        /// Do not ask
        #[arg(short, long)]
        yes: bool,
    },
}

/// Snapshot management.
pub fn backup(a: BackupArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    match a.cmd.unwrap_or(BackupCmd::Ls) {
        BackupCmd::Ls => {
            let snaps = ctx.store.snapshots()?;
            for (i, (p, t)) in snaps.iter().enumerate() {
                ctx.ui
                    .emit("snapshot", json!({ "n": i + 1, "path": p, "time": t }));
                let ago = crate::human_duration(now_ms().saturating_sub(*t) / 1000);
                ctx.ui
                    .say(&format!("{:>3}  {ago} ago  {}", i + 1, p.display()));
            }
            if snaps.is_empty() {
                ctx.ui
                    .note("No snapshot yet (one is kept before each change).");
            }
        }
        BackupCmd::Restore { which, only, yes } => {
            let path = match which.parse::<usize>() {
                Ok(n) if n >= 1 => ctx
                    .store
                    .snapshots()?
                    .get(n - 1)
                    .map(|s| s.0.clone())
                    .ok_or_else(|| {
                        fail(
                            exit::NOT_FOUND,
                            format!("no snapshot {n} (see `otpx backup ls`)"),
                        )
                    })?,
                _ => PathBuf::from(&which),
            };
            let file = crate::store::read_vault_file(&path)?;
            let mut s = session::open(ctx)?;
            if file.id != s.vault.id {
                return Err(fail(
                    exit::USAGE,
                    "this snapshot is of another vault (import it with `otpx import`)",
                ));
            }
            let old = file.unlock_dek(s.vault.dek()).map_err(core_failure)?;
            let pick = |e: &Entry| only.as_deref().is_none_or(|q| e.matches(q));
            let device = ctx.config().device_id;
            let mut changes = 0;
            if !yes
                && !ctx
                    .ui
                    .confirm("Bring back the accounts as they were in this snapshot")?
            {
                return Err(fail(exit::USAGE, "cancelled"));
            }
            for e in old.data.entries.iter().filter(|e| pick(e)) {
                match s.vault.data.entries.iter().position(|x| x.id == e.id) {
                    Some(i)
                        if s.vault.data.entries[i].same_account(e)
                            && s.vault.data.entries[i].label() == e.label() => {}
                    Some(_) => {
                        s.vault
                            .data
                            .update(e.clone(), now_ms(), &device)
                            .map_err(core_failure)?;
                        changes += 1;
                    }
                    None => {
                        // Back with its id and a new stamp, so it wins over the deletion everywhere.
                        let mut back = e.clone();
                        back.updated = s.vault.data.stamp(now_ms(), &device);
                        s.vault.data.tombstones.retain(|t| t.id != e.id);
                        s.vault.data.entries.push(back);
                        changes += 1;
                    }
                }
            }
            if only.is_none() {
                let keep: Vec<String> = old.data.entries.iter().map(|e| e.id.clone()).collect();
                let extra: Vec<String> = s
                    .vault
                    .data
                    .entries
                    .iter()
                    .filter(|e| !keep.contains(&e.id))
                    .map(|e| e.id.clone())
                    .collect();
                for id in extra {
                    s.vault
                        .data
                        .remove(&id, now_ms(), &device)
                        .map_err(core_failure)?;
                    changes += 1;
                }
            }
            if changes > 0 {
                session::save(ctx, &mut s)?;
            }
            ctx.ui.emit("restored", json!({ "changes": changes }));
            ctx.ui.say(&format!(
                "Restored ({changes} change(s)); the current state is itself a snapshot now."
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}
