//! `otpx`: your 2FA codes in the terminal, an encrypted vault synced across devices.

mod clipboard;
mod cmd;
mod config;
mod paths;
mod secrets;
mod session;
mod store;
mod sync;
mod touchid;
mod tui;
mod ui;
mod web;

use std::cell::RefCell;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::secrets::Secrets;
use crate::store::Store;
use crate::ui::Ui;

/// Stable exit codes.
pub mod exit {
    /// Success.
    pub const OK: u8 = 0;
    /// Any other error.
    pub const ERROR: u8 = 1;
    /// Bad command line or input.
    pub const USAGE: u8 = 2;
    /// The vault is locked and no prompt is possible: run `otpx unlock`.
    pub const LOCKED: u8 = 3;
    /// No vault, or no account matches.
    pub const NOT_FOUND: u8 = 4;
    /// Several accounts match: be more precise.
    pub const AMBIGUOUS: u8 = 5;
    /// Wrong password, PIN, recovery code or passphrase.
    pub const AUTH: u8 = 6;
    /// A remote kept changing during sync, or holds another vault.
    pub const CONFLICT: u8 = 7;
    /// A remote is unreachable or refused the token.
    pub const NETWORK: u8 = 8;
}

const AFTER_HELP: &str = "\
Exit codes:
  0  ok
  1  error
  2  usage (bad arguments or input)
  3  locked: run `otpx unlock` (Touch ID, PIN or password)
  4  not found (no vault, or no matching account)
  5  ambiguous: several accounts match
  6  wrong password, PIN, recovery code or passphrase
  7  sync conflict (remote kept changing, or holds another vault)
  8  network (remote unreachable or token refused)

Environment:
  OTPX_CONFIG_DIR    config directory (default ~/.config/otpx)
  OTPX_DATA_DIR      vault directory (default ~/.local/share/otpx)
  OTPX_KEYCHAIN=0    keep keys in <config>/secrets.json instead of the OS keychain
  OTPX_PASSWORD      master password for scripts and CI (discouraged: prefer `otpx unlock`)
  OTPX_OFFLINE=1     never sync automatically
  OTPX_NO_INPUT=1    never prompt (fail with exit code 3 instead)
  NO_COLOR           disable colors

Run `otpx` alone in a terminal for the interactive view.";

#[derive(Debug, Parser)]
#[command(
    name = "otpx",
    version,
    about = "Your 2FA codes in the terminal: an encrypted OTP vault, synced and shareable",
    long_about = "Your 2FA codes in the terminal.\n\nAn encrypted vault (Argon2id + \
                  XChaCha20-Poly1305) of TOTP, HOTP and Steam accounts, imported from Google \
                  Authenticator, Microsoft Authenticator, Aegis, 2FAS, andOTP, Bitwarden or \
                  any otpauth:// QR code, synced through a private GitHub repo, a gist or a \
                  folder, and opened the same way at https://maxgfr.github.io/otpx/.",
    after_long_help = AFTER_HELP
)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    command: Option<Command>,
}

/// Flags shared by every command.
#[derive(Debug, Clone, clap::Args)]
pub struct Global {
    /// Print NDJSON events on stdout (human text goes to stderr)
    #[arg(long, global = true)]
    pub json: bool,
    /// Config directory
    #[arg(long, global = true, value_name = "DIR", env = "OTPX_CONFIG_DIR")]
    pub config_dir: Option<PathBuf>,
    /// Vault directory
    #[arg(long, global = true, value_name = "DIR", env = "OTPX_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    /// Do not sync after changes
    #[arg(long, global = true)]
    pub offline: bool,
    /// Less output
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new vault (master password and recovery code)
    Init(cmd::vault::InitArgs),
    /// Unlock the vault for a while (Touch ID, PIN or password)
    Unlock(cmd::vault::UnlockArgs),
    /// Forget the cached key now
    Lock,
    /// Vault, lock, sync and device state
    Status,
    /// Add an account (otpauth:// URI, secret, QR image or screen capture)
    Add(cmd::entries::AddArgs),
    /// List accounts with their current codes
    #[command(visible_alias = "ls")]
    List(cmd::entries::ListArgs),
    /// Print (or copy) the code of one account
    Code(cmd::entries::CodeArgs),
    /// Details of one account
    Show(cmd::entries::ShowArgs),
    /// Change an account
    Edit(cmd::entries::EditArgs),
    /// Delete an account
    #[command(visible_alias = "rm")]
    Remove(cmd::entries::RemoveArgs),
    /// Import from Google/Microsoft Authenticator, Aegis, 2FAS, andOTP, Bitwarden, totp-cli, CSV, QR images
    Import(cmd::io::ImportArgs),
    /// Export to another app, QR codes for a phone, or a printable backup
    Export(cmd::io::ExportArgs),
    /// Show an account's QR code, to scan it with a phone
    Qr(cmd::io::QrArgs),
    /// Local snapshots of the vault (one per change)
    Backup(cmd::io::BackupArgs),
    /// Sync with the remotes, or set them up (GitHub repo, gist, folder)
    Sync(cmd::sync::SyncArgs),
    /// Share accounts: encrypted link, age file or QR code
    Share(cmd::share::ShareArgs),
    /// Open a share link or age file and import what it holds
    Receive(cmd::share::ReceiveArgs),
    /// This vault's public key for age shares (age1…)
    Id,
    /// Make a link that sets up another device (sync remotes and tokens)
    Link(cmd::share::LinkArgs),
    /// Change the master password
    Passwd(cmd::vault::PasswdArgs),
    /// Recovery code: status, confirm it is written down, or make a new one
    Recovery(cmd::vault::RecoveryArgs),
    /// Touch ID or PIN to unlock on this device
    QuickUnlock(cmd::vault::QuickArgs),
    /// Read or change a setting (unlock-mode, unlock-ttl, auto-sync, web-base, device-name)
    Config(cmd::vault::ConfigArgs),
    /// Open the web app served from this machine (isolated origin, works offline)
    Web(cmd::misc::WebArgs),
    /// Interactive view (the default in a terminal)
    Tui,
    /// Check this machine's setup
    Doctor,
    /// Offline self-check of codes, crypto and formats
    Selftest,
    /// Print shell completions
    Completions(cmd::misc::CompletionsArgs),
    #[command(name = "__clear-clipboard", hide = true)]
    ClearClipboard(clipboard::ClearArgs),
}

/// A failure with a stable exit code.
#[derive(Debug)]
pub struct Failure {
    /// Exit code.
    pub code: u8,
    /// What happened and what to do.
    pub message: String,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

/// An error carrying an exit code.
pub fn fail(code: u8, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Failure {
        code,
        message: message.into(),
    })
}

/// Maps a core error to an exit code.
pub fn core_failure(e: otpx_core::Error) -> anyhow::Error {
    fail(code_of_core(&e), e.to_string())
}

/// Exit code of a core error.
pub fn code_of_core(e: &otpx_core::Error) -> u8 {
    match e {
        otpx_core::Error::Decrypt
        | otpx_core::Error::NeedsPassword(_)
        | otpx_core::Error::Expired => exit::AUTH,
        otpx_core::Error::Random => exit::ERROR,
        _ => exit::USAGE,
    }
}

fn code_of(e: &anyhow::Error) -> u8 {
    if let Some(f) = e.downcast_ref::<Failure>() {
        return f.code;
    }
    if let Some(c) = e.downcast_ref::<otpx_core::Error>() {
        return code_of_core(c);
    }
    exit::ERROR
}

/// What every command gets.
pub struct Ctx {
    /// Global flags.
    pub global: Global,
    /// Output.
    pub ui: Ui,
    /// Config directory.
    pub config_dir: PathBuf,
    /// The vault directory.
    pub store: Store,
    config: RefCell<Config>,
}

impl Ctx {
    fn new(global: Global) -> anyhow::Result<Ctx> {
        let ui = Ui::new(global.json, global.quiet);
        let config_dir = paths::config_dir(global.config_dir.as_deref())?;
        let data_dir = paths::data_dir(global.data_dir.as_deref())?;
        let config = Config::load(&config_dir)?;
        Ok(Ctx {
            global,
            ui,
            config_dir,
            store: Store { dir: data_dir },
            config: RefCell::new(config),
        })
    }

    /// The config (a copy).
    pub fn config(&self) -> Config {
        self.config.borrow().clone()
    }

    /// Changes the config and writes it.
    pub fn update_config(&self, f: impl FnOnce(&mut Config)) -> anyhow::Result<()> {
        let mut c = self.config.borrow_mut();
        f(&mut c);
        c.save(&self.config_dir)
    }

    /// This device's secrets.
    pub fn secrets(&self) -> Secrets {
        Secrets::new(&self.config_dir)
    }

    /// Whether changes may sync automatically.
    pub fn may_auto_sync(&self) -> bool {
        !self.global.offline
            && std::env::var_os("OTPX_OFFLINE").is_none_or(|v| v.is_empty() || v == "0")
            && self.config.borrow().auto_sync
    }
}

/// Wall time in ms (`OTPX_NOW`, unix seconds, overrides it for tests).
pub fn now_ms() -> u64 {
    if let Some(s) = std::env::var("OTPX_NOW")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        return s * 1000;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Wall time in seconds.
pub fn now_secs() -> u64 {
    now_ms() / 1000
}

/// Parses `90`, `30s`, `15m`, `2h`, `7d` into seconds.
pub fn parse_duration(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().map_err(|_| {
        fail(
            exit::USAGE,
            format!("invalid duration {s:?} (e.g. 30s, 15m, 2h, 7d)"),
        )
    })?;
    let mult = match unit {
        "" | "s" => 1,
        "m" | "min" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 7 * 86_400,
        _ => {
            return Err(fail(
                exit::USAGE,
                format!("invalid duration unit in {s:?} (s, m, h, d, w)"),
            ));
        }
    };
    Ok(n.saturating_mul(mult))
}

/// Human form of a duration in seconds.
pub fn human_duration(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m", (secs + 30) / 60),
        3600..86_400 => format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60),
        _ => format!("{}d", secs / 86_400),
    }
}

/// The command tree, for completions.
pub fn command() -> clap::Command {
    <Cli as clap::CommandFactory>::command()
}

fn dispatch(command: Option<Command>, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let command = match command {
        Some(c) => c,
        None if ui::interactive() && !ctx.ui.is_json() => Command::Tui,
        None => Command::List(cmd::entries::ListArgs::default()),
    };
    match command {
        Command::Init(a) => cmd::vault::init(a, ctx),
        Command::Unlock(a) => cmd::vault::unlock(a, ctx),
        Command::Lock => cmd::vault::lock(ctx),
        Command::Status => cmd::vault::status(ctx),
        Command::Add(a) => cmd::entries::add(a, ctx),
        Command::List(a) => cmd::entries::list(a, ctx),
        Command::Code(a) => cmd::entries::code(a, ctx),
        Command::Show(a) => cmd::entries::show(a, ctx),
        Command::Edit(a) => cmd::entries::edit(a, ctx),
        Command::Remove(a) => cmd::entries::remove(a, ctx),
        Command::Import(a) => cmd::io::import(a, ctx),
        Command::Export(a) => cmd::io::export(a, ctx),
        Command::Qr(a) => cmd::io::qr(a, ctx),
        Command::Backup(a) => cmd::io::backup(a, ctx),
        Command::Sync(a) => cmd::sync::run(a, ctx),
        Command::Share(a) => cmd::share::share(a, ctx),
        Command::Receive(a) => cmd::share::receive(a, ctx),
        Command::Id => cmd::share::id(ctx),
        Command::Link(a) => cmd::share::link(a, ctx),
        Command::Passwd(a) => cmd::vault::passwd(a, ctx),
        Command::Recovery(a) => cmd::vault::recovery(a, ctx),
        Command::QuickUnlock(a) => cmd::vault::quick(a, ctx),
        Command::Config(a) => cmd::vault::config(a, ctx),
        Command::Web(a) => cmd::misc::web(a, ctx),
        Command::Tui => tui::run(ctx),
        Command::Doctor => cmd::misc::doctor(ctx),
        Command::Selftest => cmd::misc::selftest(ctx),
        Command::Completions(a) => cmd::misc::completions(a),
        Command::ClearClipboard(a) => clipboard::clear(a),
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    let ui = Ui::new(cli.global.json, cli.global.quiet);
    let ctx = match Ctx::new(cli.global) {
        Ok(c) => c,
        Err(e) => {
            let code = code_of(&e);
            ui.error(code, &format!("{e:#}"));
            return ExitCode::from(code);
        }
    };
    match dispatch(cli.command, &ctx) {
        Ok(code) => code,
        Err(e) => {
            let code = code_of(&e);
            ctx.ui.error(code, &format!("{e:#}"));
            ExitCode::from(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("7d").unwrap(), 604_800);
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("5y").is_err());
        assert_eq!(human_duration(42), "42s");
        assert_eq!(human_duration(3700), "1h01m");
    }

    #[test]
    fn cli_is_consistent() {
        command().debug_assert();
    }
}
