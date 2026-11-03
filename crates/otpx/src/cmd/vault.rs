//! Vault lifecycle: init, unlock, lock, status, password, recovery, quick unlock, config.

use std::process::ExitCode;

use otpx_core::crypto::Argon2Params;
use otpx_core::vault::Unlocked;
use serde_json::json;

use crate::config::UnlockMode;
use crate::session::{self, Session, read_secret};
use crate::{Ctx, core_failure, exit, fail, human_duration, now_ms, parse_duration, touchid, ui};

/// Argon2 cost of new vaults (`OTPX_TEST_FAST_KDF=1` lowers it for tests only).
pub fn kdf_params() -> Argon2Params {
    if std::env::var_os("OTPX_TEST_FAST_KDF").is_some() {
        Argon2Params::TEST
    } else {
        Argon2Params::PASSWORD
    }
}

/// `otpx init`.
#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// Read the master password from stdin (one line) instead of asking
    #[arg(long)]
    password_stdin: bool,
    /// Replace an existing vault (it is kept as a snapshot)
    #[arg(long)]
    force: bool,
}

fn strength_warning(pw: &str) -> Option<&'static str> {
    let classes = [
        pw.chars().any(|c| c.is_ascii_lowercase()),
        pw.chars().any(|c| c.is_ascii_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if pw.chars().all(|c| c.is_ascii_digit()) {
        return Some(
            "a digits-only master password is weak once the vault is copied (synced files can be attacked offline); prefer a passphrase and use `otpx quick-unlock enable pin` for a short code on this device",
        );
    }
    if pw.chars().count() < 12 && classes < 3 {
        return Some(
            "short master password: a passphrase of 4+ random words resists offline attacks far better",
        );
    }
    None
}

/// Asks for a new password twice.
pub fn new_password(from_stdin: bool, what: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let pw = read_secret(&format!("New {what}: "), from_stdin)?;
    if pw.is_empty() {
        return Err(fail(exit::USAGE, format!("empty {what}")));
    }
    if !from_stdin {
        let again = read_secret(&format!("Repeat the {what}: "), false)?;
        if *again != *pw {
            return Err(fail(exit::USAGE, format!("the two {what}s differ")));
        }
    }
    Ok(pw)
}

/// Prints the recovery code with the instructions.
fn show_recovery(ctx: &Ctx, code: &str) {
    ctx.ui
        .emit("recovery_code", json!({ "recovery_code": code }));
    if ctx.ui.is_json() {
        return;
    }
    println!();
    println!("Recovery code (opens the vault if you forget the master password):");
    println!();
    println!("    {}", ctx.ui.paint(code, "1"));
    println!();
    println!(
        "Write it down and keep it offline. It is shown only now; `otpx recovery --reset` makes a new one."
    );
    println!("Then run `otpx recovery --confirm`.");
}

/// Creates the vault.
pub fn init(a: InitArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    if ctx.store.exists() && !a.force {
        return Err(fail(
            exit::USAGE,
            format!(
                "a vault already exists in {} (use --force to replace it)",
                ctx.store.dir.display()
            ),
        ));
    }
    let pw = new_password(a.password_stdin, "master password")?;
    if let Some(w) = strength_warning(&pw) {
        ctx.ui.warn(w);
    }
    let now = now_ms();
    let created = Unlocked::create(&pw, kdf_params(), now).map_err(core_failure)?;
    let mut vault = created.vault;
    vault
        .data
        .identities
        .push(otpx_core::share::new_identity(now));
    let mut s = Session {
        vault,
        how: "password",
    };
    session::write_local(ctx, &mut s)?;
    ctx.update_config(|c| c.recovery_confirmed = false)?;
    let expires = session::remember(ctx, &s.vault, None)?;
    ctx.ui.emit(
        "init",
        json!({ "path": ctx.store.vault(), "vault": s.vault.id, "unlocked_until": expires }),
    );
    ctx.ui.say(&format!(
        "Vault created in {}.",
        ctx.store.vault().display()
    ));
    show_recovery(ctx, &created.recovery_code);
    if !ctx.ui.is_json() {
        println!();
        println!(
            "Next: `otpx import <export>` or `otpx add`, then `otpx sync setup github --repo you/otpx-vault` to never lose it."
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// `otpx unlock`.
#[derive(Debug, clap::Args)]
pub struct UnlockArgs {
    /// How long to stay unlocked (e.g. 15m, 2h); default from `otpx config unlock-ttl`
    #[arg(long, value_name = "DURATION")]
    ttl: Option<String>,
    /// Read the master password from stdin
    #[arg(long)]
    password_stdin: bool,
    /// Use the recovery code instead of the password
    #[arg(long)]
    recovery: bool,
}

/// Unlocks and caches the key.
pub fn unlock(a: UnlockArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let ttl = a.ttl.as_deref().map(parse_duration).transpose()?;
    let (file, _) = ctx.store.read()?.ok_or_else(|| {
        fail(
            exit::NOT_FOUND,
            "no vault: `otpx init` or `otpx sync setup …`",
        )
    })?;
    let s = if a.password_stdin {
        let pw = read_secret("", true)?;
        let vault = file
            .unlock_password(&pw)
            .map_err(|_| fail(exit::AUTH, "wrong master password"))?;
        Session {
            vault,
            how: "password",
        }
    } else {
        if !ui::interactive() {
            return Err(fail(
                exit::USAGE,
                "`otpx unlock` needs a terminal (or --password-stdin)",
            ));
        }
        session::prompt_unlock(ctx, &file, a.recovery)?
    };
    if ctx.config().unlock_mode == UnlockMode::AlwaysAsk {
        ctx.ui.note(
            "unlock mode is always-ask: nothing is kept (`otpx config unlock-mode keychain-ttl`)",
        );
    }
    let expires = session::remember(ctx, &s.vault, ttl)?;
    ctx.ui
        .emit("unlocked", json!({ "how": s.how, "expires": expires }));
    match expires {
        Some(0) => ctx.ui.say("Unlocked until `otpx lock`."),
        Some(t) => ctx.ui.say(&format!(
            "Unlocked for {}.",
            human_duration((t.saturating_sub(now_ms())) / 1000)
        )),
        None => ctx.ui.say("Password checked."),
    }
    if s.how == "recovery" {
        ctx.ui
            .note("Opened with the recovery code: set a new password with `otpx passwd`.");
    }
    Ok(ExitCode::SUCCESS)
}

/// Forgets the cached key.
pub fn lock(ctx: &Ctx) -> anyhow::Result<ExitCode> {
    session::forget(ctx)?;
    ctx.ui.emit("locked", json!({}));
    ctx.ui.say("Locked.");
    Ok(ExitCode::SUCCESS)
}

/// `otpx status`.
pub fn status(ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let cfg = ctx.config();
    let file = ctx.store.read()?.map(|(f, _)| f);
    let cached = match &file {
        Some(f) => session::cached(ctx, &f.id)?,
        None => None,
    };
    let open = match (&file, &cached) {
        (Some(f), Some((dek, _))) => f.unlock_dek(dek).ok(),
        _ => None,
    };
    let unlocked = open.is_some() || std::env::var_os("OTPX_PASSWORD").is_some();
    let remotes: Vec<_> = cfg
        .remotes
        .iter()
        .map(|r| json!({ "name": r.name, "target": r.describe(), "last_sync": r.last_sync }))
        .collect();
    ctx.ui.emit(
        "status",
        json!({
            "vault": file.as_ref().map(|f| f.id.clone()),
            "path": ctx.store.vault(),
            "unlocked": unlocked,
            "unlocked_until": cached.as_ref().map(|c| c.1),
            "entries": open.as_ref().map(|o| o.data.entries.len()),
            "unlock_mode": cfg.unlock_mode.as_str(),
            "touchid": cfg.quick.touchid,
            "pin": cfg.quick.pin,
            "remotes": remotes,
            "device": cfg.device_name,
            "keychain": ctx.secrets().backend(),
        }),
    );
    if ctx.ui.is_json() {
        return Ok(ExitCode::SUCCESS);
    }
    let Some(f) = file else {
        println!("No vault in {}.", ctx.store.dir.display());
        println!("Create one with `otpx init`, or fetch yours with `otpx sync setup …`.");
        return Ok(ExitCode::SUCCESS);
    };
    println!("vault    {} ({})", ctx.store.vault().display(), &f.id[..8]);
    match (&open, &cached) {
        (Some(o), Some((_, exp))) => {
            let until = if *exp == 0 {
                "until `otpx lock`".to_owned()
            } else {
                format!(
                    "for {}",
                    human_duration(exp.saturating_sub(now_ms()) / 1000)
                )
            };
            println!(
                "state    unlocked {until}, {} account(s)",
                o.data.entries.len()
            );
        }
        _ => println!("state    locked (`otpx unlock`)"),
    }
    let mut quick = Vec::new();
    if cfg.quick.touchid {
        quick.push("Touch ID");
    }
    if cfg.quick.pin {
        quick.push("PIN");
    }
    println!(
        "unlock   {} (ttl {}){}",
        cfg.unlock_mode.as_str(),
        human_duration(cfg.unlock_ttl_secs),
        if quick.is_empty() {
            String::new()
        } else {
            format!(", quick: {}", quick.join(" + "))
        }
    );
    if cfg.remotes.is_empty() {
        println!(
            "sync     none: `otpx sync setup github --repo you/otpx-vault` keeps a copy off this machine"
        );
    }
    for r in &cfg.remotes {
        let when = if r.last_sync == 0 {
            "never synced".to_owned()
        } else {
            format!(
                "synced {} ago",
                human_duration(now_ms().saturating_sub(r.last_sync) / 1000)
            )
        };
        println!("sync     {}: {} ({when})", r.name, r.describe());
    }
    println!(
        "device   {} ({}, keys in the {})",
        cfg.device_name,
        cfg.device_id,
        ctx.secrets().backend()
    );
    Ok(ExitCode::SUCCESS)
}

/// `otpx passwd`.
#[derive(Debug, clap::Args)]
pub struct PasswdArgs {
    /// Read the new password from stdin (the vault must be unlocked)
    #[arg(long)]
    password_stdin: bool,
}

/// Changes the master password.
pub fn passwd(a: PasswdArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let mut s = session::open(ctx)?;
    let pw = new_password(a.password_stdin, "master password")?;
    if let Some(w) = strength_warning(&pw) {
        ctx.ui.warn(w);
    }
    s.vault
        .set_password(&pw, kdf_params(), now_ms())
        .map_err(core_failure)?;
    session::save(ctx, &mut s)?;
    ctx.ui.emit("password_changed", json!({}));
    ctx.ui
        .say("Master password changed (on every device after their next sync).");
    Ok(ExitCode::SUCCESS)
}

/// `otpx recovery`.
#[derive(Debug, clap::Args)]
pub struct RecoveryArgs {
    /// Make a new recovery code (the old one stops working)
    #[arg(long)]
    reset: bool,
    /// Record that the recovery code is written down
    #[arg(long)]
    confirm: bool,
}

/// Recovery code management.
pub fn recovery(a: RecoveryArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    if a.reset {
        let mut s = session::open(ctx)?;
        let code = s.vault.reset_recovery(now_ms()).map_err(core_failure)?;
        session::save(ctx, &mut s)?;
        ctx.update_config(|c| c.recovery_confirmed = false)?;
        show_recovery(ctx, &code);
        return Ok(ExitCode::SUCCESS);
    }
    if a.confirm {
        ctx.update_config(|c| c.recovery_confirmed = true)?;
        ctx.ui.emit("recovery", json!({ "confirmed": true }));
        ctx.ui.say("Noted: the recovery code is written down.");
        return Ok(ExitCode::SUCCESS);
    }
    let confirmed = ctx.config().recovery_confirmed;
    ctx.ui.emit("recovery", json!({ "confirmed": confirmed }));
    ctx.ui.say(if confirmed {
        "The recovery code is written down. `otpx recovery --reset` makes a new one."
    } else {
        "The recovery code was not confirmed: if you did not keep it, `otpx recovery --reset` shows a new one."
    });
    Ok(ExitCode::SUCCESS)
}

/// `otpx quick-unlock`.
#[derive(Debug, clap::Args)]
pub struct QuickArgs {
    #[command(subcommand)]
    cmd: Option<QuickCmd>,
}

#[derive(Debug, clap::Subcommand)]
enum QuickCmd {
    /// Turn on Touch ID or a PIN for this device
    Enable {
        /// touchid or pin
        method: String,
        /// Read the PIN from stdin
        #[arg(long)]
        pin_stdin: bool,
    },
    /// Turn off Touch ID, the PIN, or both
    Disable {
        /// touchid, pin or all
        #[arg(default_value = "all")]
        method: String,
    },
}

/// Quick unlock management.
pub fn quick(a: QuickArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    match a.cmd {
        None => {
            let q = ctx.config().quick;
            ctx.ui.emit("quick_unlock", json!({ "touchid": q.touchid, "pin": q.pin, "touchid_available": touchid::available() }));
            ctx.ui.say(&format!(
                "Touch ID: {}{}\nPIN: {}",
                if q.touchid { "on" } else { "off" },
                if touchid::available() {
                    ""
                } else {
                    " (not available on this machine)"
                },
                if q.pin { "on" } else { "off" },
            ));
        }
        Some(QuickCmd::Enable { method, pin_stdin }) => {
            let s = session::open(ctx)?;
            match method.as_str() {
                "touchid" | "touch-id" | "biometrics" => {
                    if !touchid::available() {
                        return Err(fail(
                            exit::USAGE,
                            "Touch ID is not available here (macOS with a fingerprint enrolled)",
                        ));
                    }
                    if !touchid::authenticate("turn on Touch ID for otpx")? {
                        return Err(fail(exit::AUTH, "Touch ID was not confirmed"));
                    }
                    ctx.secrets().set(session::QUICK_DEK, s.vault.dek())?;
                    ctx.update_config(|c| c.quick.touchid = true)?;
                    ctx.ui
                        .say("Touch ID on: `otpx unlock` now asks for your fingerprint first.");
                }
                "pin" => {
                    let pin = new_password(pin_stdin, "PIN")?;
                    if pin.chars().count() < 4 {
                        return Err(fail(exit::USAGE, "a PIN needs at least 4 characters"));
                    }
                    session::enable_pin(ctx, &s.vault, &pin)?;
                    ctx.ui.say(&format!(
                        "PIN on for this device. It only works here (with a key kept in the {}), and {} wrong PINs erase it.",
                        ctx.secrets().backend(),
                        crate::config::PIN_ATTEMPTS
                    ));
                }
                other => {
                    return Err(fail(
                        exit::USAGE,
                        format!("unknown method {other:?} (touchid or pin)"),
                    ));
                }
            }
            ctx.ui.emit("quick_unlock", json!({ "enabled": method }));
        }
        Some(QuickCmd::Disable { method }) => {
            if matches!(method.as_str(), "touchid" | "touch-id" | "all") {
                ctx.secrets().delete(session::QUICK_DEK)?;
                ctx.update_config(|c| c.quick.touchid = false)?;
            }
            if matches!(method.as_str(), "pin" | "all") {
                session::disable_pin(ctx)?;
            }
            ctx.ui.emit("quick_unlock", json!({ "disabled": method }));
            ctx.ui.say("Done.");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `otpx config`.
#[derive(Debug, clap::Args)]
pub struct ConfigArgs {
    /// unlock-mode, unlock-ttl, auto-sync, web-base or device-name
    key: Option<String>,
    /// New value
    value: Option<String>,
}

/// Reads or changes settings.
pub fn config(a: ConfigArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let c = ctx.config();
    let all = json!({
        "unlock-mode": c.unlock_mode.as_str(),
        "unlock-ttl": human_duration(c.unlock_ttl_secs),
        "auto-sync": c.auto_sync,
        "web-base": c.web_base(),
        "device-name": c.device_name,
    });
    let Some(key) = a.key else {
        ctx.ui.emit("config", all.clone());
        if let Some(m) = all.as_object() {
            for (k, v) in m {
                ctx.ui.say(&format!(
                    "{k} = {}",
                    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
                ));
            }
        }
        return Ok(ExitCode::SUCCESS);
    };
    let Some(value) = a.value else {
        let v = all
            .get(&key)
            .ok_or_else(|| fail(exit::USAGE, format!("unknown setting {key:?}")))?;
        ctx.ui.emit("config", json!({ key.clone(): v }));
        ctx.ui
            .say(&v.as_str().map_or_else(|| v.to_string(), str::to_owned));
        return Ok(ExitCode::SUCCESS);
    };
    match key.as_str() {
        "unlock-mode" => {
            let m = UnlockMode::parse(&value).ok_or_else(|| {
                fail(
                    exit::USAGE,
                    "unlock-mode is keychain-ttl, keychain-persistent or always-ask",
                )
            })?;
            ctx.update_config(|c| c.unlock_mode = m)?;
            if m == UnlockMode::AlwaysAsk {
                session::forget(ctx)?;
            }
        }
        "unlock-ttl" => {
            let t = parse_duration(&value)?;
            ctx.update_config(|c| c.unlock_ttl_secs = t.max(10))?;
        }
        "auto-sync" => {
            let b = matches!(value.as_str(), "true" | "on" | "yes" | "1");
            ctx.update_config(|c| c.auto_sync = b)?;
        }
        "web-base" => ctx.update_config(|c| c.web_base = value.clone())?,
        "device-name" => ctx.update_config(|c| c.device_name = value.clone())?,
        _ => return Err(fail(exit::USAGE, format!("unknown setting {key:?}"))),
    }
    ctx.ui.emit("config", json!({ key: value }));
    ctx.ui.say("Saved.");
    Ok(ExitCode::SUCCESS)
}
