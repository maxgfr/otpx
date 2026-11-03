//! Opening the vault: cached key, Touch ID, PIN or password, and saving changes.

use otpx_core::crypto::Argon2Params;
use otpx_core::vault::{LocalWrap, Unlocked, VaultFile};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{PIN_ATTEMPTS, UnlockMode};
use crate::{Ctx, core_failure, exit, fail, now_ms, touchid, ui};

/// Secret names.
pub const SESSION: &str = "session";
/// The vault key kept for Touch ID.
pub const QUICK_DEK: &str = "quick-dek";
/// The device half of the PIN secret.
pub const PIN_DEVICE: &str = "pin-device";

/// An open vault.
pub struct Session {
    /// The vault.
    pub vault: Unlocked,
    /// How it was opened (`session`, `touchid`, `pin`, `password`, `env`, `recovery`).
    pub how: &'static str,
}

#[derive(Serialize, Deserialize)]
struct Cached {
    vault: String,
    dek: String,
    /// 0: until `otpx lock`.
    expires: u64,
}

/// The cached key, if still valid: `(dek, expires)`.
pub fn cached(ctx: &Ctx, vault_id: &str) -> anyhow::Result<Option<(Zeroizing<[u8; 32]>, u64)>> {
    if ctx.config().unlock_mode == UnlockMode::AlwaysAsk {
        return Ok(None);
    }
    let secrets = ctx.secrets();
    let Some(raw) = secrets.get(SESSION)? else {
        return Ok(None);
    };
    let Ok(c) = serde_json::from_slice::<Cached>(&raw) else {
        secrets.delete(SESSION)?;
        return Ok(None);
    };
    if c.vault != vault_id || (c.expires != 0 && now_ms() >= c.expires) {
        secrets.delete(SESSION)?;
        return Ok(None);
    }
    let bytes = Zeroizing::new(otpx_core::crypto::unb64(&c.dek).map_err(core_failure)?);
    let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        secrets.delete(SESSION)?;
        return Ok(None);
    };
    Ok(Some((Zeroizing::new(arr), c.expires)))
}

/// Keeps the key per the unlock mode; `ttl` overrides the configured length.
pub fn remember(ctx: &Ctx, vault: &Unlocked, ttl: Option<u64>) -> anyhow::Result<Option<u64>> {
    let cfg = ctx.config();
    let expires = match cfg.unlock_mode {
        UnlockMode::AlwaysAsk => return Ok(None),
        UnlockMode::KeychainPersistent if ttl.is_none() => 0,
        _ => now_ms() + ttl.unwrap_or(cfg.unlock_ttl_secs) * 1000,
    };
    let c = Cached {
        vault: vault.id.clone(),
        dek: otpx_core::crypto::b64(vault.dek()),
        expires,
    };
    let json = Zeroizing::new(serde_json::to_vec(&c).expect("session serializes"));
    ctx.secrets().set(SESSION, &json)?;
    Ok(Some(expires))
}

/// Forgets the cached key.
pub fn forget(ctx: &Ctx) -> anyhow::Result<()> {
    ctx.secrets().delete(SESSION)
}

fn read_file(ctx: &Ctx) -> anyhow::Result<VaultFile> {
    match ctx.store.read()? {
        Some((f, _)) => Ok(f),
        None => Err(fail(
            exit::NOT_FOUND,
            format!(
                "no vault in {}: create one with `otpx init`, or fetch yours with `otpx sync setup …` (or `otpx receive <link>` from another device)",
                ctx.store.dir.display()
            ),
        )),
    }
}

/// Reads a secret typed by the user (hidden), or one line of stdin.
pub fn read_secret(prompt: &str, from_stdin: bool) -> anyhow::Result<Zeroizing<String>> {
    if from_stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let s = line.trim_end_matches(['\n', '\r']).to_owned();
        if s.is_empty() {
            return Err(fail(exit::USAGE, "nothing on stdin"));
        }
        return Ok(Zeroizing::new(s));
    }
    if !ui::interactive() {
        return Err(fail(
            exit::USAGE,
            format!(
                "{} needs a terminal (or pass it on stdin)",
                prompt.trim_end_matches([':', ' '])
            ),
        ));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

/// Opens the vault without prompting when possible (env, cached key); otherwise asks in a
/// terminal, or fails with exit code 3.
pub fn open(ctx: &Ctx) -> anyhow::Result<Session> {
    let file = read_file(ctx)?;
    if let Ok(pw) = std::env::var("OTPX_PASSWORD")
        && !pw.is_empty()
    {
        let vault = file
            .unlock_password(&pw)
            .map_err(|_| fail(exit::AUTH, "OTPX_PASSWORD does not open this vault"))?;
        return Ok(Session { vault, how: "env" });
    }
    if let Some((dek, _)) = cached(ctx, &file.id)? {
        match file.unlock_dek(&dek) {
            Ok(vault) => {
                return Ok(Session {
                    vault,
                    how: "session",
                });
            }
            Err(_) => forget(ctx)?,
        }
    }
    if !ui::interactive() {
        return Err(fail(
            exit::LOCKED,
            "the vault is locked: run `otpx unlock` in a terminal (Touch ID, PIN or password)",
        ));
    }
    let s = prompt_unlock(ctx, &file, false)?;
    remember(ctx, &s.vault, None)?;
    Ok(s)
}

/// Unlocks interactively: Touch ID, then PIN, then password (or the recovery code).
pub fn prompt_unlock(ctx: &Ctx, file: &VaultFile, recovery: bool) -> anyhow::Result<Session> {
    let cfg = ctx.config();
    let secrets = ctx.secrets();
    if recovery {
        let code = read_secret("Recovery code: ", false)?;
        let vault = file
            .unlock_recovery(&code)
            .map_err(|_| fail(exit::AUTH, "wrong recovery code"))?;
        return Ok(Session {
            vault,
            how: "recovery",
        });
    }
    if cfg.quick.touchid && touchid::available() {
        if touchid::authenticate("unlock your otpx vault")? {
            if let Some(dek) = secrets.get(QUICK_DEK)?
                && let Ok(arr) = <[u8; 32]>::try_from(dek.as_slice())
                && let Ok(vault) = file.unlock_dek(&arr)
            {
                return Ok(Session {
                    vault,
                    how: "touchid",
                });
            }
            ctx.ui.warn("Touch ID passed but the key kept for it does not open this vault: run `otpx quick-unlock enable touchid` again");
        } else {
            ctx.ui.note("Touch ID cancelled.");
        }
    }
    if cfg.quick.pin
        && let Some(s) = pin_unlock(ctx, file)?
    {
        return Ok(s);
    }
    for attempt in 1..=3 {
        let pw = read_secret("Master password: ", false)?;
        if let Ok(vault) = file.unlock_password(&pw) {
            return Ok(Session {
                vault,
                how: "password",
            });
        }
        if attempt < 3 {
            ctx.ui.note("Wrong password, try again.");
        }
    }
    Err(fail(
        exit::AUTH,
        "wrong master password (forgot it? `otpx unlock --recovery`)",
    ))
}

fn pin_path(ctx: &Ctx) -> std::path::PathBuf {
    ctx.config_dir.join("pin.json")
}

fn pin_secret(pin: &str, device: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new([pin.as_bytes(), b"|", device].concat())
}

fn pin_unlock(ctx: &Ctx, file: &VaultFile) -> anyhow::Result<Option<Session>> {
    let Ok(text) = std::fs::read_to_string(pin_path(ctx)) else {
        return Ok(None);
    };
    let wrap: LocalWrap = serde_json::from_str(&text)?;
    let Some(device) = ctx.secrets().get(PIN_DEVICE)? else {
        ctx.ui
            .warn("the PIN's device key is gone from the keychain: set the PIN again");
        return Ok(None);
    };
    loop {
        let pin = read_secret("PIN (empty for the password): ", false)?;
        if pin.is_empty() {
            return Ok(None);
        }
        if let Ok(dek) = wrap.open(&pin_secret(&pin, &device))
            && let Ok(vault) = file.unlock_dek(&dek)
        {
            ctx.update_config(|c| c.quick.pin_failures = 0)?;
            return Ok(Some(Session { vault, how: "pin" }));
        }
        let failures = ctx.config().quick.pin_failures + 1;
        if failures >= PIN_ATTEMPTS {
            disable_pin(ctx)?;
            ctx.ui.warn(&format!(
                "{PIN_ATTEMPTS} wrong PINs: the PIN is erased, use the master password"
            ));
            return Ok(None);
        }
        ctx.update_config(|c| c.quick.pin_failures = failures)?;
        ctx.ui.note(&format!(
            "Wrong PIN ({} attempt(s) left).",
            PIN_ATTEMPTS - failures
        ));
    }
}

/// Sets a PIN for this device.
pub fn enable_pin(ctx: &Ctx, vault: &Unlocked, pin: &str) -> anyhow::Result<()> {
    let device = Zeroizing::new(otpx_core::crypto::random_bytes(32).map_err(core_failure)?);
    let wrap = LocalWrap::new(vault, &pin_secret(pin, &device), Some(Argon2Params::KEY))
        .map_err(core_failure)?;
    ctx.secrets().set(PIN_DEVICE, &device)?;
    crate::paths::write_private(
        &pin_path(ctx),
        serde_json::to_string_pretty(&wrap)?.as_bytes(),
    )?;
    ctx.update_config(|c| {
        c.quick.pin = true;
        c.quick.pin_failures = 0;
    })
}

/// Removes the PIN of this device.
pub fn disable_pin(ctx: &Ctx) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(pin_path(ctx));
    ctx.secrets().delete(PIN_DEVICE)?;
    ctx.update_config(|c| {
        c.quick.pin = false;
        c.quick.pin_failures = 0;
    })
}

/// Saves the vault: merges what another otpx wrote meanwhile, keeps a snapshot, writes, then
/// syncs when remotes are set (best effort).
pub fn save(ctx: &Ctx, s: &mut Session) -> anyhow::Result<()> {
    write_local(ctx, s)?;
    if ctx.may_auto_sync() && !ctx.config().remotes.is_empty() {
        match crate::sync::sync_all(ctx, s, None) {
            Ok(_) => {}
            Err(e) => ctx.ui.warn(&format!(
                "saved locally; sync failed: {e:#} (run `otpx sync` later)"
            )),
        }
    }
    Ok(())
}

/// Saves the vault locally only.
pub fn write_local(ctx: &Ctx, s: &mut Session) -> anyhow::Result<()> {
    let _lock = ctx.store.lock()?;
    if let Some((disk, _)) = ctx.store.read()?
        && disk.id == s.vault.id
        && let Ok(other) = disk.unlock_dek(s.vault.dek())
    {
        s.vault.absorb(&other, now_ms()).map_err(core_failure)?;
        // Same content: keep the file (a new nonce would only make a needless snapshot).
        if s.vault.data == other.data && s.vault.slots == other.slots {
            return Ok(());
        }
    }
    let json = s.vault.seal().map_err(core_failure)?.to_json();
    ctx.store.write(&json, now_ms())
}
