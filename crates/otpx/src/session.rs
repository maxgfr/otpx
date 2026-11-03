//! Opening the vault: cached key, Touch ID, PIN or password, and saving changes.

use otpx_core::vault::{KeyringChange, Unlocked, VaultFile};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{PIN_ATTEMPTS, UnlockMode};
use crate::{Ctx, core_failure, exit, fail, now_ms, touchid, ui};

/// Secret names.
pub const SESSION: &str = "session";
/// The device key of the Touch ID slot.
pub const TOUCHID_KEY: &str = "touchid-key";
/// The device key of the PIN slot.
pub const PIN_KEY: &str = "pin-key";
/// Wrong PINs in a row (kept next to the key, counted before each try).
pub const PIN_FAILS: &str = "pin-failures";

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

/// Name of this device's quick-unlock slot for `method` (`touchid`, `pin`).
pub fn device_slot(ctx: &Ctx, method: &str) -> String {
    format!("{}:{method}", ctx.config().device_id)
}

/// Quick unlock needs the OS keychain: a device key in a file next to the vault would let a
/// copy of the disk try every PIN offline.
pub fn require_keychain(ctx: &Ctx) -> anyhow::Result<()> {
    if ctx.secrets().backend() == "file" {
        return Err(fail(
            exit::USAGE,
            "quick unlock needs the OS keychain (macOS Keychain or Secret Service); it is off here (OTPX_KEYCHAIN=0 or none available)",
        ));
    }
    Ok(())
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

fn store_cache(ctx: &Ctx, vault: &Unlocked, expires: u64) -> anyhow::Result<()> {
    let c = Cached {
        vault: vault.id.clone(),
        dek: otpx_core::crypto::b64(vault.dek()),
        expires,
    };
    let json = Zeroizing::new(serde_json::to_vec(&c).expect("session serializes"));
    ctx.secrets().set(SESSION, &json)
}

/// Keeps the key per the unlock mode; `ttl` overrides the configured length.
pub fn remember(ctx: &Ctx, vault: &Unlocked, ttl: Option<u64>) -> anyhow::Result<Option<u64>> {
    let cfg = ctx.config();
    let expires = match cfg.unlock_mode {
        UnlockMode::AlwaysAsk => return Ok(None),
        UnlockMode::KeychainPersistent if ttl.is_none() => 0,
        _ => now_ms() + ttl.unwrap_or(cfg.unlock_ttl_secs) * 1000,
    };
    store_cache(ctx, vault, expires)?;
    Ok(Some(expires))
}

/// After the key rotated (password, recovery code or devices changed): the cached session, if
/// any, keeps its expiry with the new key.
fn refresh_cache(ctx: &Ctx, vault: &Unlocked) -> anyhow::Result<()> {
    let secrets = ctx.secrets();
    let Some(raw) = secrets.get(SESSION)? else {
        return Ok(());
    };
    if let Ok(c) = serde_json::from_slice::<Cached>(&raw)
        && c.vault == vault.id
        && c.dek != otpx_core::crypto::b64(vault.dek())
    {
        store_cache(ctx, vault, c.expires)?;
    }
    Ok(())
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
    let env_pw = std::env::var("OTPX_PASSWORD")
        .ok()
        .filter(|p| !p.is_empty());
    if let Some(pw) = &env_pw
        && let Ok(vault) = file.unlock_password(pw)
    {
        return Ok(Session { vault, how: "env" });
    }
    // OTPX_PASSWORD may already be the new password of a vault re-keyed elsewhere: a cached
    // key still opens this copy, and the sync re-keys it.
    if let Some((dek, _)) = cached(ctx, &file.id)? {
        match file.unlock_dek(&dek) {
            Ok(vault) => {
                return Ok(Session {
                    vault,
                    how: "session",
                });
            }
            // The key rotated (on another device): unlock again below.
            Err(_) => forget(ctx)?,
        }
    }
    if env_pw.is_some() {
        return Err(fail(exit::AUTH, "OTPX_PASSWORD does not open this vault"));
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
            match secrets.get(TOUCHID_KEY)? {
                Some(key) => match file.unlock_device(&device_slot(ctx, "touchid"), &key, None) {
                    Ok(vault) => return Ok(Session { vault, how: "touchid" }),
                    Err(e) => ctx.ui.warn(&format!("Touch ID did not open the vault ({e}): turn it on again with `otpx quick-unlock enable touchid`")),
                },
                None => ctx.ui.warn("the Touch ID key is gone from the keychain: turn it on again"),
            }
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

fn pin_failures(ctx: &Ctx) -> anyhow::Result<u32> {
    Ok(ctx
        .secrets()
        .get(PIN_FAILS)?
        .and_then(|b| std::str::from_utf8(&b).ok()?.trim().parse().ok())
        .unwrap_or(0))
}

fn erase_pin_locally(ctx: &Ctx) -> anyhow::Result<()> {
    let secrets = ctx.secrets();
    secrets.delete(PIN_KEY)?;
    secrets.delete(PIN_FAILS)?;
    ctx.update_config(|c| c.quick.pin = false)
}

fn pin_unlock(ctx: &Ctx, file: &VaultFile) -> anyhow::Result<Option<Session>> {
    let Some(key) = ctx.secrets().get(PIN_KEY)? else {
        ctx.ui
            .warn("the PIN's device key is gone from the keychain: set the PIN again");
        return Ok(None);
    };
    let name = device_slot(ctx, "pin");
    if file.device_slot(&name).is_none() {
        ctx.ui
            .warn("this device's PIN was removed (from another device?): use the master password");
        erase_pin_locally(ctx)?;
        return Ok(None);
    }
    loop {
        let pin = read_secret("PIN (empty for the password): ", false)?;
        if pin.is_empty() {
            return Ok(None);
        }
        // Count the try before making it (one lock for every otpx process): no parallel or
        // interrupted attempts escape the limit.
        let tried = {
            let _lock = ctx.store.lock()?;
            let n = pin_failures(ctx)? + 1;
            if n > PIN_ATTEMPTS {
                erase_pin_locally(ctx)?;
                ctx.ui.warn(&format!(
                    "{PIN_ATTEMPTS} wrong PINs: the PIN is erased, use the master password"
                ));
                return Ok(None);
            }
            ctx.secrets().set(PIN_FAILS, n.to_string().as_bytes())?;
            n
        };
        if let Ok(vault) = file.unlock_device(&name, &key, Some(&pin)) {
            ctx.secrets().set(PIN_FAILS, b"0")?;
            return Ok(Some(Session { vault, how: "pin" }));
        }
        if tried >= PIN_ATTEMPTS {
            erase_pin_locally(ctx)?;
            ctx.ui.warn(&format!(
                "{PIN_ATTEMPTS} wrong PINs: the PIN is erased, use the master password"
            ));
            return Ok(None);
        }
        ctx.ui.note(&format!(
            "Wrong PIN ({} attempt(s) left).",
            PIN_ATTEMPTS - tried
        ));
    }
}

/// Turns on quick unlock for this device: a device slot in the vault, its key in the keychain.
pub fn enable_quick(
    ctx: &Ctx,
    s: &mut Session,
    method: &str,
    pin: Option<&str>,
) -> anyhow::Result<()> {
    require_keychain(ctx)?;
    let cfg = ctx.config();
    let label = format!("{} ({method})", cfg.device_name);
    let key = s
        .vault
        .add_device(
            &device_slot(ctx, method),
            &label,
            pin,
            now_ms(),
            &cfg.device_id,
        )
        .map_err(core_failure)?;
    let secrets = ctx.secrets();
    match method {
        "pin" => {
            secrets.set(PIN_KEY, &key)?;
            secrets.set(PIN_FAILS, b"0")?;
        }
        _ => secrets.set(TOUCHID_KEY, &key)?,
    }
    save(ctx, s)?;
    ctx.update_config(|c| {
        if method == "pin" {
            c.quick.pin = true;
        } else {
            c.quick.touchid = true;
        }
    })
}

/// Turns quick unlock off: the slot leaves the vault (and the key rotates), the local key goes.
pub fn disable_quick(ctx: &Ctx, method: &str) -> anyhow::Result<()> {
    let secrets = ctx.secrets();
    if let Ok(mut s) = open(ctx) {
        let device = ctx.config().device_id;
        if s.vault
            .keyring
            .slots
            .iter()
            .any(|x| x.device.as_deref() == Some(device_slot(ctx, method).as_str()))
        {
            sync_before_rotation(ctx, &mut s);
        }
        if s.vault
            .remove_device(&device_slot(ctx, method), now_ms(), &device)
            .map_err(core_failure)?
        {
            save(ctx, &mut s)?;
        }
    }
    if method == "pin" {
        secrets.delete(PIN_KEY)?;
        secrets.delete(PIN_FAILS)?;
    } else {
        secrets.delete(TOUCHID_KEY)?;
    }
    ctx.update_config(|c| {
        if method == "pin" {
            c.quick.pin = false;
        } else {
            c.quick.touchid = false;
        }
    })
}

/// The vault key changed on another device: unlock `newer` with the current master password
/// and fold this session's entries and slots into it. `concurrent`: this device re-keyed too,
/// so the user must confirm both changes were theirs (someone holding an old password could
/// otherwise pass a key of their own).
pub fn rekey(
    ctx: &Ctx,
    s: &mut Session,
    newer: &VaultFile,
    concurrent: bool,
) -> anyhow::Result<()> {
    let device = ctx.config().device_id;
    if concurrent {
        if !ui::interactive() {
            return Err(fail(
                exit::CONFLICT,
                "the vault was re-keyed on two devices at once: run `otpx sync` in a terminal to confirm",
            ));
        }
        ctx.ui.warn("the vault was re-keyed on another device while this device re-keyed it too (password, recovery code or quick unlock changed on both)");
        if !ctx.ui.confirm("Did you make both changes yourself")? {
            return Err(fail(
                exit::CONFLICT,
                "not merged: the other key may come from an old password; change your master password on a trusted device",
            ));
        }
    }
    let from_env = std::env::var("OTPX_PASSWORD")
        .ok()
        .filter(|p| !p.is_empty() && !concurrent);
    let other = if let Some(pw) = &from_env {
        newer
            .unlock_password(pw)
            .map_err(|_| fail(exit::AUTH, "OTPX_PASSWORD does not open the re-keyed vault"))?
    } else {
        if !ui::interactive() {
            return Err(fail(
                exit::LOCKED,
                "the vault key changed on another device (password, recovery code or devices changed): run `otpx sync` in a terminal and enter the current master password",
            ));
        }
        ctx.ui.note(
            "The vault key changed on another device (password, recovery code or devices changed).",
        );
        let mut found = None;
        for _ in 0..3 {
            let pw = read_secret("Current master password: ", false)?;
            if let Ok(v) = newer.unlock_password(&pw) {
                found = Some(v);
                break;
            }
            ctx.ui.note("Wrong password, try again.");
        }
        found.ok_or_else(|| fail(exit::AUTH, "wrong master password"))?
    };
    // New ways to unlock that come with the other copy must be the user's own.
    let changes = s.vault.keyring_changes(&other, now_ms());
    if !changes.is_empty() {
        if from_env.is_some() || !ui::interactive() {
            return Err(fail(
                exit::LOCKED,
                format!(
                    "the re-keyed vault adds ways to unlock ({}): run `otpx sync` in a terminal to review them",
                    changes.join(", ")
                ),
            ));
        }
        ctx.ui.note("It also brings these ways to unlock:");
        for c in &changes {
            ctx.ui.note(&format!("  {}", ui::clean(c)));
        }
        if !ctx
            .ui
            .confirm("Are these all yours (set up on your own devices)")?
        {
            return Err(fail(
                exit::CONFLICT,
                "not merged: change your master password on a trusted device, then sync it",
            ));
        }
    }
    s.vault
        .absorb_rotated(&other, now_ms(), &device)
        .map_err(core_failure)?;
    note_keyring(ctx, KeyringChange::Adopted);
    remember(ctx, &s.vault, None)?;
    Ok(())
}

/// Before changing the key here, take what other devices pushed (a rotation retires their
/// copies under the old key, so they would otherwise come back only when they sync again).
pub fn sync_before_rotation(ctx: &Ctx, s: &mut Session) {
    if ctx.may_auto_sync()
        && !ctx.config().remotes.is_empty()
        && let Err(e) = crate::sync::sync_all(ctx, s, None)
    {
        ctx.ui.warn(&format!("could not sync before changing the key ({e:#}): changes other devices pushed meanwhile come back when they sync again"));
    }
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
    {
        use otpx_core::vault::Trust;
        match disk.trust(&s.vault) {
            Trust::Same => {
                if let Ok(other) = disk.unlock_dek(s.vault.dek()) {
                    s.vault.absorb(&other, now_ms()).map_err(core_failure)?;
                    // Same content: keep the file (a new nonce would only make a needless snapshot).
                    if s.vault.data == other.data && s.vault.keyring == other.keyring {
                        refresh_cache(ctx, &s.vault)?;
                        return Ok(());
                    }
                }
            }
            Trust::Stale => {}
            // Another otpx re-keyed the vault meanwhile (a sync brought a new key).
            t @ (Trust::Endorsed | Trust::Concurrent) => {
                rekey(ctx, s, &disk, t == Trust::Concurrent)?
            }
            Trust::Untrusted => {
                return Err(fail(
                    exit::CONFLICT,
                    format!(
                        "{} was re-keyed by something this device cannot verify: not overwritten",
                        ctx.store.vault().display()
                    ),
                ));
            }
        }
    }
    let json = s.vault.seal().map_err(core_failure)?.to_json();
    ctx.store.write(&json, now_ms())?;
    refresh_cache(ctx, &s.vault)
}

/// Tells the user when a merge took another device's keyring.
pub fn note_keyring(ctx: &Ctx, change: KeyringChange) {
    if change == KeyringChange::Adopted {
        ctx.ui.note("The password, recovery code or quick-unlock devices changed on another device: that change is applied here too.");
    }
}
