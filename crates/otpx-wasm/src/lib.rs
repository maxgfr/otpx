//! otpx in the browser: a thin wasm-bindgen layer over `otpx-core`, so the web app runs the
//! very same code as the CLI for OTP, crypto, merge, formats, QR and shares. Structured
//! values cross the boundary as JSON strings.

use otpx_core::crypto::Argon2Params;
use otpx_core::formats::{self, ExportFormat, Format};
use otpx_core::model::{Entry, Kind, Settings, sort_entries};
use otpx_core::vault::{LocalWrap, Unlocked, VaultFile};
use otpx_core::{share, uri};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn ms(now: f64) -> u64 {
    if now.is_finite() && now > 0.0 {
        now as u64
    } else {
        0
    }
}

/// Version of the core.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// True when `text` is an otpx vault file.
#[wasm_bindgen(js_name = isVault)]
pub fn is_vault(text: &str) -> bool {
    VaultFile::sniff(text) && VaultFile::parse(text).is_ok()
}

/// Id of a vault file.
#[wasm_bindgen(js_name = vaultId)]
pub fn vault_id(text: &str) -> Result<String, JsError> {
    Ok(VaultFile::parse(text).map_err(err)?.id)
}

/// `[[credentialId, prfSalt], …]` of the passkeys that open a vault file.
#[wasm_bindgen]
pub fn passkeys(text: &str) -> Result<String, JsError> {
    Ok(json!(VaultFile::parse(text).map_err(err)?.passkeys()).to_string())
}

/// QR codes found in an RGBA frame (camera).
#[wasm_bindgen(js_name = decodeQrRgba)]
pub fn decode_qr_rgba(width: u32, height: u32, rgba: &[u8]) -> Result<String, JsError> {
    Ok(json!(otpx_core::qr::decode_rgba(width, height, rgba).map_err(err)?).to_string())
}

/// QR codes found in an image file.
#[wasm_bindgen(js_name = decodeQrImage)]
pub fn decode_qr_image(bytes: &[u8]) -> Result<String, JsError> {
    Ok(json!(otpx_core::qr::decode_image(bytes).map_err(err)?).to_string())
}

/// An SVG QR code of `text`.
#[wasm_bindgen(js_name = qrSvg)]
pub fn qr_svg(text: &str) -> Result<String, JsError> {
    otpx_core::qr::svg(text).map_err(err)
}

/// Whether a share link needs a passphrase.
#[wasm_bindgen(js_name = linkNeedsPassphrase)]
pub fn link_needs_passphrase(link: &str) -> bool {
    share::link_needs_passphrase(link)
}

fn entry_json(e: &Entry) -> Value {
    json!({
        "id": e.id, "issuer": e.issuer, "account": e.account, "label": e.label(),
        "type": e.kind.as_str(), "algorithm": e.algorithm.as_str(), "digits": e.digits,
        "period": e.period, "counter": e.counter, "tags": e.tags, "note": e.note,
        "favorite": e.favorite, "created": e.created,
    })
}

/// Opens a share link: `{entries: [...], device, expires}` (accounts without secrets shown,
/// the share kept for [`Vault::addShared`]).
#[wasm_bindgen(js_name = openLink)]
pub fn open_link(link: &str, passphrase: Option<String>, now: f64) -> Result<String, JsError> {
    let s = share::open_link(link, passphrase.as_deref(), ms(now)).map_err(err)?;
    Ok(json!({
        "entries": s.entries.iter().map(entry_json).collect::<Vec<_>>(),
        "device": s.device,
        "expires": s.expires,
        "share": serde_json::to_string(&s).map_err(err)?,
    })
    .to_string())
}

/// Every export format: `[[name, description], …]`.
#[wasm_bindgen(js_name = exportFormats)]
pub fn export_formats() -> String {
    json!(
        ExportFormat::ALL
            .iter()
            .map(|(n, _, d)| [*n, *d])
            .collect::<Vec<_>>()
    )
    .to_string()
}

fn params(fast: bool) -> Argon2Params {
    if fast {
        Argon2Params::TEST
    } else {
        Argon2Params::PASSWORD
    }
}

/// An open vault.
#[wasm_bindgen]
pub struct Vault {
    inner: Unlocked,
    recovery: Option<String>,
}

#[wasm_bindgen]
impl Vault {
    /// A new vault. `fast` lowers the KDF cost (tests only).
    pub fn create(password: &str, now: f64, fast: bool) -> Result<Vault, JsError> {
        let c = Unlocked::create(password, params(fast), ms(now)).map_err(err)?;
        let mut inner = c.vault;
        inner.data.identities.push(share::new_identity(ms(now)));
        Ok(Vault {
            inner,
            recovery: Some(c.recovery_code),
        })
    }

    /// Opens a vault file with the master password.
    #[wasm_bindgen(js_name = unlockPassword)]
    pub fn unlock_password(file: &str, password: &str) -> Result<Vault, JsError> {
        let f = VaultFile::parse(file).map_err(err)?;
        Ok(Vault {
            inner: f.unlock_password(password).map_err(err)?,
            recovery: None,
        })
    }

    /// Opens a vault file with the recovery code.
    #[wasm_bindgen(js_name = unlockRecovery)]
    pub fn unlock_recovery(file: &str, code: &str) -> Result<Vault, JsError> {
        let f = VaultFile::parse(file).map_err(err)?;
        Ok(Vault {
            inner: f.unlock_recovery(code).map_err(err)?,
            recovery: None,
        })
    }

    /// Opens a vault file with a passkey's PRF output.
    #[wasm_bindgen(js_name = unlockPasskey)]
    pub fn unlock_passkey(file: &str, credential: &str, prf: &[u8]) -> Result<Vault, JsError> {
        let f = VaultFile::parse(file).map_err(err)?;
        Ok(Vault {
            inner: f.unlock_passkey(credential, prf).map_err(err)?,
            recovery: None,
        })
    }

    /// Opens a vault file with a local wrap (PIN) and its secret.
    #[wasm_bindgen(js_name = unlockLocal)]
    pub fn unlock_local(file: &str, wrap: &str, secret: &[u8]) -> Result<Vault, JsError> {
        let f = VaultFile::parse(file).map_err(err)?;
        let w: LocalWrap = serde_json::from_str(wrap).map_err(err)?;
        let dek = w.open(secret).map_err(err)?;
        Ok(Vault {
            inner: f.unlock_dek(&dek).map_err(err)?,
            recovery: None,
        })
    }

    /// The recovery code of a vault just created (once).
    #[wasm_bindgen(js_name = takeRecoveryCode)]
    pub fn take_recovery_code(&mut self) -> Option<String> {
        self.recovery.take()
    }

    /// Vault id.
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    /// The encrypted vault file.
    pub fn seal(&self) -> Result<String, JsError> {
        Ok(self.inner.seal().map_err(err)?.to_json())
    }

    /// Accounts, sorted (favorites first), without secrets.
    pub fn entries(&self) -> String {
        let mut v: Vec<&Entry> = self.inner.data.entries.iter().collect();
        sort_entries(&mut v);
        json!(v.iter().map(|e| entry_json(e)).collect::<Vec<_>>()).to_string()
    }

    /// Current codes: `[{id, code, remaining, period, next}]` at `now` seconds.
    pub fn codes(&self, now_secs: f64) -> String {
        let t = ms(now_secs);
        json!(self
            .inner
            .data
            .entries
            .iter()
            .map(|e| {
                let c = e.code_at(t);
                let next = (e.kind != Kind::Hotp).then(|| e.next_code_at(t).code);
                json!({ "id": e.id, "code": c.code, "remaining": c.remaining, "period": c.period, "next": next })
            })
            .collect::<Vec<_>>())
        .to_string()
    }

    /// HOTP: the code to use now, and the counter moves on.
    #[wasm_bindgen(js_name = useHotp)]
    pub fn use_hotp(&mut self, id: &str, now: f64, device: &str) -> Result<String, JsError> {
        let e = self
            .inner
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| err("no such account"))?;
        let code = e.code_at(0).code;
        self.inner
            .data
            .advance_counter(id, ms(now), device)
            .map_err(err)?;
        Ok(code)
    }

    /// Adds every account found in `text` (URIs, transfer links): `{added, duplicates, skipped, missing}`.
    #[wasm_bindgen(js_name = addText)]
    pub fn add_text(&mut self, text: &str, now: f64, device: &str) -> Result<String, JsError> {
        let got = formats::import(text.as_bytes(), Format::Uris, None).map_err(err)?;
        self.absorb_import(got, now, device)
    }

    /// Adds an account from fields `{issuer, account, secret, type, algorithm, digits, period, counter, tags, note}`.
    #[wasm_bindgen(js_name = addManual)]
    pub fn add_manual(&mut self, fields: &str, now: f64, device: &str) -> Result<String, JsError> {
        let v: Value = serde_json::from_str(fields).map_err(err)?;
        let secret = otpx_core::b32::decode(v["secret"].as_str().unwrap_or("")).map_err(err)?;
        let mut e = Entry::new(
            v["issuer"].as_str().unwrap_or(""),
            v["account"].as_str().unwrap_or(""),
            secret,
        );
        apply(&mut e, &v)?;
        if self.inner.data.entries.iter().any(|x| x.same_account(&e)) {
            return Err(err("this account is already in the vault"));
        }
        self.inner.data.add(e, ms(now), device).map_err(err)
    }

    /// Changes an account: `{id, issuer?, account?, tags?, note?, favorite?, digits?, period?, algorithm?, counter?}`.
    pub fn update(&mut self, fields: &str, now: f64, device: &str) -> Result<(), JsError> {
        let v: Value = serde_json::from_str(fields).map_err(err)?;
        let id = v["id"].as_str().unwrap_or("");
        let mut e = self
            .inner
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| err("no such account"))?;
        if let Some(s) = v["issuer"].as_str() {
            e.issuer = s.trim().to_owned();
        }
        if let Some(s) = v["account"].as_str() {
            e.account = s.trim().to_owned();
        }
        apply(&mut e, &v)?;
        self.inner.data.update(e, ms(now), device).map_err(err)
    }

    /// Deletes an account.
    pub fn remove(&mut self, id: &str, now: f64, device: &str) -> Result<(), JsError> {
        self.inner
            .data
            .remove(id, ms(now), device)
            .map(|_| ())
            .map_err(err)
    }

    /// The `otpauth://` URI of an account (for its QR code).
    pub fn uri(&self, id: &str) -> Result<String, JsError> {
        let e = self
            .inner
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| err("no such account"))?;
        Ok(uri::to_uri(e))
    }

    /// The base32 secret of an account (shown on demand).
    pub fn secret(&self, id: &str) -> Result<String, JsError> {
        let e = self
            .inner
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| err("no such account"))?;
        Ok(e.secret_b32())
    }

    /// Imports a file of any supported format: `{format, added, duplicates, skipped, missing}`.
    /// Errors starting with `needs-password:` ask for the backup's password.
    #[wasm_bindgen(js_name = importBytes)]
    pub fn import_bytes(
        &mut self,
        bytes: &[u8],
        format: &str,
        password: Option<String>,
        now: f64,
        device: &str,
    ) -> Result<String, JsError> {
        let f = Format::parse(format).unwrap_or(Format::Auto);
        let got = formats::import(bytes, f, password.as_deref()).map_err(|e| match e {
            otpx_core::Error::NeedsPassword(w) => err(format!("needs-password:{w}")),
            e => err(e),
        })?;
        self.absorb_import(got, now, device)
    }

    fn absorb_import(
        &mut self,
        got: formats::Imported,
        now: f64,
        device: &str,
    ) -> Result<String, JsError> {
        let missing = got.missing_batches();
        let (mut added, mut dup) = (0, 0);
        for e in got.entries {
            if self
                .inner
                .data
                .add_unique(e, ms(now), device)
                .map_err(err)?
            {
                added += 1;
            } else {
                dup += 1;
            }
        }
        Ok(json!({ "format": got.format, "added": added, "duplicates": dup, "skipped": got.skipped, "missing": missing }).to_string())
    }

    /// Exports accounts (`ids` JSON array, empty for all) in `format`; `password` encrypts Aegis.
    pub fn export(
        &self,
        format: &str,
        ids: &str,
        password: Option<String>,
        now: f64,
    ) -> Result<String, JsError> {
        let picked = self.pick(ids)?;
        if format == "otpx" {
            return self.seal();
        }
        let f =
            ExportFormat::parse(format).ok_or_else(|| err(format!("unknown format {format}")))?;
        if f == ExportFormat::Paper {
            return formats::paper::export(&picked, None, ms(now)).map_err(err);
        }
        formats::export(&picked, f, password.as_deref(), ms(now)).map_err(err)
    }

    /// Google Authenticator transfer URIs (one per QR code) and the labels left out.
    #[wasm_bindgen(js_name = googleTransfer)]
    pub fn google_transfer(&self, ids: &str) -> Result<String, JsError> {
        let picked = self.pick(ids)?;
        Ok(json!({
            "codes": formats::google::export(&picked).map_err(err)?,
            "left_out": formats::google::not_exportable(&picked),
        })
        .to_string())
    }

    fn pick(&self, ids: &str) -> Result<Vec<Entry>, JsError> {
        let ids: Vec<String> = if ids.trim().is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(ids).map_err(err)?
        };
        let mut v: Vec<Entry> = self
            .inner
            .data
            .entries
            .iter()
            .filter(|e| ids.is_empty() || ids.contains(&e.id))
            .cloned()
            .collect();
        v.sort_by_key(|e| e.label().to_lowercase());
        Ok(v)
    }

    /// Merges another copy of this vault (from a remote): `{changed, differs}`, `changed`
    /// when it brought something, `differs` when the remote needs the merged result.
    pub fn absorb(&mut self, file: &str, now: f64) -> Result<String, JsError> {
        let f = VaultFile::parse(file).map_err(err)?;
        if f.id != self.inner.id {
            return Err(err("other-vault: the remote holds another vault"));
        }
        let other = f.unlock_dek(self.inner.dek()).map_err(err)?;
        let before = (self.inner.data.clone(), self.inner.slots.clone());
        self.inner.absorb(&other, ms(now)).map_err(err)?;
        let changed = before.0 != self.inner.data || before.1 != self.inner.slots;
        let differs = self.inner.data != other.data || self.inner.slots != other.slots;
        Ok(json!({ "changed": changed, "differs": differs }).to_string())
    }

    /// Changes the master password.
    #[wasm_bindgen(js_name = setPassword)]
    pub fn set_password(&mut self, password: &str, now: f64, fast: bool) -> Result<(), JsError> {
        self.inner
            .set_password(password, params(fast), ms(now))
            .map_err(err)
    }

    /// Makes a new recovery code (returned).
    #[wasm_bindgen(js_name = resetRecovery)]
    pub fn reset_recovery(&mut self, now: f64) -> Result<String, JsError> {
        self.inner.reset_recovery(ms(now)).map_err(err)
    }

    /// Adds a passkey slot.
    #[wasm_bindgen(js_name = addPasskey)]
    pub fn add_passkey(
        &mut self,
        credential: &str,
        prf_salt: &str,
        prf: &[u8],
        label: &str,
        now: f64,
    ) -> Result<String, JsError> {
        self.inner
            .add_passkey(credential, prf_salt, prf, label, ms(now))
            .map_err(err)
    }

    /// Removes a slot (not the last password).
    #[wasm_bindgen(js_name = removeSlot)]
    pub fn remove_slot(&mut self, id: &str) -> Result<(), JsError> {
        self.inner.remove_slot(id).map_err(err)
    }

    /// Slots: `[{id, type, label, created}]`.
    pub fn slots(&self) -> String {
        json!(self
            .inner
            .slots
            .iter()
            .map(|s| json!({ "id": s.id, "type": s.kind, "label": s.label, "created": s.created, "credential": s.credential }))
            .collect::<Vec<_>>())
        .to_string()
    }

    /// A local wrap of the DEK for a PIN (`secret` = PIN bytes + device secret).
    #[wasm_bindgen(js_name = localWrap)]
    pub fn local_wrap(&self, secret: &[u8], fast: bool) -> Result<String, JsError> {
        let p = if fast {
            Argon2Params::TEST
        } else {
            Argon2Params::KEY
        };
        serde_json::to_string(&LocalWrap::new(&self.inner, secret, Some(p)).map_err(err)?)
            .map_err(err)
    }

    /// Encrypts device-local data (sync settings, tokens).
    #[wasm_bindgen(js_name = sealLocal)]
    pub fn seal_local(&self, plain: &str) -> Result<String, JsError> {
        self.inner.seal_local(plain.as_bytes()).map_err(err)
    }

    /// Decrypts device-local data.
    #[wasm_bindgen(js_name = openLocal)]
    pub fn open_local(&self, sealed: &str) -> Result<String, JsError> {
        let p = self.inner.open_local(sealed).map_err(err)?;
        String::from_utf8(p.to_vec()).map_err(err)
    }

    /// A share link for the accounts `ids` (JSON array).
    #[wasm_bindgen(js_name = shareLink)]
    pub fn share_link(
        &self,
        base: &str,
        ids: &str,
        expires: f64,
        passphrase: Option<String>,
    ) -> Result<String, JsError> {
        let picked = self.pick(ids)?;
        if picked.is_empty() {
            return Err(err("choose at least one account"));
        }
        share::create_link(
            base,
            &share::Share::accounts(&picked, ms(expires)),
            passphrase.as_deref().filter(|p| !p.is_empty()),
        )
        .map_err(err)
    }

    /// A device setup link carrying `device` (JSON), passphrase required.
    #[wasm_bindgen(js_name = deviceLink)]
    pub fn device_link(
        &self,
        base: &str,
        device: &str,
        expires: f64,
        passphrase: &str,
    ) -> Result<String, JsError> {
        let d: Value = serde_json::from_str(device).map_err(err)?;
        let s = share::Share {
            v: 1,
            entries: Vec::new(),
            device: Some(d),
            expires: ms(expires),
            note: String::new(),
        };
        share::create_link(base, &s, Some(passphrase)).map_err(err)
    }

    /// Adds the accounts of a share opened with [`open_link`] (its `share` field).
    #[wasm_bindgen(js_name = addShared)]
    pub fn add_shared(
        &mut self,
        share_json: &str,
        now: f64,
        device: &str,
    ) -> Result<String, JsError> {
        let s: share::Share = serde_json::from_str(share_json).map_err(err)?;
        let got = formats::Imported {
            format: "share",
            entries: s.entries,
            ..Default::default()
        };
        self.absorb_import(got, now, device)
    }

    /// Opens an age share with this vault's identities and adds its accounts.
    #[wasm_bindgen(js_name = receiveAge)]
    pub fn receive_age(
        &mut self,
        armored: &str,
        now: f64,
        device: &str,
    ) -> Result<String, JsError> {
        let s = share::age_decrypt(&self.inner.data.identities, armored.as_bytes(), ms(now))
            .map_err(err)?;
        let got = formats::Imported {
            format: "age",
            entries: s.entries,
            ..Default::default()
        };
        self.absorb_import(got, now, device)
    }

    /// The age file of accounts `ids` for `recipients` (JSON array of age1… keys).
    #[wasm_bindgen(js_name = shareAge)]
    pub fn share_age(&self, ids: &str, recipients: &str) -> Result<String, JsError> {
        let picked = self.pick(ids)?;
        let r: Vec<String> = serde_json::from_str(recipients).map_err(err)?;
        let refs: Vec<&str> = r.iter().map(String::as_str).collect();
        share::age_encrypt(&refs, &share::Share::accounts(&picked, 0)).map_err(err)
    }

    /// This vault's public age key (created on first use).
    pub fn identity(&mut self, now: f64) -> String {
        if self.inner.data.identities.is_empty() {
            self.inner
                .data
                .identities
                .push(share::new_identity(ms(now)));
        }
        self.inner
            .data
            .primary_identity()
            .map(|i| i.public.clone())
            .unwrap_or_default()
    }

    /// Synced settings `{auto_lock_secs, clipboard_clear_secs}`.
    pub fn settings(&self) -> String {
        let s = &self.inner.data.settings;
        json!({ "auto_lock_secs": s.auto_lock_secs, "clipboard_clear_secs": s.clipboard_clear_secs }).to_string()
    }

    /// Changes synced settings.
    #[wasm_bindgen(js_name = setSettings)]
    pub fn set_settings(&mut self, fields: &str, now: f64, device: &str) -> Result<(), JsError> {
        let v: Value = serde_json::from_str(fields).map_err(err)?;
        let stamp = self.inner.data.stamp(ms(now), device);
        let cur = &self.inner.data.settings;
        let n = |k: &str, d: u32| {
            v[k].as_u64()
                .and_then(|x| u32::try_from(x).ok())
                .unwrap_or(d)
        };
        self.inner.data.settings = Settings {
            auto_lock_secs: n("auto_lock_secs", cur.auto_lock_secs).clamp(30, 86_400),
            clipboard_clear_secs: n("clipboard_clear_secs", cur.clipboard_clear_secs).min(600),
            updated: stamp,
        };
        Ok(())
    }
}

fn apply(e: &mut Entry, v: &Value) -> Result<(), JsError> {
    if let Some(k) = v["type"].as_str() {
        e.kind = match k {
            "totp" => Kind::Totp,
            "hotp" => Kind::Hotp,
            "steam" => Kind::Steam,
            _ => return Err(err("type is totp, hotp or steam")),
        };
    }
    if let Some(a) = v["algorithm"].as_str() {
        e.algorithm = otpx_core::Algorithm::parse(a)
            .ok_or_else(|| err("algorithm is SHA1, SHA256 or SHA512"))?;
    }
    if let Some(d) = v["digits"].as_u64() {
        e.digits = u8::try_from(d).map_err(err)?;
    }
    if let Some(p) = v["period"].as_u64() {
        e.period = u32::try_from(p).map_err(err)?;
    }
    if let Some(c) = v["counter"].as_u64() {
        e.counter = c;
    }
    if let Some(t) = v["tags"].as_array() {
        e.tags = t
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.trim().to_owned()))
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(n) = v["note"].as_str() {
        e.note = n.to_owned();
    }
    if let Some(f) = v["favorite"].as_bool() {
        e.favorite = f;
    }
    e.validate().map_err(err)
}
