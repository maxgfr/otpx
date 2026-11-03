//! The encrypted vault file (`vault.otpx`).
//!
//! A JSON envelope, readable in a git diff:
//!
//! ```json
//! {"format":"otpx-vault","v":1,"id":"…","slots":[…],"nonce":"…","ct":"…"}
//! ```
//!
//! A random 256-bit data key (DEK) encrypts the content with XChaCha20-Poly1305. Each slot
//! wraps the DEK with a key derived from one way of unlocking: the master password
//! (Argon2id), the recovery code (HKDF of 256 random bits) or a passkey's PRF output
//! (HKDF). Changing the password re-wraps the DEK; the content does not move.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, Argon2Params, Key, b64, unb64};
use crate::model::{VaultData, random_id};
use crate::{Error, Result};

/// `format` field of a vault file.
pub const FORMAT: &str = "otpx-vault";
/// Version of the envelope.
pub const VERSION: u32 = 1;

/// How a slot derives the key that wraps the DEK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SlotKind {
    /// Master password, Argon2id.
    Password,
    /// Recovery code (256 random bits), HKDF.
    Recovery,
    /// WebAuthn PRF output of a passkey (Touch ID in browsers), HKDF.
    Passkey,
}

impl SlotKind {
    fn as_str(self) -> &'static str {
        match self {
            SlotKind::Password => "password",
            SlotKind::Recovery => "recovery",
            SlotKind::Passkey => "passkey",
        }
    }
}

/// One wrapped copy of the DEK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slot {
    /// Slot id (random).
    pub id: String,
    /// Kind of secret.
    #[serde(rename = "type")]
    pub kind: SlotKind,
    /// Argon2id cost (password slots).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argon2: Option<Argon2Params>,
    /// KDF salt.
    pub salt: String,
    /// Nonce of the wrapped DEK.
    pub nonce: String,
    /// The wrapped DEK (ciphertext and tag).
    pub wrapped: String,
    /// Passkey credential id (base64url), for `allowCredentials`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    /// Salt passed to the PRF extension (base64url).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf_salt: Option<String>,
    /// Free label ("MacBook Touch ID").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// Creation time (ms).
    #[serde(default)]
    pub created: u64,
}

/// The vault file as stored and synced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultFile {
    /// Always [`FORMAT`].
    pub format: String,
    /// Envelope version.
    pub v: u32,
    /// Vault id: two files only merge when they share it.
    pub id: String,
    /// Ways to unlock.
    pub slots: Vec<Slot>,
    /// Content nonce.
    pub nonce: String,
    /// Encrypted [`VaultData`] (JSON).
    pub ct: String,
}

fn content_aad(vault_id: &str) -> Vec<u8> {
    format!("otpx-vault:v1:{vault_id}").into_bytes()
}

fn slot_aad(vault_id: &str, slot_id: &str, kind: SlotKind) -> Vec<u8> {
    format!("otpx-slot:v1:{vault_id}:{slot_id}:{}", kind.as_str()).into_bytes()
}

/// Key derivation of a passkey slot from the PRF output.
fn passkey_kek(prf: &[u8], salt: &[u8]) -> Key {
    crypto::hkdf(prf, salt, b"otpx passkey slot v1")
}

/// Key derivation of a recovery slot.
fn recovery_kek(code: &[u8], salt: &[u8]) -> Key {
    crypto::hkdf(code, salt, b"otpx recovery slot v1")
}

/// A recovery code: 256 random bits in base32, grouped by 4 (`ABCD-EFGH-…`).
pub fn new_recovery_code() -> Result<(String, Zeroizing<Vec<u8>>)> {
    let raw = Zeroizing::new(crypto::random_bytes(32)?);
    Ok((format_recovery(&raw), raw))
}

fn format_recovery(raw: &[u8]) -> String {
    let s = crate::b32::encode(raw);
    s.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Reads a recovery code as typed (case, spaces and dashes ignored).
pub fn parse_recovery(code: &str) -> Result<Zeroizing<Vec<u8>>> {
    let raw = crate::b32::decode(code).map_err(|_| Error::Decrypt)?;
    if raw.len() != 32 {
        return Err(Error::Decrypt);
    }
    Ok(Zeroizing::new(raw))
}

impl VaultFile {
    /// Parses and checks a vault file.
    pub fn parse(json: &str) -> Result<VaultFile> {
        let f: VaultFile = serde_json::from_str(json).map_err(|e| Error::format("vault", e))?;
        if f.format != FORMAT {
            return Err(Error::format("vault", "not an otpx vault"));
        }
        if f.v != VERSION {
            return Err(Error::format(
                "vault",
                format!(
                    "version {} (this otpx reads version {VERSION}: update it)",
                    f.v
                ),
            ));
        }
        Ok(f)
    }

    /// True when `text` looks like a vault file.
    pub fn sniff(text: &str) -> bool {
        text.trim_start().starts_with('{') && text.contains("\"otpx-vault\"")
    }

    /// Pretty JSON, one field per line.
    pub fn to_json(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).expect("a vault file serializes");
        s.push('\n');
        s
    }

    fn unwrap_slot(&self, slot: &Slot, kek: &Key) -> Result<Key> {
        let dek = crypto::open(
            kek,
            &unb64(&slot.nonce)?,
            &slot_aad(&self.id, &slot.id, slot.kind),
            &unb64(&slot.wrapped)?,
        )?;
        let arr: [u8; 32] = dek.as_slice().try_into().map_err(|_| Error::Decrypt)?;
        Ok(Zeroizing::new(arr))
    }

    /// Unlocks with the master password.
    pub fn unlock_password(&self, password: &str) -> Result<Unlocked> {
        for slot in self.slots.iter().filter(|s| s.kind == SlotKind::Password) {
            let params = slot
                .argon2
                .ok_or_else(|| Error::format("vault", "password slot without Argon2 cost"))?;
            let kek = crypto::argon2id(password.as_bytes(), &unb64(&slot.salt)?, params)?;
            if let Ok(dek) = self.unwrap_slot(slot, &kek) {
                return self.unlock_dek(&dek);
            }
        }
        Err(Error::Decrypt)
    }

    /// Unlocks with the recovery code.
    pub fn unlock_recovery(&self, code: &str) -> Result<Unlocked> {
        let raw = parse_recovery(code)?;
        for slot in self.slots.iter().filter(|s| s.kind == SlotKind::Recovery) {
            let kek = recovery_kek(&raw, &unb64(&slot.salt)?);
            if let Ok(dek) = self.unwrap_slot(slot, &kek) {
                return self.unlock_dek(&dek);
            }
        }
        Err(Error::Decrypt)
    }

    /// Unlocks with a passkey's PRF output for `credential` (base64url id).
    pub fn unlock_passkey(&self, credential: &str, prf: &[u8]) -> Result<Unlocked> {
        for slot in self
            .slots
            .iter()
            .filter(|s| s.kind == SlotKind::Passkey && s.credential.as_deref() == Some(credential))
        {
            let kek = passkey_kek(prf, &unb64(&slot.salt)?);
            if let Ok(dek) = self.unwrap_slot(slot, &kek) {
                return self.unlock_dek(&dek);
            }
        }
        Err(Error::Decrypt)
    }

    /// Unlocks with the DEK itself (kept by the OS keychain or a local quick-unlock wrap).
    pub fn unlock_dek(&self, dek: &[u8; 32]) -> Result<Unlocked> {
        let plain = crypto::open(
            dek,
            &unb64(&self.nonce)?,
            &content_aad(&self.id),
            &unb64(&self.ct)?,
        )?;
        let data: VaultData =
            serde_json::from_slice(&plain).map_err(|e| Error::format("vault content", e))?;
        Ok(Unlocked {
            id: self.id.clone(),
            slots: self.slots.clone(),
            dek: Zeroizing::new(*dek),
            data,
        })
    }

    /// The passkeys that can unlock this vault: `(credential id, PRF salt)`.
    pub fn passkeys(&self) -> Vec<(String, String)> {
        self.slots
            .iter()
            .filter(|s| s.kind == SlotKind::Passkey)
            .filter_map(|s| Some((s.credential.clone()?, s.prf_salt.clone()?)))
            .collect()
    }
}

/// An open vault: the DEK and the decrypted content.
pub struct Unlocked {
    /// Vault id.
    pub id: String,
    /// Slots, kept as they were unless changed through the methods below.
    pub slots: Vec<Slot>,
    dek: Key,
    /// The content; change it, then [`Unlocked::seal`].
    pub data: VaultData,
}

impl std::fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unlocked")
            .field("id", &self.id)
            .field("entries", &self.data.entries.len())
            .finish_non_exhaustive()
    }
}

/// A new vault and its recovery code (shown once).
pub struct Created {
    /// The open vault.
    pub vault: Unlocked,
    /// The recovery code.
    pub recovery_code: String,
}

impl Unlocked {
    /// A new empty vault protected by `password`, with a recovery slot.
    pub fn create(password: &str, params: Argon2Params, now_ms: u64) -> Result<Created> {
        let mut v = Unlocked {
            id: random_id(16)?,
            slots: Vec::new(),
            dek: crypto::random_key()?,
            data: VaultData::default(),
        };
        v.set_password(password, params, now_ms)?;
        let recovery_code = v.reset_recovery(now_ms)?;
        Ok(Created {
            vault: v,
            recovery_code,
        })
    }

    /// The DEK, to cache in the OS keychain or wrap for quick unlock.
    pub fn dek(&self) -> &[u8; 32] {
        &self.dek
    }

    fn wrap(&self, kind: SlotKind, kek: &Key, slot_id: &str) -> Result<(String, String)> {
        let (nonce, ct) = crypto::seal(kek, &slot_aad(&self.id, slot_id, kind), self.dek.as_ref())?;
        Ok((b64(&nonce), b64(&ct)))
    }

    /// Replaces every password slot with one for `password`.
    pub fn set_password(
        &mut self,
        password: &str,
        params: Argon2Params,
        now_ms: u64,
    ) -> Result<()> {
        if password.is_empty() {
            return Err(Error::Entry("empty password".into()));
        }
        let salt = crypto::random_bytes(16)?;
        let kek = crypto::argon2id(password.as_bytes(), &salt, params)?;
        let id = random_id(8)?;
        let (nonce, wrapped) = self.wrap(SlotKind::Password, &kek, &id)?;
        self.slots.retain(|s| s.kind != SlotKind::Password);
        self.slots.insert(
            0,
            Slot {
                id,
                kind: SlotKind::Password,
                argon2: Some(params),
                salt: b64(&salt),
                nonce,
                wrapped,
                credential: None,
                prf_salt: None,
                label: String::new(),
                created: now_ms,
            },
        );
        Ok(())
    }

    /// Replaces the recovery slot; returns the new code (the old one stops working).
    pub fn reset_recovery(&mut self, now_ms: u64) -> Result<String> {
        let (code, raw) = new_recovery_code()?;
        let salt = crypto::random_bytes(16)?;
        let kek = recovery_kek(&raw, &salt);
        let id = random_id(8)?;
        let (nonce, wrapped) = self.wrap(SlotKind::Recovery, &kek, &id)?;
        self.slots.retain(|s| s.kind != SlotKind::Recovery);
        self.slots.push(Slot {
            id,
            kind: SlotKind::Recovery,
            argon2: None,
            salt: b64(&salt),
            nonce,
            wrapped,
            credential: None,
            prf_salt: None,
            label: String::new(),
            created: now_ms,
        });
        Ok(code)
    }

    /// Adds a passkey slot from the PRF output obtained with `prf_salt`.
    pub fn add_passkey(
        &mut self,
        credential: &str,
        prf_salt: &str,
        prf: &[u8],
        label: &str,
        now_ms: u64,
    ) -> Result<String> {
        if prf.len() < 32 {
            return Err(Error::Entry("PRF output too short".into()));
        }
        let salt = crypto::random_bytes(16)?;
        let kek = passkey_kek(prf, &salt);
        let id = random_id(8)?;
        let (nonce, wrapped) = self.wrap(SlotKind::Passkey, &kek, &id)?;
        self.slots.retain(|s| {
            !(s.kind == SlotKind::Passkey && s.credential.as_deref() == Some(credential))
        });
        self.slots.push(Slot {
            id: id.clone(),
            kind: SlotKind::Passkey,
            argon2: None,
            salt: b64(&salt),
            nonce,
            wrapped,
            credential: Some(credential.to_owned()),
            prf_salt: Some(prf_salt.to_owned()),
            label: label.to_owned(),
            created: now_ms,
        });
        Ok(id)
    }

    /// Removes a slot; the last password slot stays.
    pub fn remove_slot(&mut self, slot_id: &str) -> Result<()> {
        let Some(pos) = self.slots.iter().position(|s| s.id == slot_id) else {
            return Err(Error::Entry(format!("no slot {slot_id}")));
        };
        if self.slots[pos].kind == SlotKind::Password
            && self
                .slots
                .iter()
                .filter(|s| s.kind == SlotKind::Password)
                .count()
                == 1
        {
            return Err(Error::Entry(
                "the master password slot cannot be removed".into(),
            ));
        }
        self.slots.remove(pos);
        Ok(())
    }

    /// Encrypts the content into a vault file (fresh nonce).
    pub fn seal(&self) -> Result<VaultFile> {
        let plain = Zeroizing::new(serde_json::to_vec(&self.data).expect("vault data serializes"));
        let (nonce, ct) = crypto::seal(&self.dek, &content_aad(&self.id), &plain)?;
        Ok(VaultFile {
            format: FORMAT.into(),
            v: VERSION,
            id: self.id.clone(),
            slots: self.slots.clone(),
            nonce: b64(&nonce),
            ct: b64(&ct),
        })
    }

    /// Encrypts device-local data (the web app's sync settings and tokens) with a key
    /// derived from the DEK: readable only once the vault is open.
    pub fn seal_local(&self, plain: &[u8]) -> Result<String> {
        let key = crypto::hkdf(self.dek.as_ref(), self.id.as_bytes(), b"otpx local data v1");
        let (nonce, ct) = crypto::seal(&key, b"otpx-local-data:v1", plain)?;
        Ok(format!(
            "{}.{}",
            crypto::b64url(&nonce),
            crypto::b64url(&ct)
        ))
    }

    /// Decrypts what [`Unlocked::seal_local`] produced.
    pub fn open_local(&self, sealed: &str) -> Result<Zeroizing<Vec<u8>>> {
        let (n, c) = sealed.split_once('.').ok_or(Error::Decrypt)?;
        let key = crypto::hkdf(self.dek.as_ref(), self.id.as_bytes(), b"otpx local data v1");
        crypto::open(&key, &unb64(n)?, b"otpx-local-data:v1", &unb64(c)?)
    }

    /// Merges a newer copy of the same vault (another device's save): content entry by
    /// entry, slots from `other` when it changed them.
    pub fn absorb(&mut self, other: &Unlocked, now_ms: u64) -> Result<()> {
        if other.id != self.id {
            return Err(Error::Entry("these are two different vaults".into()));
        }
        self.data = crate::merge::merge(&self.data, &other.data, now_ms);
        // Slots: union by id; a password change elsewhere replaces ours (newest wins).
        let newest_pw = self
            .slots
            .iter()
            .chain(&other.slots)
            .filter(|s| s.kind == SlotKind::Password)
            .max_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)))
            .cloned();
        let newest_rc = self
            .slots
            .iter()
            .chain(&other.slots)
            .filter(|s| s.kind == SlotKind::Recovery)
            .max_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)))
            .cloned();
        let mut passkeys: Vec<Slot> = Vec::new();
        for s in self.slots.iter().chain(&other.slots) {
            if s.kind == SlotKind::Passkey && !passkeys.iter().any(|p| p.id == s.id) {
                passkeys.push(s.clone());
            }
        }
        passkeys.sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
        self.slots = newest_pw
            .into_iter()
            .chain(newest_rc)
            .chain(passkeys)
            .collect();
        Ok(())
    }
}

/// The DEK wrapped by a device-local secret (quick unlock: PIN, Touch ID). Never synced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalWrap {
    /// Vault this wrap opens.
    pub vault: String,
    /// Argon2id cost, when the secret is low-entropy (a PIN).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argon2: Option<Argon2Params>,
    /// Salt.
    pub salt: String,
    /// Nonce.
    pub nonce: String,
    /// Wrapped DEK.
    pub wrapped: String,
}

fn local_kek(secret: &[u8], salt: &[u8], argon: Option<Argon2Params>) -> Result<Key> {
    match argon {
        Some(p) => crypto::argon2id(secret, salt, p),
        None => Ok(crypto::hkdf(secret, salt, b"otpx local wrap v1")),
    }
}

impl LocalWrap {
    /// Wraps `vault`'s DEK with `secret` (Argon2id when `argon` is set, else HKDF).
    pub fn new(vault: &Unlocked, secret: &[u8], argon: Option<Argon2Params>) -> Result<LocalWrap> {
        let salt = crypto::random_bytes(16)?;
        let kek = local_kek(secret, &salt, argon)?;
        let aad = format!("otpx-local:v1:{}", vault.id).into_bytes();
        let (nonce, wrapped) = crypto::seal(&kek, &aad, vault.dek.as_ref())?;
        Ok(LocalWrap {
            vault: vault.id.clone(),
            argon2: argon,
            salt: b64(&salt),
            nonce: b64(&nonce),
            wrapped: b64(&wrapped),
        })
    }

    /// The DEK, given the same secret.
    pub fn open(&self, secret: &[u8]) -> Result<Key> {
        let kek = local_kek(secret, &unb64(&self.salt)?, self.argon2)?;
        let aad = format!("otpx-local:v1:{}", self.vault).into_bytes();
        let dek = crypto::open(&kek, &unb64(&self.nonce)?, &aad, &unb64(&self.wrapped)?)?;
        let arr: [u8; 32] = dek.as_slice().try_into().map_err(|_| Error::Decrypt)?;
        Ok(Zeroizing::new(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Entry;

    fn new_vault() -> Created {
        Unlocked::create("hunter2", Argon2Params::TEST, 1).unwrap()
    }

    #[test]
    fn create_seal_unlock() {
        let mut c = new_vault();
        c.vault
            .data
            .add(Entry::new("GitHub", "me", vec![1, 2, 3]), 10, "dev")
            .unwrap();
        let file = c.vault.seal().unwrap();
        let json = file.to_json();
        assert!(VaultFile::sniff(&json));
        assert!(!json.contains("GitHub"));
        let back = VaultFile::parse(&json).unwrap();
        let open = back.unlock_password("hunter2").unwrap();
        assert_eq!(open.data, c.vault.data);
        assert!(matches!(back.unlock_password("wrong"), Err(Error::Decrypt)));
        let rec = back
            .unlock_recovery(&c.recovery_code.to_lowercase())
            .unwrap();
        assert_eq!(rec.data, c.vault.data);
        assert!(back.unlock_recovery("AAAA-BBBB").is_err());
        assert_eq!(back.unlock_dek(open.dek()).unwrap().data, open.data);
    }

    #[test]
    fn password_change_keeps_content() {
        let mut c = new_vault();
        c.vault
            .set_password("new pass", Argon2Params::TEST, 2)
            .unwrap();
        let f = c.vault.seal().unwrap();
        assert!(f.unlock_password("hunter2").is_err());
        assert!(f.unlock_password("new pass").is_ok());
        assert!(f.unlock_recovery(&c.recovery_code).is_ok());
        let pw = f
            .slots
            .iter()
            .find(|s| s.kind == SlotKind::Password)
            .unwrap();
        assert!(c.vault.remove_slot(&pw.id.clone()).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let c = new_vault();
        let mut f = c.vault.seal().unwrap();
        f.id = "other".into();
        assert!(f.unlock_password("hunter2").is_err());
        // A slot relabeled by an attacker no longer unwraps: its kind is authenticated.
        let mut g = c.vault.seal().unwrap();
        g.slots[1].kind = SlotKind::Password;
        g.slots[1].argon2 = Some(Argon2Params::TEST);
        assert!(g.unlock_recovery(&c.recovery_code).is_err());
        assert!(g.unlock_password("hunter2").is_ok());
    }

    #[test]
    fn passkey_and_local_wraps() {
        let mut c = new_vault();
        let prf = [7u8; 32];
        c.vault
            .add_passkey("cred1", "salt1", &prf, "Mac", 3)
            .unwrap();
        let f = c.vault.seal().unwrap();
        assert_eq!(f.passkeys(), vec![("cred1".into(), "salt1".into())]);
        assert!(f.unlock_passkey("cred1", &prf).is_ok());
        assert!(f.unlock_passkey("cred1", &[8u8; 32]).is_err());
        assert!(f.unlock_passkey("cred2", &prf).is_err());
        let w = LocalWrap::new(&c.vault, b"1234|device", Some(Argon2Params::TEST)).unwrap();
        let dek = w.open(b"1234|device").unwrap();
        assert!(f.unlock_dek(&dek).is_ok());
        assert!(w.open(b"1235|device").is_err());
    }

    #[test]
    fn local_data() {
        let c = new_vault();
        let sealed = c.vault.seal_local(b"token").unwrap();
        assert_eq!(c.vault.open_local(&sealed).unwrap().as_slice(), b"token");
        let other = new_vault();
        assert!(other.vault.open_local(&sealed).is_err());
    }

    #[test]
    fn absorb_takes_newest_password() {
        let c = new_vault();
        let file = c.vault.seal().unwrap();
        let mut a = file.unlock_password("hunter2").unwrap();
        let mut b = file.unlock_password("hunter2").unwrap();
        b.set_password("changed", Argon2Params::TEST, 50).unwrap();
        b.data.add(Entry::new("B", "b", vec![2]), 60, "b").unwrap();
        a.data.add(Entry::new("A", "a", vec![1]), 55, "a").unwrap();
        a.absorb(&b, 100).unwrap();
        assert_eq!(a.data.entries.len(), 2);
        let f = a.seal().unwrap();
        assert!(f.unlock_password("changed").is_ok());
        assert!(f.unlock_password("hunter2").is_err());
        assert!(f.unlock_recovery(&c.recovery_code).is_ok());
    }
}
