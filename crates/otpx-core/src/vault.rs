//! The encrypted vault file (`vault.otpx`).
//!
//! ```json
//! {"format":"otpx-vault","v":1,"id":"…","key_id":"…","keyring":{…},"mac":"…","nonce":"…","ct":"…"}
//! ```
//!
//! * A random 256-bit data key (DEK) encrypts the content with XChaCha20-Poly1305; the vault
//!   id and the key id are its associated data.
//! * The **keyring** lists the ways to unlock: master password, recovery code, passkeys (PRF)
//!   and device keys (PIN, Touch ID). Every slot holds an X25519 public key and the DEK sealed
//!   to it (ephemeral X25519, HKDF-SHA256, XChaCha20-Poly1305). The slot's secret key is derived
//!   from what unlocks it (Argon2id of the password, the recovery code, the PRF output, a device
//!   key), so the DEK can be re-sealed to every slot **without** knowing their secrets.
//! * The keyring carries a revision stamp and the key ids it retired, and is authenticated by an
//!   HMAC under a key derived from the DEK: a remote without the DEK cannot add, drop, replace or
//!   relabel a slot, and an old keyring cannot be replayed once its key was retired.
//! * Changing the password, making a new recovery code or removing a slot **rotates** the DEK:
//!   whoever held the old secret (or an old copy of the file) cannot read what follows.

use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{self, Argon2Params, Key, b64, unb64};
use crate::model::{Stamp, VaultData, random_id};
use crate::{Error, Result};

/// `format` field of a vault file.
pub const FORMAT: &str = "otpx-vault";
/// Version of the envelope.
pub const VERSION: u32 = 1;
/// Retired key ids kept (more than any realistic number of rotations between two syncs).
const RETIRED_KEEP: usize = 64;
/// Password slots tried per unlock: a hostile file cannot make us run Argon2 forever.
const MAX_PASSWORD_SLOTS: usize = 4;

/// What unlocks a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SlotKind {
    /// Master password (Argon2id).
    Password,
    /// Recovery code (256 random bits).
    Recovery,
    /// WebAuthn PRF output of a passkey (Touch ID / Face ID in browsers).
    Passkey,
    /// A key kept on one device, optionally combined with a PIN (quick unlock).
    Device,
}

impl SlotKind {
    fn as_str(self) -> &'static str {
        match self {
            SlotKind::Password => "password",
            SlotKind::Recovery => "recovery",
            SlotKind::Passkey => "passkey",
            SlotKind::Device => "device",
        }
    }
}

/// One way to unlock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slot {
    /// Slot id (random).
    pub id: String,
    /// Kind of secret.
    #[serde(rename = "type")]
    pub kind: SlotKind,
    /// The slot's X25519 public key.
    pub public: String,
    /// Ephemeral public key the DEK was sealed with.
    pub epk: String,
    /// Nonce of the sealed DEK.
    pub nonce: String,
    /// The sealed DEK.
    pub wrapped: String,
    /// Argon2id cost (password slots; device slots with a PIN).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argon2: Option<Argon2Params>,
    /// Argon2id salt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    /// Passkey credential id (base64url), for `allowCredentials`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    /// Salt passed to the PRF extension (base64url).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf_salt: Option<String>,
    /// Device slots: which device (and method) holds the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Free label ("MacBook Touch ID").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// Creation time (ms).
    #[serde(default)]
    pub created: u64,
}

/// The authenticated list of slots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyring {
    /// Revision: the newer keyring wins a merge.
    pub rev: Stamp,
    /// Ways to unlock.
    pub slots: Vec<Slot>,
    /// Key ids this vault rotated away from (never accepted again).
    #[serde(default)]
    pub retired: Vec<String>,
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
    /// Id of the DEK the content is encrypted with (derived from it).
    pub key_id: String,
    /// Ways to unlock.
    pub keyring: Keyring,
    /// HMAC of the keyring under the DEK.
    pub mac: String,
    /// Content nonce.
    pub nonce: String,
    /// Encrypted [`VaultData`] (JSON).
    pub ct: String,
}

fn key_id_of(dek: &[u8; 32], vault_id: &str) -> String {
    let k = crypto::hkdf(dek, vault_id.as_bytes(), b"otpx key id v1");
    data_encoding::HEXLOWER.encode(&k[..12])
}

fn keyring_mac(dek: &[u8; 32], vault_id: &str, key_id: &str, keyring: &Keyring) -> String {
    let mk = crypto::hkdf(dek, vault_id.as_bytes(), b"otpx keyring mac v1");
    let mut msg = format!("otpx-keyring:v1:{vault_id}:{key_id}:").into_bytes();
    msg.extend(serde_json::to_vec(keyring).expect("keyring serializes"));
    b64(&crypto::hmac(mk.as_ref(), &msg))
}

fn content_aad(vault_id: &str, key_id: &str) -> Vec<u8> {
    format!("otpx-vault:v1:{vault_id}:{key_id}").into_bytes()
}

fn slot_aad(vault_id: &str, slot: &Slot) -> Vec<u8> {
    format!(
        "otpx-slot:v1:{vault_id}:{}:{}:{}",
        slot.id,
        slot.kind.as_str(),
        slot.public
    )
    .into_bytes()
}

/// The X25519 secret of a slot from its unlocking material.
fn slot_secret(material: &[u8], kind: SlotKind) -> StaticSecret {
    let info = format!("otpx {} slot x25519 v1", kind.as_str());
    let k = crypto::hkdf(material, b"", info.as_bytes());
    StaticSecret::from(*k)
}

fn kek(shared: &[u8; 32], epk: &[u8; 32], pk: &[u8; 32]) -> Key {
    crypto::hkdf(
        shared,
        &[epk.as_slice(), pk.as_slice()].concat(),
        b"otpx sealed slot v1",
    )
}

fn pk_bytes(text: &str) -> Result<[u8; 32]> {
    unb64(text)?
        .as_slice()
        .try_into()
        .map_err(|_| Error::format("vault", "bad public key"))
}

/// Seals `dek` to a slot's public key, filling `epk`, `nonce` and `wrapped`.
fn seal_slot(vault_id: &str, slot: &mut Slot, dek: &[u8; 32]) -> Result<()> {
    let pk = pk_bytes(&slot.public)?;
    let mut eph_bytes = Zeroizing::new([0u8; 32]);
    crypto::fill_random(eph_bytes.as_mut())?;
    let eph = StaticSecret::from(*eph_bytes);
    let epk = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(pk));
    if !shared.was_contributory() {
        return Err(Error::format("vault", "weak slot key"));
    }
    let k = kek(shared.as_bytes(), epk.as_bytes(), &pk);
    slot.epk = b64(epk.as_bytes());
    let (nonce, wrapped) = crypto::seal(&k, &slot_aad(vault_id, slot), dek)?;
    slot.nonce = b64(&nonce);
    slot.wrapped = b64(&wrapped);
    Ok(())
}

/// Opens a slot with its secret key.
fn open_slot(vault_id: &str, slot: &Slot, sk: &StaticSecret) -> Result<Key> {
    let pk = pk_bytes(&slot.public)?;
    if PublicKey::from(sk).as_bytes() != &pk {
        return Err(Error::Decrypt);
    }
    let epk = pk_bytes(&slot.epk)?;
    let shared = sk.diffie_hellman(&PublicKey::from(epk));
    if !shared.was_contributory() {
        return Err(Error::Decrypt);
    }
    let k = kek(shared.as_bytes(), &epk, &pk);
    let dek = crypto::open(
        &k,
        &unb64(&slot.nonce)?,
        &slot_aad(vault_id, slot),
        &unb64(&slot.wrapped)?,
    )?;
    let arr: [u8; 32] = dek.as_slice().try_into().map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(arr))
}

/// A recovery code: 256 random bits in base32, grouped by 4 (`ABCD-EFGH-…`).
pub fn new_recovery_code() -> Result<(String, Zeroizing<Vec<u8>>)> {
    let raw = Zeroizing::new(crypto::random_bytes(32)?);
    let s = crate::b32::encode(&raw);
    let code = s
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-");
    Ok((code, raw))
}

/// Reads a recovery code as typed (case, spaces and dashes ignored).
pub fn parse_recovery(code: &str) -> Result<Zeroizing<Vec<u8>>> {
    let raw = crate::b32::decode(code).map_err(|_| Error::Decrypt)?;
    if raw.len() != 32 {
        return Err(Error::Decrypt);
    }
    Ok(Zeroizing::new(raw))
}

/// The material of a device slot: the device key, stretched with the PIN when there is one.
fn device_material(
    device_key: &[u8],
    pin: Option<&str>,
    slot_salt: Option<&str>,
    argon: Option<Argon2Params>,
) -> Result<Zeroizing<Vec<u8>>> {
    match (pin, slot_salt, argon) {
        (None, None, None) => Ok(Zeroizing::new(device_key.to_vec())),
        (Some(pin), Some(salt), Some(p)) => {
            let stretched = crypto::argon2id(pin.as_bytes(), &unb64(salt)?, p)?;
            Ok(Zeroizing::new([device_key, stretched.as_slice()].concat()))
        }
        _ => Err(Error::Decrypt),
    }
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
        if f.keyring.slots.len() > 64 {
            return Err(Error::format("vault", "too many slots"));
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

    fn try_slots<'a>(
        &'a self,
        kind: SlotKind,
        limit: usize,
        mut sk: impl FnMut(&'a Slot) -> Result<StaticSecret>,
    ) -> Result<Unlocked> {
        for slot in self
            .keyring
            .slots
            .iter()
            .filter(|s| s.kind == kind)
            .take(limit)
        {
            let Ok(secret) = sk(slot) else { continue };
            if let Ok(dek) = open_slot(&self.id, slot, &secret)
                && let Ok(v) = self.unlock_dek(&dek)
            {
                return Ok(v);
            }
        }
        Err(Error::Decrypt)
    }

    /// Unlocks with the master password.
    pub fn unlock_password(&self, password: &str) -> Result<Unlocked> {
        self.try_slots(SlotKind::Password, MAX_PASSWORD_SLOTS, |slot| {
            let p = slot.argon2.ok_or(Error::Decrypt)?;
            let salt = unb64(slot.salt.as_deref().ok_or(Error::Decrypt)?)?;
            let k = crypto::argon2id(password.as_bytes(), &salt, p)?;
            Ok(slot_secret(k.as_ref(), SlotKind::Password))
        })
    }

    /// Unlocks with the recovery code.
    pub fn unlock_recovery(&self, code: &str) -> Result<Unlocked> {
        let raw = parse_recovery(code)?;
        let sk = slot_secret(&raw, SlotKind::Recovery);
        self.try_slots(SlotKind::Recovery, 4, |_| Ok(sk.clone()))
    }

    /// Unlocks with a passkey's PRF output for `credential` (base64url id).
    pub fn unlock_passkey(&self, credential: &str, prf: &[u8]) -> Result<Unlocked> {
        let sk = slot_secret(prf, SlotKind::Passkey);
        for slot in
            self.keyring.slots.iter().filter(|s| {
                s.kind == SlotKind::Passkey && s.credential.as_deref() == Some(credential)
            })
        {
            if let Ok(dek) = open_slot(&self.id, slot, &sk) {
                return self.unlock_dek(&dek);
            }
        }
        Err(Error::Decrypt)
    }

    /// The device slot named `device`, if this vault still has one.
    pub fn device_slot(&self, device: &str) -> Option<&Slot> {
        self.keyring
            .slots
            .iter()
            .find(|s| s.kind == SlotKind::Device && s.device.as_deref() == Some(device))
    }

    /// Unlocks with a device key (and the PIN when the slot has one).
    pub fn unlock_device(
        &self,
        device: &str,
        device_key: &[u8],
        pin: Option<&str>,
    ) -> Result<Unlocked> {
        let slot = self
            .device_slot(device)
            .ok_or_else(|| Error::Entry("this device's quick unlock was removed".into()))?;
        let material = device_material(device_key, pin, slot.salt.as_deref(), slot.argon2)?;
        let dek = open_slot(&self.id, slot, &slot_secret(&material, SlotKind::Device))?;
        self.unlock_dek(&dek)
    }

    /// Unlocks with the DEK itself (cached by the OS keychain for a session).
    pub fn unlock_dek(&self, dek: &[u8; 32]) -> Result<Unlocked> {
        if key_id_of(dek, &self.id) != self.key_id {
            return Err(Error::Decrypt);
        }
        if !crypto::ct_eq(
            keyring_mac(dek, &self.id, &self.key_id, &self.keyring).as_bytes(),
            self.mac.as_bytes(),
        ) {
            return Err(Error::Decrypt);
        }
        let plain = crypto::open(
            dek,
            &unb64(&self.nonce)?,
            &content_aad(&self.id, &self.key_id),
            &unb64(&self.ct)?,
        )?;
        let data: VaultData =
            serde_json::from_slice(&plain).map_err(|e| Error::format("vault content", e))?;
        Ok(Unlocked {
            id: self.id.clone(),
            key_id: self.key_id.clone(),
            dek: Zeroizing::new(*dek),
            keyring: self.keyring.clone(),
            data,
        })
    }

    /// The passkeys that can unlock this vault: `(credential id, PRF salt)`.
    pub fn passkeys(&self) -> Vec<(String, String)> {
        self.keyring
            .slots
            .iter()
            .filter(|s| s.kind == SlotKind::Passkey)
            .filter_map(|s| Some((s.credential.clone()?, s.prf_salt.clone()?)))
            .collect()
    }

    /// Whether this file's key was rotated away by `other` (an older copy), so it must not
    /// be trusted over it.
    pub fn retired_by(&self, other: &Keyring) -> bool {
        other.retired.contains(&self.key_id)
    }
}

/// An open vault: the DEK, the keyring and the decrypted content.
pub struct Unlocked {
    /// Vault id.
    pub id: String,
    key_id: String,
    dek: Key,
    /// Ways to unlock (change them through the methods below).
    pub keyring: Keyring,
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

/// Result of [`Unlocked::absorb`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringChange {
    /// Ours was kept.
    Kept,
    /// The other copy's keyring (and key) replaced ours: the password, the recovery code or the
    /// devices changed elsewhere.
    Adopted,
}

impl Unlocked {
    /// A new empty vault protected by `password`, with a recovery slot.
    pub fn create(
        password: &str,
        params: Argon2Params,
        now_ms: u64,
        device: &str,
    ) -> Result<Created> {
        let id = random_id(16)?;
        let dek = crypto::random_key()?;
        let mut v = Unlocked {
            key_id: key_id_of(&dek, &id),
            id,
            dek,
            keyring: Keyring {
                rev: Stamp::default(),
                slots: Vec::new(),
                retired: Vec::new(),
            },
            data: VaultData::default(),
        };
        v.keyring
            .slots
            .push(v.password_slot(password, params, now_ms)?);
        let (code, slot) = v.recovery_slot(now_ms)?;
        v.keyring.slots.push(slot);
        v.keyring.rev = v.data.stamp(now_ms, device);
        Ok(Created {
            vault: v,
            recovery_code: code,
        })
    }

    /// The DEK, to cache in the OS keychain for a session.
    pub fn dek(&self) -> &[u8; 32] {
        &self.dek
    }

    /// Id of the current DEK.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    fn new_slot(&self, kind: SlotKind, sk: &StaticSecret, now_ms: u64) -> Result<Slot> {
        let mut slot = Slot {
            id: random_id(8)?,
            kind,
            public: b64(PublicKey::from(sk).as_bytes()),
            epk: String::new(),
            nonce: String::new(),
            wrapped: String::new(),
            argon2: None,
            salt: None,
            credential: None,
            prf_salt: None,
            device: None,
            label: String::new(),
            created: now_ms,
        };
        seal_slot(&self.id, &mut slot, &self.dek)?;
        Ok(slot)
    }

    fn password_slot(&self, password: &str, params: Argon2Params, now_ms: u64) -> Result<Slot> {
        if password.is_empty() {
            return Err(Error::Entry("empty password".into()));
        }
        let salt = crypto::random_bytes(16)?;
        let k = crypto::argon2id(password.as_bytes(), &salt, params)?;
        let mut slot = self.new_slot(
            SlotKind::Password,
            &slot_secret(k.as_ref(), SlotKind::Password),
            now_ms,
        )?;
        slot.argon2 = Some(params);
        slot.salt = Some(b64(&salt));
        // The cost and salt are part of the slot now: seal again so they are bound to it.
        seal_slot(&self.id, &mut slot, &self.dek)?;
        Ok(slot)
    }

    fn recovery_slot(&self, now_ms: u64) -> Result<(String, Slot)> {
        let (code, raw) = new_recovery_code()?;
        let slot = self.new_slot(
            SlotKind::Recovery,
            &slot_secret(&raw, SlotKind::Recovery),
            now_ms,
        )?;
        Ok((code, slot))
    }

    /// A new DEK sealed to every remaining slot; the old key is retired.
    fn rotate(&mut self, now_ms: u64, device: &str) -> Result<()> {
        let old = std::mem::take(&mut self.key_id);
        let dek = crypto::random_key()?;
        self.key_id = key_id_of(&dek, &self.id);
        self.dek = dek;
        for slot in &mut self.keyring.slots {
            seal_slot(&self.id, slot, &self.dek)?;
        }
        self.keyring.retired.retain(|k| *k != old);
        self.keyring.retired.push(old);
        if self.keyring.retired.len() > RETIRED_KEEP {
            let extra = self.keyring.retired.len() - RETIRED_KEEP;
            self.keyring.retired.drain(..extra);
        }
        self.bump(now_ms, device);
        Ok(())
    }

    fn bump(&mut self, now_ms: u64, device: &str) {
        let s = self.data.stamp(now_ms, device);
        self.keyring.rev = if s > self.keyring.rev {
            s
        } else {
            Stamp::next(&self.keyring.rev, now_ms, device)
        };
    }

    /// Replaces the master password (and rotates the key: the old password, and every old copy
    /// of the file, stop giving access to what follows).
    pub fn set_password(
        &mut self,
        password: &str,
        params: Argon2Params,
        now_ms: u64,
        device: &str,
    ) -> Result<()> {
        let slot = self.password_slot(password, params, now_ms)?;
        self.keyring.slots.retain(|s| s.kind != SlotKind::Password);
        self.keyring.slots.insert(0, slot);
        self.rotate(now_ms, device)
    }

    /// Replaces the recovery code (and rotates the key); returns the new code.
    pub fn reset_recovery(&mut self, now_ms: u64, device: &str) -> Result<String> {
        let (code, slot) = self.recovery_slot(now_ms)?;
        self.keyring.slots.retain(|s| s.kind != SlotKind::Recovery);
        self.keyring.slots.push(slot);
        self.rotate(now_ms, device)?;
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
        device: &str,
    ) -> Result<String> {
        if prf.len() < 32 {
            return Err(Error::Entry("PRF output too short".into()));
        }
        let mut slot = self.new_slot(
            SlotKind::Passkey,
            &slot_secret(prf, SlotKind::Passkey),
            now_ms,
        )?;
        slot.credential = Some(credential.to_owned());
        slot.prf_salt = Some(prf_salt.to_owned());
        slot.label = label.to_owned();
        seal_slot(&self.id, &mut slot, &self.dek)?;
        let id = slot.id.clone();
        self.keyring.slots.retain(|s| {
            !(s.kind == SlotKind::Passkey && s.credential.as_deref() == Some(credential))
        });
        self.keyring.slots.push(slot);
        self.bump(now_ms, device);
        Ok(id)
    }

    /// Adds (or replaces) the quick-unlock slot of `device_name` ("<device id>:pin"); returns the
    /// 32-byte device key to keep on that device. With a PIN, the slot also needs the PIN
    /// (Argon2id), so the device key alone does not open the vault.
    pub fn add_device(
        &mut self,
        device_name: &str,
        label: &str,
        pin: Option<&str>,
        now_ms: u64,
        device: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let key = Zeroizing::new(crypto::random_bytes(32)?);
        let (salt, argon) = match pin {
            Some(_) => (
                Some(b64(&crypto::random_bytes(16)?)),
                Some(Argon2Params::KEY),
            ),
            None => (None, None),
        };
        let material = device_material(&key, pin, salt.as_deref(), argon)?;
        let mut slot = self.new_slot(
            SlotKind::Device,
            &slot_secret(&material, SlotKind::Device),
            now_ms,
        )?;
        slot.device = Some(device_name.to_owned());
        slot.salt = salt;
        slot.argon2 = argon;
        slot.label = label.to_owned();
        seal_slot(&self.id, &mut slot, &self.dek)?;
        self.keyring
            .slots
            .retain(|s| !(s.kind == SlotKind::Device && s.device.as_deref() == Some(device_name)));
        self.keyring.slots.push(slot);
        self.bump(now_ms, device);
        Ok(key)
    }

    /// Removes a slot and rotates the key (a removed passkey or device cannot read what follows);
    /// the last password slot stays.
    pub fn remove_slot(&mut self, slot_id: &str, now_ms: u64, device: &str) -> Result<()> {
        let Some(pos) = self.keyring.slots.iter().position(|s| s.id == slot_id) else {
            return Err(Error::Entry(format!("no slot {slot_id}")));
        };
        if self.keyring.slots[pos].kind == SlotKind::Password
            && self
                .keyring
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
        self.keyring.slots.remove(pos);
        self.rotate(now_ms, device)
    }

    /// Removes the device slot named `device_name`, if any.
    pub fn remove_device(&mut self, device_name: &str, now_ms: u64, device: &str) -> Result<bool> {
        let ids: Vec<String> = self
            .keyring
            .slots
            .iter()
            .filter(|s| s.kind == SlotKind::Device && s.device.as_deref() == Some(device_name))
            .map(|s| s.id.clone())
            .collect();
        if ids.is_empty() {
            return Ok(false);
        }
        self.keyring.slots.retain(|s| !ids.contains(&s.id));
        self.rotate(now_ms, device)?;
        Ok(true)
    }

    /// Encrypts the content into a vault file (fresh nonce).
    pub fn seal(&self) -> Result<VaultFile> {
        let plain = Zeroizing::new(serde_json::to_vec(&self.data).expect("vault data serializes"));
        let (nonce, ct) = crypto::seal(&self.dek, &content_aad(&self.id, &self.key_id), &plain)?;
        Ok(VaultFile {
            format: FORMAT.into(),
            v: VERSION,
            id: self.id.clone(),
            key_id: self.key_id.clone(),
            mac: keyring_mac(&self.dek, &self.id, &self.key_id, &self.keyring),
            keyring: self.keyring.clone(),
            nonce: b64(&nonce),
            ct: b64(&ct),
        })
    }

    /// Merges another open copy of the same vault (another device's save). The content merges
    /// entry by entry. The keyring of the copy whose key the other one retired loses; otherwise
    /// the newer revision wins, and its key comes with it.
    ///
    /// A copy under a key this vault retired is stale or forged (whoever knew an old password can
    /// write one): its content is ignored. Use [`Unlocked::absorb_own`] for this device's own
    /// older copy, whose changes must survive a rotation made elsewhere.
    pub fn absorb(&mut self, other: &Unlocked, now_ms: u64) -> Result<KeyringChange> {
        self.absorb_inner(other, now_ms, false)
    }

    /// Like [`Unlocked::absorb`] for a copy this device wrote itself (opened with its own cached
    /// key), so its content is merged even when its key was retired meanwhile.
    pub fn absorb_own(&mut self, other: &Unlocked, now_ms: u64) -> Result<KeyringChange> {
        self.absorb_inner(other, now_ms, true)
    }

    fn absorb_inner(&mut self, other: &Unlocked, now_ms: u64, own: bool) -> Result<KeyringChange> {
        if other.id != self.id {
            return Err(Error::Entry("these are two different vaults".into()));
        }
        let other_retired = self.keyring.retired.contains(&other.key_id);
        if !other_retired || own {
            self.data = crate::merge::merge(&self.data, &other.data, now_ms);
        }
        let adopt = if other_retired {
            false
        } else if other.keyring.retired.contains(&self.key_id) {
            true
        } else {
            other.keyring.rev > self.keyring.rev
        };
        if !adopt {
            // Remember a concurrent rotation we did not take, so it is never accepted later.
            if other.key_id != self.key_id && !self.keyring.retired.contains(&other.key_id) {
                self.keyring.retired.push(other.key_id.clone());
            }
            return Ok(KeyringChange::Kept);
        }
        let mut retired = other.keyring.retired.clone();
        for k in self
            .keyring
            .retired
            .iter()
            .chain(std::iter::once(&self.key_id))
        {
            if *k != other.key_id && !retired.contains(k) {
                retired.push(k.clone());
            }
        }
        self.keyring = other.keyring.clone();
        self.keyring.retired = retired;
        self.dek = Zeroizing::new(*other.dek);
        self.key_id = other.key_id.clone();
        Ok(KeyringChange::Adopted)
    }

    /// Encrypts device-local data (the web app's sync settings) with a key derived from the DEK.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Entry;

    const P: Argon2Params = Argon2Params::TEST;

    fn new_vault() -> Created {
        Unlocked::create("hunter2", P, 1, "a").unwrap()
    }

    fn reopen(v: &Unlocked) -> VaultFile {
        VaultFile::parse(&v.seal().unwrap().to_json()).unwrap()
    }

    #[test]
    fn create_seal_unlock() {
        let mut c = new_vault();
        c.vault
            .data
            .add(Entry::new("GitHub", "me", vec![1, 2, 3]), 10, "dev")
            .unwrap();
        let json = c.vault.seal().unwrap().to_json();
        assert!(VaultFile::sniff(&json));
        assert!(!json.contains("GitHub"));
        let back = VaultFile::parse(&json).unwrap();
        let open = back.unlock_password("hunter2").unwrap();
        assert_eq!(open.data, c.vault.data);
        assert!(matches!(back.unlock_password("wrong"), Err(Error::Decrypt)));
        assert_eq!(
            back.unlock_recovery(&c.recovery_code.to_lowercase())
                .unwrap()
                .data,
            c.vault.data
        );
        assert!(back.unlock_recovery("AAAA-BBBB").is_err());
        assert_eq!(back.unlock_dek(open.dek()).unwrap().data, open.data);
    }

    #[test]
    fn password_change_rotates_the_key() {
        let mut c = new_vault();
        let old_file = reopen(&c.vault);
        let old_dek = *c.vault.dek();
        c.vault.set_password("new pass", P, 2, "a").unwrap();
        c.vault
            .data
            .add(Entry::new("Later", "x", vec![9; 10]), 3, "a")
            .unwrap();
        let f = reopen(&c.vault);
        assert!(f.unlock_password("hunter2").is_err());
        assert!(f.unlock_password("new pass").is_ok());
        // The recovery code still works (re-sealed without knowing it).
        assert!(f.unlock_recovery(&c.recovery_code).is_ok());
        // The old key and the old password open nothing written after the change.
        assert!(f.unlock_dek(&old_dek).is_err());
        let old_open = old_file.unlock_password("hunter2").unwrap();
        assert!(f.unlock_dek(old_open.dek()).is_err());
        assert!(f.keyring.retired.contains(&old_file.key_id));
    }

    #[test]
    fn recovery_reset_rotates_and_kills_the_old_code() {
        let mut c = new_vault();
        let code2 = c.vault.reset_recovery(5, "a").unwrap();
        let f = reopen(&c.vault);
        assert!(f.unlock_recovery(&c.recovery_code).is_err());
        assert!(f.unlock_recovery(&code2).is_ok());
        assert!(f.unlock_password("hunter2").is_ok());
    }

    #[test]
    fn keyring_tampering_is_detected() {
        let c = new_vault();
        let good = c.vault.seal().unwrap();
        // A remote swaps in the slots of another vault (or bumps a revision): the MAC fails.
        let other = Unlocked::create("attacker", P, 1, "x").unwrap();
        let mut forged = good.clone();
        forged.keyring.slots = other.vault.seal().unwrap().keyring.slots;
        assert!(forged.unlock_password("attacker").is_err());
        assert!(forged.unlock_password("hunter2").is_err());
        let mut bumped = good.clone();
        bumped.keyring.rev.t = u64::MAX;
        assert!(bumped.unlock_dek(c.vault.dek()).is_err());
        let mut relabeled = good.clone();
        relabeled.keyring.slots[1].kind = SlotKind::Password;
        assert!(relabeled.unlock_recovery(&c.recovery_code).is_err());
        // Cutting the cost of a password slot breaks its seal.
        let mut cheap = good;
        cheap.keyring.slots[0].argon2 = Some(Argon2Params { m: 32, t: 1, p: 1 });
        assert!(cheap.unlock_password("hunter2").is_err());
    }

    #[test]
    fn a_retired_keyring_is_never_adopted_again() {
        let c = new_vault();
        let before = reopen(&c.vault);
        let mut a = before.unlock_password("hunter2").unwrap();
        a.set_password("rotated", P, 10, "a").unwrap();
        // An attacker who knew the old password replays an old copy with a newer-looking content.
        let mut stale_old = before.unlock_password("hunter2").unwrap();
        stale_old
            .data
            .add(Entry::new("Forged", "x", vec![5; 10]), 99, "z")
            .unwrap();
        assert_eq!(a.absorb(&stale_old, 20).unwrap(), KeyringChange::Kept);
        // Its content is ignored too: an old key can forge entries or deletions.
        assert!(a.data.entries.is_empty());
        let f = reopen(&a);
        assert!(f.unlock_password("rotated").is_ok());
        assert!(f.unlock_password("hunter2").is_err());
    }

    #[test]
    fn absorb_adopts_a_rotation_made_elsewhere() {
        let c = new_vault();
        let file = reopen(&c.vault);
        let mut a = file.unlock_password("hunter2").unwrap();
        let mut b = file.unlock_password("hunter2").unwrap();
        b.set_password("changed", P, 50, "b").unwrap();
        b.data.add(Entry::new("B", "b", vec![2]), 60, "b").unwrap();
        a.data.add(Entry::new("A", "a", vec![1]), 55, "a").unwrap();
        assert_eq!(a.absorb(&b, 100).unwrap(), KeyringChange::Adopted);
        assert_eq!(a.data.entries.len(), 2);
        let f = reopen(&a);
        assert!(f.unlock_password("changed").is_ok());
        assert!(f.unlock_password("hunter2").is_err());
        assert!(f.unlock_recovery(&c.recovery_code).is_ok());
        // And the other way: b absorbing a's old-key copy keeps b's keyring.
        let mut b2 = reopen(&b).unlock_password("changed").unwrap();
        let a_old = file.unlock_password("hunter2").unwrap();
        assert_eq!(b2.absorb(&a_old, 101).unwrap(), KeyringChange::Kept);
    }

    #[test]
    fn removed_passkeys_stay_removed() {
        let mut c = new_vault();
        let prf = [7u8; 32];
        let id = c
            .vault
            .add_passkey("cred1", "salt1", &prf, "Phone", 3, "a")
            .unwrap();
        let with = reopen(&c.vault);
        assert_eq!(with.passkeys(), vec![("cred1".into(), "salt1".into())]);
        assert!(with.unlock_passkey("cred1", &prf).is_ok());
        assert!(with.unlock_passkey("cred1", &[8u8; 32]).is_err());
        c.vault.remove_slot(&id, 4, "a").unwrap();
        // A remote still holding the old file: merging it back does not restore the passkey.
        let old = with.unlock_passkey("cred1", &prf).unwrap();
        c.vault.absorb(&old, 5).unwrap();
        let f = reopen(&c.vault);
        assert!(f.passkeys().is_empty());
        assert!(f.unlock_passkey("cred1", &prf).is_err());
    }

    #[test]
    fn device_slots_survive_rotation_and_need_the_pin() {
        let mut c = new_vault();
        let touch = c
            .vault
            .add_device("dev1:touchid", "Mac", None, 2, "a")
            .unwrap();
        let pin = c
            .vault
            .add_device("dev1:pin", "Mac PIN", Some("1234"), 3, "a")
            .unwrap();
        c.vault.set_password("next", P, 4, "a").unwrap();
        let f = reopen(&c.vault);
        assert!(f.unlock_device("dev1:touchid", &touch, None).is_ok());
        assert!(f.unlock_device("dev1:pin", &pin, Some("1234")).is_ok());
        assert!(f.unlock_device("dev1:pin", &pin, Some("1235")).is_err());
        assert!(f.unlock_device("dev1:pin", &pin, None).is_err());
        assert!(f.unlock_device("dev1:pin", &touch, Some("1234")).is_err());
        assert!(c.vault.remove_device("dev1:pin", 5, "a").unwrap());
        assert!(
            reopen(&c.vault)
                .unlock_device("dev1:pin", &pin, Some("1234"))
                .is_err()
        );
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
    fn cannot_remove_the_last_password() {
        let mut c = new_vault();
        let pw = c
            .vault
            .keyring
            .slots
            .iter()
            .find(|s| s.kind == SlotKind::Password)
            .unwrap()
            .id
            .clone();
        assert!(c.vault.remove_slot(&pw, 2, "a").is_err());
    }
}
