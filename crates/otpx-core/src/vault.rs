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
use crate::model::{OldKey, Stamp, VaultData, random_id};
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
    /// Creation time (ms), for display.
    #[serde(default)]
    pub created: u64,
    /// When it was made (the newest password, recovery code or device slot wins a merge).
    #[serde(default)]
    pub stamp: Stamp,
}

/// A slot removed on purpose (so a merge does not bring it back).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removed {
    /// Slot id.
    pub id: String,
    /// When.
    pub stamp: Stamp,
}

/// Proof that the holder of a previous key made the current one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endorsement {
    /// The endorsing (previous) key id.
    pub from: String,
    /// HMAC under that key of `(vault id, from, current key id)`.
    pub mac: String,
}

/// The authenticated list of slots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyring {
    /// Revision.
    pub rev: Stamp,
    /// Ways to unlock.
    pub slots: Vec<Slot>,
    /// Key ids this vault rotated away from (never accepted again).
    #[serde(default)]
    pub retired: Vec<String>,
    /// Slots removed on purpose.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<Removed>,
    /// Endorsements of the current key by previous ones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endorsements: Vec<Endorsement>,
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

/// How far another copy of this vault can be trusted, before opening it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Same key: open it with ours.
    Same,
    /// Under a key we rotated away from: stale or replayed; ours replaces it.
    Stale,
    /// Re-keyed by a device holding our current key: open it with the current password.
    Endorsed,
    /// Re-keyed from a key we also rotated away from, while we re-keyed too: open it only if
    /// the user confirms both changes were theirs (an old password could forge this).
    Concurrent,
    /// A new key nothing we hold vouches for: refuse (a remote can seal a key of its own to
    /// the public keys of the slots).
    Untrusted,
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

fn endorsement_mac(old_dek: &[u8], vault_id: &str, from: &str, to: &str) -> String {
    let mk = crypto::hkdf(old_dek, vault_id.as_bytes(), b"otpx rotate v1");
    b64(&crypto::hmac(
        mk.as_ref(),
        format!("otpx-rotate:v1:{vault_id}:{from}:{to}").as_bytes(),
    ))
}

fn endorsed_by(keyring: &Keyring, vault_id: &str, key_id: &str, from: &str, dek: &[u8]) -> bool {
    let want = endorsement_mac(dek, vault_id, from, key_id);
    keyring
        .endorsements
        .iter()
        .any(|e| e.from == from && crypto::ct_eq(e.mac.as_bytes(), want.as_bytes()))
}

/// Slot-by-slot union of two keyrings: deliberate removals stay removed, and for the master
/// password, the recovery code, each passkey and each device, the newest slot wins.
fn merge_slots(a: &Keyring, b: &Keyring) -> (Vec<Slot>, Vec<Removed>) {
    let mut removed: Vec<Removed> = Vec::new();
    for r in a.removed.iter().chain(&b.removed) {
        match removed.iter_mut().find(|x| x.id == r.id) {
            Some(x) if x.stamp >= r.stamp => {}
            Some(x) => x.stamp = r.stamp.clone(),
            None => removed.push(r.clone()),
        }
    }
    removed.sort_by(|x, y| x.id.cmp(&y.id));
    let group = |s: &Slot| match s.kind {
        SlotKind::Password => "password".to_owned(),
        SlotKind::Recovery => "recovery".to_owned(),
        SlotKind::Passkey => format!("passkey:{}", s.credential.as_deref().unwrap_or(&s.id)),
        SlotKind::Device => format!("device:{}", s.device.as_deref().unwrap_or(&s.id)),
    };
    let mut best: std::collections::BTreeMap<String, Slot> = std::collections::BTreeMap::new();
    for s in a.slots.iter().chain(&b.slots) {
        if removed.iter().any(|r| r.id == s.id) {
            continue;
        }
        let g = group(s);
        match best.get(&g) {
            Some(cur) if (&cur.stamp, &cur.id) >= (&s.stamp, &s.id) => {}
            _ => {
                best.insert(g, s.clone());
            }
        }
    }
    let mut slots: Vec<Slot> = best.into_values().collect();
    slots.sort_by(|x, y| (x.kind as u8, &x.stamp, &x.id).cmp(&(y.kind as u8, &y.stamp, &y.id)));
    (slots, removed)
}

fn union(a: &[String], b: &[String]) -> Vec<String> {
    let mut v: Vec<String> = a.to_vec();
    for x in b {
        if !v.contains(x) {
            v.push(x.clone());
        }
    }
    if v.len() > RETIRED_KEEP {
        let extra = v.len() - RETIRED_KEEP;
        v.drain(..extra);
    }
    v
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
                && let Ok(mut v) = self.unlock_dek(&dek)
            {
                v.opened_by = Some(slot.id.clone());
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
                let mut v = self.unlock_dek(&dek)?;
                v.opened_by = Some(slot.id.clone());
                return Ok(v);
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
        let mut v = self.unlock_dek(&dek)?;
        v.opened_by = Some(slot.id.clone());
        Ok(v)
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
            opened_by: None,
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

    /// How far `vault` (the copy this device holds) can trust this file.
    pub fn trust(&self, vault: &Unlocked) -> Trust {
        if self.id != vault.id {
            return Trust::Untrusted;
        }
        if self.key_id == vault.key_id {
            return Trust::Same;
        }
        if vault.keyring.retired.contains(&self.key_id) {
            return Trust::Stale;
        }
        if endorsed_by(
            &self.keyring,
            &self.id,
            &self.key_id,
            &vault.key_id,
            vault.dek.as_ref(),
        ) {
            return Trust::Endorsed;
        }
        // Endorsed by a key we also rotated away from: two devices re-keyed at once.
        for k in &vault.data.keys {
            if let Ok(dek) = unb64(&k.key)
                && endorsed_by(&self.keyring, &self.id, &self.key_id, &k.id, &dek)
            {
                return Trust::Concurrent;
            }
        }
        Trust::Untrusted
    }
}

/// An open vault: the DEK, the keyring and the decrypted content.
pub struct Unlocked {
    /// Vault id.
    pub id: String,
    /// The slot this copy was opened with (None: opened with a cached key).
    pub opened_by: Option<String>,
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
            opened_by: None,
            key_id: key_id_of(&dek, &id),
            id,
            dek,
            keyring: Keyring {
                rev: Stamp::default(),
                slots: Vec::new(),
                retired: Vec::new(),
                removed: Vec::new(),
                endorsements: Vec::new(),
            },
            data: VaultData::default(),
        };
        let pw = v.password_slot(password, params, now_ms, device)?;
        v.keyring.slots.push(pw);
        let (code, slot) = v.recovery_slot(now_ms, device)?;
        v.keyring.slots.push(slot);
        v.bump(now_ms, device);
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

    fn new_slot(
        &mut self,
        kind: SlotKind,
        sk: &StaticSecret,
        now_ms: u64,
        device: &str,
    ) -> Result<Slot> {
        let stamp = self.next_stamp(now_ms, device);
        Ok(Slot {
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
            stamp,
        })
    }

    /// A stamp newer than anything in the content and the keyring.
    fn next_stamp(&self, now_ms: u64, device: &str) -> Stamp {
        let mut last = self.data.max_stamp();
        for s in self
            .keyring
            .slots
            .iter()
            .map(|s| &s.stamp)
            .chain(self.keyring.removed.iter().map(|r| &r.stamp))
            .chain(std::iter::once(&self.keyring.rev))
        {
            if *s > last {
                last = s.clone();
            }
        }
        Stamp::next(&last, now_ms, device)
    }

    fn password_slot(
        &mut self,
        password: &str,
        params: Argon2Params,
        now_ms: u64,
        device: &str,
    ) -> Result<Slot> {
        if password.is_empty() {
            return Err(Error::Entry("empty password".into()));
        }
        let salt = crypto::random_bytes(16)?;
        let k = crypto::argon2id(password.as_bytes(), &salt, params)?;
        let mut slot = self.new_slot(
            SlotKind::Password,
            &slot_secret(k.as_ref(), SlotKind::Password),
            now_ms,
            device,
        )?;
        slot.argon2 = Some(params);
        slot.salt = Some(b64(&salt));
        seal_slot(&self.id, &mut slot, &self.dek)?;
        Ok(slot)
    }

    fn recovery_slot(&mut self, now_ms: u64, device: &str) -> Result<(String, Slot)> {
        let (code, raw) = new_recovery_code()?;
        let mut slot = self.new_slot(
            SlotKind::Recovery,
            &slot_secret(&raw, SlotKind::Recovery),
            now_ms,
            device,
        )?;
        seal_slot(&self.id, &mut slot, &self.dek)?;
        Ok((code, slot))
    }

    fn reseal_all(&mut self) -> Result<()> {
        for slot in &mut self.keyring.slots {
            seal_slot(&self.id, slot, &self.dek)?;
        }
        Ok(())
    }

    /// A new DEK sealed to every remaining slot; the old key is retired and keeps, inside the
    /// content, the ability to vouch for the new one.
    fn rotate(&mut self, now_ms: u64, device: &str) -> Result<()> {
        let old_id = self.key_id.clone();
        if !self.data.keys.iter().any(|k| k.id == old_id) {
            self.data.keys.push(OldKey {
                id: old_id.clone(),
                key: b64(self.dek.as_ref()),
            });
        }
        if self.data.keys.len() > RETIRED_KEEP {
            let extra = self.data.keys.len() - RETIRED_KEEP;
            self.data.keys.drain(..extra);
        }
        let dek = crypto::random_key()?;
        self.key_id = key_id_of(&dek, &self.id);
        self.dek = dek;
        self.reseal_all()?;
        self.keyring.retired = union(&self.keyring.retired, std::slice::from_ref(&old_id));
        let mut endorsements = Vec::new();
        for k in &self.data.keys {
            if let Ok(old) = unb64(&k.key) {
                endorsements.push(Endorsement {
                    from: k.id.clone(),
                    mac: endorsement_mac(&old, &self.id, &k.id, &self.key_id),
                });
            }
        }
        self.keyring.endorsements = endorsements;
        self.bump(now_ms, device);
        Ok(())
    }

    fn bump(&mut self, now_ms: u64, device: &str) {
        self.keyring.rev = self.next_stamp(now_ms, device);
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
        let slot = self.password_slot(password, params, now_ms, device)?;
        self.keyring.slots.retain(|s| s.kind != SlotKind::Password);
        self.keyring.slots.insert(0, slot);
        self.rotate(now_ms, device)
    }

    /// Replaces the recovery code (and rotates the key); returns the new code.
    pub fn reset_recovery(&mut self, now_ms: u64, device: &str) -> Result<String> {
        let (code, slot) = self.recovery_slot(now_ms, device)?;
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
            device,
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
            device,
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

    fn drop_slots(&mut self, ids: &[String], now_ms: u64, device: &str) -> Result<()> {
        let stamp = self.next_stamp(now_ms, device);
        self.keyring.slots.retain(|s| !ids.contains(&s.id));
        for id in ids {
            self.keyring.removed.push(Removed {
                id: id.clone(),
                stamp: stamp.clone(),
            });
        }
        if self.keyring.removed.len() > 256 {
            let extra = self.keyring.removed.len() - 256;
            self.keyring.removed.drain(..extra);
        }
        self.rotate(now_ms, device)
    }

    /// Removes a slot and rotates the key (a removed passkey or device cannot read what follows);
    /// the last password slot stays.
    pub fn remove_slot(&mut self, slot_id: &str, now_ms: u64, device: &str) -> Result<()> {
        let Some(slot) = self.keyring.slots.iter().find(|s| s.id == slot_id) else {
            return Err(Error::Entry(format!("no slot {slot_id}")));
        };
        if slot.kind == SlotKind::Password
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
        self.drop_slots(&[slot_id.to_owned()], now_ms, device)
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
        self.drop_slots(&ids, now_ms, device)?;
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

    /// Merges another copy under the **same key** (another device's save): entries merge one by
    /// one, slots merge one by one (removals stick, the newest password, recovery code, passkey
    /// and device slot win).
    pub fn absorb(&mut self, other: &Unlocked, now_ms: u64) -> Result<KeyringChange> {
        if other.id != self.id {
            return Err(Error::Entry("these are two different vaults".into()));
        }
        if other.key_id != self.key_id {
            return Err(Error::Entry(
                "this copy is under another key: check its trust first".into(),
            ));
        }
        self.data = crate::merge::merge(&self.data, &other.data, now_ms);
        let before = self.keyring.clone();
        let (slots, removed) = merge_slots(&self.keyring, &other.keyring);
        self.keyring.slots = slots;
        self.keyring.removed = removed;
        self.keyring.retired = union(&self.keyring.retired, &other.keyring.retired);
        if other.keyring.rev > self.keyring.rev {
            self.keyring.rev = other.keyring.rev.clone();
        }
        if other.keyring.endorsements.len() > self.keyring.endorsements.len() {
            self.keyring.endorsements = other.keyring.endorsements.clone();
        }
        Ok(
            if self.keyring.slots != before.slots || self.keyring.removed != before.removed {
                KeyringChange::Adopted
            } else {
                KeyringChange::Kept
            },
        )
    }

    /// What taking `other`'s keyring would add or replace here, beyond the slot it was opened
    /// with: each line names a way to unlock ("recovery code", "device MacBook (touchid)",
    /// "passkey Phone"). Show it to the user before [`Unlocked::absorb_rotated`]: someone who
    /// knew an old password could slip a slot of their own into a re-keyed copy.
    pub fn keyring_changes(&self, other: &Unlocked) -> Vec<String> {
        let (merged, _) = merge_slots(&self.keyring, &other.keyring);
        merged
            .iter()
            .filter(|s| !self.keyring.slots.iter().any(|x| x.id == s.id))
            .filter(|s| other.opened_by.as_deref() != Some(s.id.as_str()))
            .map(|s| match s.kind {
                SlotKind::Password => "master password".to_owned(),
                SlotKind::Recovery => "recovery code".to_owned(),
                SlotKind::Passkey => format!(
                    "passkey {}",
                    if s.label.is_empty() {
                        "(unnamed)"
                    } else {
                        &s.label
                    }
                ),
                SlotKind::Device => format!(
                    "quick unlock {}",
                    if s.label.is_empty() {
                        s.device.as_deref().unwrap_or("?")
                    } else {
                        &s.label
                    }
                ),
            })
            .collect()
    }

    /// Takes a copy re-keyed elsewhere ([`Trust::Endorsed`] or, once the user confirmed,
    /// [`Trust::Concurrent`]), opened with the current password. This copy's entries and slots
    /// are kept. When this copy had re-keyed too, the key rotates once more, so neither
    /// device's retired secrets open what follows.
    pub fn absorb_rotated(
        &mut self,
        other: &Unlocked,
        now_ms: u64,
        device: &str,
    ) -> Result<KeyringChange> {
        if other.id != self.id {
            return Err(Error::Entry("these are two different vaults".into()));
        }
        let linear = other.keyring.retired.contains(&self.key_id);
        // The slot the user just opened must survive the merge: otherwise the copy carries a
        // newer password (or code) than the one typed, which is what a forgery made with an
        // old password looks like.
        let (merged, _) = merge_slots(&self.keyring, &other.keyring);
        let Some(opened) = other.opened_by.as_deref() else {
            return Err(Error::Entry(
                "open the re-keyed copy with the master password first".into(),
            ));
        };
        if !merged.iter().any(|s| s.id == opened) {
            return Err(Error::Entry(
                "the password typed is not the current one of that copy (an older or forged copy?): nothing was merged".into(),
            ));
        }
        self.data = crate::merge::merge(&self.data, &other.data, now_ms);
        if !self.data.keys.iter().any(|k| k.id == self.key_id) {
            self.data.keys.push(OldKey {
                id: self.key_id.clone(),
                key: b64(self.dek.as_ref()),
            });
        }
        let (slots, removed) = merge_slots(&self.keyring, &other.keyring);
        let mut retired = union(&self.keyring.retired, &other.keyring.retired);
        retired = union(&retired, std::slice::from_ref(&self.key_id));
        self.keyring = Keyring {
            rev: other.keyring.rev.clone().max(self.keyring.rev.clone()),
            slots,
            retired,
            removed,
            endorsements: other.keyring.endorsements.clone(),
        };
        self.dek = Zeroizing::new(*other.dek);
        self.key_id = other.key_id.clone();
        self.opened_by = other.opened_by.clone();
        self.reseal_all()?;
        if !linear {
            self.rotate(now_ms, device)?;
        }
        Ok(KeyringChange::Adopted)
    }

    /// Folds in this device's own older copy saved under a key it rotated away from (its
    /// entries only; the keyring stays).
    pub fn absorb_own(&mut self, older: &Unlocked, now_ms: u64) {
        self.data = crate::merge::merge(&self.data, &older.data, now_ms);
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
        assert!(f.unlock_recovery(&c.recovery_code).is_ok());
        assert!(f.unlock_dek(&old_dek).is_err());
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
        let mut cheap = good;
        cheap.keyring.slots[0].argon2 = Some(Argon2Params { m: 32, t: 1, p: 1 });
        assert!(cheap.unlock_password("hunter2").is_err());
    }

    /// A remote that knows no secret seals a key of its own to the victim's public slots: the
    /// victim's password opens it, but nothing the victim holds endorses it.
    #[test]
    fn a_forged_rekey_is_untrusted() {
        let c = new_vault();
        let published = reopen(&c.vault);
        let mut forged = published.unlock_password("hunter2").unwrap();
        // The attacker cannot open it; simulate what it can build: fresh key, same public slots.
        let dek = crypto::random_key().unwrap();
        forged.key_id = key_id_of(&dek, &forged.id);
        forged.dek = dek;
        forged.reseal_all().unwrap();
        forged.keyring.retired.push(published.key_id.clone());
        forged.keyring.endorsements = vec![Endorsement {
            from: published.key_id.clone(),
            mac: b64(&[0u8; 32]),
        }];
        forged.data = VaultData::default();
        let file = reopen(&forged);
        assert!(
            file.unlock_password("hunter2").is_ok(),
            "the victim's password opens the forgery"
        );
        let victim = published.unlock_password("hunter2").unwrap();
        assert_eq!(file.trust(&victim), Trust::Untrusted);
        let mut v2 = published.unlock_password("hunter2").unwrap();
        assert!(
            v2.absorb(&file.unlock_password("hunter2").unwrap(), 9)
                .is_err()
        );
    }

    #[test]
    fn a_real_rotation_is_endorsed_and_followed() {
        let c = new_vault();
        let file = reopen(&c.vault);
        let mut a = file.unlock_password("hunter2").unwrap();
        let mut b = file.unlock_password("hunter2").unwrap();
        a.set_password("changed", P, 50, "a").unwrap();
        a.data.add(Entry::new("A", "a", vec![1]), 51, "a").unwrap();
        b.data.add(Entry::new("B", "b", vec![2]), 52, "b").unwrap();
        b.add_device("b:pin", "B", Some("1234"), 53, "b").unwrap();
        let af = reopen(&a);
        assert_eq!(af.trust(&b), Trust::Endorsed);
        let opened = af.unlock_password("changed").unwrap();
        assert_eq!(
            b.absorb_rotated(&opened, 60, "b").unwrap(),
            KeyringChange::Adopted
        );
        let merged = reopen(&b);
        assert!(merged.unlock_password("changed").is_ok());
        assert!(merged.unlock_password("hunter2").is_err());
        assert!(merged.unlock_recovery(&c.recovery_code).is_ok());
        assert!(merged.device_slot("b:pin").is_some());
        assert_eq!(
            merged
                .unlock_password("changed")
                .unwrap()
                .data
                .entries
                .len(),
            2
        );
        // Several rotations later, a device still on the first key follows them too.
        let mut a2 = merged.unlock_password("changed").unwrap();
        a2.reset_recovery(70, "a").unwrap();
        a2.set_password("third", P, 71, "a").unwrap();
        let far = reopen(&a2);
        let laggard = file.unlock_password("hunter2").unwrap();
        assert_eq!(far.trust(&laggard), Trust::Endorsed);
    }

    #[test]
    fn concurrent_rotations_need_confirmation_and_keep_the_newest_password() {
        let c = new_vault();
        let file = reopen(&c.vault);
        let mut a = file.unlock_password("hunter2").unwrap();
        let mut b = file.unlock_password("hunter2").unwrap();
        a.set_password("new-pw", P, 50, "a").unwrap();
        let code_b = b.reset_recovery(60, "b").unwrap();
        let af = reopen(&a);
        assert_eq!(af.trust(&b), Trust::Concurrent);
        let opened = af.unlock_password("new-pw").unwrap();
        assert_eq!(b.keyring_changes(&opened), Vec::<String>::new());
        b.absorb_rotated(&opened, 70, "b").unwrap();
        let merged = reopen(&b);
        assert!(merged.unlock_password("new-pw").is_ok());
        assert!(
            merged.unlock_password("hunter2").is_err(),
            "the old password must not come back"
        );
        assert!(merged.unlock_recovery(&code_b).is_ok());
        assert!(merged.unlock_recovery(&c.recovery_code).is_err());
        // A rotated once more: neither A's nor B's key reads what follows.
        assert_ne!(merged.key_id, af.key_id);
        assert_eq!(merged.trust(&a), Trust::Endorsed);
    }

    /// Someone with an old password and an old copy forges a re-key whose newest password is
    /// theirs, keeping the owner's current password slot so it still opens.
    #[test]
    fn an_old_key_forgery_is_refused() {
        let c = new_vault();
        let old = reopen(&c.vault);
        let mut owner = old.unlock_password("hunter2").unwrap();
        owner.set_password("new-pw", P, 50, "owner").unwrap();
        let published = reopen(&owner);
        let mut forged = old.unlock_password("hunter2").unwrap();
        forged
            .set_password("attacker-pw", P, 9_000_000_000_000, "x")
            .unwrap();
        let owner_slot = published
            .keyring
            .slots
            .iter()
            .find(|s| s.kind == SlotKind::Password)
            .unwrap()
            .clone();
        forged.keyring.slots.push(owner_slot);
        forged.reseal_all().unwrap();
        let file = reopen(&forged);
        let opened = file.unlock_password("new-pw").unwrap();
        // A device still on the old key sees an endorsed re-key...
        let mut stale = old.unlock_password("hunter2").unwrap();
        assert_eq!(file.trust(&stale), Trust::Endorsed);
        // ...but the password typed did not win the merge: refused.
        assert!(stale.absorb_rotated(&opened, 60, "s").is_err());
        // A forgery that keeps the owner's password but adds its own device slot is shown.
        let mut sneaky = old.unlock_password("hunter2").unwrap();
        sneaky
            .add_device("evil:touchid", "MacBook (touchid)", None, 70, "x")
            .unwrap();
        sneaky
            .keyring
            .slots
            .retain(|s| s.kind != SlotKind::Password);
        let mut owner_slot = published
            .keyring
            .slots
            .iter()
            .find(|s| s.kind == SlotKind::Password)
            .unwrap()
            .clone();
        owner_slot.stamp.t = 9_000_000_000_000;
        sneaky.keyring.slots.push(owner_slot);
        sneaky.rotate(71, "x").unwrap();
        let f2 = reopen(&sneaky);
        let o2 = f2.unlock_password("new-pw").unwrap();
        let laggard = old.unlock_password("hunter2").unwrap();
        assert_eq!(
            laggard.keyring_changes(&o2),
            vec!["quick unlock MacBook (touchid)".to_owned()]
        );
    }

    #[test]
    fn a_retired_copy_is_stale() {
        let c = new_vault();
        let before = reopen(&c.vault);
        let mut a = before.unlock_password("hunter2").unwrap();
        a.set_password("rotated", P, 10, "a").unwrap();
        assert_eq!(before.trust(&a), Trust::Stale);
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
        assert_eq!(with.trust(&c.vault), Trust::Stale);
        let f = reopen(&c.vault);
        assert!(f.passkeys().is_empty());
        assert!(f.unlock_passkey("cred1", &prf).is_err());
    }

    #[test]
    fn same_key_merges_slots_one_by_one() {
        let c = new_vault();
        let file = reopen(&c.vault);
        let mut a = file.unlock_password("hunter2").unwrap();
        let mut b = file.unlock_password("hunter2").unwrap();
        a.add_passkey("ca", "sa", &[1u8; 32], "A", 5, "a").unwrap();
        b.add_passkey("cb", "sb", &[2u8; 32], "B", 6, "b").unwrap();
        a.absorb(&b, 7).unwrap();
        assert_eq!(reopen(&a).passkeys().len(), 2);
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
