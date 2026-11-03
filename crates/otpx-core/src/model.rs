//! Accounts and the decrypted vault content.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::otp::{self, Algorithm};
use crate::{Error, Result, b32};

/// A hybrid logical timestamp: milliseconds, a counter for equal milliseconds and the device
/// that wrote it. Ordered by `(t, c, d)`, so every device picks the same winner.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct Stamp {
    /// Unix time in milliseconds.
    pub t: u64,
    /// Tie-break counter within the same millisecond.
    #[serde(default)]
    pub c: u32,
    /// Device id.
    #[serde(default)]
    pub d: String,
}

impl Stamp {
    /// The next stamp after `last` at wall time `now_ms`, written by `device`.
    pub fn next(last: &Stamp, now_ms: u64, device: &str) -> Stamp {
        if now_ms > last.t {
            Stamp {
                t: now_ms,
                c: 0,
                d: device.to_owned(),
            }
        } else {
            Stamp {
                t: last.t,
                c: last.c.saturating_add(1),
                d: device.to_owned(),
            }
        }
    }
}

/// OTP type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Time-based (RFC 6238).
    #[default]
    Totp,
    /// Counter-based (RFC 4226).
    Hotp,
    /// Steam Guard (time-based, 5 characters).
    Steam,
}

impl Kind {
    /// Lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Totp => "totp",
            Kind::Hotp => "hotp",
            Kind::Steam => "steam",
        }
    }
}

/// Serializes the secret as canonical base32.
mod secret_b32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::b32::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        crate::b32::decode(&text).map_err(serde::de::Error::custom)
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One OTP account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    /// Stable id (random, 128 bits, hex).
    #[zeroize(skip)]
    pub id: String,
    /// OTP type.
    #[zeroize(skip)]
    #[serde(rename = "type")]
    pub kind: Kind,
    /// Service name ("GitHub").
    #[serde(default)]
    pub issuer: String,
    /// Account name ("me@example.com").
    #[serde(default)]
    pub account: String,
    /// Raw shared secret.
    #[serde(with = "secret_b32")]
    pub secret: Vec<u8>,
    /// HMAC algorithm.
    #[zeroize(skip)]
    #[serde(default)]
    pub algorithm: Algorithm,
    /// Code length (5 for Steam).
    pub digits: u8,
    /// TOTP period in seconds.
    #[serde(default = "default_period")]
    pub period: u32,
    /// HOTP counter: the next code to show.
    #[serde(default)]
    pub counter: u64,
    /// Free tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Free note.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// Shown first.
    #[serde(default, skip_serializing_if = "is_false")]
    pub favorite: bool,
    /// Creation time (ms).
    #[serde(default)]
    pub created: u64,
    /// Last change.
    #[zeroize(skip)]
    #[serde(default)]
    pub updated: Stamp,
}

fn default_period() -> u32 {
    30
}

/// A code ready to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Code {
    /// The code.
    pub code: String,
    /// Seconds before it changes (0 for HOTP).
    pub remaining: u32,
    /// Period in seconds (0 for HOTP).
    pub period: u32,
}

impl Entry {
    /// A new TOTP entry with the defaults most services use (SHA-1, 6 digits, 30 s).
    pub fn new(issuer: &str, account: &str, secret: Vec<u8>) -> Entry {
        Entry {
            id: String::new(),
            kind: Kind::Totp,
            issuer: issuer.trim().to_owned(),
            account: account.trim().to_owned(),
            secret,
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            counter: 0,
            tags: Vec::new(),
            note: String::new(),
            favorite: false,
            created: 0,
            updated: Stamp::default(),
        }
    }

    /// Checks the fields; Steam entries are normalized to 5 characters, SHA-1, 30 s.
    pub fn validate(&mut self) -> Result<()> {
        if self.secret.is_empty() {
            return Err(Error::Entry("empty secret".into()));
        }
        if self.issuer.is_empty() && self.account.is_empty() {
            return Err(Error::Entry(
                "an issuer or an account name is needed".into(),
            ));
        }
        match self.kind {
            Kind::Steam => {
                self.digits = 5;
                self.algorithm = Algorithm::Sha1;
                self.period = 30;
            }
            Kind::Totp | Kind::Hotp => {
                if !(4..=10).contains(&self.digits) {
                    return Err(Error::Entry(format!(
                        "{} digits (expected 4 to 10)",
                        self.digits
                    )));
                }
                if self.kind == Kind::Totp && !(1..=86_400).contains(&self.period) {
                    return Err(Error::Entry(format!(
                        "period of {} s (expected 1 to 86400)",
                        self.period
                    )));
                }
            }
        }
        Ok(())
    }

    /// `Issuer (account)`, `Issuer` or `account`.
    pub fn label(&self) -> String {
        match (self.issuer.is_empty(), self.account.is_empty()) {
            (false, false) => format!("{} ({})", self.issuer, self.account),
            (false, true) => self.issuer.clone(),
            _ => self.account.clone(),
        }
    }

    /// The secret in base32.
    pub fn secret_b32(&self) -> String {
        b32::encode(&self.secret)
    }

    /// The code at `unix` seconds (HOTP: the code of the current counter).
    pub fn code_at(&self, unix: u64) -> Code {
        match self.kind {
            Kind::Totp => Code {
                code: otp::totp(&self.secret, unix, self.period, self.digits, self.algorithm),
                remaining: otp::remaining(unix, self.period),
                period: self.period,
            },
            Kind::Steam => Code {
                code: otp::steam(&self.secret, unix),
                remaining: otp::remaining(unix, 30),
                period: 30,
            },
            Kind::Hotp => Code {
                code: otp::hotp(&self.secret, self.counter, self.digits, self.algorithm),
                remaining: 0,
                period: 0,
            },
        }
    }

    /// The code of the next period (TOTP/Steam) or of the next counter (HOTP).
    pub fn next_code_at(&self, unix: u64) -> Code {
        match self.kind {
            Kind::Hotp => Code {
                code: otp::hotp(
                    &self.secret,
                    self.counter.saturating_add(1),
                    self.digits,
                    self.algorithm,
                ),
                remaining: 0,
                period: 0,
            },
            _ => {
                let p = if self.kind == Kind::Steam {
                    30
                } else {
                    self.period
                };
                let next = unix + u64::from(otp::remaining(unix, p));
                self.code_at(next)
            }
        }
    }

    /// True when `query` (case-insensitive) occurs in the issuer, account, tags or note,
    /// or is a prefix of the id.
    pub fn matches(&self, query: &str) -> bool {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        self.id.starts_with(&q)
            || self.issuer.to_lowercase().contains(&q)
            || self.account.to_lowercase().contains(&q)
            || self.label().to_lowercase().contains(&q)
            || self.tags.iter().any(|t| t.to_lowercase().contains(&q))
            || self.note.to_lowercase().contains(&q)
    }

    /// Same account in another app's export: same secret, kind and parameters.
    pub fn same_account(&self, other: &Entry) -> bool {
        self.secret == other.secret
            && self.kind == other.kind
            && self.algorithm == other.algorithm
            && self.digits == other.digits
            && (self.kind == Kind::Hotp || self.period == other.period)
    }

    /// A copy without bookkeeping (id, stamps), as it travels in shares and exports.
    pub fn portable(&self) -> Entry {
        let mut e = self.clone();
        e.id = String::new();
        e.created = 0;
        e.updated = Stamp::default();
        e.favorite = false;
        e
    }
}

/// A deleted entry, kept so other devices delete it too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    /// Id of the deleted entry.
    pub id: String,
    /// When it was deleted.
    pub deleted: Stamp,
    /// HOTP counter of the deleted entry, so a later edit that brings it back elsewhere
    /// cannot move the counter back.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub counter: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// An age X25519 identity, shared by every device of the vault so shares sent to it open
/// anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    /// `AGE-SECRET-KEY-1…`.
    pub secret: String,
    /// `age1…`.
    #[zeroize(skip)]
    pub public: String,
    /// Creation time (ms); the oldest identity is the one others encrypt to.
    #[zeroize(skip)]
    pub created: u64,
}

/// Synced preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// Lock the web app after this many seconds without activity.
    #[serde(default = "default_auto_lock")]
    pub auto_lock_secs: u32,
    /// Clear the clipboard this many seconds after a copy.
    #[serde(default = "default_clipboard")]
    pub clipboard_clear_secs: u32,
    /// Last change.
    #[serde(default)]
    pub updated: Stamp,
}

fn default_auto_lock() -> u32 {
    300
}

fn default_clipboard() -> u32 {
    20
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            auto_lock_secs: default_auto_lock(),
            clipboard_clear_secs: default_clipboard(),
            updated: Stamp::default(),
        }
    }
}

/// The decrypted vault content.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VaultData {
    /// Accounts.
    #[serde(default)]
    pub entries: Vec<Entry>,
    /// Deletions still propagating.
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    /// Sharing identities.
    #[serde(default)]
    pub identities: Vec<Identity>,
    /// Preferences.
    #[serde(default)]
    pub settings: Settings,
}

/// Random lowercase hex id of `bytes` bytes.
pub fn random_id(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    crate::crypto::fill_random(&mut buf)?;
    Ok(data_encoding::HEXLOWER.encode(&buf))
}

impl VaultData {
    /// The newest stamp in the data.
    pub fn max_stamp(&self) -> Stamp {
        let mut m = self.settings.updated.clone();
        for e in &self.entries {
            if e.updated > m {
                m = e.updated.clone();
            }
        }
        for t in &self.tombstones {
            if t.deleted > m {
                m = t.deleted.clone();
            }
        }
        m
    }

    /// A fresh stamp for a change made now by `device`.
    pub fn stamp(&self, now_ms: u64, device: &str) -> Stamp {
        Stamp::next(&self.max_stamp(), now_ms, device)
    }

    /// Adds an entry (validated, with a new id and stamps). Returns its id.
    pub fn add(&mut self, mut entry: Entry, now_ms: u64, device: &str) -> Result<String> {
        entry.validate()?;
        entry.id = random_id(16)?;
        entry.created = now_ms;
        entry.updated = self.stamp(now_ms, device);
        let id = entry.id.clone();
        self.entries.push(entry);
        Ok(id)
    }

    /// Adds `entry` unless an entry for the same account exists. Returns whether it was added.
    pub fn add_unique(&mut self, entry: Entry, now_ms: u64, device: &str) -> Result<bool> {
        if self.entries.iter().any(|e| e.same_account(&entry)) {
            return Ok(false);
        }
        self.add(entry, now_ms, device)?;
        Ok(true)
    }

    /// Replaces the entry with the same id (validated, new stamp).
    pub fn update(&mut self, mut entry: Entry, now_ms: u64, device: &str) -> Result<()> {
        entry.validate()?;
        let stamp = self.stamp(now_ms, device);
        let slot = self
            .entries
            .iter_mut()
            .find(|e| e.id == entry.id)
            .ok_or_else(|| Error::Entry(format!("no entry with id {}", entry.id)))?;
        entry.created = slot.created;
        entry.updated = stamp;
        *slot = entry;
        Ok(())
    }

    /// Deletes an entry, leaving a tombstone. Returns the removed entry.
    pub fn remove(&mut self, id: &str, now_ms: u64, device: &str) -> Result<Entry> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| Error::Entry(format!("no entry with id {id}")))?;
        let deleted = self.stamp(now_ms, device);
        let entry = self.entries.remove(pos);
        self.tombstones.retain(|t| t.id != id);
        self.tombstones.push(Tombstone {
            id: id.to_owned(),
            deleted,
            counter: entry.counter,
        });
        Ok(entry)
    }

    /// HOTP: moves to the next counter and returns the new current code.
    pub fn advance_counter(&mut self, id: &str, now_ms: u64, device: &str) -> Result<Code> {
        let stamp = self.stamp(now_ms, device);
        let e = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| Error::Entry(format!("no entry with id {id}")))?;
        if e.kind != Kind::Hotp {
            return Err(Error::Entry("only HOTP entries have a counter".into()));
        }
        e.counter = e.counter.saturating_add(1);
        e.updated = stamp;
        Ok(e.code_at(0))
    }

    /// Entries matching `query`, favorites first, then by label.
    pub fn find(&self, query: &str) -> Vec<&Entry> {
        let mut v: Vec<&Entry> = self.entries.iter().filter(|e| e.matches(query)).collect();
        sort_entries(&mut v);
        v
    }

    /// The single entry `query` designates: an exact id or label wins over partial matches.
    pub fn resolve(&self, query: &str) -> std::result::Result<&Entry, Vec<&Entry>> {
        let q = query.trim().to_lowercase();
        let exact: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| {
                e.id == q
                    || e.label().to_lowercase() == q
                    || e.issuer.to_lowercase() == q
                    || e.account.to_lowercase() == q
            })
            .collect();
        if exact.len() == 1 {
            return Ok(exact[0]);
        }
        let found = if exact.is_empty() {
            self.find(query)
        } else {
            exact
        };
        if found.len() == 1 {
            Ok(found[0])
        } else {
            Err(found)
        }
    }

    /// The identity others encrypt to (the oldest one).
    pub fn primary_identity(&self) -> Option<&Identity> {
        self.identities
            .iter()
            .min_by_key(|i| (i.created, &i.public))
    }
}

/// Favorites first, then issuer, account and id (case-insensitive).
pub fn sort_entries(v: &mut [&Entry]) {
    v.sort_by(|a, b| {
        b.favorite
            .cmp(&a.favorite)
            .then_with(|| a.issuer.to_lowercase().cmp(&b.issuer.to_lowercase()))
            .then_with(|| a.account.to_lowercase().cmp(&b.account.to_lowercase()))
            .then_with(|| a.id.cmp(&b.id))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(issuer: &str, account: &str) -> Entry {
        Entry::new(issuer, account, b"12345678901234567890".to_vec())
    }

    #[test]
    fn add_update_remove() {
        let mut v = VaultData::default();
        let id = v.add(entry("GitHub", "me"), 1000, "a").unwrap();
        assert_eq!(v.entries[0].updated.t, 1000);
        let mut e = v.entries[0].clone();
        e.note = "work".into();
        // A clock that went backwards still yields a newer stamp.
        v.update(e, 500, "a").unwrap();
        assert!(
            v.entries[0].updated
                > Stamp {
                    t: 1000,
                    c: 0,
                    d: "a".into()
                }
        );
        assert_eq!(v.entries[0].created, 1000);
        v.remove(&id, 2000, "a").unwrap();
        assert!(v.entries.is_empty());
        assert_eq!(v.tombstones.len(), 1);
    }

    #[test]
    fn resolve_prefers_exact() {
        let mut v = VaultData::default();
        v.add(entry("Git", "me"), 1, "a").unwrap();
        v.add(entry("GitHub", "me"), 2, "a").unwrap();
        assert_eq!(v.resolve("git").unwrap().issuer, "Git");
        assert!(v.resolve("me").is_err());
        assert!(v.resolve("nothing").unwrap_err().is_empty());
    }

    #[test]
    fn duplicates_are_skipped() {
        let mut v = VaultData::default();
        assert!(v.add_unique(entry("A", "x"), 1, "a").unwrap());
        assert!(!v.add_unique(entry("B", "y"), 2, "a").unwrap());
    }

    #[test]
    fn hotp_counter() {
        let mut v = VaultData::default();
        let mut e = entry("Bank", "me");
        e.kind = Kind::Hotp;
        let id = v.add(e, 1, "a").unwrap();
        assert_eq!(v.entries[0].code_at(0).code, "755224");
        assert_eq!(v.advance_counter(&id, 2, "a").unwrap().code, "287082");
    }

    #[test]
    fn validation() {
        let mut e = entry("A", "");
        e.digits = 12;
        assert!(e.validate().is_err());
        let mut s = entry("Steam", "me");
        s.kind = Kind::Steam;
        s.digits = 6;
        s.validate().unwrap();
        assert_eq!(s.digits, 5);
        assert!(Entry::new("", "", vec![1]).validate().is_err());
    }
}
