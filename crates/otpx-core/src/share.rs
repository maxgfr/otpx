//! Sharing accounts (or a device setup) outside the vault.
//!
//! * **Links**: `https://…/otpx/#s=1.<ciphertext>.<key>`. Everything is in the URL
//!   fragment, which browsers never send to the server; the key is random per link. An
//!   optional passphrase (sent another way) is mixed into the key with Argon2id. Without
//!   a server, a link cannot be destroyed after use: the expiry is checked when it opens.
//! * **age**: encrypted to an `age1…` public key, readable by `otpx receive` or the `age`
//!   tool, for when the recipient has an identity.
//! * QR codes of single accounts live in [`crate::qr`] and [`crate::uri`].

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, Argon2Params, b64url, unb64};
use crate::model::{Entry, Identity};
use crate::{Error, Result};

/// Where links point by default.
pub const DEFAULT_BASE: &str = "https://maxgfr.github.io/otpx/";

/// What a share carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    /// Payload version (1).
    pub v: u32,
    /// Accounts (without vault bookkeeping).
    #[serde(default)]
    pub entries: Vec<Entry>,
    /// A device setup (sync remotes, tokens) for `otpx link`, opaque to the core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<serde_json::Value>,
    /// Expiry (ms since the epoch), 0 for none.
    #[serde(default)]
    pub expires: u64,
    /// A note from the sender.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

impl Share {
    /// A share of `entries` expiring at `expires` (0: never).
    pub fn accounts(entries: &[Entry], expires: u64) -> Share {
        Share {
            v: 1,
            entries: entries.iter().map(Entry::portable).collect(),
            device: None,
            expires,
            note: String::new(),
        }
    }

    fn check(self, now_ms: u64) -> Result<Share> {
        if self.v != 1 {
            return Err(Error::format(
                "share",
                format!("version {} (update otpx)", self.v),
            ));
        }
        if self.expires != 0 && now_ms > self.expires {
            return Err(Error::Expired);
        }
        Ok(self)
    }
}

const AAD: &[u8] = b"otpx-share:v1";

fn link_key(raw: &[u8], passphrase: Option<(&str, &[u8])>) -> Result<crypto::Key> {
    match passphrase {
        None => Ok(crypto::hkdf(raw, b"", b"otpx share link v1")),
        Some((pass, salt)) => {
            let stretched = crypto::argon2id(pass.as_bytes(), salt, Argon2Params::KEY)?;
            let ikm = Zeroizing::new([raw, stretched.as_ref()].concat());
            Ok(crypto::hkdf(&ikm, salt, b"otpx share link v1 passphrase"))
        }
    }
}

/// A share link under `base` (e.g. [`DEFAULT_BASE`]).
pub fn create_link(base: &str, share: &Share, passphrase: Option<&str>) -> Result<String> {
    let raw = Zeroizing::new(crypto::random_bytes(32)?);
    let salt = crypto::random_bytes(16)?;
    let pass = passphrase.filter(|p| !p.is_empty());
    let key = link_key(&raw, pass.map(|p| (p, salt.as_slice())))?;
    let plain = Zeroizing::new(serde_json::to_vec(share).expect("share serializes"));
    let (nonce, ct) = crypto::seal(&key, AAD, &plain)?;
    let blob = b64url(&[nonce, ct].concat());
    let base = base.split('#').next().unwrap_or(base);
    Ok(match pass {
        None => format!("{base}#s=1.{blob}.{}", b64url(&raw)),
        Some(_) => format!("{base}#s=1p.{}.{blob}.{}", b64url(&salt), b64url(&raw)),
    })
}

/// True when the link needs a passphrase.
pub fn link_needs_passphrase(link: &str) -> bool {
    fragment(link).is_some_and(|f| f.starts_with("1p."))
}

fn fragment(link: &str) -> Option<&str> {
    let frag = link.split_once('#').map_or(link, |(_, f)| f);
    frag.split('&').find_map(|p| p.strip_prefix("s="))
}

/// Opens a share link (or just its fragment).
pub fn open_link(link: &str, passphrase: Option<&str>, now_ms: u64) -> Result<Share> {
    let f = fragment(link.trim()).ok_or_else(|| Error::format("share link", "no #s= part"))?;
    let parts: Vec<&str> = f.split('.').collect();
    let (salt, blob, raw) = match parts.as_slice() {
        ["1", blob, raw] => (None, *blob, *raw),
        ["1p", salt, blob, raw] => (Some(unb64(salt)?), *blob, *raw),
        _ => return Err(Error::format("share link", "truncated or unknown version")),
    };
    let raw = Zeroizing::new(unb64(raw)?);
    let key = match &salt {
        None => link_key(&raw, None)?,
        Some(s) => {
            let p = passphrase
                .filter(|p| !p.is_empty())
                .ok_or(Error::NeedsPassword("share link"))?;
            link_key(&raw, Some((p, s)))?
        }
    };
    let blob = unb64(blob)?;
    if blob.len() < crypto::NONCE_LEN + 16 {
        return Err(Error::format("share link", "truncated"));
    }
    let (nonce, ct) = blob.split_at(crypto::NONCE_LEN);
    let plain = crypto::open(&key, nonce, AAD, ct)?;
    let share: Share = serde_json::from_slice(&plain).map_err(|e| Error::format("share", e))?;
    share.check(now_ms)
}

/// A new age X25519 identity.
pub fn new_identity(now_ms: u64) -> Identity {
    use age::secrecy::ExposeSecret;
    let id = age::x25519::Identity::generate();
    Identity {
        secret: id.to_string().expose_secret().to_owned(),
        public: id.to_public().to_string(),
        created: now_ms,
    }
}

/// Checks an `age1…` recipient.
pub fn parse_recipient(text: &str) -> Result<age::x25519::Recipient> {
    text.trim()
        .parse::<age::x25519::Recipient>()
        .map_err(|e| Error::format("age recipient", e))
}

/// Encrypts a share to age recipients, ASCII-armored.
pub fn age_encrypt(recipients: &[&str], share: &Share) -> Result<String> {
    let rs: Vec<age::x25519::Recipient> = recipients
        .iter()
        .map(|r| parse_recipient(r))
        .collect::<Result<_>>()?;
    if rs.is_empty() {
        return Err(Error::Entry("no recipient".into()));
    }
    let enc = age::Encryptor::with_recipients(rs.iter().map(|r| r as &dyn age::Recipient))
        .map_err(|e| Error::format("age", e))?;
    let mut out = Vec::new();
    let armor = age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)
        .map_err(|e| Error::format("age", e))?;
    let mut w = enc
        .wrap_output(armor)
        .map_err(|e| Error::format("age", e))?;
    let plain = Zeroizing::new(serde_json::to_vec(share).expect("share serializes"));
    w.write_all(&plain).map_err(|e| Error::format("age", e))?;
    w.finish()
        .and_then(|a| a.finish())
        .map_err(|e| Error::format("age", e))?;
    String::from_utf8(out).map_err(|e| Error::format("age", e))
}

/// Opens an age share with any of `identities`.
pub fn age_decrypt(identities: &[Identity], data: &[u8], now_ms: u64) -> Result<Share> {
    let ids: Vec<age::x25519::Identity> = identities
        .iter()
        .filter_map(|i| i.secret.parse::<age::x25519::Identity>().ok())
        .collect();
    if ids.is_empty() {
        return Err(Error::Entry(
            "this vault has no identity yet (`otpx id`)".into(),
        ));
    }
    let dec = age::Decryptor::new(age::armor::ArmoredReader::new(data))
        .map_err(|e| Error::format("age", e))?;
    if dec.is_scrypt() {
        return Err(Error::Unsupported(
            "passphrase age files here (try `otpx import`)".into(),
        ));
    }
    let mut r = dec
        .decrypt(ids.iter().map(|i| i as &dyn age::Identity))
        .map_err(|_| Error::Decrypt)?;
    let mut plain = Zeroizing::new(Vec::new());
    r.read_to_end(&mut plain).map_err(|_| Error::Decrypt)?;
    let share: Share = serde_json::from_slice(&plain).map_err(|e| Error::format("share", e))?;
    share.check(now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Share {
        Share::accounts(&[Entry::new("GitHub", "me", vec![1, 2, 3, 4, 5])], 0)
    }

    #[test]
    fn link_round_trip() {
        let link = create_link(DEFAULT_BASE, &sample(), None).unwrap();
        assert!(link.starts_with("https://maxgfr.github.io/otpx/#s=1."));
        assert!(!link_needs_passphrase(&link));
        assert_eq!(open_link(&link, None, 1).unwrap(), sample());
        let frag = link.split_once('#').unwrap().1;
        assert_eq!(open_link(frag, None, 1).unwrap(), sample());
        let mut bad = link.clone();
        bad.pop();
        bad.push(if link.ends_with('A') { 'B' } else { 'A' });
        assert!(open_link(&bad, None, 1).is_err());
    }

    #[test]
    fn passphrase_and_expiry() {
        let mut s = sample();
        s.expires = 100;
        let link = create_link(DEFAULT_BASE, &s, Some("tulip")).unwrap();
        assert!(link_needs_passphrase(&link));
        assert!(matches!(
            open_link(&link, None, 1),
            Err(Error::NeedsPassword(_))
        ));
        assert!(open_link(&link, Some("rose"), 1).is_err());
        assert_eq!(open_link(&link, Some("tulip"), 99).unwrap(), s);
        assert!(matches!(
            open_link(&link, Some("tulip"), 101),
            Err(Error::Expired)
        ));
    }

    #[test]
    fn age_round_trip() {
        let me = new_identity(1);
        let other = new_identity(2);
        let armored = age_encrypt(&[&me.public], &sample()).unwrap();
        assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
        assert_eq!(
            age_decrypt(&[other.clone(), me.clone()], armored.as_bytes(), 1).unwrap(),
            sample()
        );
        assert!(age_decrypt(&[other], armored.as_bytes(), 1).is_err());
        assert!(parse_recipient("age1nope").is_err());
    }
}
