//! andOTP backups: a JSON array, or encrypted with AES-256-GCM, the key coming from
//! PBKDF2-HMAC-SHA1 (`iterations(4, BE) | salt(12) | nonce(12) | ct+tag`) or, in old
//! backups, from SHA-256 of the password (`nonce(12) | ct+tag`).

use serde_json::{Value, json};
use sha2::Digest;
use zeroize::Zeroizing;

use super::Imported;
use crate::model::{Entry, Kind};
use crate::otp::Algorithm;
use crate::{Error, Result, b32};

const NAME: &str = "andOTP";

fn gcm(key: &[u8], nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    crate::crypto::aes_gcm_open(key, nonce, ct)
}

fn decrypt(bytes: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() > 4 + 12 + 12 + 16 {
        let iter = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if (1..=10_000_000).contains(&iter) {
            let mut key = Zeroizing::new([0u8; 32]);
            pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
                password.as_bytes(),
                &bytes[4..16],
                iter,
                key.as_mut(),
            );
            if let Ok(p) = gcm(key.as_ref(), &bytes[16..28], &bytes[28..]) {
                return Ok(p);
            }
        }
    }
    if bytes.len() > 12 + 16 {
        let key = sha2::Sha256::digest(password.as_bytes());
        if let Ok(p) = gcm(&key, &bytes[..12], &bytes[12..]) {
            return Ok(p);
        }
    }
    Err(Error::Decrypt)
}

/// Reads an andOTP backup.
pub fn import(bytes: &[u8], password: Option<&str>, mut out: Imported) -> Result<Imported> {
    let plain;
    let text: &[u8] = match std::str::from_utf8(bytes) {
        Ok(t) if t.trim_start().starts_with('[') => bytes,
        _ => {
            let pw = password.ok_or(Error::NeedsPassword(NAME))?;
            plain = decrypt(bytes, pw)?;
            &plain
        }
    };
    let v: Value = serde_json::from_slice(text).map_err(|e| Error::format(NAME, e))?;
    for item in v
        .as_array()
        .ok_or_else(|| Error::format(NAME, "not a list"))?
    {
        let label = item["label"].as_str().unwrap_or("").to_owned();
        out.push(&label, entry_of(item));
    }
    Ok(out)
}

fn entry_of(item: &Value) -> Result<Entry> {
    let secret = b32::decode(item["secret"].as_str().unwrap_or(""))?;
    let issuer = item["issuer"].as_str().unwrap_or("");
    let label = item["label"].as_str().unwrap_or("");
    // Old backups put "Issuer - account" or "Issuer:account" in the label.
    let (issuer, account) = if issuer.is_empty() {
        match label.split_once(" - ").or_else(|| label.split_once(':')) {
            Some((i, a)) => (i.trim().to_owned(), a.trim().to_owned()),
            None => (String::new(), label.to_owned()),
        }
    } else {
        super::split_label(issuer, label)
    };
    let mut e = Entry::new(&issuer, &account, secret);
    e.kind = match item["type"]
        .as_str()
        .unwrap_or("TOTP")
        .to_ascii_uppercase()
        .as_str()
    {
        "TOTP" => Kind::Totp,
        "HOTP" => Kind::Hotp,
        "STEAM" => Kind::Steam,
        other => return Err(Error::Unsupported(format!("{other} tokens"))),
    };
    e.algorithm = Algorithm::parse(item["algorithm"].as_str().unwrap_or("SHA1"))
        .ok_or_else(|| Error::Unsupported(format!("algorithm {}", item["algorithm"])))?;
    e.digits = u8::try_from(item["digits"].as_u64().unwrap_or(6)).unwrap_or(6);
    e.period = u32::try_from(item["period"].as_u64().unwrap_or(30)).unwrap_or(30);
    e.counter = item["counter"].as_u64().unwrap_or(0);
    e.tags = item["tags"]
        .as_array()
        .map(|t| {
            t.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    Ok(e)
}

/// Writes a plain andOTP backup.
pub fn export(entries: &[Entry]) -> String {
    let items: Vec<Value> = entries
        .iter()
        .map(|e| {
            let mut v = json!({
                "secret": b32::encode(&e.secret),
                "issuer": e.issuer,
                "label": e.account,
                "digits": e.digits,
                "type": e.kind.as_str().to_ascii_uppercase(),
                "algorithm": e.algorithm.as_str(),
                "thumbnail": "Default",
                "last_used": 0,
                "used_frequency": 0,
                "tags": e.tags,
            });
            match e.kind {
                Kind::Hotp => v["counter"] = json!(e.counter),
                _ => v["period"] = json!(e.period),
            }
            v
        })
        .collect();
    serde_json::to_string_pretty(&items).expect("json") + "\n"
}

#[cfg(test)]
pub(crate) fn encrypt_for_tests(plain: &[u8], password: &str) -> Vec<u8> {
    let salt = crate::crypto::random_bytes(12).unwrap();
    let iter: u32 = 1000;
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), &salt, iter, &mut key);
    let (nonce, ct) = crate::crypto::aes_gcm_seal(&key, plain).unwrap();
    [iter.to_be_bytes().as_slice(), &salt, &nonce, &ct].concat()
}
