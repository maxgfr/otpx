//! 2FAS backups (`.2fas`): JSON `services`, or `servicesEncrypted` =
//! `base64(ciphertext||tag):base64(salt):base64(iv)` with PBKDF2-HMAC-SHA256 (10 000
//! iterations) and AES-256-GCM.

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::Imported;
use crate::model::{Entry, Kind};
use crate::otp::Algorithm;
use crate::{Error, Result, b32, crypto};

const NAME: &str = "2FAS";

fn decrypt(blob: &str, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let parts: Vec<&str> = blob.split(':').collect();
    if parts.len() < 3 {
        return Err(Error::format(NAME, "servicesEncrypted is not data:salt:iv"));
    }
    let data = crypto::unb64(parts[0])?;
    let salt = crypto::unb64(parts[1])?;
    let iv = crypto::unb64(parts[2])?;
    if iv.len() != 12 {
        return Err(Error::format(NAME, "IV is not 12 bytes"));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, 10_000, key.as_mut());
    crypto::aes_gcm_open(key.as_ref(), &iv, &data)
}

/// Reads a 2FAS backup.
pub fn import(text: &str, password: Option<&str>, mut out: Imported) -> Result<Imported> {
    let v: Value = serde_json::from_str(text).map_err(|e| Error::format(NAME, e))?;
    let services: Value = if let Some(enc) = v["servicesEncrypted"].as_str() {
        let pw = password.ok_or(Error::NeedsPassword(NAME))?;
        let plain = decrypt(enc, pw)?;
        serde_json::from_slice(&plain).map_err(|e| Error::format(NAME, e))?
    } else {
        v["services"].clone()
    };
    let groups: Vec<(String, String)> = v["groups"]
        .as_array()
        .map(|g| {
            g.iter()
                .filter_map(|x| {
                    Some((x["id"].as_str()?.to_owned(), x["name"].as_str()?.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default();
    for s in services.as_array().into_iter().flatten() {
        let name = s["name"].as_str().unwrap_or("").to_owned();
        out.push(&name, entry_of(s, &groups));
    }
    Ok(out)
}

fn entry_of(s: &Value, groups: &[(String, String)]) -> Result<Entry> {
    let otp = &s["otp"];
    let secret = b32::decode(s["secret"].as_str().unwrap_or(""))?;
    let issuer = otp["issuer"]
        .as_str()
        .filter(|i| !i.is_empty())
        .or(s["name"].as_str())
        .unwrap_or("");
    let mut e = Entry::new(issuer, otp["account"].as_str().unwrap_or(""), secret);
    e.kind = match otp["tokenType"]
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
    e.algorithm = Algorithm::parse(otp["algorithm"].as_str().unwrap_or("SHA1"))
        .ok_or_else(|| Error::Unsupported(format!("algorithm {}", otp["algorithm"])))?;
    e.digits = u8::try_from(otp["digits"].as_u64().unwrap_or(6)).unwrap_or(6);
    e.period = u32::try_from(otp["period"].as_u64().unwrap_or(30)).unwrap_or(30);
    e.counter = otp["counter"].as_u64().unwrap_or(0);
    if let Some(g) = s["groupId"].as_str()
        && let Some((_, n)) = groups.iter().find(|(id, _)| id == g)
    {
        e.tags.push(n.clone());
    }
    Ok(e)
}

/// Writes a plain 2FAS backup (schema version 4).
pub fn export(entries: &[Entry], now_ms: u64) -> String {
    let services: Vec<Value> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let mut otp = json!({
                "account": e.account,
                "issuer": e.issuer,
                "digits": e.digits,
                "period": e.period,
                "algorithm": e.algorithm.as_str(),
                "tokenType": e.kind.as_str().to_ascii_uppercase(),
                "source": "Link",
            });
            if e.kind == Kind::Hotp {
                otp["counter"] = json!(e.counter);
            }
            json!({
                "name": if e.issuer.is_empty() { &e.account } else { &e.issuer },
                "secret": b32::encode(&e.secret),
                "updatedAt": now_ms,
                "otp": otp,
                "order": {"position": i},
            })
        })
        .collect();
    let doc = json!({
        "services": services,
        "groups": [],
        "updatedAt": now_ms,
        "schemaVersion": 4,
        "appVersionCode": 5000000,
        "appVersionName": "otpx",
        "appOrigin": "otpx",
    });
    serde_json::to_string_pretty(&doc).expect("json") + "\n"
}

#[cfg(test)]
pub(crate) fn encrypt_for_tests(plain: &[u8], password: &str) -> String {
    let salt = crypto::random_bytes(16).unwrap();
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, 10_000, &mut key);
    let (iv, ct) = crypto::aes_gcm_seal(&key, plain).unwrap();
    format!(
        "{}:{}:{}",
        crypto::b64(&ct),
        crypto::b64(&salt),
        crypto::b64(&iv)
    )
}
