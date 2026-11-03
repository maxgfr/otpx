//! totp-cli (yitsushi/totp-cli) credentials: an age file encrypted with a passphrase
//! (scrypt) holding `[{"name": namespace, "accounts": [{"name", "token", "prefix",
//! "algorithm", "length", "timePeriod"}]}]`. The namespace becomes the issuer.

use std::io::Read;

use serde_json::Value;
use zeroize::Zeroizing;

use super::Imported;
use crate::model::Entry;
use crate::otp::Algorithm;
use crate::{Error, Result, b32};

const NAME: &str = "totp-cli";

/// Opens an age file encrypted with a passphrase.
pub(crate) fn age_decrypt_passphrase(bytes: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let reader = age::armor::ArmoredReader::new(bytes);
    let dec = age::Decryptor::new(reader).map_err(|e| Error::format(NAME, e))?;
    if !dec.is_scrypt() {
        return Err(Error::Unsupported(
            "age files for a public key (use `otpx receive`)".into(),
        ));
    }
    let mut id = age::scrypt::Identity::new(age::secrecy::SecretString::from(password.to_owned()));
    // totp-cli writes 15; 2^18 still opens in about a second and bounds memory to 256 MiB.
    id.set_max_work_factor(18);
    let mut r = dec
        .decrypt(std::iter::once(&id as &dyn age::Identity))
        .map_err(|_| Error::Decrypt)?;
    let mut out = Zeroizing::new(Vec::new());
    r.read_to_end(&mut out).map_err(|_| Error::Decrypt)?;
    Ok(out)
}

/// Reads a totp-cli credentials file (encrypted) or its JSON content.
pub fn import(bytes: &[u8], password: Option<&str>, mut out: Imported) -> Result<Imported> {
    let plain;
    let json: &[u8] = if bytes.trim_ascii_start().starts_with(b"[") {
        bytes
    } else {
        let pw = password.ok_or(Error::NeedsPassword(NAME))?;
        plain = age_decrypt_passphrase(bytes, pw)?;
        &plain
    };
    let v: Value = serde_json::from_slice(json).map_err(|e| Error::format(NAME, e))?;
    for ns in v
        .as_array()
        .ok_or_else(|| Error::format(NAME, "not a list of namespaces"))?
    {
        let issuer = ns["name"].as_str().unwrap_or("");
        for acct in ns["accounts"].as_array().into_iter().flatten() {
            let name = acct["name"].as_str().unwrap_or("");
            let entry = (|| -> Result<Entry> {
                let mut e = Entry::new(
                    issuer,
                    name,
                    b32::decode(acct["token"].as_str().unwrap_or(""))?,
                );
                if let Some(a) = acct["algorithm"].as_str().filter(|a| !a.is_empty()) {
                    e.algorithm = Algorithm::parse(a)
                        .ok_or_else(|| Error::Unsupported(format!("algorithm {a}")))?;
                }
                if let Some(l) = acct["length"].as_u64().filter(|l| *l > 0) {
                    e.digits = u8::try_from(l).unwrap_or(6);
                }
                if let Some(p) = acct["timePeriod"].as_u64().filter(|p| *p > 0) {
                    e.period = u32::try_from(p).unwrap_or(30);
                }
                if let Some(p) = acct["prefix"].as_str().filter(|p| !p.is_empty()) {
                    e.note = format!("totp-cli prefix: {p}");
                }
                Ok(e)
            })();
            out.push(&format!("{issuer}.{name}"), entry);
        }
    }
    Ok(out)
}
