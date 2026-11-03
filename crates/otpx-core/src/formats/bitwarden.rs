//! Bitwarden unencrypted JSON exports: the `login.totp` field of each item holds an
//! `otpauth://` URI, a `steam://` secret or a bare base32 secret.

use serde_json::{Value, json};

use super::Imported;
use crate::model::{Entry, Kind};
use crate::{Error, Result, b32, uri};

const NAME: &str = "Bitwarden";

/// Reads a Bitwarden export (items without a TOTP are ignored).
pub fn import(text: &str, mut out: Imported) -> Result<Imported> {
    let v: Value = serde_json::from_str(text).map_err(|e| Error::format(NAME, e))?;
    if v["encrypted"].as_bool() == Some(true) {
        return Err(Error::Unsupported(
            "encrypted Bitwarden exports: export again as \"JSON\" (not \"JSON (Encrypted)\")"
                .into(),
        ));
    }
    for item in v["items"].as_array().into_iter().flatten() {
        let Some(totp) = item["login"]["totp"]
            .as_str()
            .filter(|t| !t.trim().is_empty())
        else {
            continue;
        };
        let name = item["name"].as_str().unwrap_or("").trim();
        let user = item["login"]["username"].as_str().unwrap_or("").trim();
        let entry = entry_of(totp.trim(), name, user).map(|mut e| {
            if let Some(n) = item["notes"].as_str() {
                e.note = n.to_owned();
            }
            e.favorite = item["favorite"].as_bool().unwrap_or(false);
            e
        });
        out.push(name, entry);
    }
    Ok(out)
}

fn entry_of(totp: &str, name: &str, user: &str) -> Result<Entry> {
    if totp.to_ascii_lowercase().starts_with("otpauth://") {
        let mut e = uri::parse(totp)?;
        if e.issuer.is_empty() {
            e.issuer = name.to_owned();
        }
        if e.account.is_empty() || e.account == "unnamed" {
            e.account = user.to_owned();
        }
        return Ok(e);
    }
    if let Some(s) = totp.strip_prefix("steam://") {
        let mut e = Entry::new(name, user, b32::decode(s)?);
        e.kind = Kind::Steam;
        return Ok(e);
    }
    Ok(Entry::new(name, user, b32::decode(totp)?))
}

/// Writes a Bitwarden JSON export (one login item per account).
pub fn export(entries: &[Entry]) -> Result<String> {
    let mut items = Vec::new();
    for e in entries {
        let name = if e.issuer.is_empty() {
            e.account.clone()
        } else {
            e.issuer.clone()
        };
        let totp = if e.kind == Kind::Steam {
            format!("steam://{}", b32::encode(&e.secret))
        } else {
            uri::to_uri(e)
        };
        items.push(json!({
            "id": super::uuid4()?,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "reprompt": 0,
            "name": name,
            "notes": if e.note.is_empty() { Value::Null } else { json!(e.note) },
            "favorite": e.favorite,
            "login": {"uris": [], "username": e.account, "password": null, "totp": totp},
            "collectionIds": null,
        }));
    }
    let doc = json!({"encrypted": false, "folders": [], "items": items});
    Ok(serde_json::to_string_pretty(&doc).expect("json") + "\n")
}
