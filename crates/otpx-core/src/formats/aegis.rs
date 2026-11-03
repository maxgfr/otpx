//! Aegis vaults (`docs/vault.md` of beemdevelopment/Aegis): plain, or encrypted with a
//! master key wrapped by scrypt-derived password slots, AES-256-GCM everywhere.

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::Imported;
use crate::model::{Entry, Kind};
use crate::otp::Algorithm;
use crate::{Error, Result, b32, crypto};

const NAME: &str = "Aegis";

fn hex(s: &str) -> Result<Vec<u8>> {
    data_encoding::HEXLOWER_PERMISSIVE
        .decode(s.as_bytes())
        .map_err(|_| Error::format(NAME, "invalid hex"))
}

fn gcm_open(key: &[u8], nonce: &[u8], ct: &[u8], tag: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != 12 {
        return Err(Error::format(NAME, "nonce is not 12 bytes"));
    }
    crypto::aes_gcm_open(key, nonce, &[ct, tag].concat())
}

fn gcm_seal(key: &[u8], plain: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (nonce, mut ct) = crypto::aes_gcm_seal(key, plain)?;
    let tag = ct.split_off(ct.len() - 16);
    Ok((nonce, ct, tag))
}

/// scrypt as Aegis runs it (N, r, p from the slot, 32-byte key).
fn scrypt_key(password: &str, salt: &[u8], n: u64, r: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    // Aegis writes N=2^15, r=8, p=1; anything far above is a memory bomb.
    if !n.is_power_of_two()
        || !(2..=(1 << 18)).contains(&n)
        || !(1..=8).contains(&r)
        || !(1..=2).contains(&p)
    {
        return Err(Error::format(NAME, "unsupported scrypt parameters"));
    }
    let log_n = u8::try_from(n.trailing_zeros()).map_err(|_| Error::format(NAME, "scrypt N"))?;
    let params = scrypt::Params::new(log_n, r, p).map_err(|e| Error::format(NAME, e))?;
    let mut out = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password.as_bytes(), salt, &params, out.as_mut())
        .map_err(|e| Error::format(NAME, e))?;
    Ok(out)
}

fn master_key(header: &Value, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let slots = header["slots"]
        .as_array()
        .ok_or_else(|| Error::format(NAME, "no slots"))?;
    for slot in slots
        .iter()
        .filter(|s| s["type"].as_i64() == Some(1))
        .take(4)
    {
        let get = |k: &str| {
            slot[k]
                .as_str()
                .ok_or_else(|| Error::format(NAME, format!("slot without {k}")))
        };
        let key = scrypt_key(
            password,
            &hex(get("salt")?)?,
            slot["n"].as_u64().unwrap_or(32768),
            u32::try_from(slot["r"].as_u64().unwrap_or(8)).unwrap_or(8),
            u32::try_from(slot["p"].as_u64().unwrap_or(1)).unwrap_or(1),
        )?;
        let kp = &slot["key_params"];
        let nonce = hex(kp["nonce"].as_str().unwrap_or(""))?;
        let tag = hex(kp["tag"].as_str().unwrap_or(""))?;
        if let Ok(mk) = gcm_open(key.as_ref(), &nonce, &hex(get("key")?)?, &tag) {
            return Ok(mk);
        }
    }
    Err(Error::Decrypt)
}

/// Reads an Aegis export.
pub fn import(text: &str, password: Option<&str>, mut out: Imported) -> Result<Imported> {
    let v: Value = serde_json::from_str(text).map_err(|e| Error::format(NAME, e))?;
    let db: Value = if v["db"].is_object() {
        v["db"].clone()
    } else {
        let ct = crypto::unb64(
            v["db"]
                .as_str()
                .ok_or_else(|| Error::format(NAME, "no db"))?,
        )?;
        let pw = password.ok_or(Error::NeedsPassword(NAME))?;
        let mk = master_key(&v["header"], pw)?;
        let params = &v["header"]["params"];
        let plain = gcm_open(
            &mk,
            &hex(params["nonce"].as_str().unwrap_or(""))?,
            &ct,
            &hex(params["tag"].as_str().unwrap_or(""))?,
        )?;
        serde_json::from_slice(&plain).map_err(|e| Error::format(NAME, e))?
    };
    let groups: Vec<(String, String)> = db["groups"]
        .as_array()
        .map(|g| {
            g.iter()
                .filter_map(|x| {
                    Some((
                        x["uuid"].as_str()?.to_owned(),
                        x["name"].as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    for item in db["entries"].as_array().into_iter().flatten() {
        let name = item["name"].as_str().unwrap_or("");
        let issuer = item["issuer"].as_str().unwrap_or("");
        out.push(&format!("{issuer} {name}"), entry_of(item, &groups));
    }
    Ok(out)
}

fn entry_of(item: &Value, groups: &[(String, String)]) -> Result<Entry> {
    let info = &item["info"];
    let kind = match item["type"].as_str().unwrap_or("totp") {
        "totp" => Kind::Totp,
        "hotp" => Kind::Hotp,
        "steam" => Kind::Steam,
        other => return Err(Error::Unsupported(format!("{other} entries"))),
    };
    let secret = b32::decode(info["secret"].as_str().unwrap_or(""))?;
    let mut e = Entry::new(
        item["issuer"].as_str().unwrap_or(""),
        item["name"].as_str().unwrap_or(""),
        secret,
    );
    e.kind = kind;
    e.algorithm = Algorithm::parse(info["algo"].as_str().unwrap_or("SHA1"))
        .ok_or_else(|| Error::Unsupported(format!("algorithm {}", info["algo"])))?;
    e.digits = u8::try_from(info["digits"].as_u64().unwrap_or(6)).unwrap_or(6);
    e.period = u32::try_from(info["period"].as_u64().unwrap_or(30)).unwrap_or(30);
    e.counter = info["counter"].as_u64().unwrap_or(0);
    e.note = item["note"].as_str().unwrap_or("").to_owned();
    e.favorite = item["favorite"].as_bool().unwrap_or(false);
    // Aegis v3 lists group uuids; older vaults have a single `group` name.
    if let Some(ids) = item["groups"].as_array() {
        for id in ids.iter().filter_map(Value::as_str) {
            if let Some((_, name)) = groups.iter().find(|(u, _)| u == id) {
                e.tags.push(name.clone());
            }
        }
    } else if let Some(g) = item["group"].as_str() {
        e.tags.push(g.to_owned());
    }
    Ok(e)
}

/// Writes an Aegis export; encrypted (scrypt N=2^15, r=8, p=1) when `password` is set.
pub fn export(entries: &[Entry], password: Option<&str>) -> Result<String> {
    let mut tag_ids: Vec<(String, String)> = Vec::new();
    for t in entries.iter().flat_map(|e| &e.tags) {
        if !tag_ids.iter().any(|(n, _)| n == t) {
            tag_ids.push((t.clone(), super::uuid4()?));
        }
    }
    let mut items = Vec::new();
    for e in entries {
        let mut info = json!({
            "secret": b32::encode(&e.secret),
            "algo": e.algorithm.as_str(),
            "digits": e.digits,
        });
        match e.kind {
            Kind::Hotp => info["counter"] = json!(e.counter),
            _ => info["period"] = json!(e.period),
        }
        let groups: Vec<&str> = e
            .tags
            .iter()
            .filter_map(|t| {
                tag_ids
                    .iter()
                    .find(|(n, _)| n == t)
                    .map(|(_, u)| u.as_str())
            })
            .collect();
        items.push(json!({
            "type": e.kind.as_str(),
            "uuid": super::uuid4()?,
            "name": e.account,
            "issuer": e.issuer,
            "note": e.note,
            "favorite": e.favorite,
            "icon": null,
            "info": info,
            "groups": groups,
        }));
    }
    let db = json!({
        "version": 3,
        "entries": items,
        "groups": tag_ids.iter().map(|(n, u)| json!({"uuid": u, "name": n})).collect::<Vec<_>>(),
    });
    let doc = match password {
        None => json!({"version": 1, "header": {"slots": null, "params": null}, "db": db}),
        Some(pw) => {
            let mk = Zeroizing::new(crypto::random_bytes(32)?);
            let salt = crypto::random_bytes(32)?;
            let key = scrypt_key(pw, &salt, 32768, 8, 1)?;
            let (kn, kct, ktag) = gcm_seal(key.as_ref(), &mk)?;
            let plain = Zeroizing::new(serde_json::to_vec(&db).expect("db serializes"));
            let (n, ct, tag) = gcm_seal(&mk, &plain)?;
            let h = |b: &[u8]| data_encoding::HEXLOWER.encode(b);
            json!({
                "version": 1,
                "header": {
                    "slots": [{
                        "type": 1, "uuid": super::uuid4()?, "key": h(&kct),
                        "key_params": {"nonce": h(&kn), "tag": h(&ktag)},
                        "n": 32768, "r": 8, "p": 1, "salt": h(&salt),
                        "repaired": true, "is_backup": false,
                    }],
                    "params": {"nonce": h(&n), "tag": h(&tag)},
                },
                "db": crypto::b64(&ct),
            })
        }
    };
    Ok(serde_json::to_string_pretty(&doc).expect("json") + "\n")
}
