//! CSV with a header line. Columns are matched by name, so exports of most password
//! managers work: an `otpauth`/`uri`/`totp`/`url` column holding URIs, or `secret` with
//! optional `issuer`/`name`/`title`, `account`/`username`/`login`, `algorithm`, `digits`,
//! `period`, `type`, `counter`, `tags`, `note`.

use super::Imported;
use crate::model::{Entry, Kind};
use crate::otp::Algorithm;
use crate::{Error, Result, b32, uri};

const NAME: &str = "CSV";

fn col(headers: &[String], names: &[&str]) -> Option<usize> {
    headers.iter().position(|h| names.contains(&h.as_str()))
}

/// Reads a CSV file.
pub fn import(text: &str, mut out: Imported) -> Result<Imported> {
    let delim = if text
        .lines()
        .next()
        .is_some_and(|l| l.matches(';').count() > l.matches(',').count())
    {
        b';'
    } else {
        b','
    };
    let mut rd = ::csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .trim(::csv::Trim::All)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = rd
        .headers()
        .map_err(|e| Error::format(NAME, e))?
        .iter()
        .map(|h| h.to_ascii_lowercase().replace([' ', '_', '-'], ""))
        .collect();
    let c_uri = col(
        &headers,
        &[
            "otpauth",
            "uri",
            "url",
            "totp",
            "otp",
            "otpurl",
            "otpauthurl",
        ],
    );
    let c_secret = col(&headers, &["secret", "key", "seed", "totpsecret"]);
    if c_uri.is_none() && c_secret.is_none() {
        return Err(Error::format(NAME, "no secret, totp or otpauth column"));
    }
    let c_issuer = col(&headers, &["issuer", "name", "title", "service"]);
    let c_account = col(
        &headers,
        &["account", "username", "user", "login", "email", "label"],
    );
    let c_algo = col(&headers, &["algorithm", "algo"]);
    let c_digits = col(&headers, &["digits", "length"]);
    let c_period = col(&headers, &["period", "interval", "step"]);
    let c_type = col(&headers, &["type", "kind", "tokentype"]);
    let c_counter = col(&headers, &["counter"]);
    let c_tags = col(&headers, &["tags", "group", "folder"]);
    let c_note = col(&headers, &["note", "notes"]);
    for (n, rec) in rd.records().enumerate() {
        let rec = match rec {
            Ok(r) => r,
            Err(e) => {
                out.skipped.push(format!("line {}: {e}", n + 2));
                continue;
            }
        };
        let get = |c: Option<usize>| c.and_then(|i| rec.get(i)).unwrap_or("").trim();
        let what = format!("line {}", n + 2);
        let u = get(c_uri);
        let entry = (|| -> Result<Entry> {
            let mut e = if u.to_ascii_lowercase().starts_with("otpauth://") {
                uri::parse(u)?
            } else {
                let s = if get(c_secret).is_empty() {
                    u
                } else {
                    get(c_secret)
                };
                let mut e = Entry::new("", "", b32::decode(s)?);
                if let Some(a) = Algorithm::parse(get(c_algo)) {
                    e.algorithm = a;
                }
                if let Ok(d) = get(c_digits).parse() {
                    e.digits = d;
                }
                if let Ok(p) = get(c_period).parse() {
                    e.period = p;
                }
                e.kind = match get(c_type).to_ascii_lowercase().as_str() {
                    "hotp" => Kind::Hotp,
                    "steam" => Kind::Steam,
                    _ => Kind::Totp,
                };
                e.counter = get(c_counter).parse().unwrap_or(0);
                e
            };
            if !get(c_issuer).is_empty() && e.issuer.is_empty() {
                e.issuer = get(c_issuer).to_owned();
            }
            if !get(c_account).is_empty() && (e.account.is_empty() || e.account == "unnamed") {
                e.account = get(c_account).to_owned();
            }
            if !get(c_tags).is_empty() {
                e.tags = get(c_tags)
                    .split(['|', ','])
                    .map(|t| t.trim().to_owned())
                    .filter(|t| !t.is_empty())
                    .collect();
            }
            e.note = get(c_note).to_owned();
            Ok(e)
        })();
        out.push(&what, entry);
    }
    Ok(out)
}

/// Writes CSV: `issuer,account,secret,algorithm,digits,period,type,counter,tags,note,otpauth`.
pub fn export(entries: &[Entry]) -> Result<String> {
    let mut w = ::csv::Writer::from_writer(Vec::new());
    let err = |e: ::csv::Error| Error::format(NAME, e);
    w.write_record([
        "issuer",
        "account",
        "secret",
        "algorithm",
        "digits",
        "period",
        "type",
        "counter",
        "tags",
        "note",
        "otpauth",
    ])
    .map_err(err)?;
    for e in entries {
        w.write_record([
            e.issuer.as_str(),
            e.account.as_str(),
            &b32::encode(&e.secret),
            e.algorithm.as_str(),
            &e.digits.to_string(),
            &e.period.to_string(),
            e.kind.as_str(),
            &e.counter.to_string(),
            &e.tags.join("|"),
            e.note.as_str(),
            &uri::to_uri(e),
        ])
        .map_err(err)?;
    }
    let bytes = w.into_inner().map_err(|e| Error::format(NAME, e))?;
    String::from_utf8(bytes).map_err(|e| Error::format(NAME, e))
}
