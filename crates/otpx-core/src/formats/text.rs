//! Plain text holding `otpauth://` and `otpauth-migration://` URIs.

use super::Imported;
use crate::uri;

/// Every URI in `text`, wherever it appears (one per line, or inside other text).
pub fn find_uris(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| {
        c.is_whitespace() || c == '"' || c == '\'' || c == '<' || c == '>' || c == ','
    })
    .map(|t| t.trim_end_matches(['.', ';', ')']))
    .filter(|t| {
        let l = t.get(..10).unwrap_or("").to_ascii_lowercase();
        l == "otpauth://" || l == "otpauth-mi"
    })
}

/// Imports every URI of `text`.
pub fn import(text: &str, mut out: Imported) -> Imported {
    for u in find_uris(text) {
        if u.to_ascii_lowercase().starts_with("otpauth-migration://") {
            match super::google::decode(u) {
                Ok(payload) => {
                    out.batches
                        .push((payload.batch_index, payload.batch_size.max(1)));
                    for p in payload.otp_parameters {
                        let what = if p.issuer.is_empty() {
                            p.name.clone()
                        } else {
                            format!("{}: {}", p.issuer, p.name)
                        };
                        out.push(&what, super::google::to_entry(&p));
                    }
                }
                Err(e) => out.skipped.push(format!("transfer code: {e}")),
            }
        } else {
            let what: String = u
                .chars()
                .take(40)
                .collect::<String>()
                .replace("secret=", "");
            let what = what.split('?').next().unwrap_or("").to_owned();
            out.push(&what, uri::parse(u));
        }
    }
    out
}
