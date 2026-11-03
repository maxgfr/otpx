//! Commands, grouped by topic.

pub mod entries;
pub mod io;
pub mod misc;
pub mod share;
pub mod sync;
pub mod vault;

use otpx_core::Entry;
use otpx_core::model::VaultData;

use crate::{exit, fail};

/// The single entry `query` designates, or an error listing the candidates.
pub fn resolve<'a>(data: &'a VaultData, query: &str) -> anyhow::Result<&'a Entry> {
    match data.resolve(query) {
        Ok(e) => Ok(e),
        Err(found) if found.is_empty() => Err(fail(
            exit::NOT_FOUND,
            format!("no account matches {query:?} (see `otpx ls`)"),
        )),
        Err(found) => {
            let list: Vec<String> = found
                .iter()
                .take(10)
                .map(|e| format!("  {}  {}", &e.id[..8], e.label()))
                .collect();
            Err(fail(
                exit::AMBIGUOUS,
                format!(
                    "{} accounts match {query:?}; be more precise or use an id:\n{}",
                    found.len(),
                    list.join("\n")
                ),
            ))
        }
    }
}

/// JSON description of an entry (never the secret).
pub fn entry_json(e: &Entry) -> serde_json::Value {
    serde_json::json!({
        "id": e.id,
        "issuer": e.issuer,
        "account": e.account,
        "label": e.label(),
        "type": e.kind.as_str(),
        "algorithm": e.algorithm.as_str(),
        "digits": e.digits,
        "period": e.period,
        "counter": e.counter,
        "tags": e.tags,
        "note": e.note,
        "favorite": e.favorite,
    })
}

/// Groups a code for reading: `123 456`, `1234 5678`.
pub fn group_code(code: &str) -> String {
    match code.len() {
        6 => format!("{} {}", &code[..3], &code[3..]),
        8 => format!("{} {}", &code[..4], &code[4..]),
        _ => code.to_owned(),
    }
}
