//! Microsoft Authenticator's database (`/data/data/com.azure.authenticator/databases/PhoneFactor`
//! on a rooted Android phone). Table `accounts`: `account_type` 0 is a regular TOTP account
//! (base32 secret, 6 digits); 1 is a Microsoft personal account (base64 secret, 8 digits).
//! Work/school push accounts carry no usable secret and are reported as skipped.

use std::path::Path;

use super::{Format, Imported};
use crate::model::Entry;
use crate::{Error, Result, b32, crypto};

const NAME: &str = "Microsoft Authenticator";

/// Reads the `PhoneFactor` database at `path`.
pub fn import_path(path: &Path) -> Result<Imported> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| Error::format(NAME, e))?;
    let mut stmt = conn
        .prepare("SELECT name, username, oath_secret_key, account_type FROM accounts")
        .map_err(|e| Error::format(NAME, format!("{e} (is this the PhoneFactor database?)")))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, Option<i64>>(3)?.unwrap_or(-1),
            ))
        })
        .map_err(|e| Error::format(NAME, e))?;
    let mut out = Imported::new(Format::MsAuth);
    for row in rows {
        let (issuer, user, secret, kind) = row.map_err(|e| Error::format(NAME, e))?;
        let what = format!("{issuer} ({user})");
        let entry = match kind {
            0 => b32::decode(&secret).map(|s| Entry::new(&issuer, &user, s)),
            1 => crypto::unb64(&secret).map(|s| {
                let mut e = Entry::new(&issuer, &user, s);
                e.digits = 8;
                e
            }),
            _ => Err(Error::Unsupported(
                "work or school push account: sign in again and add it with its QR code".into(),
            )),
        };
        out.push(&what, entry);
    }
    Ok(out)
}
