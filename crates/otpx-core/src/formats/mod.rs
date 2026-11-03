//! Import from and export to other authenticators.
//!
//! Import reads, with automatic detection: `otpauth://` URIs, Google Authenticator transfer
//! QR codes (`otpauth-migration://`), Aegis (plain or encrypted), 2FAS (plain or encrypted),
//! andOTP (plain or encrypted), Bitwarden JSON, totp-cli, CSV, otpx vaults and QR code
//! images of any of the URI kinds. Microsoft Authenticator's database needs the `sqlite`
//! feature (see [`msauth`]).

pub mod aegis;
pub mod andotp;
pub mod bitwarden;
pub mod csv;
pub mod google;
#[cfg(feature = "sqlite")]
pub mod msauth;
pub mod paper;
pub mod text;
pub mod totpcli;
pub mod twofas;

use serde::Serialize;

use crate::model::Entry;
use crate::{Error, Result};

/// A format otpx reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Guess from the content.
    Auto,
    /// `otpauth://` and `otpauth-migration://` URIs, one per line.
    Uris,
    /// Aegis vault (`aegis-export-*.json`).
    Aegis,
    /// 2FAS backup (`.2fas`).
    TwoFas,
    /// andOTP backup (`.json` or `.json.aes`).
    AndOtp,
    /// Bitwarden unencrypted JSON export.
    Bitwarden,
    /// totp-cli credentials file (age, scrypt).
    TotpCli,
    /// CSV with a header line.
    Csv,
    /// Another otpx vault.
    Otpx,
    /// A QR code image (PNG, JPEG, GIF, WebP, BMP).
    Image,
    /// Microsoft Authenticator `PhoneFactor` database (rooted Android).
    MsAuth,
}

impl Format {
    /// Parses a format name as given on the command line.
    pub fn parse(name: &str) -> Option<Format> {
        Some(match name.to_ascii_lowercase().as_str() {
            "auto" => Format::Auto,
            "uri" | "uris" | "otpauth" | "google" | "google-authenticator" | "migration" => {
                Format::Uris
            }
            "aegis" => Format::Aegis,
            "2fas" | "twofas" => Format::TwoFas,
            "andotp" => Format::AndOtp,
            "bitwarden" => Format::Bitwarden,
            "totp-cli" | "totpcli" => Format::TotpCli,
            "csv" => Format::Csv,
            "otpx" => Format::Otpx,
            "image" | "qr" | "png" | "jpg" | "jpeg" => Format::Image,
            "microsoft" | "msauth" | "microsoft-authenticator" | "phonefactor" => Format::MsAuth,
            _ => return None,
        })
    }

    /// Display name.
    pub fn name(self) -> &'static str {
        match self {
            Format::Auto => "auto",
            Format::Uris => "otpauth URIs",
            Format::Aegis => "Aegis",
            Format::TwoFas => "2FAS",
            Format::AndOtp => "andOTP",
            Format::Bitwarden => "Bitwarden",
            Format::TotpCli => "totp-cli",
            Format::Csv => "CSV",
            Format::Otpx => "otpx",
            Format::Image => "QR image",
            Format::MsAuth => "Microsoft Authenticator",
        }
    }
}

/// What an import found.
#[derive(Debug, Default, Serialize)]
pub struct Imported {
    /// Format that was read.
    pub format: &'static str,
    /// Accounts read (not yet in any vault).
    #[serde(skip)]
    pub entries: Vec<Entry>,
    /// Items that could not be read, with the reason.
    pub skipped: Vec<String>,
    /// For Google transfer codes: `(batch index, batch size)` pairs seen, to tell the user
    /// when some QR codes of a multi-code transfer are missing.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub batches: Vec<(i32, i32)>,
}

impl Imported {
    fn new(format: Format) -> Imported {
        Imported {
            format: format.name(),
            ..Default::default()
        }
    }

    /// Adds an entry after validation, or records why it was skipped.
    pub(crate) fn push(&mut self, what: &str, entry: Result<Entry>) {
        match entry.and_then(|mut e| e.validate().map(|()| e)) {
            Ok(e) => self.entries.push(e),
            Err(err) => self.skipped.push(format!("{what}: {err}")),
        }
    }

    /// Batch indexes of a Google transfer that were not imported.
    pub fn missing_batches(&self) -> Vec<i32> {
        let Some(size) = self.batches.iter().map(|b| b.1).max() else {
            return Vec::new();
        };
        (0..size)
            .filter(|i| !self.batches.iter().any(|b| b.0 == *i))
            .collect()
    }
}

fn is_image(b: &[u8]) -> bool {
    b.starts_with(b"\x89PNG")
        || b.starts_with(&[0xff, 0xd8, 0xff])
        || b.starts_with(b"GIF8")
        || (b.len() > 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP")
        || b.starts_with(b"BM")
}

/// Guesses the format of `bytes`.
pub fn detect(bytes: &[u8]) -> Format {
    if is_image(bytes) {
        return Format::Image;
    }
    if bytes.starts_with(b"SQLite format 3\0") {
        return Format::MsAuth;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        // Binary and not an image: andOTP's encrypted backup has no header at all.
        return Format::AndOtp;
    };
    let t = text.trim_start_matches('\u{feff}').trim_start();
    if t.starts_with("age-encryption.org/") || t.starts_with("-----BEGIN AGE ENCRYPTED FILE-----") {
        return Format::TotpCli;
    }
    if crate::vault::VaultFile::sniff(t) {
        return Format::Otpx;
    }
    if (t.starts_with('{') || t.starts_with('['))
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(t)
    {
        if v.get("header").is_some() && v.get("db").is_some() {
            return Format::Aegis;
        }
        if v.get("services").is_some() || v.get("servicesEncrypted").is_some() {
            return Format::TwoFas;
        }
        if v.get("items").is_some() {
            return Format::Bitwarden;
        }
        if let Some(arr) = v.as_array() {
            if arr.iter().any(|x| x.get("accounts").is_some()) {
                return Format::TotpCli;
            }
            return Format::AndOtp;
        }
    }
    let first = t.lines().next().unwrap_or("").to_ascii_lowercase();
    if !first.contains("otpauth:") && (first.contains(',') || first.contains(';')) {
        return Format::Csv;
    }
    if text::find_uris(t).next().is_some() {
        return Format::Uris;
    }
    Format::Uris
}

/// Reads accounts from `bytes`. `password` opens encrypted backups.
pub fn import(bytes: &[u8], format: Format, password: Option<&str>) -> Result<Imported> {
    let format = if format == Format::Auto {
        detect(bytes)
    } else {
        format
    };
    let as_text = || {
        std::str::from_utf8(bytes)
            .map(|t| t.trim_start_matches('\u{feff}'))
            .map_err(|_| Error::format(format.name(), "not UTF-8 text"))
    };
    match format {
        Format::Auto | Format::Uris => Ok(text::import(as_text()?, Imported::new(Format::Uris))),
        Format::Image => {
            let texts = crate::qr::decode_image(bytes)?;
            if texts.is_empty() {
                return Err(Error::Qr("no QR code found in the image".into()));
            }
            Ok(text::import(&texts.join("\n"), Imported::new(Format::Image)))
        }
        Format::Aegis => aegis::import(as_text()?, password, Imported::new(format)),
        Format::TwoFas => twofas::import(as_text()?, password, Imported::new(format)),
        Format::AndOtp => andotp::import(bytes, password, Imported::new(format)),
        Format::Bitwarden => bitwarden::import(as_text()?, Imported::new(format)),
        Format::TotpCli => totpcli::import(bytes, password, Imported::new(format)),
        Format::Csv => csv::import(as_text()?, Imported::new(format)),
        Format::Otpx => {
            let file = crate::vault::VaultFile::parse(as_text()?)?;
            let pw = password.ok_or(Error::NeedsPassword("otpx"))?;
            let open = file
                .unlock_password(pw)
                .or_else(|_| file.unlock_recovery(pw))?;
            let mut out = Imported::new(format);
            for e in &open.data.entries {
                out.push(&e.label(), Ok(e.portable()));
            }
            Ok(out)
        }
        Format::MsAuth => Err(Error::Unsupported(
            "Microsoft Authenticator databases are read by the otpx CLI (`otpx import PhoneFactor`)"
                .into(),
        )),
    }
}

/// A format otpx writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// `otpauth://` URIs, one per line.
    Uris,
    /// Google Authenticator transfer URIs (`otpauth-migration://`), one per QR code.
    Google,
    /// Aegis vault; encrypted when a password is given.
    Aegis,
    /// 2FAS backup (plain).
    TwoFas,
    /// andOTP backup (plain).
    AndOtp,
    /// Bitwarden JSON.
    Bitwarden,
    /// CSV.
    Csv,
    /// Printable HTML sheet with a QR code per account.
    Paper,
}

impl ExportFormat {
    /// Parses a format name.
    pub fn parse(name: &str) -> Option<ExportFormat> {
        Some(match name.to_ascii_lowercase().as_str() {
            "uri" | "uris" | "otpauth" | "txt" => ExportFormat::Uris,
            "google" | "google-authenticator" | "migration" => ExportFormat::Google,
            "aegis" => ExportFormat::Aegis,
            "2fas" | "twofas" => ExportFormat::TwoFas,
            "andotp" => ExportFormat::AndOtp,
            "bitwarden" => ExportFormat::Bitwarden,
            "csv" => ExportFormat::Csv,
            "paper" | "html" | "print" => ExportFormat::Paper,
            _ => return None,
        })
    }

    /// Every format, with its name, for help texts and the web app.
    pub const ALL: &'static [(&'static str, ExportFormat, &'static str)] = &[
        (
            "uris",
            ExportFormat::Uris,
            "otpauth:// URIs, one per line (any app)",
        ),
        (
            "google",
            ExportFormat::Google,
            "Google Authenticator transfer QR codes",
        ),
        (
            "aegis",
            ExportFormat::Aegis,
            "Aegis vault (encrypted with --password)",
        ),
        ("2fas", ExportFormat::TwoFas, "2FAS backup"),
        ("andotp", ExportFormat::AndOtp, "andOTP backup"),
        ("bitwarden", ExportFormat::Bitwarden, "Bitwarden JSON"),
        ("csv", ExportFormat::Csv, "CSV"),
        (
            "paper",
            ExportFormat::Paper,
            "printable HTML backup with QR codes",
        ),
    ];

    /// Usual file extension.
    pub fn extension(self) -> &'static str {
        match self {
            ExportFormat::Uris | ExportFormat::Google => "txt",
            ExportFormat::Aegis | ExportFormat::AndOtp | ExportFormat::Bitwarden => "json",
            ExportFormat::TwoFas => "2fas",
            ExportFormat::Csv => "csv",
            ExportFormat::Paper => "html",
        }
    }
}

/// Writes `entries` in `format`. `password` encrypts formats that support it (Aegis).
pub fn export(
    entries: &[Entry],
    format: ExportFormat,
    password: Option<&str>,
    now_ms: u64,
) -> Result<String> {
    Ok(match format {
        ExportFormat::Uris => {
            let mut s: String = entries
                .iter()
                .map(|e| crate::uri::to_uri(e) + "\n")
                .collect();
            if s.is_empty() {
                s.push('\n');
            }
            s
        }
        ExportFormat::Google => google::export(entries)?.join("\n") + "\n",
        ExportFormat::Aegis => aegis::export(entries, password)?,
        ExportFormat::TwoFas => twofas::export(entries, now_ms),
        ExportFormat::AndOtp => andotp::export(entries),
        ExportFormat::Bitwarden => bitwarden::export(entries)?,
        ExportFormat::Csv => csv::export(entries)?,
        ExportFormat::Paper => paper::export(entries, None, now_ms)?,
    })
}

/// A random RFC 4122 v4 UUID (Aegis and Bitwarden want one per item).
pub(crate) fn uuid4() -> Result<String> {
    let mut b = crate::crypto::random_bytes(16)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = data_encoding::HEXLOWER.encode(&b);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

/// Splits `Issuer:account` labels other apps put in the name field.
pub(crate) fn split_label(issuer: &str, name: &str) -> (String, String) {
    let name = name.trim();
    let issuer = issuer.trim();
    if let Some((i, a)) = name.split_once(':')
        && (issuer.is_empty() || i.trim().eq_ignore_ascii_case(issuer))
    {
        return (i.trim().to_owned(), a.trim().to_owned());
    }
    (issuer.to_owned(), name.to_owned())
}

#[cfg(test)]
mod tests;
