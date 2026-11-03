//! Google Authenticator's "Transfer accounts" QR codes: `otpauth-migration://offline?data=`
//! followed by a base64 protobuf `MigrationPayload` (schema as in Aegis, which also decodes
//! the algorithm and digit count fields).

use percent_encoding::percent_decode_str;

use crate::model::{Entry, Kind};
use crate::otp::Algorithm;
use crate::{Error, Result, crypto};

/// `MigrationPayload`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct MigrationPayload {
    /// Accounts.
    #[prost(message, repeated, tag = "1")]
    pub otp_parameters: Vec<OtpParameters>,
    /// Format version (1).
    #[prost(int32, tag = "2")]
    pub version: i32,
    /// Number of QR codes of the transfer.
    #[prost(int32, tag = "3")]
    pub batch_size: i32,
    /// Index of this QR code, from 0.
    #[prost(int32, tag = "4")]
    pub batch_index: i32,
    /// Id shared by the QR codes of one transfer.
    #[prost(int32, tag = "5")]
    pub batch_id: i32,
}

/// `OtpParameters`. Enums are kept as integers (same wire format).
#[derive(Clone, PartialEq, prost::Message)]
pub struct OtpParameters {
    /// Raw secret.
    #[prost(bytes = "vec", tag = "1")]
    pub secret: Vec<u8>,
    /// Account name, sometimes `Issuer:account`.
    #[prost(string, tag = "2")]
    pub name: String,
    /// Issuer.
    #[prost(string, tag = "3")]
    pub issuer: String,
    /// 0 unspecified, 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5.
    #[prost(int32, tag = "4")]
    pub algorithm: i32,
    /// 0 unspecified, 1 six, 2 eight.
    #[prost(int32, tag = "5")]
    pub digits: i32,
    /// 0 unspecified, 1 HOTP, 2 TOTP.
    #[prost(int32, tag = "6")]
    pub r#type: i32,
    /// HOTP counter.
    #[prost(int64, tag = "7")]
    pub counter: i64,
}

/// Decodes one transfer URI.
pub fn decode(uri: &str) -> Result<MigrationPayload> {
    let query = uri
        .split_once('?')
        .map(|(_, q)| q)
        .ok_or_else(|| Error::Uri("transfer URI without data".into()))?;
    let data = query
        .split('&')
        .find_map(|p| p.strip_prefix("data="))
        .ok_or_else(|| Error::Uri("transfer URI without data".into()))?;
    // `+` may have become a space on the way; it is never a space in base64.
    let data = percent_decode_str(data)
        .decode_utf8_lossy()
        .replace(' ', "+");
    let bytes =
        crypto::unb64(&data).map_err(|_| Error::Uri("transfer data is not base64".into()))?;
    <MigrationPayload as prost::Message>::decode(bytes.as_slice())
        .map_err(|e| Error::Uri(format!("transfer data: {e}")))
}

/// One account of a transfer as an entry.
pub fn to_entry(p: &OtpParameters) -> Result<Entry> {
    let (issuer, account) = super::split_label(&p.issuer, &p.name);
    let mut e = Entry::new(&issuer, &account, p.secret.clone());
    e.algorithm = match p.algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        4 => return Err(Error::Unsupported("MD5 accounts".into())),
        n => return Err(Error::Entry(format!("unknown algorithm {n}"))),
    };
    e.digits = match p.digits {
        0 | 1 => 6,
        2 => 8,
        n => return Err(Error::Entry(format!("unknown digit count {n}"))),
    };
    match p.r#type {
        1 => {
            e.kind = Kind::Hotp;
            e.counter = u64::try_from(p.counter).unwrap_or(0);
        }
        0 | 2 => e.kind = Kind::Totp,
        n => return Err(Error::Entry(format!("unknown type {n}"))),
    }
    Ok(e)
}

/// Accounts per QR code: small enough for a phone camera to read easily.
pub const PER_CODE: usize = 8;

/// Transfer URIs for `entries`, [`PER_CODE`] per QR code. Steam accounts and periods other
/// than 30 s cannot travel this way: Google Authenticator has no field for them.
pub fn export(entries: &[Entry]) -> Result<Vec<String>> {
    let usable: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.kind != Kind::Steam && (e.kind == Kind::Hotp || e.period == 30))
        .filter(|e| matches!(e.digits, 6 | 8))
        .collect();
    let chunks: Vec<&[&Entry]> = usable.chunks(PER_CODE).collect();
    let size = i32::try_from(chunks.len()).unwrap_or(i32::MAX);
    let mut id_bytes = [0u8; 4];
    crypto::fill_random(&mut id_bytes)?;
    let batch_id = i32::from_be_bytes(id_bytes) & 0x7fff_ffff;
    let mut out = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let payload = MigrationPayload {
            otp_parameters: chunk
                .iter()
                .map(|e| OtpParameters {
                    secret: e.secret.clone(),
                    name: e.account.clone(),
                    issuer: e.issuer.clone(),
                    algorithm: match e.algorithm {
                        Algorithm::Sha1 => 1,
                        Algorithm::Sha256 => 2,
                        Algorithm::Sha512 => 3,
                    },
                    digits: if e.digits == 8 { 2 } else { 1 },
                    r#type: if e.kind == Kind::Hotp { 1 } else { 2 },
                    counter: i64::try_from(e.counter).unwrap_or(i64::MAX),
                })
                .collect(),
            version: 1,
            batch_size: size,
            batch_index: i32::try_from(i).unwrap_or(0),
            batch_id,
        };
        let bytes = prost::Message::encode_to_vec(&payload);
        let b64 = crypto::b64(&bytes);
        let data: String =
            percent_encoding::utf8_percent_encode(&b64, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        out.push(format!("otpauth-migration://offline?data={data}"));
    }
    Ok(out)
}

/// Entries [`export`] leaves out, by label.
pub fn not_exportable(entries: &[Entry]) -> Vec<String> {
    entries
        .iter()
        .filter(|e| {
            e.kind == Kind::Steam
                || (e.kind == Kind::Totp && e.period != 30)
                || !matches!(e.digits, 6 | 8)
        })
        .map(Entry::label)
        .collect()
}
