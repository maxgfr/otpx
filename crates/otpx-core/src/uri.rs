//! `otpauth://` Key URIs (Google's Key Uri Format, plus the `steam` type of Aegis and
//! `encoder=steam` of KeePassXC).

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

use crate::model::{Entry, Kind};
use crate::otp::Algorithm;
use crate::{Error, Result, b32};

/// Characters kept as is in URI components.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'@');

fn decode(text: &str) -> String {
    percent_decode_str(&text.replace('+', "%20"))
        .decode_utf8_lossy()
        .into_owned()
}

fn encode(text: &str) -> String {
    utf8_percent_encode(text, COMPONENT).to_string()
}

/// Parses one `otpauth://` URI.
pub fn parse(uri: &str) -> Result<Entry> {
    let uri = uri.trim();
    let rest = uri
        .strip_prefix("otpauth://")
        .or_else(|| {
            uri.get(..10)
                .filter(|p| p.eq_ignore_ascii_case("otpauth://"))
                .map(|_| &uri[10..])
        })
        .ok_or_else(|| Error::Uri("does not start with otpauth://".into()))?;
    let (kind_s, rest) = rest
        .split_once('/')
        .ok_or_else(|| Error::Uri("missing type (totp or hotp)".into()))?;
    let mut kind = match kind_s.to_ascii_lowercase().as_str() {
        "totp" => Kind::Totp,
        "hotp" => Kind::Hotp,
        "steam" => Kind::Steam,
        other => return Err(Error::Uri(format!("unknown type {other:?}"))),
    };
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = decode(label);
    let (mut issuer, account) = match label.split_once(':') {
        Some((i, a)) => (i.trim().to_owned(), a.trim().to_owned()),
        None => (String::new(), label.trim().to_owned()),
    };
    let mut secret = None;
    let mut entry = Entry::new("", "", Vec::new());
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = decode(v);
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(b32::decode(&v)?),
            "issuer" => {
                if !v.trim().is_empty() {
                    issuer = v.trim().to_owned();
                }
            }
            "algorithm" => {
                entry.algorithm = Algorithm::parse(&v)
                    .ok_or_else(|| Error::Uri(format!("unknown algorithm {v:?}")))?;
            }
            "digits" => {
                entry.digits = v
                    .parse()
                    .map_err(|_| Error::Uri(format!("digits {v:?} is not a number")))?;
            }
            "period" => {
                entry.period = v
                    .parse()
                    .map_err(|_| Error::Uri(format!("period {v:?} is not a number")))?;
            }
            "counter" => {
                entry.counter = v
                    .parse()
                    .map_err(|_| Error::Uri(format!("counter {v:?} is not a number")))?;
            }
            "encoder" if v.eq_ignore_ascii_case("steam") => kind = Kind::Steam,
            _ => {}
        }
    }
    entry.kind = kind;
    entry.issuer = issuer;
    entry.account = account;
    entry.secret = secret.ok_or_else(|| Error::Uri("missing secret".into()))?;
    if entry.issuer.is_empty() && entry.account.is_empty() {
        entry.account = "unnamed".into();
    }
    entry.validate()?;
    Ok(entry)
}

/// The `otpauth://` URI of an entry (what authenticator apps scan).
pub fn to_uri(e: &Entry) -> String {
    let label = if e.issuer.is_empty() {
        encode(&e.account)
    } else {
        format!("{}:{}", encode(&e.issuer), encode(&e.account))
    };
    let mut q = format!("secret={}", b32::encode(&e.secret));
    if !e.issuer.is_empty() {
        q.push_str(&format!("&issuer={}", encode(&e.issuer)));
    }
    match e.kind {
        Kind::Steam => {
            // Aegis and Authenticator Pro read `steam`; KeePassXC reads `encoder=steam`.
            return format!("otpauth://steam/{label}?{q}&encoder=steam");
        }
        Kind::Hotp => q.push_str(&format!("&counter={}", e.counter)),
        Kind::Totp => {}
    }
    q.push_str(&format!(
        "&algorithm={}&digits={}",
        e.algorithm.as_str(),
        e.digits
    ));
    if e.kind == Kind::Totp {
        q.push_str(&format!("&period={}", e.period));
    }
    format!("otpauth://{}/{label}?{q}", e.kind.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_example() {
        let e =
            parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
                .unwrap();
        assert_eq!(e.issuer, "Example");
        assert_eq!(e.account, "alice@google.com");
        assert_eq!((e.digits, e.period, e.algorithm), (6, 30, Algorithm::Sha1));
    }

    #[test]
    fn full_parameters_and_round_trip() {
        let e = parse("otpauth://hotp/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&counter=7").unwrap();
        assert_eq!(e.kind, Kind::Hotp);
        assert_eq!(e.issuer, "ACME Co");
        assert_eq!(e.account, "john.doe@email.com");
        assert_eq!(
            (e.digits, e.counter, e.algorithm),
            (8, 7, Algorithm::Sha256)
        );
        let again = parse(&to_uri(&e)).unwrap();
        assert_eq!(again, e);
    }

    #[test]
    fn steam_and_quirks() {
        let e = parse("otpauth://totp/Steam:me?secret=JBSWY3DPEHPK3PXP&encoder=steam").unwrap();
        assert_eq!((e.kind, e.digits), (Kind::Steam, 5));
        assert_eq!(parse(&to_uri(&e)).unwrap(), e);
        // Lowercase secret, `+` for spaces, issuer only in the parameter.
        let q = parse("OTPAUTH://TOTP/me?secret=jbswy3dpehpk3pxp&issuer=My+Bank").unwrap();
        assert_eq!((q.issuer.as_str(), q.account.as_str()), ("My Bank", "me"));
        assert!(parse("otpauth://totp/x").is_err());
        assert!(parse("https://example.com").is_err());
        assert!(parse("otpauth://xotp/x?secret=JBSWY3DP").is_err());
    }
}
