//! One-time passwords: HOTP (RFC 4226), TOTP (RFC 6238) and Steam Guard codes.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};

/// HMAC hash function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    /// SHA-1, what nearly every service uses.
    #[default]
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl Algorithm {
    /// Name as written in `otpauth://` URIs.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }

    /// Parses `SHA1`, `sha-256`, `HmacSHA512`… (case-insensitive).
    pub fn parse(text: &str) -> Option<Algorithm> {
        let t: String = text
            .to_ascii_uppercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        match t.trim_start_matches("HMAC") {
            "SHA1" => Some(Algorithm::Sha1),
            "SHA256" => Some(Algorithm::Sha256),
            "SHA512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }
}

fn mac(algo: Algorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    fn run<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut m = <M as KeyInit>::new_from_slice(key).expect("HMAC takes keys of any length");
        m.update(msg);
        m.finalize().into_bytes().to_vec()
    }
    match algo {
        Algorithm::Sha1 => run::<Hmac<sha1::Sha1>>(key, msg),
        Algorithm::Sha256 => run::<Hmac<sha2::Sha256>>(key, msg),
        Algorithm::Sha512 => run::<Hmac<sha2::Sha512>>(key, msg),
    }
}

/// The 31-bit dynamically truncated value of RFC 4226 §5.3.
fn truncated(algo: Algorithm, secret: &[u8], counter: u64) -> u32 {
    let h = mac(algo, secret, &counter.to_be_bytes());
    let off = usize::from(h[h.len() - 1] & 0x0f);
    u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]])
}

/// HOTP code for `counter`, zero-padded to `digits` (1 to 10).
pub fn hotp(secret: &[u8], counter: u64, digits: u8, algo: Algorithm) -> String {
    let digits = digits.clamp(1, 10);
    let value = u64::from(truncated(algo, secret, counter)) % 10u64.pow(u32::from(digits));
    format!("{value:0width$}", width = usize::from(digits))
}

/// Time step of `unix` seconds for `period` seconds (at least 1).
pub fn step(unix: u64, period: u32) -> u64 {
    unix / u64::from(period.max(1))
}

/// Seconds left before the code of `unix` changes.
pub fn remaining(unix: u64, period: u32) -> u32 {
    let p = u64::from(period.max(1));
    u32::try_from(p - unix % p).unwrap_or(u32::MAX)
}

/// TOTP code at `unix` seconds.
pub fn totp(secret: &[u8], unix: u64, period: u32, digits: u8, algo: Algorithm) -> String {
    hotp(secret, step(unix, period), digits, algo)
}

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

/// Steam Guard code at `unix` seconds: 5 characters, SHA-1, 30-second steps.
pub fn steam(secret: &[u8], unix: u64) -> String {
    let mut v = truncated(Algorithm::Sha1, secret, step(unix, 30));
    let n = STEAM_ALPHABET.len() as u32;
    (0..5)
        .map(|_| {
            let c = STEAM_ALPHABET[(v % n) as usize];
            v /= n;
            char::from(c)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC4226: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc4226_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (c, want) in expected.iter().enumerate() {
            assert_eq!(hotp(RFC4226, c as u64, 6, Algorithm::Sha1), *want);
        }
    }

    #[test]
    fn rfc6238_vectors() {
        let s1 = b"12345678901234567890".as_slice();
        let s256 = b"12345678901234567890123456789012".as_slice();
        let s512 = b"1234567890123456789012345678901234567890123456789012345678901234".as_slice();
        let table: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, a, b, c) in table {
            assert_eq!(totp(s1, *t, 30, 8, Algorithm::Sha1), *a, "sha1 t={t}");
            assert_eq!(totp(s256, *t, 30, 8, Algorithm::Sha256), *b, "sha256 t={t}");
            assert_eq!(totp(s512, *t, 30, 8, Algorithm::Sha512), *c, "sha512 t={t}");
        }
    }

    #[test]
    fn same_codes_as_totp_rs() {
        let secret = crate::b32::decode("JBSWY3DPEHPK3PXP").unwrap();
        for (algo, theirs) in [
            (Algorithm::Sha1, totp_rs::Algorithm::SHA1),
            (Algorithm::Sha256, totp_rs::Algorithm::SHA256),
            (Algorithm::Sha512, totp_rs::Algorithm::SHA512),
        ] {
            let t = totp_rs::Builder::new()
                .with_algorithm(theirs)
                .with_digits(6)
                .with_step_duration(30)
                .with_secret(secret.clone())
                .build_noncompliant();
            for time in [0u64, 59, 1_700_000_000, 1_800_000_123, 4_000_000_000] {
                assert_eq!(
                    totp(&secret, time, 30, 6, algo),
                    t.generate(time).to_string()
                );
            }
        }
    }

    #[test]
    fn steam_codes() {
        let secret = crate::b32::decode("JBSWY3DPEHPK3PXP").unwrap();
        let t = totp_rs::Builder::new_steam()
            .with_secret(secret.clone())
            .build_noncompliant();
        for time in [0u64, 1_700_000_000, 1_800_000_123] {
            assert_eq!(steam(&secret, time), t.generate(time).to_string());
        }
    }

    #[test]
    fn countdown() {
        assert_eq!(remaining(0, 30), 30);
        assert_eq!(remaining(29, 30), 1);
        assert_eq!(remaining(30, 30), 30);
        assert_eq!(Algorithm::parse("HmacSHA256"), Some(Algorithm::Sha256));
        assert_eq!(Algorithm::parse("sha-512"), Some(Algorithm::Sha512));
        assert_eq!(Algorithm::parse("md5"), None);
    }
}
