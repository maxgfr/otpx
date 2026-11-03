//! Lenient base32 for OTP secrets: case, spaces, dashes and padding are ignored.

use data_encoding::{BASE32_NOPAD, Encoding};
use std::sync::LazyLock;

use crate::{Error, Result};

static LENIENT: LazyLock<Encoding> = LazyLock::new(|| {
    let mut spec = BASE32_NOPAD.specification();
    // Some apps emit secrets whose last character carries non-zero padding bits.
    spec.check_trailing_bits = false;
    spec.encoding().expect("valid base32 specification")
});

/// Decodes a secret as typed or exported by authenticator apps.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let clean: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if clean.is_empty() {
        return Err(Error::Secret("empty".into()));
    }
    let bytes = LENIENT
        .decode(clean.as_bytes())
        .map_err(|_| Error::Secret("not base32 (letters A-Z and digits 2-7)".into()))?;
    if bytes.is_empty() {
        return Err(Error::Secret("too short".into()));
    }
    Ok(bytes)
}

/// Canonical form: uppercase, no padding.
pub fn encode(bytes: &[u8]) -> String {
    BASE32_NOPAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenient_decoding() {
        let canon = decode("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(decode("jbsw y3dp-ehpk 3pxp").unwrap(), canon);
        assert_eq!(decode("JBSWY3DPEHPK3PXP====").unwrap(), canon);
        assert_eq!(encode(&canon), "JBSWY3DPEHPK3PXP");
        assert!(decode("").is_err());
        assert!(decode("0189").is_err());
        // 'B' at the end of a 2-char group leaves non-zero padding bits.
        assert!(decode("MB").is_ok());
    }
}
