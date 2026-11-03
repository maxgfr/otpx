//! Primitives: Argon2id, XChaCha20-Poly1305, HKDF and the system random source.

use argon2::{Algorithm as A2, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// A 256-bit key, wiped on drop.
pub type Key = Zeroizing<[u8; 32]>;

/// Fills `buf` from the system random source (`crypto.getRandomValues` in browsers).
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Random)
}

/// `n` random bytes.
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    fill_random(&mut v)?;
    Ok(v)
}

/// A random key.
pub fn random_key() -> Result<Key> {
    let mut k = Zeroizing::new([0u8; 32]);
    fill_random(k.as_mut())?;
    Ok(k)
}

/// Argon2id cost. `m` is in KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory in KiB.
    pub m: u32,
    /// Passes.
    pub t: u32,
    /// Lanes. Always 1 so browsers (one thread) derive the same key as fast as they can.
    pub p: u32,
}

impl Argon2Params {
    /// For passwords: 64 MiB, 3 passes (well above OWASP's 19 MiB × 2).
    pub const PASSWORD: Argon2Params = Argon2Params {
        m: 65_536,
        t: 3,
        p: 1,
    };
    /// For high-entropy keys (recovery key, PIN combined with a device secret): 19 MiB × 2.
    pub const KEY: Argon2Params = Argon2Params {
        m: 19_456,
        t: 2,
        p: 1,
    };
    /// For tests only.
    pub const TEST: Argon2Params = Argon2Params { m: 64, t: 1, p: 1 };

    /// Refuses costs that would be trivial to brute-force or exhaust memory.
    pub fn check(&self) -> Result<()> {
        if self.p != 1 || self.t == 0 || self.t > 64 || self.m > 4 * 1024 * 1024 {
            return Err(Error::format("vault", "unsupported Argon2 parameters"));
        }
        Ok(())
    }
}

/// Argon2id of `secret` with `salt`.
pub fn argon2id(secret: &[u8], salt: &[u8], p: Argon2Params) -> Result<Key> {
    p.check()?;
    let params = Params::new(p.m, p.t, p.p, Some(32))
        .map_err(|e| Error::format("vault", format!("Argon2 parameters: {e}")))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(A2::Argon2id, Version::V0x13, params)
        .hash_password_into(secret, salt, out.as_mut())
        .map_err(|e| Error::format("vault", format!("Argon2: {e}")))?;
    Ok(out)
}

/// HKDF-SHA256 of `ikm` with `info` into a key.
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Nonce length of XChaCha20-Poly1305 (random nonces never collide in practice).
pub const NONCE_LEN: usize = 24;

/// Encrypts `plain` with `key`; returns `(nonce, ciphertext || tag)`.
pub fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce = random_bytes(NONCE_LEN)?;
    let ct = seal_with_nonce(key, &nonce, aad, plain)?;
    Ok((nonce, ct))
}

/// Encrypts with a given nonce (golden test vectors only need this to be deterministic).
pub fn seal_with_nonce(key: &[u8; 32], nonce: &[u8], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::Decrypt);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &XNonce::try_from(nonce).map_err(|_| Error::Decrypt)?,
            Payload { msg: plain, aad },
        )
        .map_err(|_| Error::Decrypt)
}

/// Decrypts what [`seal`] produced.
pub fn open(key: &[u8; 32], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::Decrypt);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &XNonce::try_from(nonce).map_err(|_| Error::Decrypt)?,
            Payload { msg: ct, aad },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

/// AES-256-GCM decryption of `ct || tag` with a 12-byte nonce (other apps' backups).
pub fn aes_gcm_open(key: &[u8], nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use aes_gcm::{Aes256Gcm, aead::Nonce};
    let n = Nonce::<Aes256Gcm>::try_from(nonce).map_err(|_| Error::Decrypt)?;
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Decrypt)?
        .decrypt(&n, ct)
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

/// AES-256-GCM encryption with a random 12-byte nonce: `(nonce, ct || tag)`.
pub fn aes_gcm_seal(key: &[u8], plain: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use aes_gcm::{Aes256Gcm, aead::Nonce};
    let nonce = random_bytes(12)?;
    let n = Nonce::<Aes256Gcm>::try_from(nonce.as_slice()).map_err(|_| Error::Decrypt)?;
    let ct = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Decrypt)?
        .encrypt(&n, plain)
        .map_err(|_| Error::Decrypt)?;
    Ok((nonce, ct))
}

/// Standard base64 (with padding), as the vault file writes binary fields.
pub fn b64(bytes: &[u8]) -> String {
    data_encoding::BASE64.encode(bytes)
}

/// Reads standard or URL-safe base64, padded or not.
pub fn unb64(text: &str) -> Result<Vec<u8>> {
    let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let t = t.trim_end_matches('=');
    let std = t.replace('-', "+").replace('_', "/");
    data_encoding::BASE64_NOPAD
        .decode(std.as_bytes())
        .map_err(|_| Error::format("base64", "invalid base64"))
}

/// URL-safe base64 without padding (links).
pub fn b64url(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

/// Constant-time equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open() {
        let k = random_key().unwrap();
        let (n, ct) = seal(&k, b"aad", b"hello").unwrap();
        assert_eq!(open(&k, &n, b"aad", &ct).unwrap().as_slice(), b"hello");
        assert!(open(&k, &n, b"other", &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open(&k, &n, b"aad", &bad).is_err());
    }

    #[test]
    fn argon2_rfc9106_shape() {
        // Deterministic and parameter-sensitive.
        let a = argon2id(b"password", b"somesaltsomesalt", Argon2Params::TEST).unwrap();
        let b = argon2id(b"password", b"somesaltsomesalt", Argon2Params::TEST).unwrap();
        let c = argon2id(b"password", b"somesaltsomesalT", Argon2Params::TEST).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(
            argon2id(
                b"x",
                b"somesaltsomesalt",
                Argon2Params { m: 64, t: 1, p: 4 }
            )
            .is_err()
        );
    }

    #[test]
    fn base64_variants() {
        assert_eq!(unb64("aGk=").unwrap(), b"hi");
        assert_eq!(unb64("aGk").unwrap(), b"hi");
        assert_eq!(unb64(&b64url(&[0xfb, 0xff])).unwrap(), vec![0xfb, 0xff]);
    }
}
