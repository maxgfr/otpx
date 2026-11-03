# Security model (short)

- Vault: random 256-bit key encrypts the content (XChaCha20-Poly1305); slots wrap
  that key: master password (Argon2id 64 MiB, 3 passes), recovery code (256 bits),
  passkeys (WebAuthn PRF, web app). Remotes only ever see ciphertext.
- Unlock caching (`otpx config unlock-mode`): `keychain-ttl` (default 15 min in
  the macOS Keychain / Secret Service), `keychain-persistent`, `always-ask`.
  Touch ID (`otpx quick-unlock enable touchid`) gates the keychain read; a PIN
  works on that device only and is erased after 5 wrong tries.
- Clipboard copies are cleared after 20 s (vault setting).
- The web app at maxgfr.github.io shares an origin with other sites of that
  domain; it stores only ciphertext and locks after inactivity. `otpx web`
  serves the same app from localhost for an isolated origin.
- Lost password: `! otpx unlock --recovery`, then `! otpx passwd`.
