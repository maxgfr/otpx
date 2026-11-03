# Security model (short)

- Vault: random 256-bit key encrypts the content (XChaCha20-Poly1305), sealed to each
  way to unlock (master password via Argon2id 64 MiB × 3, recovery code, passkeys, device
  keys for Touch ID / PIN) in an authenticated keyring. Remotes only ever see ciphertext.
- Changing the password / recovery code / devices rotates the key. Other devices then
  exit 3 on `otpx sync` with "the vault key changed": ask the user to run `! otpx sync`
  and type the current master password once.
- Unlock caching (`otpx config unlock-mode`): `keychain-ttl` (default 15 min in
  the macOS Keychain / Secret Service), `keychain-persistent`, `always-ask`.
  Touch ID (`otpx quick-unlock enable touchid`) gates the keychain read; a PIN
  works on that device only and is erased after 5 wrong tries.
- Clipboard copies are cleared after 20 s (vault setting).
- The web app at maxgfr.github.io shares an origin with other sites of that
  domain; it stores only ciphertext and locks after inactivity. `otpx web`
  serves the same app from localhost for an isolated origin.
- Lost password: `! otpx unlock --recovery`, then `! otpx passwd`.
