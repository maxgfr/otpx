# Security

## Reporting

Please report vulnerabilities privately through GitHub's *Report a vulnerability* on
https://github.com/maxgfr/otpx/security, not in a public issue.

## Model

**What is protected.** The OTP secrets (and their labels, notes and tags) in the vault.

**Vault file.** `{"format":"otpx-vault","v":1,"id","slots":[…],"nonce","ct"}`. A random 256-bit
data key encrypts the content with XChaCha20-Poly1305 (random 192-bit nonce per save, vault id
in the associated data). Each slot wraps the data key with XChaCha20-Poly1305 under a key
derived from one way of unlocking, with the vault id, slot id and slot kind in the associated
data (a slot cannot be relabeled or moved to another vault):

| slot | key derivation |
|---|---|
| password | Argon2id, 64 MiB, 3 passes, 1 lane, 16-byte salt (parameters stored, so they can rise) |
| recovery | HKDF-SHA256 of a 256-bit random code |
| passkey | HKDF-SHA256 of the WebAuthn PRF output |

Device-local wraps (PIN, Touch ID) never leave the device:

- **PIN**: Argon2id (19 MiB, 2 passes) of the PIN plus a 32-byte device secret kept in the OS
  keychain (CLI) or encrypted by a non-extractable WebCrypto key (web app). Five wrong PINs
  erase it. A copy of the disk alone cannot be brute-forced offline.
- **Touch ID (CLI, macOS)**: the data key sits in the login keychain and otpx reads it only after
  LocalAuthentication confirms a fingerprint. A command-line tool cannot carry the entitlement
  that makes the keychain itself enforce biometrics, so another process running as you could
  read that keychain item after a system prompt. Use `always-ask` if that matters to you.

**Unlock cache (CLI).** `keychain-ttl` keeps the data key in the OS keychain for 15 minutes by
default; `keychain-persistent` until `otpx lock`; `always-ask` never. With `OTPX_KEYCHAIN=0` the
cache is a 0600 file in the config directory.

**Sync.** Remotes receive only the encrypted file. A remote that alters it is detected (the
merge refuses a file that does not decrypt). A remote can withhold updates or serve an older
copy: entries then merge by timestamp, and deletions it hides come back on the next sync from
another device. GitHub tokens are stored in the keychain (CLI) or encrypted with a key derived
from the data key (web app).

**Shares.** Link: XChaCha20-Poly1305 with a random 256-bit key carried in the URL fragment
(never sent by browsers); an optional passphrase is mixed in through Argon2id. Expiry is
checked when the link is opened; without a server, a link cannot be destroyed after use.
age: X25519 recipients (the vault's identity is synced so every device can open shares).

**Web app.** Strict CSP in a `<meta>` tag (`default-src 'none'`, scripts from the page's own
origin with Subresource Integrity, `connect-src` limited to `api.github.com` and
`gist.githubusercontent.com`), Trusted Types with no policy (no HTML sinks), no third-party
code. It stores only the encrypted vault, a sealed blob of device settings and non-secret
preferences in IndexedDB, locks after inactivity (5 minutes by default) and on demand.

**Known limit of the hosted web app.** `maxgfr.github.io/otpx` shares its origin with other
projects of `maxgfr.github.io`. A compromised page there could read this app's IndexedDB (only
ciphertext) and, while the vault is open in the same browser, script it. Use `otpx web` (a
localhost origin of its own) when that matters, or a browser profile reserved for otpx.

**Clipboard.** Codes copied by otpx are cleared after 20 seconds (setting), when the clipboard
still holds that code.

**Not protected against.** Malware running as you while the vault is unlocked; someone who
knows your master password or holds your recovery code; a phishing site you type codes into.

## Supply chain

Releases are built by GitHub Actions from a tagged commit, with SHA256SUMS and build
provenance attestations (`gh attestation verify otpx-<target> --repo maxgfr/otpx`). CI runs
`cargo deny` and `cargo audit`. The web app has no runtime npm dependency.
