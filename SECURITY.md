# Security

## Reporting

Please report vulnerabilities privately through GitHub's *Report a vulnerability* on
https://github.com/maxgfr/otpx/security, not in a public issue.

## Model

**What is protected.** The OTP secrets (and their labels, notes and tags) in the vault.

**Vault file.** `{"format":"otpx-vault","v":1,"id","key_id","keyring","mac","nonce","ct"}`.

- A random 256-bit data key encrypts the content with XChaCha20-Poly1305 (random 192-bit nonce
  per save; the vault id and key id are associated data).
- The **keyring** lists the ways to unlock. Each slot holds an X25519 public key and the data key
  sealed to it (ephemeral X25519, HKDF-SHA256, XChaCha20-Poly1305). The slot's secret key comes
  from what unlocks it:

  | slot | secret key derived from |
  |---|---|
  | password | Argon2id of the master password (64 MiB, 3 passes, 1 lane; cost and salt bound to the slot) |
  | recovery | a 256-bit random recovery code |
  | passkey | the WebAuthn PRF output of the passkey |
  | device | a 256-bit key kept on one device (OS keychain, or the browser), plus Argon2id of a PIN when it has one |

- The keyring carries a revision and the key ids it retired, and is authenticated by an HMAC
  under a key derived from the data key. A remote, a backup or anyone without the data key cannot
  add, drop, replace, relabel or weaken a slot; a keyring whose key was retired is never accepted
  again, and the content of a copy under a retired key is ignored (an old key could forge it).
- **Rotation.** Changing the master password, making a new recovery code or removing a passkey or
  device draws a new data key, seals it to every remaining slot (public keys: no secret needed)
  and retires the old one. Whoever knew the old password or code, or holds an old copy of the file
  (git history, gist revisions, backups), can read those old copies, never what follows.
  Other devices then ask for the current master password once (`otpx sync` in a terminal, or the
  web app's *Unlock again*), and their unsynced changes are kept.

**Quick unlock (device slots).**

- **Touch ID (CLI, macOS)**: the device key sits in the login keychain and otpx reads it only after
  LocalAuthentication confirms a fingerprint. A command-line tool cannot carry the entitlement that
  makes the keychain itself enforce biometrics, so another process running as you could read that
  item after a system prompt. Use `always-ask` and no quick unlock if that matters to you.
- **PIN (CLI)**: the device key is in the OS keychain; the PIN is stretched with Argon2id (19 MiB,
  2 passes). Each try is counted in the keychain before it is made, under the vault lock; five wrong
  PINs erase the device key. otpx refuses quick unlock when the keychain is off (`OTPX_KEYCHAIN=0`),
  since a key in a file next to the vault would let a disk copy try every PIN.
- **PIN (web app)**: the device key is encrypted by a non-extractable WebCrypto key in IndexedDB;
  tries are counted before they are made, across tabs. A script running on the same origin could
  use that WebCrypto key and try PINs itself: on the shared `maxgfr.github.io` origin, prefer a
  passkey or `otpx web`.
- Device slots survive rotations; removing one rotates the key.

**Unlock cache (CLI).** `keychain-ttl` keeps the data key in the OS keychain for 15 minutes by
default; `keychain-persistent` until `otpx lock`; `always-ask` never. Changing the mode or the TTL
drops the cache. A key rotated elsewhere makes the cache useless; otpx then asks again.

**Sync.** Remotes receive only the encrypted file. A file that does not decrypt, or whose keyring
fails its MAC, is refused. A remote can withhold updates or serve an older copy: entries merge by
timestamp, and what it hides comes back from the next device that syncs. Deletions are remembered
for 3 years: a device offline longer than that can bring a deleted account back. GitHub writes are
conditional on the file's sha; gists have no conditional write, so otpx checks the revision it
replaced and merges it again. GitHub tokens are stored in the keychain (CLI) or encrypted with a
key derived from the data key (web app).

**Device links** (`otpx link`) carry remotes and tokens: they always need a passphrase, show their
targets before anything is applied, never replace an existing remote of the same name, and are
refused when the remote holds another vault than the device's.

**Untrusted input.** Imported backups and vault files are attacker-controlled: Argon2 (≤ 1 GiB,
≤ 10 passes; 256 MiB in browsers), scrypt (Aegis ≤ 2^18, age ≤ 2^18), PBKDF2 (≤ 1 M iterations),
image size (≤ 8192 px, 256 MiB) and Google transfer batches (≤ 100 codes) are bounded, and a vault
file with weaker-than-minimum Argon2 costs is refused by release builds.

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
projects of `maxgfr.github.io`. A compromised page there could read this app's IndexedDB (the
encrypted vault and, if a PIN is set, enough to try PINs) and, while the vault is open in the same
browser, script it. Use `otpx web` (a localhost origin of its own) when that matters, or a browser
profile reserved for otpx. The app only talks to `otpx web`'s local API when served from localhost.

**Clipboard.** Codes (and recovery codes and links, after 60 s) copied by otpx are cleared after
20 seconds (setting). The CLI and Chromium clear only if the clipboard still holds that text;
browsers that do not let the page read the clipboard get cleared whatever it holds by then, and
only when the page has focus (a clear that comes due in the background happens when it is back).

**Not protected against.** Malware running as you while the vault is unlocked; someone who
knows your master password or holds your recovery code; a phishing site you type codes into.

## Supply chain

Releases are built by GitHub Actions from a tagged commit, with SHA256SUMS and build
provenance attestations (`gh attestation verify otpx-<target> --repo maxgfr/otpx`). CI runs
`cargo deny` and `cargo audit`. The web app has no runtime npm dependency.
