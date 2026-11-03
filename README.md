# otpx

Your 2FA codes in the terminal and the browser, from one encrypted vault you keep where you choose.

```bash
brew install maxgfr/tap/otpx
otpx init                                   # master password + recovery code
otpx import google-export-1.png             # Google Authenticator transfer QR codes
otpx sync setup github --repo you/otpx-vault
otpx code github --copy                     # copied, cleared after 20 s
otpx                                        # the interactive view
```

Web app: **https://maxgfr.github.io/otpx/** (same vault, same Rust core, works offline, installable).
Agent skill: `npx skills add maxgfr/otpx   # add -a <agent> to target one agent (e.g. -a codex)`

## What it does

- **Codes**: TOTP (SHA-1/256/512, any length and period), HOTP, Steam Guard. One Rust core
  computes them in the CLI, the TUI and the browser (WebAssembly), checked against the RFC
  4226 and 6238 vectors and against `totp-rs`.
- **Import from everything**: Google Authenticator transfer QR codes (screenshots, camera in
  the web app, `--screen` on macOS, multi-code batches), Microsoft Authenticator (rooted
  Android `PhoneFactor` database; otherwise re-scan each site's QR code), Aegis and 2FAS
  (plain or encrypted), andOTP, Bitwarden, totp-cli, CSV, `otpauth://` lists, QR images.
- **Export to everything**: otpauth URIs, Google Authenticator transfer QR codes (to move back
  to a phone), Aegis (optionally encrypted), 2FAS, andOTP, Bitwarden, CSV, a printable paper
  backup with one QR code per account, or the encrypted vault itself.
- **Nothing is lost**: sync to a private GitHub repository (git keeps every version), a secret
  gist or any folder (iCloud Drive, Dropbox, Syncthing), several at once. Changes merge account
  by account, so two devices editing offline both keep their changes; HOTP counters never go
  back. Every local write keeps a snapshot (`otpx backup ls`, `otpx backup restore`).
- **Unlock your way**: master password, recovery code, Touch ID on macOS, a PIN per device,
  passkeys (Touch ID / Face ID) in the web app, and a session kept in the OS keychain for 15
  minutes, until `otpx lock`, or never (`otpx config unlock-mode`).
- **Share**: an encrypted link whose key stays in the URL fragment (optional passphrase,
  expiry), an [age](https://age-encryption.org) file for someone's public key, or a QR code.
  `otpx link` hands your sync setup to a new device.

## Quick start

```bash
otpx init                         # creates ~/.local/share/otpx/vault.otpx
otpx add 'otpauth://totp/GitHub:me?secret=…&issuer=GitHub'
otpx add --screen                 # macOS: drag a rectangle around a QR code
otpx ls                           # every account with its code
otpx code aws --copy              # by issuer, account, any part, or id
otpx unlock --ttl 2h              # Touch ID, PIN or password
otpx quick-unlock enable touchid
otpx export --format google --qr  # move accounts to a phone
otpx share link github --expires 1h --passphrase
otpx web                          # the web app on http://localhost:7357, linked to this vault
otpx doctor                       # what is missing (remote, recovery code, tokens)
```

In the interactive view: `/` search, `⏎` copy, `r` QR code, `a` add, `f` favorite, `d` delete,
`s` sync, `l` lock, `q` quit.

## New computer

```bash
brew install maxgfr/tap/otpx
otpx sync setup github --repo you/otpx-vault   # fetches the vault
otpx unlock
```

Or run `otpx link` on a machine that already syncs and `otpx receive '<link>'` on the new one.
In the web app: *Get my vault from GitHub*, or open the device link.

## Security model

- The vault is one JSON file: a random 256-bit key encrypts the accounts with
  XChaCha20-Poly1305 and is sealed to each way to unlock (master password through Argon2id
  64 MiB × 3, recovery code, passkey PRF, device keys for Touch ID and PINs) in an authenticated
  keyring that a remote cannot alter. Changing the password, the recovery code or the devices
  rotates the key, so an old password or an old copy of the file reads nothing new.
  Remotes, backups and exports of the vault only ever hold ciphertext.
- GitHub tokens stay in the OS keychain (CLI) or encrypted with the vault key (web app).
- Copied codes are cleared from the clipboard after 20 s.
- The web app has a strict Content Security Policy, Trusted Types, no third-party code and no
  server: it talks only to `api.github.com` when you set up sync. It is served from
  `maxgfr.github.io`, an origin shared with other sites; it stores only ciphertext and locks
  itself. `otpx web` serves the same app from localhost for an isolated origin.

Details and limits: [SECURITY.md](SECURITY.md).

## Exit codes

| code | meaning |
|---|---|
| 0 | ok |
| 1 | error |
| 2 | usage (bad arguments or input) |
| 3 | locked: run `otpx unlock` |
| 4 | not found (no vault, or no matching account) |
| 5 | ambiguous: several accounts match |
| 6 | wrong password, PIN, recovery code or passphrase |
| 7 | sync conflict |
| 8 | network (remote unreachable or token refused) |

`--json` prints one event per line on stdout, errors included.

## Environment

| variable | effect |
|---|---|
| `OTPX_CONFIG_DIR` | config directory (default `~/.config/otpx`) |
| `OTPX_DATA_DIR` | vault directory (default `~/.local/share/otpx`) |
| `OTPX_KEYCHAIN=0` | keep keys in `<config>/secrets.json` (0600) instead of the OS keychain |
| `OTPX_PASSWORD` | master password for scripts and CI (discouraged) |
| `OTPX_GITHUB_TOKEN` | token for GitHub remotes when none is stored |
| `OTPX_OFFLINE=1` | never sync automatically |
| `OTPX_NO_INPUT=1` | never prompt (fail with exit code 3) |
| `NO_COLOR` | no colors |

## Building from source

```bash
cargo build --release -p otpx                 # the CLI
scripts/build-web.sh                          # wasm core + web app into web/dist
cargo build --release -p otpx --features embed-web   # CLI with `otpx web` inside
scripts/check.sh                              # everything CI runs
```

Rust 1.99, wasm-pack, Bun 1.4.

## Layout

| path | what |
|---|---|
| `crates/otpx-core` | OTP, vault crypto, merge, import/export, QR, shares (no I/O, builds for wasm32) |
| `crates/otpx` | the CLI, TUI, keychain/Touch ID/PIN, sync backends, `otpx web` |
| `crates/otpx-wasm` | the core for the browser |
| `web/` | the web app (TypeScript, Bun, no framework) |
| `skills/otpx` | the agent skill |
| `testdata/golden` | a vault every build must open with the same codes, natively and in wasm |

## License

MIT or Apache-2.0, at your option.
