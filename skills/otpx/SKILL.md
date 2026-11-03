---
name: otpx
description: Use when the user wants a 2FA / OTP / TOTP code for an account, or wants to add, list, edit, delete, import (Google Authenticator, Microsoft Authenticator, Aegis, 2FAS, andOTP, Bitwarden, totp-cli, QR screenshots), export, back up, sync (GitHub repo, gist, folder) or share authenticator accounts with the otpx CLI.
license: MIT
metadata:
  version: "0.1.0"
---

# otpx

otpx keeps OTP accounts (TOTP, HOTP, Steam) in one encrypted vault file
(`~/.local/share/otpx/vault.otpx`, Argon2id + XChaCha20-Poly1305) and syncs it
to the user's private GitHub repo, a gist or a folder. The same vault opens in
the terminal (`otpx`), at https://maxgfr.github.io/otpx/ and with `otpx web`.
If `otpx` is missing: `brew install maxgfr/tap/otpx`.

Run every command with `--json` and read stdout: one JSON object per line,
`{"event": …}`. A failure is `{"event":"error","error":{"code","exitCode","message"}}`
and the process exits with that code. `otpx <command> --help` is the reference.

| exit | code | what to do |
|---|---|---|
| 3 | `locked` | ask the user to run `! otpx unlock` (Touch ID, PIN or password), then retry |
| 4 | `not_found` | no vault (`otpx init` or `otpx sync setup …`), or no matching account: list them |
| 5 | `ambiguous` | the message lists candidates with ids: retry with an id or ask the user |
| 6 | `auth` | wrong password/passphrase: let the user retype it themselves |
| 7 | `conflict` | remote kept changing or holds another vault: rerun `otpx sync`, else report |
| 8 | `network` | remote unreachable or token refused: report the message |

## Guardrails

- **Never handle the master password, PIN, recovery code, tokens or secrets.**
  They never go in a message, a command line or your output. When a command
  needs one, ask the user to run it themselves with `!` (it prompts without
  echoing): `! otpx unlock`, `! otpx init`, `! otpx sync setup github --repo you/otpx-vault`,
  `! otpx passwd`. Do not set `OTPX_PASSWORD`. Do not read `~/.config/otpx/`.
- **Show codes, never secrets.** Do not run `otpx show --secret`, `otpx qr`,
  `otpx export …` to stdout, or `otpx share …` unless the user asks for that
  exact thing; then say what the output contains (a secret, a link that adds
  the account for whoever holds it) before running it.
- **Prefer copying.** For "give me my GitHub code", `otpx code github --copy --json`
  puts it on the clipboard (cleared after 20 s) and keeps it out of the
  transcript; print it (`otpx code github --json`) only when the user wants to
  read it. A code is valid for `remaining` seconds: if under 5, say so or use
  `--next`.
- **Deleting is the user's call.** `otpx rm` can lock them out of an account.
  Confirm the exact account first, then pass `--yes`. It is undoable with
  `otpx backup restore 1 --only <id>`.
- **HOTP codes are single-use.** `otpx code` on an HOTP account advances its
  counter; do not call it twice to "check".

## Recipes

Status first: `otpx status --json` (vault present, `unlocked`, entry count, remotes).

- **A code:** `otpx code <query> --json` (query: issuer, account, any part, or id prefix).
- **List:** `otpx ls --json` (codes included; `--no-codes` for names only; `--tag work`).
- **Add from a QR code on screen:** ask the user to run `! otpx add --screen` (macOS:
  they drag a rectangle around it), or save a screenshot and run
  `otpx add --image <path> --json`. From a link the user pasted: `otpx add '<otpauth://…>' --json`
  (prefer `--secret-stdin` style for raw secrets: have the user run it).
- **Leave Google Authenticator:** in the app ⋮ → Transfer accounts → Export;
  screenshot each QR code; `otpx import shot1.png shot2.png --json`. The result
  warns when some transfer codes of the batch are missing.
- **Leave Microsoft Authenticator:** it has no export. Re-add each account from
  its site's security page QR code (`otpx add --screen`). Rooted Android only:
  `otpx import PhoneFactor` (copied from `/data/data/com.azure.authenticator/databases/`).
  Work/school push accounts cannot move: say so.
- **Other apps:** `otpx import <file> --json` detects Aegis, 2FAS, andOTP,
  Bitwarden, totp-cli, CSV, otpauth lists, otpx vaults. Encrypted backups need
  the user: `! otpx import <file>` (it asks for the backup password).
  Dry run first when unsure: `--dry-run`.
- **Sync / new computer:** see [sync](references/sync.md).
- **Export / back up:** see [formats](references/formats.md).
- **Share an account:** see [sharing](references/sharing.md).
- **Security questions:** see [security](references/security.md).

After any change, the vault saves locally (a snapshot of the previous state is
kept) and syncs if remotes are set; a sync failure is a warning, not a loss:
suggest `otpx sync` later.
