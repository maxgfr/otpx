# Import and export formats

Import (`otpx import <files…> [--format F] [--dry-run]`, detection is automatic):

| source | what to give |
|---|---|
| Google Authenticator | screenshots of the Transfer accounts QR codes (PNG/JPEG), or the `otpauth-migration://` text |
| Microsoft Authenticator | no export; rooted Android `PhoneFactor` SQLite file |
| Aegis | `aegis-export-*.json`, plain or encrypted (asks for the password) |
| 2FAS | `.2fas`, plain or encrypted |
| andOTP | `.json` or `.json.aes` |
| Bitwarden | unencrypted JSON export (items with a TOTP) |
| totp-cli | `~/.config/totp-cli/credentials` (asks for its password) |
| any | text with `otpauth://` links, CSV with a header, QR code images, another otpx vault |

Duplicates (same secret and parameters) are skipped.

Export (`otpx export --format F --out FILE`; files are written 0600):

| format | for |
|---|---|
| `uris` | any app: one `otpauth://` per line |
| `google` | back to a phone: `otpx export --format google --qr` shows the transfer QR codes one by one in the terminal (Steam and non-30 s accounts cannot go) |
| `aegis` | Aegis; `--encrypt` asks for a password (the only encrypted third-party format) |
| `2fas`, `andotp`, `bitwarden`, `csv` | those apps |
| `paper` | printable HTML: a QR code and the secret per account |
| `otpx` | the encrypted vault itself |

Everything except `otpx` and `aegis --encrypt` holds secrets in clear: tell the
user to delete the file after use. Prefer `--out` to `--stdout`.
