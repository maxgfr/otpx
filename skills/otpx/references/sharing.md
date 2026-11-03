# Sharing accounts

- **Link** (`otpx share link <query…> [--expires 1d] [--passphrase]`): an
  encrypted link to https://maxgfr.github.io/otpx/#s=… ; the key is in the URL
  fragment, which browsers never send to a server. Opens in the web app or with
  `otpx receive '<link>'`. Without a server a link cannot be revoked: whoever
  has it can add the account until it expires. A passphrase (asked in the
  terminal, so the user runs it) adds a second factor sent another way.
- **age** (`otpx share age <query…> --to age1… [--out file]`): for someone who
  gave their key (`otpx id` prints yours). They run `otpx receive file.age`.
- **QR code** (`otpx share qr <query>`): for an authenticator app on a phone in
  the same room; it shows the secret, so only on the user's request.

Sharing gives a copy of the secret: the other person can generate codes forever.
State that before creating a share.
