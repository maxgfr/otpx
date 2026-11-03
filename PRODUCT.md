# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Vanilla TypeScript bundled with Bun (`Bun.build`), no UI framework. All OTP, crypto, merge, import/export, QR and share logic comes from the Rust core compiled to WebAssembly (`crates/otpx-wasm`); the TypeScript layer owns only the DOM, storage (IndexedDB), camera, WebAuthn and `fetch`. Deployed as static files to GitHub Pages at `https://maxgfr.github.io/otpx/`, and embedded in the `otpx` binary for `otpx web` (served on `127.0.0.1`).

## Users

The owner (maxgfr), a developer who lives in the terminal, replacing Google Authenticator and Microsoft Authenticator. The web app is how they get a code where the CLI is not installed, how a phone gets the vault, and how people they share an account with open a share link. *(Inferred, not yet confirmed: primary use is personal; recipients of share links are the only other audience; phone and desktop matter equally.)*

## Product Purpose

Generate 2FA codes from an encrypted vault that the owner controls and can always export. Success: codes appear in a second, the vault survives the loss of any one device, and leaving otpx for another app is one export away.

## Positioning

One Rust core runs the same code in the terminal, in the browser and in tests, so a vault made anywhere opens everywhere. The vault is a single encrypted file the owner stores where they choose (a private GitHub repository, a gist, a synced folder); there is no otpx server and no account.

## Operating Context

- Logging into a site on a laptop: the otpx tab sits next to the login form; search, copy, paste, done.
- On a phone: installed as a PWA from the home screen, unlocked with Touch ID / Face ID (passkey PRF) or a PIN.
- Migrating: scanning Google Authenticator's "Transfer accounts" QR codes with the camera, importing Aegis/2FAS/andOTP/Bitwarden files, re-adding Microsoft Authenticator accounts from their QR codes.
- Moving devices: opening a device link from the CLI (`otpx link`), or pointing the app at the GitHub repository.
- Sharing: opening `#s=` share links sent by someone else.

## Capabilities and Constraints

- TOTP (SHA1/256/512, any period and length), HOTP, Steam.
- Unlock: master password (Argon2id 64 MiB), recovery code, passkey PRF (biometrics), device-local PIN.
- Sync: GitHub repository (Contents API), secret gist, local file, the local `otpx web` server; entry-level merge so nothing is lost.
- Strict CSP via `<meta>` (no inline scripts or styles, no third-party origins except `api.github.com`), Trusted Types enforced: no `innerHTML`.
- Shared origin: `maxgfr.github.io` also serves other projects; only ciphertext is persisted, and the app locks itself.
- Terminology: *vault*, *account*, *code*, *remote*, *recovery code*, *share link*, *device link*.

## Brand Commitments

- Name: otpx, lowercase.
- The owner asked for a sober UI.
- Voice: plain, short, precise; says what happens to the user's data.

## Evidence on Hand

No testimonials, users, metrics or press exist. Do not invent any. Demonstration accounts must be labeled as examples.

## Product Principles

1. The code is the content: everything else steps back when a code is on screen.
2. Say where the secret goes: every action that sends, stores or exposes secrets states it in one line.
3. Nothing is lost silently: merges keep both sides, deletions are undoable, errors name the fix.
4. Same truth everywhere: the web app never computes differently from the CLI.

## Accessibility & Inclusion

WCAG 2.2 AA. Codes readable at a glance (large, tabular figures, grouped), never conveyed by color alone; full keyboard use on desktop; reduced motion honored; French and English, chosen from the browser *(inferred)*.
