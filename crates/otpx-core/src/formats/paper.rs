//! A printable HTML backup: one QR code per account (scan it back into any app), the
//! secret in text, and optionally the vault's recovery code.

use crate::model::{Entry, Kind};
use crate::{Result, qr, uri};

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn grouped(secret: &str) -> String {
    secret
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The HTML sheet. `recovery_code` is printed at the top when given.
pub fn export(entries: &[Entry], recovery_code: Option<&str>, now_ms: u64) -> Result<String> {
    let mut cards = String::new();
    for e in entries {
        let svg = qr::svg(&uri::to_uri(e))?;
        let params = match e.kind {
            Kind::Totp => format!(
                "TOTP · {} · {} digits · {} s",
                e.algorithm.as_str(),
                e.digits,
                e.period
            ),
            Kind::Hotp => format!(
                "HOTP · {} · {} digits · counter {}",
                e.algorithm.as_str(),
                e.digits,
                e.counter
            ),
            Kind::Steam => "Steam Guard".to_owned(),
        };
        cards.push_str(&format!(
            "<section class=\"card\"><div class=\"qr\">{svg}</div><div><h2>{}</h2><p class=\"acct\">{}</p><p class=\"secret\">{}</p><p class=\"meta\">{}</p></div></section>\n",
            esc(if e.issuer.is_empty() { "—" } else { &e.issuer }),
            esc(&e.account),
            esc(&grouped(&e.secret_b32())),
            esc(&params),
        ));
    }
    let recovery = recovery_code
        .map(|c| format!("<section class=\"recovery\"><h2>Recovery code</h2><p class=\"secret\">{}</p><p>Opens the otpx vault if the master password is lost.</p></section>", esc(c)))
        .unwrap_or_default();
    let date = now_ms / 1000;
    Ok(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>otpx paper backup</title>
<style>
body {{ font: 14px/1.4 ui-sans-serif, system-ui, sans-serif; color: #111; margin: 2rem; }}
header p {{ color: #555; }}
.card, .recovery {{ display: flex; gap: 1.25rem; align-items: center; border: 1px solid #ccc; border-radius: 6px; padding: 1rem; margin: 0 0 1rem; break-inside: avoid; }}
.recovery {{ display: block; border-width: 2px; }}
.qr svg {{ width: 9rem; height: 9rem; display: block; }}
h1 {{ font-size: 1.4rem; margin: 0 0 .25rem; }}
h2 {{ font-size: 1.1rem; margin: 0; }}
.acct {{ margin: .15rem 0 .5rem; }}
.secret {{ font: 600 1rem/1.5 ui-monospace, monospace; letter-spacing: .04em; word-break: break-all; margin: 0; }}
.meta {{ color: #555; margin: .35rem 0 0; }}
@media print {{ body {{ margin: 1cm; }} }}
</style>
</head>
<body>
<header><h1>otpx paper backup</h1><p>{} account(s) · made at unix time {date}. Anyone holding this sheet can generate your codes: keep it somewhere safe, offline.</p></header>
{recovery}
{cards}</body>
</html>
"#,
        entries.len()
    ))
}
