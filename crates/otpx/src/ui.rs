//! Terminal output: human text, or one JSON object per line (`--json`).

use std::io::{IsTerminal, Write};

use serde_json::{Map, Value, json};

use crate::{exit, fail};

/// Where and how to print.
#[derive(Debug, Clone)]
pub struct Ui {
    json: bool,
    quiet: bool,
    color: bool,
}

/// Mark of a passed check.
pub const OK: &str = "✓";
/// Mark of a failed check.
pub const KO: &str = "✗";

impl Ui {
    /// Output settings from the global flags, `NO_COLOR` and whether stdout is a terminal.
    pub fn new(json: bool, quiet: bool) -> Ui {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Ui {
            json,
            quiet,
            color: !json && !no_color && std::io::stdout().is_terminal(),
        }
    }

    /// NDJSON mode.
    pub fn is_json(&self) -> bool {
        self.json
    }

    /// Emits a JSON event (NDJSON mode only): `{"event": name, ...fields}`.
    pub fn emit(&self, event: &str, fields: Value) {
        if !self.json {
            return;
        }
        let mut obj = Map::new();
        obj.insert("event".into(), Value::String(event.into()));
        if let Value::Object(m) = fields {
            obj.extend(m);
        }
        let line = clean_json(&Value::Object(obj).to_string());
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}").and_then(|()| out.flush());
    }

    /// Primary output: stdout in human mode, stderr in NDJSON mode.
    pub fn say(&self, text: &str) {
        if self.json {
            if !self.quiet {
                eprintln!("{text}");
            }
        } else {
            println!("{text}");
        }
    }

    /// Secondary information on stderr, hidden by `--quiet`.
    pub fn note(&self, text: &str) {
        if !self.quiet {
            eprintln!("{text}");
        }
    }

    /// A warning on stderr (kept with `--quiet`), and a `warning` event.
    pub fn warn(&self, text: &str) {
        self.emit("warning", json!({ "message": text }));
        eprintln!("{} {text}", self.paint_err("warning:", "33"));
    }

    /// Reports an error: an `error` event in NDJSON mode, one line on stderr otherwise.
    pub fn error(&self, code: u8, message: &str) {
        if self.json {
            self.emit("error", json!({ "error": { "code": code_name(code), "exitCode": code, "message": message } }));
        }
        let shown: Vec<_> = message.split('\n').map(clean).collect();
        eprintln!("{} {}", self.paint_err("error:", "31"), shown.join("\n"));
    }

    /// Wraps `text` in an ANSI color when stdout has colors.
    pub fn paint(&self, text: &str, sgr: &str) -> String {
        if self.color {
            format!("\x1b[{sgr}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    fn paint_err(&self, text: &str, sgr: &str) -> String {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        if !no_color && std::io::stderr().is_terminal() {
            format!("\x1b[{sgr}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    /// Dimmed text.
    pub fn dim(&self, text: &str) -> String {
        self.paint(text, "2")
    }

    /// A check line: `✓ name: detail` or `✗ name: detail (hint)`.
    pub fn check(&self, name: &str, ok: bool, detail: &str, hint: Option<&str>) {
        self.emit(
            "check",
            json!({ "name": name, "ok": ok, "detail": detail, "hint": hint }),
        );
        let mark = if ok {
            self.paint(OK, "32")
        } else {
            self.paint(KO, "31")
        };
        let mut line = format!("{mark} {name}: {}", clean(detail));
        if let Some(h) = hint
            && !ok
        {
            line.push_str(&format!(" ({h})"));
        }
        self.say(&line);
    }

    /// Asks a yes/no question; anything but `y`/`yes` is no. Without a terminal: refuses.
    pub fn confirm(&self, question: &str) -> anyhow::Result<bool> {
        if !interactive() {
            return Err(fail(
                exit::USAGE,
                format!("{question}: pass --yes (no terminal to ask)"),
            ));
        }
        eprint!("{question} [y/N] ");
        std::io::stderr().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let answer = line.trim().to_ascii_lowercase();
        Ok(answer == "y" || answer == "yes")
    }
}

/// Stable names of the exit codes, for `--json` errors.
pub fn code_name(code: u8) -> &'static str {
    match code {
        exit::OK => "ok",
        exit::USAGE => "usage",
        exit::LOCKED => "locked",
        exit::NOT_FOUND => "not_found",
        exit::AMBIGUOUS => "ambiguous",
        exit::AUTH => "auth",
        exit::CONFLICT => "conflict",
        exit::NETWORK => "network",
        _ => "error",
    }
}

/// True when the user can answer prompts (stdin and stderr are terminals).
pub fn interactive() -> bool {
    std::env::var_os("OTPX_NO_INPUT").is_none()
        && std::io::stdin().is_terminal()
        && std::io::stderr().is_terminal()
}

/// Characters that could move the cursor, rewrite or hide what the terminal shows.
fn unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

/// Text from an imported file or a remote, made safe to print.
pub fn clean(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.chars().any(unsafe_char) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if unsafe_char(c) {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Like [`clean`] for a JSON text: the characters become `\uXXXX` escapes.
pub fn clean_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if unsafe_char(c) {
            let mut units = [0u16; 2];
            for u in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_escapes_terminal_controls() {
        let evil = "GitHub\u{1b}[2K\r\u{202e}moc.evil";
        assert!(!clean(evil).chars().any(unsafe_char));
        let v = json!({ "issuer": "a\u{9b}b\u{1b}" });
        let line = clean_json(&v.to_string());
        assert!(!line.chars().any(unsafe_char));
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap(), v);
    }
}
