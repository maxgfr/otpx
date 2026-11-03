//! Accounts: add, list, code, show, edit, remove.

use std::process::ExitCode;

use otpx_core::model::{Entry, Kind, sort_entries};
use otpx_core::otp::Algorithm;
use serde_json::json;

use super::{entry_json, group_code, resolve};
use crate::session::{self, read_secret};
use crate::{Ctx, clipboard, core_failure, exit, fail, now_ms, now_secs, ui};

/// `otpx add`.
#[derive(Debug, Default, clap::Args)]
pub struct AddArgs {
    /// An otpauth:// URI (or an otpauth-migration:// transfer link); `-` reads it from stdin
    uri: Option<String>,
    /// Service name
    #[arg(long)]
    issuer: Option<String>,
    /// Account name (email, username)
    #[arg(long)]
    account: Option<String>,
    /// Base32 secret (prefer --secret-stdin: arguments end up in the shell history)
    #[arg(long, conflicts_with = "secret_stdin")]
    secret: Option<String>,
    /// Read the base32 secret from stdin
    #[arg(long)]
    secret_stdin: bool,
    /// totp, hotp or steam
    #[arg(long = "type", value_name = "TYPE")]
    kind: Option<String>,
    /// SHA1, SHA256 or SHA512
    #[arg(long)]
    algorithm: Option<String>,
    /// Code length
    #[arg(long)]
    digits: Option<u8>,
    /// TOTP period in seconds
    #[arg(long)]
    period: Option<u32>,
    /// HOTP counter
    #[arg(long)]
    counter: Option<u64>,
    /// Tag (repeatable)
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Note
    #[arg(long)]
    note: Option<String>,
    /// Read the QR code(s) of an image (screenshot, photo)
    #[arg(long, value_name = "PATH")]
    image: Option<std::path::PathBuf>,
    /// Select a QR code on the screen (macOS: drag a rectangle around it)
    #[arg(long)]
    screen: bool,
}

/// Captures part of the screen and returns the image (macOS `screencapture -i`).
pub fn capture_screen() -> anyhow::Result<Vec<u8>> {
    if !cfg!(target_os = "macos") {
        return Err(fail(
            exit::USAGE,
            "--screen needs macOS; take a screenshot and pass --image instead",
        ));
    }
    let dir = std::env::temp_dir().join(format!("otpx-{}", std::process::id()));
    crate::paths::make_private_dir(&dir)?;
    let path = dir.join("qr.png");
    eprintln!("Drag a rectangle around the QR code (Esc cancels)…");
    let status = std::process::Command::new("screencapture")
        .args(["-i", "-x", "-t", "png"])
        .arg(&path)
        .status()?;
    let bytes = std::fs::read(&path);
    let _ = std::fs::remove_dir_all(&dir);
    if !status.success() {
        return Err(fail(exit::USAGE, "screen capture failed"));
    }
    bytes.map_err(|_| fail(exit::USAGE, "screen capture cancelled"))
}

fn apply_overrides(e: &mut Entry, a: &AddArgs) -> anyhow::Result<()> {
    if let Some(i) = &a.issuer {
        e.issuer = i.trim().to_owned();
    }
    if let Some(acc) = &a.account {
        e.account = acc.trim().to_owned();
    }
    if let Some(k) = &a.kind {
        e.kind = match k.to_ascii_lowercase().as_str() {
            "totp" => Kind::Totp,
            "hotp" => Kind::Hotp,
            "steam" => Kind::Steam,
            _ => return Err(fail(exit::USAGE, "--type is totp, hotp or steam")),
        };
    }
    if let Some(al) = &a.algorithm {
        e.algorithm = Algorithm::parse(al)
            .ok_or_else(|| fail(exit::USAGE, "--algorithm is SHA1, SHA256 or SHA512"))?;
    }
    if let Some(d) = a.digits {
        e.digits = d;
    }
    if let Some(p) = a.period {
        e.period = p;
    }
    if let Some(c) = a.counter {
        e.counter = c;
    }
    e.tags.extend(a.tags.iter().cloned());
    if let Some(n) = &a.note {
        e.note = n.clone();
    }
    Ok(())
}

fn prompt_line(label: &str) -> anyhow::Result<String> {
    use std::io::Write;
    eprint!("{label}: ");
    std::io::stderr().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_owned())
}

/// Adds accounts.
pub fn add(a: AddArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut texts: Vec<String> = Vec::new();
    if let Some(u) = &a.uri {
        texts.push(if u == "-" {
            read_secret("", true)?.to_string()
        } else {
            u.clone()
        });
    }
    if let Some(p) = &a.image {
        let bytes =
            std::fs::read(p).map_err(|e| fail(exit::USAGE, format!("{}: {e}", p.display())))?;
        texts.extend(otpx_core::qr::decode_image(&bytes).map_err(core_failure)?);
    }
    if a.screen {
        texts.extend(otpx_core::qr::decode_image(&capture_screen()?).map_err(core_failure)?);
    }
    if (a.image.is_some() || a.screen) && texts.is_empty() {
        return Err(fail(exit::NOT_FOUND, "no QR code found in the image"));
    }
    if !texts.is_empty() {
        let got = otpx_core::formats::import(
            texts.join("\n").as_bytes(),
            otpx_core::formats::Format::Uris,
            None,
        )
        .map_err(core_failure)?;
        for s in &got.skipped {
            ctx.ui.warn(&format!("skipped {s}"));
        }
        entries = got.entries;
        if entries.is_empty() {
            return Err(fail(exit::USAGE, "no otpauth:// account in what was given"));
        }
    } else {
        let secret = match (&a.secret, a.secret_stdin) {
            (Some(s), _) => s.clone(),
            (None, true) => read_secret("", true)?.to_string(),
            (None, false) if ui::interactive() => {
                read_secret("Secret (base32): ", false)?.to_string()
            }
            _ => {
                return Err(fail(
                    exit::USAGE,
                    "give an otpauth:// URI, --secret-stdin, --image or --screen",
                ));
            }
        };
        let bytes = otpx_core::b32::decode(&secret).map_err(core_failure)?;
        let mut e = Entry::new("", "", bytes);
        let mut a2 = AddArgs {
            tags: a.tags.clone(),
            ..AddArgs::default()
        };
        a2.issuer.clone_from(&a.issuer);
        a2.account.clone_from(&a.account);
        if a2.issuer.is_none() && a2.account.is_none() && ui::interactive() {
            a2.issuer = Some(prompt_line("Issuer (service)")?);
            a2.account = Some(prompt_line("Account")?);
        }
        e.issuer = a2.issuer.unwrap_or_default();
        e.account = a2.account.unwrap_or_default();
        entries.push(e);
    }
    for e in &mut entries {
        apply_overrides(e, &a)?;
        e.validate().map_err(core_failure)?;
    }
    let mut s = session::open(ctx)?;
    let device = ctx.config().device_id;
    let mut added = 0;
    for e in entries {
        let label = e.label();
        if s.vault.data.entries.iter().any(|x| x.same_account(&e)) {
            ctx.ui.warn(&format!(
                "{} is already in the vault (same secret): skipped",
                ui::clean(&label)
            ));
            continue;
        }
        let id = s
            .vault
            .data
            .add(e, now_ms(), &device)
            .map_err(core_failure)?;
        let e = s
            .vault
            .data
            .entries
            .iter()
            .find(|x| x.id == id)
            .expect("just added");
        ctx.ui.emit("added", entry_json(e));
        let c = e.code_at(now_secs());
        ctx.ui.say(&format!(
            "Added {}  {}",
            ui::clean(&label),
            ctx.ui.paint(&group_code(&c.code), "1")
        ));
        added += 1;
    }
    if added > 0 {
        session::save(ctx, &mut s)?;
    }
    Ok(ExitCode::SUCCESS)
}

/// `otpx list`.
#[derive(Debug, Default, clap::Args)]
pub struct ListArgs {
    /// Only accounts matching this text (issuer, account, tag, note)
    query: Option<String>,
    /// Only accounts with this tag
    #[arg(long)]
    tag: Option<String>,
    /// Do not compute codes
    #[arg(long)]
    no_codes: bool,
}

/// Lists accounts.
pub fn list(a: ListArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let s = session::open(ctx)?;
    let now = now_secs();
    let mut found = s.vault.data.find(a.query.as_deref().unwrap_or(""));
    if let Some(t) = &a.tag {
        found.retain(|e| e.tags.iter().any(|x| x.eq_ignore_ascii_case(t)));
    }
    sort_entries(&mut found);
    let width = found
        .iter()
        .map(|e| e.label().chars().count())
        .max()
        .unwrap_or(0)
        .min(48);
    for e in &found {
        let mut j = entry_json(e);
        let code = (!a.no_codes && e.kind != Kind::Hotp).then(|| e.code_at(now));
        if let Some(c) = &code {
            j["code"] = json!(c.code);
            j["remaining"] = json!(c.remaining);
        }
        ctx.ui.emit("entry", j);
        if !ctx.ui.is_json() {
            let label: String = ui::clean(&e.label()).chars().take(48).collect();
            let star = if e.favorite { "★ " } else { "  " };
            let right = match &code {
                Some(c) => format!(
                    "{}  {}",
                    ctx.ui.paint(&group_code(&c.code), "1"),
                    ctx.ui.dim(&format!("{:>2}s", c.remaining))
                ),
                None if e.kind == Kind::Hotp => ctx.ui.dim("(hotp: otpx code)"),
                None => String::new(),
            };
            println!("{star}{}  {label:<width$}  {right}", ctx.ui.dim(&e.id[..6]));
        }
    }
    if found.is_empty() && !ctx.ui.is_json() {
        ctx.ui.note(if s.vault.data.entries.is_empty() {
            "No account yet: `otpx add`, or `otpx import <file>` (see `otpx import --help`)."
        } else {
            "No account matches."
        });
    }
    Ok(ExitCode::SUCCESS)
}

/// `otpx code`.
#[derive(Debug, clap::Args)]
pub struct CodeArgs {
    /// Account: id, issuer, account name or any part of them
    query: String,
    /// Copy the code (cleared from the clipboard after a while) instead of printing it
    #[arg(short, long)]
    copy: bool,
    /// Also print the next code (TOTP) / do not advance the counter (HOTP)
    #[arg(long)]
    next: bool,
    /// Keep printing the code as it changes (Ctrl-C to stop)
    #[arg(short, long)]
    watch: bool,
}

/// Prints one code.
pub fn code(a: CodeArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let mut s = session::open(ctx)?;
    let e = resolve(&s.vault.data, &a.query)?.clone();
    if e.kind == Kind::Hotp {
        // An HOTP code is used once: show the current counter's code, then move on.
        let c = e.code_at(0);
        if !a.next {
            let device = ctx.config().device_id;
            s.vault
                .data
                .advance_counter(&e.id, now_ms(), &device)
                .map_err(core_failure)?;
            session::save(ctx, &mut s)?;
        }
        let clear = u64::from(s.vault.data.settings.clipboard_clear_secs);
        return output_code(ctx, &e, &c.code, 0, a.copy.then_some(clear), None);
    }
    if a.watch && !ctx.ui.is_json() && !a.copy {
        loop {
            let c = e.code_at(now_secs());
            eprint!(
                "\r{}  {}  {:>2}s ",
                ui::clean(&e.label()),
                ctx.ui.paint(&group_code(&c.code), "1"),
                c.remaining
            );
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    let now = now_secs();
    let c = e.code_at(now);
    let next = a.next.then(|| e.next_code_at(now).code);
    let clear = u64::from(s.vault.data.settings.clipboard_clear_secs);
    output_code(ctx, &e, &c.code, c.remaining, a.copy.then_some(clear), next)
}

/// Prints or copies a code; `copy` is the clipboard delay when copying.
fn output_code(
    ctx: &Ctx,
    e: &Entry,
    code: &str,
    remaining: u32,
    copy: Option<u64>,
    next: Option<String>,
) -> anyhow::Result<ExitCode> {
    if let Some(clear) = copy {
        clipboard::copy(code, clear)?;
    }
    ctx.ui.emit(
        "code",
        json!({
            "id": e.id, "issuer": e.issuer, "account": e.account, "label": e.label(),
            "code": if copy.is_some() { serde_json::Value::Null } else { json!(code) },
            "copied": copy.is_some(), "remaining": remaining, "next": next,
        }),
    );
    if ctx.ui.is_json() {
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(clear) = copy {
        let left = if remaining > 0 {
            format!(", valid {remaining}s")
        } else {
            String::new()
        };
        ctx.ui.note(&format!(
            "Copied the code of {}{left} (clipboard cleared in {clear}s).",
            ui::clean(&e.label())
        ));
    } else if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        let left = if remaining > 0 {
            ctx.ui.dim(&format!("  {remaining}s"))
        } else {
            String::new()
        };
        let nx = next
            .map(|n| ctx.ui.dim(&format!("  next {}", group_code(&n))))
            .unwrap_or_default();
        println!("{}{left}{nx}", ctx.ui.paint(&group_code(code), "1"));
    } else {
        // Piped: the bare code, for scripts.
        println!("{code}");
    }
    Ok(ExitCode::SUCCESS)
}

/// `otpx show`.
#[derive(Debug, clap::Args)]
pub struct ShowArgs {
    /// Account
    query: String,
    /// Also print the secret and the otpauth:// URI
    #[arg(long)]
    secret: bool,
}

/// Details of one account.
pub fn show(a: ShowArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let s = session::open(ctx)?;
    let e = resolve(&s.vault.data, &a.query)?;
    let mut j = entry_json(e);
    if a.secret {
        j["secret"] = json!(e.secret_b32());
        j["uri"] = json!(otpx_core::uri::to_uri(e));
    }
    ctx.ui.emit("entry", j);
    if ctx.ui.is_json() {
        return Ok(ExitCode::SUCCESS);
    }
    let p = |k: &str, v: &str| println!("{:<10}{}", k, ui::clean(v));
    p("id", &e.id);
    p("issuer", &e.issuer);
    p("account", &e.account);
    p("type", e.kind.as_str());
    p("algorithm", e.algorithm.as_str());
    p("digits", &e.digits.to_string());
    match e.kind {
        Kind::Hotp => p("counter", &e.counter.to_string()),
        _ => p("period", &format!("{}s", e.period)),
    }
    if !e.tags.is_empty() {
        p("tags", &e.tags.join(", "));
    }
    if !e.note.is_empty() {
        p("note", &e.note);
    }
    if a.secret {
        p("secret", &e.secret_b32());
        p("uri", &otpx_core::uri::to_uri(e));
    }
    Ok(ExitCode::SUCCESS)
}

/// `otpx edit`.
#[derive(Debug, clap::Args)]
pub struct EditArgs {
    /// Account
    query: String,
    /// New service name
    #[arg(long)]
    issuer: Option<String>,
    /// New account name
    #[arg(long)]
    account: Option<String>,
    /// Add a tag (repeatable)
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Remove a tag (repeatable)
    #[arg(long = "untag")]
    untags: Vec<String>,
    /// New note
    #[arg(long)]
    note: Option<String>,
    /// Mark as favorite (shown first)
    #[arg(long, overrides_with = "no_favorite")]
    favorite: bool,
    /// Unmark as favorite
    #[arg(long)]
    no_favorite: bool,
    /// Code length
    #[arg(long)]
    digits: Option<u8>,
    /// TOTP period in seconds
    #[arg(long)]
    period: Option<u32>,
    /// SHA1, SHA256 or SHA512
    #[arg(long)]
    algorithm: Option<String>,
    /// HOTP counter
    #[arg(long)]
    counter: Option<u64>,
}

/// Changes an account.
pub fn edit(a: EditArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let mut s = session::open(ctx)?;
    let mut e = resolve(&s.vault.data, &a.query)?.clone();
    if let Some(v) = a.issuer {
        e.issuer = v;
    }
    if let Some(v) = a.account {
        e.account = v;
    }
    for t in a.tags {
        if !e.tags.contains(&t) {
            e.tags.push(t);
        }
    }
    e.tags
        .retain(|t| !a.untags.iter().any(|u| u.eq_ignore_ascii_case(t)));
    if let Some(v) = a.note {
        e.note = v;
    }
    if a.favorite {
        e.favorite = true;
    }
    if a.no_favorite {
        e.favorite = false;
    }
    if let Some(v) = a.digits {
        e.digits = v;
    }
    if let Some(v) = a.period {
        e.period = v;
    }
    if let Some(v) = a.algorithm {
        e.algorithm = Algorithm::parse(&v)
            .ok_or_else(|| fail(exit::USAGE, "--algorithm is SHA1, SHA256 or SHA512"))?;
    }
    if let Some(v) = a.counter {
        e.counter = v;
    }
    let device = ctx.config().device_id;
    s.vault
        .data
        .update(e.clone(), now_ms(), &device)
        .map_err(core_failure)?;
    session::save(ctx, &mut s)?;
    ctx.ui.emit("updated", entry_json(&e));
    ctx.ui.say(&format!("Updated {}.", ui::clean(&e.label())));
    Ok(ExitCode::SUCCESS)
}

/// `otpx remove`.
#[derive(Debug, clap::Args)]
pub struct RemoveArgs {
    /// Account
    query: String,
    /// Do not ask
    #[arg(short, long)]
    yes: bool,
}

/// Deletes an account.
pub fn remove(a: RemoveArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let mut s = session::open(ctx)?;
    let e = resolve(&s.vault.data, &a.query)?.clone();
    if !a.yes
        && !ctx.ui.confirm(&format!(
            "Delete {}? You may lock yourself out of that account",
            ui::clean(&e.label())
        ))?
    {
        return Err(fail(exit::USAGE, "cancelled"));
    }
    let device = ctx.config().device_id;
    s.vault
        .data
        .remove(&e.id, now_ms(), &device)
        .map_err(core_failure)?;
    session::save(ctx, &mut s)?;
    ctx.ui
        .emit("removed", json!({ "id": e.id, "label": e.label() }));
    ctx.ui.say(&format!(
        "Deleted {} (undo: `otpx backup restore 1 --only {}`).",
        ui::clean(&e.label()),
        &e.id[..8]
    ));
    Ok(ExitCode::SUCCESS)
}
