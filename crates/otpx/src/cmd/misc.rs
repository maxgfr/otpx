//! web, doctor, selftest, completions.

use std::path::PathBuf;
use std::process::ExitCode;

use otpx_core::crypto::Argon2Params;
use otpx_core::formats::{self, ExportFormat, Format};
use otpx_core::model::Entry;
use serde_json::json;

use crate::{Ctx, exit, fail, human_duration, now_ms, touchid};

/// `otpx web`.
#[derive(Debug, clap::Args)]
pub struct WebArgs {
    /// Port (fixed by default so the browser keeps the app's settings between runs)
    #[arg(long, default_value_t = 7357)]
    port: u16,
    /// Do not open the browser
    #[arg(long)]
    no_open: bool,
    /// Serve this directory instead of the embedded app (development)
    #[arg(long, value_name = "DIR")]
    dir: Option<PathBuf>,
}

/// Serves the web app locally.
pub fn web(a: WebArgs, ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let src = crate::web::Source::pick(a.dir)?;
    crate::web::serve(ctx, src, a.port, !a.no_open)?;
    Ok(ExitCode::SUCCESS)
}

/// `otpx doctor`.
pub fn doctor(ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let cfg = ctx.config();
    let mut ok = true;
    let file = ctx.store.read();
    let has_vault = matches!(file, Ok(Some(_)));
    match &file {
        Ok(Some((f, _))) => ctx.ui.check(
            "vault",
            true,
            &format!("{} ({})", ctx.store.vault().display(), &f.id[..8]),
            None,
        ),
        Ok(None) => {
            ok = false;
            ctx.ui.check(
                "vault",
                false,
                "none",
                Some("`otpx init`, or `otpx sync setup …` to fetch yours"),
            );
        }
        Err(e) => {
            ok = false;
            ctx.ui.check(
                "vault",
                false,
                &format!("{e:#}"),
                Some("fix the permissions or restore `otpx backup ls`"),
            );
        }
    }
    let secrets = ctx.secrets();
    let probe = secrets.get("probe");
    ctx.ui.check(
        "keychain",
        probe.is_ok(),
        &format!("keys kept in the {}", secrets.backend()),
        Some("unlock the login keychain, or set OTPX_KEYCHAIN=0"),
    );
    ok &= probe.is_ok();
    if has_vault {
        let remote_ok = !cfg.remotes.is_empty();
        ctx.ui.check(
            "off-device copy",
            remote_ok,
            &if remote_ok {
                format!("{} remote(s)", cfg.remotes.len())
            } else {
                "none: losing this machine loses the vault".into()
            },
            Some("`otpx sync setup github --repo you/otpx-vault`"),
        );
        ok &= remote_ok;
        for r in &cfg.remotes {
            let age = now_ms().saturating_sub(r.last_sync) / 1000;
            let fresh = r.last_sync != 0 && age < 7 * 86_400;
            let detail = if r.last_sync == 0 {
                "never synced".to_owned()
            } else {
                format!("synced {} ago", human_duration(age))
            };
            ctx.ui.check(
                &format!("remote {}", r.name),
                fresh,
                &detail,
                Some("`otpx sync`"),
            );
            if r.needs_token() {
                let t = crate::sync::token(ctx, r).is_ok();
                ctx.ui.check(
                    &format!("token {}", r.name),
                    t,
                    if t { "present" } else { "missing" },
                    Some("`otpx sync setup` again"),
                );
                ok &= t;
            }
        }
        ctx.ui.check(
            "recovery code",
            cfg.recovery_confirmed,
            if cfg.recovery_confirmed {
                "written down"
            } else {
                "not confirmed"
            },
            Some("`otpx recovery --reset` shows a new one, then `otpx recovery --confirm`"),
        );
        ok &= cfg.recovery_confirmed;
    }
    ctx.ui.check(
        "touch id",
        true,
        &match (touchid::available(), cfg.quick.touchid) {
            (true, true) => "on".to_owned(),
            (true, false) => "available (`otpx quick-unlock enable touchid`)".to_owned(),
            (false, _) => "not available here".to_owned(),
        },
        None,
    );
    ctx.ui.emit("doctor", json!({ "ok": ok }));
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(exit::ERROR)
    })
}

/// `otpx selftest`: codes, crypto, formats, QR, shares; no files, no network.
pub fn selftest(ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let mut failures = Vec::new();
    let mut check = |name: &str, ok: bool| {
        ctx.ui
            .check(name, ok, if ok { "ok" } else { "FAILED" }, None);
        if !ok {
            failures.push(name.to_owned());
        }
    };
    check(
        "rfc4226 hotp",
        otpx_core::otp::hotp(b"12345678901234567890", 1, 6, otpx_core::Algorithm::Sha1) == "287082",
    );
    check(
        "rfc6238 totp",
        otpx_core::otp::totp(
            b"12345678901234567890",
            59,
            30,
            8,
            otpx_core::Algorithm::Sha1,
        ) == "94287082",
    );
    let vault_ok = (|| -> otpx_core::Result<bool> {
        let mut c =
            otpx_core::vault::Unlocked::create("selftest", Argon2Params::KEY, 1, "selftest")?;
        c.vault.data.add(
            Entry::new("Self", "test", b"12345678901234567890".to_vec()),
            1,
            "t",
        )?;
        let f = otpx_core::vault::VaultFile::parse(&c.vault.seal()?.to_json())?;
        let back = f.unlock_password("selftest")?;
        Ok(back.data == c.vault.data
            && f.unlock_password("nope").is_err()
            && f.unlock_recovery(&c.recovery_code).is_ok())
    })();
    check("vault encryption", vault_ok.unwrap_or(false));
    let fmt_ok = (|| -> otpx_core::Result<bool> {
        let e = vec![Entry::new("Self", "test", b"12345678901234567890".to_vec())];
        for (_, f, _) in ExportFormat::ALL
            .iter()
            .filter(|x| x.1 != ExportFormat::Paper)
        {
            let out = formats::export(&e, *f, None, 0)?;
            let back = formats::import(out.as_bytes(), Format::Auto, None)?;
            if back.entries.len() != 1 || back.entries[0].secret != e[0].secret {
                return Ok(false);
            }
        }
        Ok(true)
    })();
    check("import/export formats", fmt_ok.unwrap_or(false));
    let share_ok = (|| -> otpx_core::Result<bool> {
        let s = otpx_core::share::Share::accounts(&[Entry::new("A", "b", vec![1; 10])], 0);
        let l = otpx_core::share::create_link(otpx_core::share::DEFAULT_BASE, &s, Some("p"))?;
        Ok(otpx_core::share::open_link(&l, Some("p"), 1)? == s)
    })();
    check("share links", share_ok.unwrap_or(false));
    check(
        "qr codes",
        otpx_core::qr::svg("otpauth://totp/x?secret=JBSWY3DP").is_ok(),
    );
    ctx.ui.emit(
        "selftest",
        json!({ "ok": failures.is_empty(), "failed": failures }),
    );
    if failures.is_empty() {
        ctx.ui.say("selftest ok");
        Ok(ExitCode::SUCCESS)
    } else {
        Err(fail(
            exit::ERROR,
            format!("selftest failed: {}", failures.join(", ")),
        ))
    }
}

/// `otpx completions`.
#[derive(Debug, clap::Args)]
pub struct CompletionsArgs {
    /// bash, zsh, fish, elvish or powershell
    shell: clap_complete::Shell,
}

/// Prints completions.
pub fn completions(a: CompletionsArgs) -> anyhow::Result<ExitCode> {
    clap_complete::generate(
        a.shell,
        &mut crate::command(),
        "otpx",
        &mut std::io::stdout(),
    );
    Ok(ExitCode::SUCCESS)
}
