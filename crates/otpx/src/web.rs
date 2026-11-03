//! `otpx web`: the web app served from this machine.
//!
//! Its origin (`http://127.0.0.1:<port>`) is its own, unlike the GitHub Pages copy which
//! shares `maxgfr.github.io` with other sites. With a one-time token in the URL fragment,
//! the page also reads and writes the local vault file through `/api/vault` (encrypted
//! blobs only: the page decrypts with your password, like everywhere else).

use std::borrow::Cow;
use std::path::PathBuf;

use tiny_http::{Header, Method, Response, Server};

use crate::sync::Version;
use crate::{Ctx, exit, fail, now_ms};

#[cfg(feature = "embed-web")]
#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/dist"]
struct Assets;

/// Where the files come from.
pub enum Source {
    /// Embedded at build time.
    Embedded,
    /// A directory (development).
    Dir(PathBuf),
}

impl Source {
    /// The embedded build if any, else `web/dist` next to the sources.
    pub fn pick(dir: Option<PathBuf>) -> anyhow::Result<Source> {
        if let Some(d) = dir {
            return Ok(Source::Dir(d));
        }
        if cfg!(feature = "embed-web") {
            return Ok(Source::Embedded);
        }
        let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../web/dist");
        if dev.join("index.html").is_file() {
            return Ok(Source::Dir(dev));
        }
        Err(fail(
            exit::NOT_FOUND,
            "this otpx build has no web app inside: use https://maxgfr.github.io/otpx/, or build it (scripts/build-web.sh) and pass --dir web/dist",
        ))
    }

    fn get(&self, path: &str) -> Option<Cow<'static, [u8]>> {
        match self {
            #[cfg(feature = "embed-web")]
            Source::Embedded => Assets::get(path).map(|f| f.data),
            #[cfg(not(feature = "embed-web"))]
            Source::Embedded => None,
            Source::Dir(d) => {
                let p = d.join(path);
                // No escaping the directory.
                let canon = p.canonicalize().ok()?;
                if !canon.starts_with(d.canonicalize().ok()?) {
                    return None;
                }
                std::fs::read(canon).ok().map(Cow::Owned)
            }
        }
    }
}

fn mime(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "wasm" => "application/wasm",
        "json" | "webmanifest" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn header(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("valid header")
}

fn secured<R: std::io::Read>(mut r: Response<R>) -> Response<R> {
    for (k, v) in [
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("X-Frame-Options", "DENY"),
        ("Cache-Control", "no-store"),
        (
            "Permissions-Policy",
            "camera=(self), microphone=(), geolocation=()",
        ),
        (
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' https://api.github.com; img-src 'self' data: blob:; style-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'",
        ),
    ] {
        r.add_header(header(k, v));
    }
    r
}

fn version_of(text: &str) -> Version {
    data_encoding::HEXLOWER.encode(&<sha2::Sha256 as sha2::Digest>::digest(text.as_bytes())[..16])
}

/// Serves until Ctrl-C.
pub fn serve(ctx: &Ctx, source: Source, port: u16, open_browser: bool) -> anyhow::Result<()> {
    let server = Server::http(("127.0.0.1", port)).map_err(|e| {
        fail(
            exit::ERROR,
            format!("cannot listen on 127.0.0.1:{port}: {e} (try --port)"),
        )
    })?;
    let port = server.server_addr().to_ip().map_or(port, |a| a.port());
    let token = otpx_core::model::random_id(24).map_err(crate::core_failure)?;
    let base = format!("http://127.0.0.1:{port}/");
    let url = format!("{base}#local={token}");
    ctx.ui
        .emit("web", serde_json::json!({ "url": base, "port": port }));
    ctx.ui.say(&format!(
        "otpx web app on {base} (local vault linked). Ctrl-C to stop."
    ));
    if !open_browser || open::that(&url).is_err() {
        ctx.ui.note(&format!("Open {url}"));
    }
    let allowed_hosts = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    for mut req in server.incoming_requests() {
        // DNS rebinding: only our own host names.
        let host = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Host"))
            .map(|h| h.value.as_str().to_owned())
            .unwrap_or_default();
        if !allowed_hosts.contains(&host) {
            let _ = req.respond(Response::from_string("forbidden host").with_status_code(403));
            continue;
        }
        let url_path = req.url().split('?').next().unwrap_or("/").to_owned();
        if url_path == "/api/vault" {
            let auth = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("X-Otpx-Token"))
                .map(|h| h.value.as_str().to_owned());
            if auth.as_deref() != Some(token.as_str()) {
                let _ = req.respond(secured(
                    Response::from_string("missing or wrong token").with_status_code(401),
                ));
                continue;
            }
            let resp = api_vault(ctx, &mut req);
            let _ = req.respond(secured(resp));
            continue;
        }
        let rel = url_path.trim_start_matches('/');
        let rel = if rel.is_empty() || rel.ends_with('/') {
            format!("{rel}index.html")
        } else {
            rel.to_owned()
        };
        match source.get(&rel) {
            Some(body) => {
                let r = Response::from_data(body.into_owned())
                    .with_header(header("Content-Type", mime(&rel)));
                let _ = req.respond(secured(r));
            }
            None => {
                let _ = req.respond(secured(
                    Response::from_string("not found").with_status_code(404),
                ));
            }
        }
    }
    Ok(())
}

fn api_vault(ctx: &Ctx, req: &mut tiny_http::Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let json = |status: u16, v: serde_json::Value| {
        Response::from_string(v.to_string())
            .with_status_code(status)
            .with_header(header("Content-Type", "application/json"))
    };
    match req.method() {
        Method::Get => match ctx.store.read() {
            Ok(Some((_, text))) => json(
                200,
                serde_json::json!({ "content": text, "version": version_of(&text) }),
            ),
            Ok(None) => json(404, serde_json::json!({ "error": "no vault" })),
            Err(e) => json(500, serde_json::json!({ "error": e.to_string() })),
        },
        Method::Put => {
            let mut body = String::new();
            if std::io::Read::read_to_string(&mut req.as_reader().take(16 << 20), &mut body)
                .is_err()
            {
                return json(400, serde_json::json!({ "error": "unreadable body" }));
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
                return json(400, serde_json::json!({ "error": "not JSON" }));
            };
            let content = v["content"].as_str().unwrap_or_default();
            let base = v["version"].as_str();
            if otpx_core::vault::VaultFile::parse(content).is_err() {
                return json(400, serde_json::json!({ "error": "not an otpx vault" }));
            }
            let Ok(_lock) = ctx.store.lock() else {
                return json(500, serde_json::json!({ "error": "cannot lock the vault" }));
            };
            let current = ctx.store.read().ok().flatten().map(|(_, t)| version_of(&t));
            if current.as_deref() != base {
                return json(409, serde_json::json!({ "error": "changed meanwhile" }));
            }
            match ctx.store.write(content, now_ms()) {
                Ok(()) => json(200, serde_json::json!({ "version": version_of(content) })),
                Err(e) => json(500, serde_json::json!({ "error": e.to_string() })),
            }
        }
        _ => json(405, serde_json::json!({ "error": "method" })),
    }
}

use std::io::Read as _;
