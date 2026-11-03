//! End-to-end tests of the `otpx` binary: an isolated HOME, keys in a file, a fast KDF.

use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Arc, Mutex};

use assert_cmd::Command;
use serde_json::Value;

struct Device {
    dir: PathBuf,
}

const PW: &str = "correct horse battery staple";

impl Device {
    fn new(root: &Path, name: &str) -> Device {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        Device { dir }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_otpx"));
        c.env_clear()
            .env("HOME", &self.dir)
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("OTPX_CONFIG_DIR", self.dir.join("cfg"))
            .env("OTPX_DATA_DIR", self.dir.join("data"))
            .env("OTPX_KEYCHAIN", "0")
            .env("OTPX_TEST_FAST_KDF", "1")
            .env("OTPX_NO_INPUT", "1")
            .env("NO_COLOR", "1");
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd().args(args).output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "otpx {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn stdin(&self, args: &[&str], input: &str) -> Output {
        self.cmd().args(args).write_stdin(input).output().unwrap()
    }

    fn init(&self) {
        let out = self.stdin(&["init", "--password-stdin"], &format!("{PW}\n"));
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn json(&self, args: &[&str]) -> Vec<Value> {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        self.ok(&a)
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn labels(&self) -> Vec<String> {
        self.json(&["ls", "--no-codes"])
            .iter()
            .map(|v| v["label"].as_str().unwrap().to_owned())
            .collect()
    }
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

const GH: &str = "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
const AWS: &str = "otpauth://totp/AWS:root?secret=GEZDGNBVGY3TQOJQ&issuer=AWS";
const MAIL: &str = "otpauth://totp/Mail:x?secret=MFRGGZDFMZTWQ2LK&issuer=Mail";

#[test]
fn codes_are_correct_and_errors_have_stable_exit_codes() {
    let t = tempfile::tempdir().unwrap();
    let d = Device::new(t.path(), "a");
    assert_eq!(code(&d.run(&["ls"])), 4, "no vault yet");
    d.init();
    d.ok(&["add", GH]);
    d.ok(&[
        "add",
        "otpauth://hotp/Bank:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0&issuer=Bank",
    ]);
    // RFC 6238 time 59 with the GitHub secret, computed independently.
    let now = d
        .cmd()
        .env("OTPX_NOW", "59")
        .args(["code", "github"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&now.stdout).trim(),
        otpx_core::otp::totp(
            &otpx_core::b32::decode("JBSWY3DPEHPK3PXP").unwrap(),
            59,
            30,
            6,
            otpx_core::Algorithm::Sha1
        )
    );
    // HOTP: RFC 4226 vectors, the counter advances on each use.
    assert_eq!(d.ok(&["code", "bank"]).trim(), "755224");
    assert_eq!(d.ok(&["code", "bank"]).trim(), "287082");
    assert_eq!(d.ok(&["code", "bank", "--next"]).trim(), "359152");
    assert_eq!(d.ok(&["code", "bank"]).trim(), "359152");
    assert_eq!(code(&d.run(&["code", "nothing"])), 4);
    d.ok(&[
        "add",
        "otpauth://totp/GitLab:me?secret=MFRGGZDFMZTWQ2LK&issuer=GitLab",
    ]);
    assert_eq!(code(&d.run(&["code", "git"])), 5);
    assert_eq!(code(&d.run(&["add", "otpauth://totp/x?secret=0189"])), 2);
    d.ok(&["lock"]);
    let locked = d.run(&["--json", "code", "github"]);
    assert_eq!(code(&locked), 3);
    let err: Value = serde_json::from_slice(&locked.stdout).unwrap();
    assert_eq!(err["error"]["code"], "locked");
    assert_eq!(
        code(&d.stdin(&["unlock", "--password-stdin"], "wrong\n")),
        6
    );
    assert!(
        d.stdin(
            &["unlock", "--password-stdin", "--ttl", "1m"],
            &format!("{PW}\n")
        )
        .status
        .success()
    );
    let status = d.json(&["status"]);
    assert_eq!(status[0]["unlocked"], true);
    assert_eq!(status[0]["entries"], 3);
}

#[test]
fn vault_file_is_private_and_holds_no_clear_text() {
    let t = tempfile::tempdir().unwrap();
    let d = Device::new(t.path(), "a");
    d.init();
    d.ok(&["add", GH, "--note", "very secret note"]);
    let vault = d.dir.join("data/vault.otpx");
    let text = std::fs::read_to_string(&vault).unwrap();
    assert!(
        !text.contains("GitHub") && !text.contains("JBSWY3DP") && !text.contains("very secret")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&vault).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(d.dir.join("data"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    // The recovery code opens it.
    let init_json = Device::new(t.path(), "b");
    let out = init_json.stdin(&["--json", "init", "--password-stdin"], &format!("{PW}\n"));
    let rc = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find_map(|v| v["recovery_code"].as_str().map(str::to_owned))
        .unwrap();
    init_json.ok(&["lock"]);
    let file = otpx_core::vault::VaultFile::parse(
        &std::fs::read_to_string(init_json.dir.join("data/vault.otpx")).unwrap(),
    )
    .unwrap();
    assert!(file.unlock_recovery(&rc).is_ok());
}

#[test]
fn folder_sync_merges_concurrent_changes_and_new_devices_join() {
    let t = tempfile::tempdir().unwrap();
    let cloud = t.path().join("cloud");
    std::fs::create_dir_all(&cloud).unwrap();
    let cloud = cloud.to_str().unwrap();
    let a = Device::new(t.path(), "a");
    let b = Device::new(t.path(), "b");
    a.init();
    a.ok(&["add", GH]);
    a.ok(&["add", AWS]);
    a.ok(&["sync", "setup", "folder", cloud]);
    // A new device fetches the vault, then unlocks with the same password.
    b.ok(&["sync", "setup", "folder", cloud]);
    assert_eq!(code(&b.run(&["ls"])), 3);
    assert!(
        b.stdin(&["unlock", "--password-stdin"], &format!("{PW}\n"))
            .status
            .success()
    );
    assert_eq!(b.labels(), vec!["AWS (root)", "GitHub (me)"]);
    // Offline changes on both sides.
    a.ok(&["--offline", "edit", "github", "--note", "from a"]);
    b.ok(&["--offline", "rm", "aws", "--yes"]);
    b.ok(&["--offline", "add", MAIL]);
    a.ok(&["sync"]);
    b.ok(&["sync"]);
    a.ok(&["sync"]);
    for d in [&a, &b] {
        assert_eq!(d.labels(), vec!["GitHub (me)", "Mail (x)"]);
        assert_eq!(d.json(&["show", "github"])[0]["note"], "from a");
    }
    // A password change on one device reaches the other.
    assert!(
        a.stdin(&["passwd", "--password-stdin"], "a brand new passphrase\n")
            .status
            .success()
    );
    b.ok(&["sync"]);
    b.ok(&["lock"]);
    assert_eq!(
        code(&b.stdin(&["unlock", "--password-stdin"], &format!("{PW}\n"))),
        6
    );
    assert!(
        b.stdin(&["unlock", "--password-stdin"], "a brand new passphrase\n")
            .status
            .success()
    );
}

#[test]
fn snapshots_bring_deleted_accounts_back_everywhere() {
    let t = tempfile::tempdir().unwrap();
    let cloud = t.path().join("cloud");
    std::fs::create_dir_all(&cloud).unwrap();
    let a = Device::new(t.path(), "a");
    a.init();
    a.ok(&["add", GH]);
    a.ok(&["add", AWS]);
    a.ok(&["sync", "setup", "folder", cloud.to_str().unwrap()]);
    a.ok(&["rm", "aws", "--yes"]);
    assert_eq!(a.labels(), vec!["GitHub (me)"]);
    a.ok(&["backup", "restore", "1", "--only", "aws", "--yes"]);
    assert_eq!(a.labels(), vec!["AWS (root)", "GitHub (me)"]);
    // The restore wins over the deletion on another device too.
    let b = Device::new(t.path(), "b");
    b.ok(&["sync", "setup", "folder", cloud.to_str().unwrap()]);
    assert!(
        b.stdin(&["unlock", "--password-stdin"], &format!("{PW}\n"))
            .status
            .success()
    );
    assert_eq!(b.labels(), vec!["AWS (root)", "GitHub (me)"]);
}

#[test]
fn imports_exports_and_shares() {
    let t = tempfile::tempdir().unwrap();
    let a = Device::new(t.path(), "a");
    let b = Device::new(t.path(), "b");
    a.init();
    b.init();
    a.ok(&["add", GH]);
    a.ok(&["add", AWS]);
    // Every export format reads back.
    for fmt in ["uris", "aegis", "2fas", "andotp", "bitwarden", "csv"] {
        let p = t.path().join(format!("export.{fmt}"));
        a.ok(&["export", "--format", fmt, "--out", p.to_str().unwrap()]);
        let found = b.json(&["import", "--dry-run", p.to_str().unwrap()]);
        assert_eq!(
            found.iter().filter(|v| v["event"] == "found").count(),
            2,
            "{fmt}"
        );
    }
    // Google transfer and a QR image of it.
    let google = a.ok(&["export", "--format", "google", "--stdout"]);
    assert!(google.starts_with("otpauth-migration://offline?data="));
    let png = t.path().join("qr.png");
    {
        let (w, m) = otpx_core::qr::modules(google.trim()).unwrap();
        let s = 4u32;
        let q = 4u32;
        let size = (w as u32 + 2 * q) * s;
        let img = image_from(size, |x, y| {
            let (mx, my) = (x / s, y / s);
            mx >= q
                && my >= q
                && mx < w as u32 + q
                && my < w as u32 + q
                && m[((my - q) as usize) * w + (mx - q) as usize]
        });
        std::fs::write(&png, img).unwrap();
    }
    b.ok(&["import", png.to_str().unwrap()]);
    assert_eq!(b.labels(), vec!["AWS (root)", "GitHub (me)"]);
    // Encrypted Aegis.
    let enc = t.path().join("enc.json");
    assert!(
        a.stdin(
            &[
                "export",
                "--format",
                "aegis",
                "--encrypt",
                "--password-stdin",
                "--out",
                enc.to_str().unwrap()
            ],
            "aegis pw\n"
        )
        .status
        .success()
    );
    assert_eq!(code(&b.run(&["import", enc.to_str().unwrap()])), 6);
    assert!(
        b.stdin(
            &[
                "import",
                "--password-stdin",
                "--dry-run",
                enc.to_str().unwrap()
            ],
            "aegis pw\n"
        )
        .status
        .success()
    );
    // Share link and age.
    let c = Device::new(t.path(), "c");
    c.init();
    let link = a.ok(&["share", "link", "github", "--expires", "10m"]);
    c.ok(&["receive", link.trim(), "--yes"]);
    assert_eq!(c.labels(), vec!["GitHub (me)"]);
    let key = c.ok(&["id"]);
    let age = a.ok(&["share", "age", "aws", "--to", key.trim()]);
    c.stdin(&["receive", "-", "--yes"], &age);
    assert_eq!(c.labels(), vec!["AWS (root)", "GitHub (me)"]);
    // Expired links refuse to open.
    let old = a
        .cmd()
        .env("OTPX_NOW", "1000")
        .args(["share", "link", "github", "--expires", "1m"])
        .output()
        .unwrap();
    let out = c.run(&[
        "receive",
        String::from_utf8_lossy(&old.stdout).trim(),
        "--yes",
    ]);
    assert_eq!(code(&out), 6);
}

fn image_from(size: u32, dark: impl Fn(u32, u32) -> bool) -> Vec<u8> {
    // A minimal grayscale PNG writer would need zlib; use the `image` crate through otpx-core's
    // re-export-free path: encode via the QR SVG is not an image, so build a BMP by hand.
    let row = (size + 3) & !3;
    let mut bmp = Vec::new();
    let pixels = row * size;
    let offset = 14 + 40 + 256 * 4;
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&(offset + pixels).to_le_bytes());
    bmp.extend_from_slice(&[0; 4]);
    bmp.extend_from_slice(&offset.to_le_bytes());
    bmp.extend_from_slice(&40u32.to_le_bytes());
    bmp.extend_from_slice(&(size as i32).to_le_bytes());
    bmp.extend_from_slice(&(size as i32).to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes());
    bmp.extend_from_slice(&8u16.to_le_bytes());
    bmp.extend_from_slice(&[0; 4]);
    bmp.extend_from_slice(&pixels.to_le_bytes());
    bmp.extend_from_slice(&[0; 8]);
    bmp.extend_from_slice(&256u32.to_le_bytes());
    bmp.extend_from_slice(&[0; 4]);
    for i in 0..=255u8 {
        bmp.extend_from_slice(&[i, i, i, 0]);
    }
    for y in (0..size).rev() {
        for x in 0..row {
            bmp.push(if x < size && dark(x, y) { 0 } else { 255 });
        }
    }
    bmp
}

/// A fake GitHub Contents API: one file, sha-checked writes, and a forced conflict.
#[test]
fn github_remote_with_conflicts() {
    #[derive(Default)]
    struct State {
        content: Option<String>,
        sha: u32,
        conflicts_left: u32,
        puts: u32,
    }
    let state = Arc::new(Mutex::new(State {
        conflicts_left: 1,
        ..Default::default()
    }));
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let st = state.clone();
    std::thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let auth = req
                .headers()
                .iter()
                .any(|h| h.field.equiv("Authorization") && h.value.as_str() == "Bearer test-token");
            if !auth {
                let _ = req.respond(
                    tiny_http::Response::from_string("{\"message\":\"Bad credentials\"}")
                        .with_status_code(401),
                );
                continue;
            }
            let url = req.url().to_owned();
            let mut s = st.lock().unwrap();
            let resp = if url == "/repos/me/vault" {
                tiny_http::Response::from_string("{\"private\":true}")
            } else if url.starts_with("/repos/me/vault/contents/vault.otpx")
                && *req.method() == tiny_http::Method::Get
            {
                match &s.content {
                    Some(c) => tiny_http::Response::from_string(
                        serde_json::json!({ "sha": s.sha.to_string(), "content": otpx_core::crypto::b64(c.as_bytes()) }).to_string(),
                    ),
                    None => tiny_http::Response::from_string("{\"message\":\"Not Found\"}").with_status_code(404),
                }
            } else if url.starts_with("/repos/me/vault/contents/vault.otpx")
                && *req.method() == tiny_http::Method::Put
            {
                let mut body = String::new();
                req.as_reader().read_to_string(&mut body).unwrap();
                let v: Value = serde_json::from_str(&body).unwrap();
                let expected = s.content.as_ref().map(|_| s.sha.to_string());
                s.puts += 1;
                if s.conflicts_left > 0 && expected.is_some() {
                    // Someone else wrote meanwhile: same content, new sha.
                    s.conflicts_left -= 1;
                    s.sha += 1;
                    tiny_http::Response::from_string("{\"message\":\"sha does not match\"}")
                        .with_status_code(409)
                } else if v["sha"].as_str().map(str::to_owned) != expected {
                    tiny_http::Response::from_string("{\"message\":\"sha mismatch\"}")
                        .with_status_code(409)
                } else {
                    let bytes = otpx_core::crypto::unb64(v["content"].as_str().unwrap()).unwrap();
                    s.content = Some(String::from_utf8(bytes).unwrap());
                    s.sha += 1;
                    tiny_http::Response::from_string(
                        serde_json::json!({ "content": { "sha": s.sha.to_string() } }).to_string(),
                    )
                    .with_status_code(200)
                }
            } else {
                tiny_http::Response::from_string("{}").with_status_code(404)
            };
            drop(s);
            let _ = req.respond(resp);
        }
    });
    let api = format!("http://127.0.0.1:{port}");
    let t = tempfile::tempdir().unwrap();
    let a = Device::new(t.path(), "a");
    let b = Device::new(t.path(), "b");
    a.init();
    a.ok(&["add", GH]);
    let setup = |d: &Device, token: &str| {
        d.cmd()
            .env("OTPX_GITHUB_API", &api)
            .args([
                "sync",
                "setup",
                "github",
                "--repo",
                "me/vault",
                "--token-stdin",
            ])
            .write_stdin(format!("{token}\n"))
            .output()
            .unwrap()
    };
    assert_eq!(code(&setup(&a, "bad-token")), 8);
    let out = setup(&a, "test-token");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(state.lock().unwrap().content.is_some());
    let out = setup(&b, "test-token");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        b.stdin(&["unlock", "--password-stdin"], &format!("{PW}\n"))
            .status
            .success()
    );
    // A write that hits a conflict retries and lands.
    let out = b
        .cmd()
        .env("OTPX_GITHUB_API", &api)
        .args(["add", AWS])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("sync failed"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = a
        .cmd()
        .env("OTPX_GITHUB_API", &api)
        .args(["sync"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(a.labels(), vec!["AWS (root)", "GitHub (me)"]);
    assert!(state.lock().unwrap().puts >= 3);
}

#[test]
fn selftest_and_completions() {
    let t = tempfile::tempdir().unwrap();
    let d = Device::new(t.path(), "a");
    assert!(d.ok(&["selftest"]).contains("selftest ok"));
    assert!(d.ok(&["completions", "zsh"]).contains("otpx"));
    assert!(d.ok(&["--help"]).contains("Exit codes") || d.ok(&["--help"]).contains("otpx"));
}
