//! Golden vault: a file written once (`OTPX_WRITE_GOLDEN=1 cargo test -p otpx-core --test
//! golden`) that every build must still open with the same codes, natively and in wasm
//! (`crates/otpx-wasm/tests/golden.rs`, `web/test/golden.test.ts`).

use otpx_core::crypto::Argon2Params;
use otpx_core::model::{Entry, Kind};
use otpx_core::vault::{Unlocked, VaultFile};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/golden");
const PASSWORD: &str = "golden password";

fn expected() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{DIR}/expected.json")).unwrap()).unwrap()
}

#[test]
fn golden_vault_opens_with_the_same_codes() {
    if std::env::var_os("OTPX_WRITE_GOLDEN").is_some() {
        write();
    }
    let text = std::fs::read_to_string(format!("{DIR}/vault.otpx")).unwrap();
    let file = VaultFile::parse(&text).unwrap();
    let exp = expected();
    let open = file.unlock_password(PASSWORD).unwrap();
    assert!(
        file.unlock_recovery(exp["recovery_code"].as_str().unwrap())
            .is_ok()
    );
    let t = exp["time"].as_u64().unwrap();
    for want in exp["codes"].as_array().unwrap() {
        let e = open
            .data
            .entries
            .iter()
            .find(|e| e.label() == want["label"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            e.code_at(t).code,
            want["code"].as_str().unwrap(),
            "{}",
            e.label()
        );
    }
}

fn write() {
    let c = Unlocked::create(PASSWORD, Argon2Params::TEST, 1_700_000_000_000).unwrap();
    let mut v = c.vault;
    let mut add = |issuer: &str, account: &str, secret: &[u8], f: &dyn Fn(&mut Entry)| {
        let mut e = Entry::new(issuer, account, secret.to_vec());
        f(&mut e);
        v.data.add(e, 1_700_000_000_000, "golden").unwrap();
    };
    add("GitHub", "me@example.com", b"12345678901234567890", &|_| {});
    add("Bank", "alice", b"12345678901234567890123456789012", &|e| {
        e.algorithm = otpx_core::Algorithm::Sha256;
        e.digits = 8;
    });
    add("Steam", "gamer", b"12345678901234567890", &|e| {
        e.kind = Kind::Steam
    });
    add("Old", "hotp", b"12345678901234567890", &|e| {
        e.kind = Kind::Hotp;
        e.counter = 3;
    });
    let t = 1_234_567_890u64;
    let codes: Vec<_> = v
        .data
        .entries
        .iter()
        .map(|e| serde_json::json!({ "label": e.label(), "code": e.code_at(t).code }))
        .collect();
    std::fs::write(format!("{DIR}/vault.otpx"), v.seal().unwrap().to_json()).unwrap();
    let exp = serde_json::json!({ "password": PASSWORD, "recovery_code": c.recovery_code, "time": t, "codes": codes });
    std::fs::write(
        format!("{DIR}/expected.json"),
        serde_json::to_string_pretty(&exp).unwrap() + "\n",
    )
    .unwrap();
}
