//! The golden vault opens in wasm with the same codes (`wasm-pack test --node crates/otpx-wasm`).

use otpx_wasm::Vault;
use wasm_bindgen_test::wasm_bindgen_test;

const VAULT: &str = include_str!("../../../testdata/golden/vault.otpx");
const EXPECTED: &str = include_str!("../../../testdata/golden/expected.json");

#[wasm_bindgen_test]
fn golden_vault_in_wasm() {
    let exp: serde_json::Value = serde_json::from_str(EXPECTED).unwrap();
    let v = Vault::unlock_password(VAULT, exp["password"].as_str().unwrap())
        .map_err(|_| "unlock")
        .unwrap();
    let entries: serde_json::Value = serde_json::from_str(&v.entries()).unwrap();
    let codes: serde_json::Value =
        serde_json::from_str(&v.codes(exp["time"].as_f64().unwrap())).unwrap();
    for want in exp["codes"].as_array().unwrap() {
        let id = entries
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == want["label"])
            .unwrap()["id"]
            .clone();
        let got = codes
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap();
        assert_eq!(got["code"], want["code"]);
    }
    // A vault made in wasm opens again after sealing.
    let mut fresh = Vault::create("pw", 1.0, "test")
        .map_err(|_| "create")
        .unwrap();
    assert!(fresh.take_recovery_code().is_some());
    let sealed = fresh.seal().map_err(|_| "seal").unwrap();
    assert!(Vault::unlock_password(&sealed, "pw").is_ok());
}
