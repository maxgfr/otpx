use super::*;
use crate::model::{Entry, Kind};
use crate::otp::Algorithm;

fn samples() -> Vec<Entry> {
    let mut a = Entry::new(
        "GitHub",
        "me@example.com",
        crate::b32::decode("JBSWY3DPEHPK3PXP").unwrap(),
    );
    a.tags = vec!["work".into()];
    a.note = "2FA for the org".into();
    let mut b = Entry::new("Bank", "alice", b"12345678901234567890".to_vec());
    b.kind = Kind::Hotp;
    b.counter = 4;
    b.digits = 8;
    b.algorithm = Algorithm::Sha256;
    let mut c = Entry::new("Steam", "gamer", vec![9; 20]);
    c.kind = Kind::Steam;
    c.validate().unwrap();
    let mut d = Entry::new("Odd", "x", vec![7; 10]);
    d.period = 60;
    d.algorithm = Algorithm::Sha512;
    vec![a, b, c, d]
}

/// The fields every format must carry.
fn core_fields(e: &Entry) -> (Kind, String, String, Vec<u8>, Algorithm, u8, u32, u64) {
    let period = if e.kind == Kind::Hotp { 0 } else { e.period };
    let counter = if e.kind == Kind::Hotp { e.counter } else { 0 };
    (
        e.kind,
        e.issuer.clone(),
        e.account.clone(),
        e.secret.clone(),
        e.algorithm,
        e.digits,
        period,
        counter,
    )
}

fn round_trip(fmt: ExportFormat, password: Option<&str>) -> Imported {
    let out = export(&samples(), fmt, password, 1_700_000_000_000).unwrap();
    let back = import(out.as_bytes(), Format::Auto, password).unwrap();
    assert!(back.skipped.is_empty(), "{fmt:?}: {:?}", back.skipped);
    back
}

#[test]
fn every_format_round_trips() {
    for (fmt, pw) in [
        (ExportFormat::Uris, None),
        (ExportFormat::Aegis, None),
        (ExportFormat::Aegis, Some("aegis pass")),
        (ExportFormat::TwoFas, None),
        (ExportFormat::AndOtp, None),
        (ExportFormat::Bitwarden, None),
        (ExportFormat::Csv, None),
    ] {
        let back = round_trip(fmt, pw);
        let want: Vec<_> = samples().iter().map(core_fields).collect();
        let got: Vec<_> = back.entries.iter().map(core_fields).collect();
        assert_eq!(got, want, "{fmt:?}");
    }
}

#[test]
fn tags_and_notes_survive_where_supported() {
    for fmt in [ExportFormat::Aegis, ExportFormat::Csv] {
        let back = round_trip(fmt, None);
        assert_eq!(back.entries[0].tags, vec!["work".to_owned()], "{fmt:?}");
        assert_eq!(back.entries[0].note, "2FA for the org", "{fmt:?}");
    }
}

#[test]
fn encrypted_aegis_needs_the_password() {
    let out = export(&samples(), ExportFormat::Aegis, Some("pw"), 0).unwrap();
    assert!(!out.contains("GitHub"));
    assert!(matches!(
        import(out.as_bytes(), Format::Auto, None),
        Err(Error::NeedsPassword(_))
    ));
    assert!(matches!(
        import(out.as_bytes(), Format::Auto, Some("nope")),
        Err(Error::Decrypt)
    ));
}

#[test]
fn google_transfer_round_trip_and_batches() {
    let mut many = Vec::new();
    for i in 0..(google::PER_CODE + 3) {
        many.push(Entry::new(
            "Svc",
            &format!("user{i}"),
            vec![u8::try_from(i).unwrap(); 10],
        ));
    }
    many.extend(samples());
    let uris = google::export(&many).unwrap();
    assert_eq!(uris.len(), 2);
    // Steam and the 60-second account cannot travel to Google Authenticator.
    assert_eq!(
        google::not_exportable(&many),
        vec!["Steam (gamer)".to_owned(), "Odd (x)".to_owned()]
    );
    let all = import(uris.join("\n").as_bytes(), Format::Auto, None).unwrap();
    assert_eq!(all.entries.len(), many.len() - 2);
    assert!(all.missing_batches().is_empty());
    let half = import(uris[1].as_bytes(), Format::Auto, None).unwrap();
    assert_eq!(half.missing_batches(), vec![0]);
    let hotp = all.entries.iter().find(|e| e.kind == Kind::Hotp).unwrap();
    assert_eq!(
        (hotp.counter, hotp.digits, hotp.algorithm),
        (4, 8, Algorithm::Sha256)
    );
}

#[test]
fn real_google_transfer_uri() {
    // A transfer made by Google Authenticator (account "Example:alice@google.com",
    // secret JBSWY3DPEHPK3PXP), as encoded by the app with the `+` turned into `%2B`.
    let payload = google::MigrationPayload {
        otp_parameters: vec![google::OtpParameters {
            secret: crate::b32::decode("JBSWY3DPEHPK3PXP").unwrap(),
            name: "Example:alice@google.com".into(),
            issuer: "Example".into(),
            algorithm: 1,
            digits: 1,
            r#type: 2,
            counter: 0,
        }],
        version: 1,
        batch_size: 1,
        batch_index: 0,
        batch_id: -1_320_898_453,
    };
    let b64 = crate::crypto::b64(&prost::Message::encode_to_vec(&payload));
    let uri = format!(
        "otpauth-migration://offline?data={}",
        b64.replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let got = import(uri.as_bytes(), Format::Auto, None).unwrap();
    assert_eq!(got.entries.len(), 1);
    assert_eq!(
        (
            got.entries[0].issuer.as_str(),
            got.entries[0].account.as_str()
        ),
        ("Example", "alice@google.com")
    );
    // Same with the raw `+` turned into a space by a careless copy.
    let spaced = format!("otpauth-migration://offline?data={}", b64.replace('+', " "));
    assert_eq!(google::decode(&spaced).unwrap(), payload);
}

#[test]
fn encrypted_2fas_and_andotp() {
    let plain = export(&samples(), ExportFormat::TwoFas, None, 0).unwrap();
    let v: serde_json::Value = serde_json::from_str(&plain).unwrap();
    let services = serde_json::to_vec(&v["services"]).unwrap();
    let enc = serde_json::json!({
        "services": [],
        "servicesEncrypted": twofas::encrypt_for_tests(&services, "2fas pw"),
        "schemaVersion": 4,
    })
    .to_string();
    assert!(matches!(
        import(enc.as_bytes(), Format::Auto, None),
        Err(Error::NeedsPassword(_))
    ));
    assert_eq!(
        import(enc.as_bytes(), Format::Auto, Some("2fas pw"))
            .unwrap()
            .entries
            .len(),
        4
    );

    let plain = export(&samples(), ExportFormat::AndOtp, None, 0).unwrap();
    let enc = andotp::encrypt_for_tests(plain.as_bytes(), "andotp pw");
    assert_eq!(detect(&enc), Format::AndOtp);
    assert_eq!(
        import(&enc, Format::Auto, Some("andotp pw"))
            .unwrap()
            .entries
            .len(),
        4
    );
    assert!(import(&enc, Format::Auto, Some("bad")).is_err());
}

#[test]
fn totp_cli_file() {
    let json = r#"[{"name":"work","accounts":[{"name":"github","token":"JBSWY3DPEHPK3PXP","prefix":"","algorithm":"","length":0,"timePeriod":0},{"name":"aws","token":"GEZDGNBVGY3TQOJQ","prefix":"x","algorithm":"sha256","length":8,"timePeriod":60}]}]"#;
    let plain = import(json.as_bytes(), Format::Auto, None).unwrap();
    assert_eq!(plain.format, "totp-cli");
    assert_eq!(plain.entries.len(), 2);
    assert_eq!(
        (
            plain.entries[1].digits,
            plain.entries[1].period,
            plain.entries[1].algorithm
        ),
        (8, 60, Algorithm::Sha256)
    );
    // The encrypted file is an armored age file with a scrypt passphrase stanza.
    let enc = {
        use std::io::Write;
        let e = age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(
            "cli pw".to_owned(),
        ));
        let mut out = Vec::new();
        let armor =
            age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)
                .unwrap();
        let mut w = e.wrap_output(armor).unwrap();
        w.write_all(json.as_bytes()).unwrap();
        w.finish().unwrap().finish().unwrap();
        out
    };
    assert_eq!(detect(&enc), Format::TotpCli);
    assert_eq!(
        import(&enc, Format::Auto, Some("cli pw"))
            .unwrap()
            .entries
            .len(),
        2
    );
}

#[test]
fn bitwarden_variants_and_csv_headers() {
    let bw = r#"{"encrypted":false,"items":[
        {"name":"Site","login":{"username":"u","totp":"JBSWY3DPEHPK3PXP"}},
        {"name":"Game","login":{"username":"g","totp":"steam://JBSWY3DPEHPK3PXP"}},
        {"name":"NoTotp","login":{"username":"n","totp":null}}]}"#;
    let got = import(bw.as_bytes(), Format::Auto, None).unwrap();
    assert_eq!(got.entries.len(), 2);
    assert_eq!(got.entries[1].kind, Kind::Steam);
    let csv = "Title;Username;TOTP Secret\nMail;bob;JBSWY3DPEHPK3PXP\nBroken;x;!!!\n";
    let got = import(csv.as_bytes(), Format::Auto, None).unwrap();
    assert_eq!(got.format, "CSV");
    assert_eq!(
        (
            got.entries[0].issuer.as_str(),
            got.entries[0].account.as_str()
        ),
        ("Mail", "bob")
    );
    assert_eq!(got.skipped.len(), 1);
}

#[test]
fn uris_inside_other_text() {
    let text = "My codes:\n - otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP.\n<a href=\"otpauth://totp/B:b?secret=GEZDGNBVGY3TQOJQ\">b</a>";
    assert_eq!(
        import(text.as_bytes(), Format::Auto, None)
            .unwrap()
            .entries
            .len(),
        2
    );
}

#[test]
fn otpx_vault_import_and_paper() {
    let mut c = crate::vault::Unlocked::create("pw", crate::crypto::Argon2Params::TEST, 1).unwrap();
    for e in samples() {
        c.vault.data.add(e, 1, "d").unwrap();
    }
    let json = c.vault.seal().unwrap().to_json();
    assert_eq!(detect(json.as_bytes()), Format::Otpx);
    assert_eq!(
        import(json.as_bytes(), Format::Auto, Some("pw"))
            .unwrap()
            .entries
            .len(),
        4
    );
    let html = paper::export(&samples(), Some(&c.recovery_code), 0).unwrap();
    assert!(html.contains("JBSW Y3DP EHPK 3PXP"));
    assert!(html.contains(&c.recovery_code));
    assert!(html.matches("<svg").count() == 4);
}

#[test]
fn format_names() {
    for (name, fmt, _) in ExportFormat::ALL {
        assert_eq!(ExportFormat::parse(name), Some(*fmt));
    }
    assert_eq!(Format::parse("Microsoft"), Some(Format::MsAuth));
}
