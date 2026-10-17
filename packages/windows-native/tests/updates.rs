use anynote_crypto_core::{codec::canonical, crypto::hash};
use anynote_windows_native::updates::UpdatePolicy;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
#[test]
fn update_installer_dispatch_rejects_archives_and_invalid_pe_offsets() {
    let mut pe = vec![0u8; 128];
    pe[..2].copy_from_slice(b"MZ");
    pe[60..64].copy_from_slice(&64u32.to_le_bytes());
    pe[64..68].copy_from_slice(b"PE\0\0");
    UpdatePolicy::windows_installer(&pe).unwrap();
    for bytes in [
        b"PK\x03\x04".to_vec(),
        b"PK\x05\x06".to_vec(),
        vec![],
        pe[..67].to_vec(),
    ] {
        assert_eq!(
            UpdatePolicy::windows_installer(&bytes).unwrap_err().0,
            "UPDATE_FORMAT_UNSUPPORTED"
        );
    }
    for offset in [0, 63, 125, u32::MAX] {
        let mut bad = pe.clone();
        bad[60..64].copy_from_slice(&offset.to_le_bytes());
        assert!(UpdatePolicy::windows_installer(&bad).is_err());
    }
    // A ZIP prefix cannot enter the updater ZIP extractor even if other bytes
    // include a PE header or the publisher signed an unsupported archive.
    pe[..4].copy_from_slice(b"PK\x03\x04");
    assert!(UpdatePolicy::windows_installer(&pe).is_err());
}
#[test]
fn maintained_signatures_bind_update_application_version_platform_channel_url_and_payload() {
    let fixture: Value = serde_json::from_slice(include_bytes!(
        "../../../fixtures/windows/p14/updates/signatures.json"
    ))
    .unwrap();
    let policy: UpdatePolicy = serde_json::from_value(fixture["policy"].clone()).unwrap();
    let claims = &fixture["claims"];
    let signature = fixture["claims_signature"].as_str().unwrap();
    let url = claims["url"].as_str().unwrap();
    let verified = policy
        .signed_claims("0.14.0", "0.14.1", url, claims, signature)
        .unwrap();
    let payload = STANDARD
        .decode(fixture["artifact_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(verified.artifact_sha256, hash(&payload));
    let key_text = STANDARD.decode(&policy.public_key).unwrap();
    let key = minisign_verify::PublicKey::decode(std::str::from_utf8(&key_text).unwrap()).unwrap();
    let sig_text = STANDARD
        .decode(fixture["artifact_signature"].as_str().unwrap())
        .unwrap();
    let sig = minisign_verify::Signature::decode(std::str::from_utf8(&sig_text).unwrap()).unwrap();
    key.verify(&payload, &sig, true).unwrap();
    let mut bad = payload.clone();
    bad[0] ^= 1;
    assert!(key.verify(&bad, &sig, true).is_err());
    for field in [
        "application_id",
        "version",
        "platform",
        "channel",
        "url",
        "artifact_sha256",
    ] {
        let mut bad = claims.clone();
        bad[field] = serde_json::json!("tampered");
        assert!(
            policy
                .signed_claims("0.14.0", "0.14.1", url, &bad, signature)
                .is_err()
        );
    }
    assert!(
        policy
            .signed_claims("0.14.1", "0.14.1", url, claims, signature)
            .is_err()
    );
    assert!(
        policy
            .signed_claims("0.15.0", "0.14.1", url, claims, signature)
            .is_err()
    );
    assert!(
        policy
            .signed_claims("0.14.0", "9.9.9", url, claims, signature)
            .is_err()
    );
    assert!(
        policy
            .signed_claims(
                "0.14.0",
                "0.14.1",
                "https://attacker.example/other.exe",
                claims,
                signature
            )
            .is_err()
    );
    let mut wrong: UpdatePolicy = serde_json::from_value(fixture["policy"].clone()).unwrap();
    wrong.channel = "stable".into();
    assert!(
        wrong
            .signed_claims("0.14.0", "0.14.1", url, claims, signature)
            .is_err()
    );
    assert!(
        !canonical(&fixture)
            .unwrap()
            .windows(11)
            .any(|w| w == b"PRIVATE KEY")
    );
}
