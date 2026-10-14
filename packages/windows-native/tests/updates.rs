use anynote_crypto_core::{codec::canonical, crypto::hash};
use anynote_windows_native::updates::UpdatePolicy;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
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
