//! PUBLIC fixtures only. These failures reach the cryptographic operations.
use crate::{
    Error,
    codec::{Codec, canonical},
    crypto::*,
    local,
};
use serde_json::{Value, json};
#[test]
fn aead_authenticates_aad_keys_lengths_and_tag() {
    let key = random_key().unwrap();
    let nonce = libsodium_rs::random::bytes(24);
    let cipher = encrypt(b"PUBLIC test", b"bound context", &nonce, &key).unwrap();
    assert_eq!(
        &*decrypt(&cipher, b"bound context", &nonce, &key).unwrap(),
        b"PUBLIC test"
    );
    assert_eq!(
        decrypt(&cipher, b"other context", &nonce, &key).unwrap_err(),
        Error("INTEGRITY_FAILURE")
    );
    assert_eq!(
        decrypt(&cipher, b"bound context", &nonce, &[0; 32]).unwrap_err(),
        Error("INTEGRITY_FAILURE")
    );
    assert_eq!(
        decrypt(&cipher, b"bound context", &[0; 24], &key).unwrap_err(),
        Error("INTEGRITY_FAILURE")
    );
    let mut changed = cipher.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(
        decrypt(&changed, b"bound context", &nonce, &key).unwrap_err(),
        Error("INTEGRITY_FAILURE")
    );
    assert_eq!(
        encrypt(b"x", b"", &[0; 23], &key).unwrap_err(),
        Error("INVALID_NONCE")
    );
    assert_eq!(
        encrypt(b"x", b"", &nonce, &[0; 31]).unwrap_err(),
        Error("INVALID_KEY_LENGTH")
    );
}
#[test]
fn native_kdf_rejects_actual_concurrent_jobs_before_allocation() {
    let c = std::sync::Arc::new(Codec::new().unwrap());
    let f: Value = serde_json::from_str(include_str!(
        "../../../fixtures/protocol/p02/v1/crypto.json"
    ))
    .unwrap();
    let parameters = canonical(&f["objects"]["parameters"]).unwrap();
    let phrase = f["inputs"]["phrase"].as_str().unwrap().to_owned();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let jobs: Vec<_> = (0..4)
        .map(|_| {
            let (c, b, p, s) = (
                c.clone(),
                barrier.clone(),
                parameters.clone(),
                phrase.clone(),
            );
            std::thread::spawn(move || {
                b.wait();
                local::phrase_kek(&c, &s, &p)
            })
        })
        .collect();
    let results: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error("KDF_BUSY"))))
            .count(),
        3
    );
    assert_eq!(
        hex::encode(results.iter().find_map(|r| r.as_ref().ok()).unwrap()),
        f["expected"]["phrase_kek_hex"]
    );
    for (field, value) in [
        ("memlimit", 67108863),
        ("memlimit", 268435457),
        ("opslimit", 2),
        ("opslimit", 11),
    ] {
        let mut p = f["objects"]["parameters"].clone();
        p[field] = json!(value);
        assert!(local::phrase_kek(&c, &phrase, &canonical(&p).unwrap()).is_err());
    }
    assert_eq!(
        local::phrase_kek(&c, "1234", &parameters).unwrap_err(),
        Error("STRONG_PHRASE_REQUIRED")
    );
}
#[test]
fn authenticated_frames_cannot_hide_invalid_payloads_or_tags() {
    use crate::objects;
    let c = Codec::new().unwrap();
    let f: Value = serde_json::from_str(include_str!(
        "../../../fixtures/protocol/p02/v1/crypto.json"
    ))
    .unwrap();
    let i = &f["inputs"];
    let o = &f["objects"];
    let group = hex::decode(i["group_key_hex"].as_str().unwrap()).unwrap();
    let secret = hex::decode(i["signing_secret_hex"].as_str().unwrap()).unwrap();
    let public = hex::decode(i["signing_public_hex"].as_str().unwrap()).unwrap();
    let dek = hex::decode(i["object_key_hex"].as_str().unwrap()).unwrap();
    let context = canonical(&o["payload"]["context"]).unwrap();
    for field in ["nonce", "tag", "wrap"] {
        let mut b = o["bundle"].clone();
        match field {
            "nonce" => b["envelope"]["header"]["nonce"] = json!(b64(&[0; 24])),
            "tag" => {
                let mut x = un64(b["ciphertext"].as_str().unwrap()).unwrap();
                *x.last_mut().unwrap() ^= 1;
                b["ciphertext"] = json!(b64(&x));
                b["envelope"]["header"]["ciphertext_digest"] = json!(hash(&x));
            }
            _ => {
                let mut x = un64(b["wrap"]["ciphertext"].as_str().unwrap()).unwrap();
                *x.last_mut().unwrap() ^= 1;
                b["wrap"]["ciphertext"] = json!(b64(&x));
                b["envelope"]["header"]["key_wrap_digest"] = json!(hash(&crate::codec::domain(
                    "p02-v1",
                    "hash",
                    "wrap",
                    &canonical(&b["wrap"]).unwrap()
                )));
            }
        }
        b["envelope"]["signature"] = json!(
            sign(
                &c.signing("p02-v1", "header", &b["envelope"]["header"])
                    .unwrap(),
                &secret
            )
            .unwrap()
        );
        assert_eq!(
            objects::open_object(&c, &canonical(&b).unwrap(), &group, &public, &context)
                .unwrap_err(),
            Error("INTEGRITY_FAILURE")
        );
    }
    for field in ["unknown-field", "inner-context"] {
        let mut p = o["payload"].clone();
        let mut b = o["bundle"].clone();
        if field == "unknown-field" {
            p["extra"] = json!(true);
        } else {
            p["context"]["object_id"] = json!(b64(&[249; 16]));
        }
        let cipher = encrypt(
            &canonical(&p).unwrap(),
            &objects::aad(
                "object-payload",
                &json!({"context":o["payload"]["context"]}),
            )
            .unwrap(),
            &un64(b["envelope"]["header"]["nonce"].as_str().unwrap()).unwrap(),
            &dek,
        )
        .unwrap();
        b["ciphertext"] = json!(b64(&cipher));
        b["envelope"]["header"]["ciphertext_bytes"] = json!(cipher.len().to_string());
        b["envelope"]["header"]["ciphertext_digest"] = json!(hash(&cipher));
        b["envelope"]["signature"] = json!(
            sign(
                &c.signing("p02-v1", "header", &b["envelope"]["header"])
                    .unwrap(),
                &secret
            )
            .unwrap()
        );
        assert_eq!(
            objects::open_object(&c, &canonical(&b).unwrap(), &group, &public, &context)
                .unwrap_err(),
            Error(if field == "unknown-field" {
                "SCHEMA_MISMATCH"
            } else {
                "CONTEXT_MISMATCH"
            })
        );
    }
}
