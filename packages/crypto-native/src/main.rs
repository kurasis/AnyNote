// PUBLIC deterministic corpus runner only; never enrolls a device or handles R.
use libsodium_rs::crypto_sign::{KeyPair, PublicKey};
use serde_json::Value;
use std::{fs, io};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    libsodium_rs::ensure_init()?;
    let path = std::env::args()
        .nth(1)
        .ok_or("PUBLIC fixture path required")?;
    let f: Value = serde_json::from_slice(&fs::read(path)?)?;
    if f["purpose"] != "PUBLIC_TEST_ONLY_NOT_PRODUCT_AUTHORIZATION" {
        return Err("Not a public corpus".into());
    }
    let h = f["canonical_header"]
        .as_str()
        .ok_or("Missing header")?
        .as_bytes();
    let signature: [u8; 64] = hex::decode(f["signature_hex"].as_str().ok_or("Missing signature")?)?
        .try_into()
        .map_err(|_| io::Error::other("Bad signature length"))?;
    let public = PublicKey::from_bytes(&hex::decode(
        f["public_key_hex"].as_str().ok_or("Missing key")?,
    )?)?;
    let key = KeyPair::from_seed(&[1; 32])?;
    assert!(anynote_public_signature::verify_object(
        h, &signature, &public
    ));
    let native = anynote_public_signature::sign_object(h, &key.secret_key)?;
    assert_eq!(native, signature);
    let mut bad = signature;
    bad[0] ^= 1;
    assert!(!anynote_public_signature::verify_object(h, &bad, &public));
    let mut changed = h.to_vec();
    changed.push(b' ');
    assert!(!anynote_public_signature::verify_object(
        &changed, &signature, &public
    ));
    println!(
        "{}",
        serde_json::json!({"status":"PASS","checks":4,"native_signature_hex":hex::encode(native),"scope":"PUBLIC_SIGNING_BYTES_NOT_JSON_AUTHORITY"})
    );
    Ok(())
}
