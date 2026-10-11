use crate::{Error, Result, require};
use crate::{
    codec::{Codec, canonical, domain, text},
    crypto::*,
    objects::aad,
};
use serde_json::{Value, json};
use std::sync::Mutex;
use zeroize::Zeroizing;
static KDF: Mutex<()> = Mutex::new(());
pub fn phrase_kek(c: &Codec, phrase: &str, parameters: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let p = c.decode("p02-v1", "argon2-parameters", parameters)?;
    require(
        (24..=1024).contains(&phrase.len())
            && phrase
                .split(ecma_whitespace)
                .filter(|word| !word.is_empty())
                .count()
                >= 5,
        "STRONG_PHRASE_REQUIRED",
    )?;
    let _guard = KDF.try_lock().map_err(|_| Error("KDF_BUSY"))?;
    libsodium_rs::crypto_pwhash::pwhash(
        32,
        phrase.as_bytes(),
        &un64(text(&p["salt"])?)?,
        p["opslimit"].as_u64().unwrap(),
        p["memlimit"].as_u64().unwrap() as usize,
        libsodium_rs::crypto_pwhash::ALG_ARGON2ID13,
    )
    .map(Zeroizing::new)
    .map_err(|_| Error("KDF_FAILURE"))
}
// Match the frozen browser strength predicate; KDF bytes are never normalized.
fn ecma_whitespace(c: char) -> bool {
    matches!(c, '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}
pub fn prf_kek(
    c: &Codec,
    context: &[u8],
    credential: &str,
    salt: &[u8],
    result: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let context = c.decode("p02-v1", "unlock-context", context)?;
    require(
        context["method"] == "webauthn-prf",
        "WRAPPER_METHOD_MISMATCH",
    )?;
    require(
        !credential.is_empty()
            && credential.len() <= 1366
            && un64(credential).is_ok()
            && salt.len() == 32,
        "INVALID_CREDENTIAL_ID",
    )?;
    hkdf(
        result,
        salt,
        &domain(
            "p02-v1",
            "hkdf",
            "local-prf-kek",
            &canonical(&json!({"context":context,"credential_id":credential}))?,
        ),
    )
}
pub fn native_kek(c: &Codec, descriptor: &[u8], result: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let d = crate::codec::strict(descriptor, 65536)?;
    require(
        d.get("nonce").is_none() && d.get("ciphertext").is_none(),
        "INVALID_DESCRIPTOR",
    )?;
    let mut w = d.clone();
    w["nonce"] = json!(b64(&[0; 12]));
    w["ciphertext"] = json!(b64(&[0; 48]));
    c.validate("p02-v1", "native-wrapper", &w)?;
    hkdf(
        result,
        &un64(text(&d["prf_salt"])?)?,
        &domain("p02-v1", "hkdf", "windows-prf-kek", &canonical(&d)?),
    )
}
pub fn wrap(c: &Codec, kind: &str, descriptor: &[u8], key: &[u8], kek: &[u8]) -> Result<Value> {
    require(
        ["phrase-wrapper", "prf-wrapper"].contains(&kind),
        "UNSUPPORTED_SCHEMA",
    )?;
    require(key.len() == 32, "INVALID_KEY_LENGTH")?;
    let mut w = crate::codec::strict(descriptor, 65536)?;
    require(
        w.get("nonce").is_none() && w.get("ciphertext").is_none(),
        "INVALID_DESCRIPTOR",
    )?;
    let n = libsodium_rs::random::bytes(24);
    w["nonce"] = json!(b64(&n));
    w["ciphertext"] = json!(b64(&[0; 48]));
    c.validate("p02-v1", kind, &w)?;
    w["ciphertext"] = json!(b64(&encrypt(
        key,
        &aad("local-unlock", &crate::codec::strict(descriptor, 65536)?)?,
        &n,
        kek
    )?));
    Ok(w)
}
pub fn unwrap(
    c: &Codec,
    kind: &str,
    bytes: &[u8],
    expected: &[u8],
    kek: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    require(
        ["phrase-wrapper", "prf-wrapper"].contains(&kind),
        "UNSUPPORTED_SCHEMA",
    )?;
    let w = c.decode("p02-v1", kind, bytes)?;
    let mut d = w.clone();
    d.as_object_mut().unwrap().remove("nonce");
    d.as_object_mut().unwrap().remove("ciphertext");
    require(
        d == crate::codec::strict(expected, 65536)?,
        "LOCAL_CONTEXT_MISMATCH",
    )?;
    let key = decrypt(
        &un64(text(&w["ciphertext"])?)?,
        &aad("local-unlock", &d)?,
        &un64(text(&w["nonce"])?)?,
        kek,
    )?;
    require(key.len() == 32, "INVALID_KEY_LENGTH")?;
    Ok(key)
}
pub fn wrap_native(c: &Codec, descriptor: &[u8], key: &[u8], result: &[u8]) -> Result<Value> {
    use aes_gcm::{
        Aes256Gcm, KeyInit,
        aead::{Aead, Payload},
    };
    require(key.len() == 32, "INVALID_KEY_LENGTH")?;
    let mut d = crate::codec::strict(descriptor, 65536)?;
    let kek = native_kek(c, descriptor, result)?;
    let n = libsodium_rs::random::bytes(12);
    let cipher = Aes256Gcm::new_from_slice(&kek)
        .map_err(|_| Error("INVALID_KEY_LENGTH"))?
        .encrypt(
            aes_gcm::Nonce::try_from(n.as_slice())
                .map_err(|_| Error("INVALID_NONCE"))?
                .as_ref(),
            Payload {
                msg: key,
                aad: &aad("local-unlock", &d)?,
            },
        )
        .map_err(|_| Error("CRYPTO_FAILURE"))?;
    d["nonce"] = json!(b64(&n));
    d["ciphertext"] = json!(b64(&cipher));
    c.validate("p02-v1", "native-wrapper", &d)?;
    Ok(d)
}
pub fn unwrap_native(
    c: &Codec,
    bytes: &[u8],
    expected: &[u8],
    result: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use aes_gcm::{
        Aes256Gcm, KeyInit,
        aead::{Aead, Payload},
    };
    let w = c.decode("p02-v1", "native-wrapper", bytes)?;
    let mut d = w.clone();
    d.as_object_mut().unwrap().remove("nonce");
    d.as_object_mut().unwrap().remove("ciphertext");
    require(
        d == crate::codec::strict(expected, 65536)?,
        "LOCAL_CONTEXT_MISMATCH",
    )?;
    let kek = native_kek(c, expected, result)?;
    let n = un64(text(&w["nonce"])?)?;
    let cipher = un64(text(&w["ciphertext"])?)?;
    let plain = Aes256Gcm::new_from_slice(&kek)
        .map_err(|_| Error("INVALID_KEY_LENGTH"))?
        .decrypt(
            aes_gcm::Nonce::try_from(n.as_slice())
                .map_err(|_| Error("INVALID_NONCE"))?
                .as_ref(),
            Payload {
                msg: &cipher,
                aad: &aad("local-unlock", &d)?,
            },
        )
        .map_err(|_| Error("INTEGRITY_FAILURE"))?;
    require(plain.len() == 32, "INVALID_KEY_LENGTH")?;
    Ok(Zeroizing::new(plain))
}
