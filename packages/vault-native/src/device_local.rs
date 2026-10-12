//! Additive P08 AEAD frame, byte-equivalent to the maintained browser adapter.
use super::*;
use libsodium_rs::crypto_aead::xchacha20poly1305 as aead;

pub(crate) fn control_id(scope: &Scope) -> Result<String> {
    let mut bytes = b"AnyNote/P08/local-control\0".to_vec();
    bytes.extend(canonical(
        &serde_json::to_value(scope).map_err(|_| Error("INVALID_PROFILE"))?,
    )?);
    Ok(b64(&un64(&hash(&bytes))?[..16]))
}
fn validate(kind: &str, value: &Value) -> Result<()> {
    static CODEC: std::sync::OnceLock<Codec> = std::sync::OnceLock::new();
    if CODEC.get().is_none() {
        let _ = CODEC.set(Codec::new()?);
    }
    CODEC
        .get()
        .ok_or(Error("SCHEMA_CONFIGURATION"))?
        .validate("p08-local-v1", kind, value)
        .map_err(|_| Error("SCHEMA_MISMATCH"))
}
fn context(scope: &Scope, pins: &Value, id: &str, kind: &str) -> Result<Value> {
    scope.validate()?;
    check(
        valid_id(id)
            && ["device-control", "roster-page"].contains(&kind)
            && un64(text(&pins["root_fingerprint"])?)?.len() == 32,
        "INVALID_LOCAL_FRAME",
    )?;
    Ok(
        json!({"purpose":"device-lifecycle-local-context","version":1,"service_id":scope.service_id,"account_id":scope.account_id,"device_id":scope.device_id,"profile_id":scope.profile_id,"record_id":id,"record_kind":kind,"root_fingerprint":pins["root_fingerprint"]}),
    )
}
fn aad(context: &Value) -> Result<Vec<u8>> {
    let mut bytes = b"AnyNote/P08/local-lifecycle\0".to_vec();
    bytes.extend(canonical(context)?);
    Ok(bytes)
}
pub(crate) fn seal(
    scope: &Scope,
    pins: &Value,
    id: &str,
    kind: &str,
    data: &Value,
    key: &[u8],
) -> Result<Value> {
    validate(
        if kind == "device-control" {
            "local-control"
        } else {
            "local-roster-page"
        },
        data,
    )?;
    let context = context(scope, pins, id, kind)?;
    let plain = Zeroizing::new(canonical(data)?);
    check(plain.len() <= 262144, "RESOURCE_LIMIT")?;
    let nonce = aead::Nonce::try_from(libsodium_rs::random::bytes(24).as_slice())
        .map_err(|_| Error("INVALID_NONCE"))?;
    let key = aead::Key::from_bytes(key).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    let ciphertext = aead::encrypt(&plain, Some(&aad(&context)?), &nonce, &key)
        .map_err(|_| Error("CRYPTO_FAILURE"))?;
    Ok(
        json!({"contract":"p08-local-v1","protocol":"anynote","protocol_version":1,"purpose":"device-lifecycle-local","context":context,"nonce":b64(nonce.as_ref()),"ciphertext":b64(&ciphertext)}),
    )
}
pub(crate) fn open(
    scope: &Scope,
    pins: &Value,
    id: &str,
    kind: &str,
    frame: &Value,
    key: &[u8],
) -> Result<Value> {
    validate("local-frame", frame)?;
    check(
        frame.as_object().is_some_and(|v| v.len() == 7)
            && frame["contract"] == "p08-local-v1"
            && frame["protocol"] == "anynote"
            && frame["protocol_version"] == 1
            && frame["purpose"] == "device-lifecycle-local"
            && frame["context"] == context(scope, pins, id, kind)?,
        "LOCAL_CONTEXT_MISMATCH",
    )?;
    let cipher = un64(text(&frame["ciphertext"])?)?;
    check((16..=262160).contains(&cipher.len()), "RESOURCE_LIMIT")?;
    let nonce = aead::Nonce::try_from(un64(text(&frame["nonce"])?)?.as_slice())
        .map_err(|_| Error("INVALID_NONCE"))?;
    let key = aead::Key::from_bytes(key).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    let plain = Zeroizing::new(
        aead::decrypt(&cipher, Some(&aad(&frame["context"])?), &nonce, &key)
            .map_err(|_| Error("INTEGRITY_FAILURE"))?,
    );
    let data = strict(&plain, 262144)?;
    validate(
        if kind == "device-control" {
            "local-control"
        } else {
            "local-roster-page"
        },
        &data,
    )?;
    Ok(data)
}
