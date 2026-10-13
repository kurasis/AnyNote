//! P11 bounded encrypted public parts with private candidate keys in the manifest.
use super::*;
use libsodium_rs::crypto_aead::xchacha20poly1305 as aead;

fn number(v: &Value) -> Result<u64> {
    text(v)?
        .parse::<u64>()
        .map_err(|_| Error("INTEGRITY_FAILURE"))
}
type Prepared = (Value, Vec<(String, Vec<u8>)>);
const PART: usize = 262_144;
const TOTAL: usize = 33_554_432;
fn validate(codec: &Codec, kind: &str, v: &Value) -> Result<()> {
    codec
        .validate("p11-sync", kind, v)
        .map_err(|_| Error("SCHEMA_MISMATCH"))
}
fn context(scope: &Scope, pins: &Value, id: &str, kind: &str) -> Result<Value> {
    scope.validate()?;
    check(
        valid_id(id)
            && [
                "note-control",
                "group-evidence",
                "sync-control",
                "content-part",
            ]
            .contains(&kind),
        "INVALID_LOCAL_FRAME",
    )?;
    Ok(
        json!({"purpose":"paged-content-context","version":1,"service_id":scope.service_id,"account_id":scope.account_id,"device_id":scope.device_id,"profile_id":scope.profile_id,"record_id":id,"record_kind":kind,"root_fingerprint":pins["root_fingerprint"]}),
    )
}
fn aad(ctx: &Value) -> Result<Vec<u8>> {
    let mut bytes = b"AnyNote/P11/local-pages\0".to_vec();
    bytes.extend(canonical(ctx)?);
    Ok(bytes)
}
fn seal_value(
    codec: &Codec,
    scope: &Scope,
    pins: &Value,
    id: &str,
    kind: &str,
    value: &Value,
    key: &[u8],
) -> Result<Value> {
    let ctx = context(scope, pins, id, kind)?;
    validate(codec, "local-context", &ctx)?;
    let plain = Zeroizing::new(canonical(value)?);
    check(
        plain.len()
            <= if kind == "content-part" {
                360_448
            } else {
                65_536
            },
        "RESOURCE_LIMIT",
    )?;
    let nonce = aead::Nonce::try_from(libsodium_rs::random::bytes(24).as_slice())
        .map_err(|_| Error("INVALID_NONCE"))?;
    let key = aead::Key::from_bytes(key).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    let cipher = aead::encrypt(&plain, Some(&aad(&ctx)?), &nonce, &key)
        .map_err(|_| Error("CRYPTO_FAILURE"))?;
    let f = json!({"contract":"p11-local-v1","protocol":"anynote","protocol_version":1,"purpose":"paged-content-local","context":ctx,"nonce":b64(nonce.as_ref()),"ciphertext":b64(&cipher)});
    validate(codec, "local-frame", &f)?;
    Ok(f)
}
fn open_value(
    codec: &Codec,
    scope: &Scope,
    pins: &Value,
    id: &str,
    kind: &str,
    f: &Value,
    key: &[u8],
) -> Result<Value> {
    validate(codec, "local-frame", f)?;
    check(
        f["context"] == context(scope, pins, id, kind)?,
        "LOCAL_CONTEXT_MISMATCH",
    )?;
    let cipher = un64(text(&f["ciphertext"])?)?;
    check(
        cipher.len() >= 16
            && cipher.len()
                <= if kind == "content-part" {
                    360_464
                } else {
                    65_552
                },
        "RESOURCE_LIMIT",
    )?;
    let nonce = aead::Nonce::try_from(un64(text(&f["nonce"])?)?.as_slice())
        .map_err(|_| Error("INVALID_NONCE"))?;
    let key = aead::Key::from_bytes(key).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    let plain = Zeroizing::new(
        aead::decrypt(&cipher, Some(&aad(&f["context"])?), &nonce, &key)
            .map_err(|_| Error("INTEGRITY_FAILURE"))?,
    );
    strict(
        &plain,
        if kind == "content-part" {
            360_448
        } else {
            65_536
        },
    )
}
pub(crate) fn manifest(
    codec: &Codec,
    scope: &Scope,
    pins: &Value,
    id: &str,
    kind: &str,
    f: &Value,
    key: &[u8],
) -> Result<Value> {
    let m = open_value(codec, scope, pins, id, kind, f, key)?;
    validate(codec, "manifest", &m)?;
    check(
        m["kind"] == kind && (kind == "group-evidence" || m["private"].is_null()),
        "INTEGRITY_FAILURE",
    )?;
    let size = number(&m["bytes"])?;
    check(size > 0 && size <= TOTAL as u64, "RESOURCE_LIMIT")?;
    let mut ids = std::collections::BTreeSet::new();
    for p in m["parts"].as_array().ok_or(Error("INTEGRITY_FAILURE"))? {
        check(
            ids.insert(text(&p["record_id"])?.to_owned()),
            "DUPLICATE_RECORD",
        )?;
    }
    Ok(m)
}
fn open_part(
    codec: &Codec,
    scope: &Scope,
    pins: &Value,
    id: &str,
    index: usize,
    f: &Value,
    key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let p = open_value(codec, scope, pins, id, "content-part", f, key)?;
    validate(codec, "local-part", &p)?;
    let bytes = Zeroizing::new(un64(text(&p["record_bytes"])?)?);
    check(
        number(&p["index"])? == index as u64
            && number(&p["bytes"])? == bytes.len() as u64
            && !bytes.is_empty()
            && bytes.len() <= PART
            && p["digest"] == hash(&bytes),
        "INTEGRITY_FAILURE",
    )?;
    Ok(bytes)
}
fn seal_part(
    codec: &Codec,
    scope: &Scope,
    pins: &Value,
    id: &str,
    index: usize,
    bytes: &[u8],
    key: &[u8],
) -> Result<Value> {
    let p = json!({"purpose":"paged-content-part","version":1,"index":index.to_string(),"bytes":bytes.len().to_string(),"digest":hash(bytes),"record_bytes":b64(bytes)});
    validate(codec, "local-part", &p)?;
    seal_value(codec, scope, pins, id, "content-part", &p, key)
}
pub(crate) fn prepare(
    codec: &Codec,
    scope: &Scope,
    pins: &Value,
    id: &str,
    kind: &str,
    data: &Value,
    key: &[u8],
) -> Result<Prepared> {
    let mut public = data.clone();
    let mut private = if kind == "group-evidence" && !public["pending_key"].is_null() {
        json!({"pending_key":public["pending_key"]})
    } else {
        Value::Null
    };
    if let Some(v) = public.as_object_mut() {
        v.remove("pending_key");
    }
    let bytes = Zeroizing::new(canonical(&public)?);
    wipe_value(&mut public);
    check(!bytes.is_empty() && bytes.len() <= TOTAL, "RESOURCE_LIMIT")?;
    let mut refs = Vec::new();
    let mut frames = Vec::new();
    for (index, part) in bytes.chunks(PART).enumerate() {
        let part_id = random_id();
        let f = seal_part(codec, scope, pins, &part_id, index, part, key)?;
        refs.push(json!({"record_id":part_id,"digest":hash(part),"bytes":part.len().to_string()}));
        frames.push((part_id, canonical(&f)?));
    }
    let mut m = json!({"purpose":"paged-content-manifest","version":1,"kind":kind,"parts":refs,"digest":hash(&bytes),"bytes":bytes.len().to_string(),"private":private});
    wipe_value(&mut private);
    let result = (|| {
        validate(codec, "manifest", &m)?;
        seal_value(codec, scope, pins, id, kind, &m, key)
    })();
    wipe_value(&mut m);
    Ok((result?, frames))
}
pub(crate) fn open(
    codec: &Codec,
    conn: &Connection,
    scope: &Scope,
    pins: &Value,
    binding: (&str, &str),
    f: &Value,
    key: &[u8],
) -> Result<Value> {
    let (id, kind) = binding;
    let mut m = manifest(codec, scope, pins, id, kind, f, key)?;
    let result = (|| {
        let refs = m["parts"].as_array().ok_or(Error("INTEGRITY_FAILURE"))?;
        let mut bytes = Zeroizing::new(Vec::new());
        for (index, p) in refs.iter().enumerate() {
            let part_id = text(&p["record_id"])?;
            let f = frame(conn, part_id)?;
            let chunk = open_part(codec, scope, pins, part_id, index, &f, key)?;
            check(
                number(&p["bytes"])? == chunk.len() as u64
                    && p["digest"] == hash(&chunk)
                    && (index == refs.len() - 1 || chunk.len() == PART),
                "INTEGRITY_FAILURE",
            )?;
            check(bytes.len() + chunk.len() <= TOTAL, "RESOURCE_LIMIT")?;
            bytes.extend(chunk.iter());
        }
        check(
            number(&m["bytes"])? == bytes.len() as u64 && m["digest"] == hash(&bytes),
            "INTEGRITY_FAILURE",
        )?;
        let mut data = strict(&bytes, TOTAL)?;
        if !m["private"].is_null() {
            check(data.get("pending_key").is_none(), "INTEGRITY_FAILURE")?;
            data.as_object_mut()
                .ok_or(Error("INTEGRITY_FAILURE"))?
                .insert("pending_key".into(), m["private"]["pending_key"].clone());
        }
        Ok(data)
    })();
    wipe_value(&mut m);
    result
}
pub(crate) fn rotate(
    codec: &Codec,
    scope: &Scope,
    pins: &Value,
    id: &str,
    f: &Value,
    old: &[u8],
    next: &[u8],
) -> Result<Value> {
    let kind = text(&f["context"]["record_kind"])?;
    if kind == "content-part" {
        let p = open_value(codec, scope, pins, id, kind, f, old)?;
        validate(codec, "local-part", &p)?;
        let index = number(&p["index"])? as usize;
        check(index < 128, "INTEGRITY_FAILURE")?;
        let bytes = open_part(codec, scope, pins, id, index, f, old)?;
        return seal_part(codec, scope, pins, id, index, &bytes, next);
    }
    let mut m = manifest(codec, scope, pins, id, kind, f, old)?;
    let result = seal_value(codec, scope, pins, id, kind, &m, next);
    wipe_value(&mut m);
    result
}
