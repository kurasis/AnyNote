//! Protected P13 records for trusted native content coordinators. No renderer raw-write route.
use super::*;
use libsodium_rs::crypto_aead::xchacha20poly1305 as aead;
fn values<'a>(v: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    v[field].as_array().ok_or(Error("INTEGRITY_FAILURE"))
}
const PART: usize = 262144;
const TOTAL: usize = 16777216;
const KINDS: &[&str] = &[
    "content-control",
    "search-page",
    "file-metadata",
    "export-state",
    "import-state",
    "preview-state",
    "content-part",
];
pub fn control_id(scope: &Scope) -> Result<String> {
    let mut bytes = b"AnyNote/P13/content-control\0".to_vec();
    bytes.extend(canonical(&json!(scope))?);
    Ok(b64(&un64(&hash(&bytes))?[..16]))
}
fn context(scope: &Scope, pins: &Value, id: &str, kind: &str) -> Result<Value> {
    check(
        valid_id(id) && KINDS.contains(&kind),
        "INVALID_CONTENT_RECORD",
    )?;
    let mut value = json!(scope);
    let map = value.as_object_mut().ok_or(Error("INVALID_PROFILE"))?;
    map.insert("purpose".into(), json!("protected-content-context"));
    map.insert("version".into(), json!(1));
    map.insert("record_id".into(), json!(id));
    map.insert("record_kind".into(), json!(kind));
    map.insert("root_fingerprint".into(), pins["root_fingerprint"].clone());
    Ok(value)
}
fn aad(ctx: &Value) -> Result<Vec<u8>> {
    let mut bytes = b"AnyNote/P13/protected-content\0".to_vec();
    bytes.extend(canonical(ctx)?);
    Ok(bytes)
}
fn seal(
    scope: &Scope,
    pins: &Value,
    id: &str,
    kind: &str,
    value: &Value,
    key: &[u8],
) -> Result<Value> {
    let ctx = context(scope, pins, id, kind)?;
    let plain = Zeroizing::new(canonical(value)?);
    check(plain.len() <= 360432, "RESOURCE_LIMIT")?;
    let nonce = aead::Nonce::try_from(libsodium_rs::random::bytes(24).as_slice())
        .map_err(|_| Error("INVALID_NONCE"))?;
    let key = aead::Key::from_bytes(key).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    let cipher = aead::encrypt(&plain, Some(&aad(&ctx)?), &nonce, &key)
        .map_err(|_| Error("CRYPTO_FAILURE"))?;
    Ok(
        json!({"contract":"p13-content-v1","protocol":"anynote","protocol_version":1,"purpose":"protected-content-local","context":ctx,"nonce":b64(nonce.as_ref()),"ciphertext":b64(&cipher)}),
    )
}
fn open(
    scope: &Scope,
    pins: &Value,
    id: &str,
    kind: &str,
    frame: &Value,
    key: &[u8],
) -> Result<Value> {
    check(
        frame.as_object().is_some_and(|m| m.len() == 7)
            && frame["contract"] == "p13-content-v1"
            && frame["protocol"] == "anynote"
            && frame["protocol_version"] == 1
            && frame["purpose"] == "protected-content-local"
            && frame["context"] == context(scope, pins, id, kind)?,
        "LOCAL_CONTEXT_MISMATCH",
    )?;
    let cipher = un64(text(&frame["ciphertext"])?)?;
    check((16..=360448).contains(&cipher.len()), "RESOURCE_LIMIT")?;
    let nonce = aead::Nonce::try_from(un64(text(&frame["nonce"])?)?.as_slice())
        .map_err(|_| Error("INVALID_NONCE"))?;
    let key = aead::Key::from_bytes(key).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    let plain = Zeroizing::new(
        aead::decrypt(&cipher, Some(&aad(&frame["context"])?), &nonce, &key)
            .map_err(|_| Error("INTEGRITY_FAILURE"))?,
    );
    strict(&plain, 360432)
}
pub(crate) fn rotate(
    scope: &Scope,
    pins: &Value,
    id: &str,
    kind: &str,
    frame: &Value,
    key: &[u8],
    next: &[u8],
) -> Result<Value> {
    let mut value = open(scope, pins, id, kind, frame, key)?;
    let result = seal(scope, pins, id, kind, &value, next);
    wipe_value(&mut value);
    result
}
fn refs(
    scope: &Scope,
    pins: &Value,
    id: &str,
    kind: &str,
    frame: &Value,
    key: &[u8],
) -> Result<Value> {
    let manifest = open(scope, pins, id, kind, frame, key)?;
    let bytes = manifest["bytes"]
        .as_u64()
        .ok_or(Error("INTEGRITY_FAILURE"))?;
    let parts = values(&manifest, "parts")?;
    check(
        kind != "content-part"
            && manifest["purpose"] == "protected-content-manifest"
            && manifest["version"] == 1
            && manifest["kind"] == kind
            && (1..=TOTAL as u64).contains(&bytes)
            && parts.len() == bytes.div_ceil(PART as u64) as usize,
        "INTEGRITY_FAILURE",
    )?;
    let mut seen = std::collections::BTreeSet::new();
    for (index, p) in parts.iter().enumerate() {
        check(
            valid_id(text(&p["record_id"])?)
                && seen.insert(text(&p["record_id"])?)
                && p["index"] == index
                && p["bytes"]
                    .as_u64()
                    .is_some_and(|b| b > 0 && b <= PART as u64)
                && un64(text(&p["digest"])?)?.len() == 32,
            "INTEGRITY_FAILURE",
        )?;
    }
    Ok(manifest)
}
fn read(
    conn: &Connection,
    scope: &Scope,
    pins: &Value,
    id: &str,
    kind: &str,
    key: &[u8],
) -> Result<Value> {
    let manifest = refs(scope, pins, id, kind, &frame(conn, id)?, key)?;
    let mut bytes = Zeroizing::new(Vec::new());
    for (index, p) in values(&manifest, "parts")?.iter().enumerate() {
        let part_id = text(&p["record_id"])?;
        let mut part = open(
            scope,
            pins,
            part_id,
            "content-part",
            &frame(conn, part_id)?,
            key,
        )?;
        let chunk = Zeroizing::new(un64(text(&part["record_bytes"])?)?);
        check(
            part["purpose"] == "protected-content-part"
                && part["version"] == 1
                && part["root_id"] == id
                && part["root_kind"] == kind
                && part["index"] == index
                && part["bytes"] == p["bytes"]
                && part["digest"] == p["digest"]
                && chunk.len() == p["bytes"].as_u64().unwrap_or(0) as usize
                && hash(&chunk) == p["digest"]
                && (index == values(&manifest, "parts")?.len() - 1 || chunk.len() == PART),
            "INTEGRITY_FAILURE",
        )?;
        bytes.extend(chunk.iter());
        wipe_value(&mut part);
        check(bytes.len() <= TOTAL, "RESOURCE_LIMIT")?;
    }
    check(
        manifest["bytes"] == bytes.len() && manifest["digest"] == hash(&bytes),
        "INTEGRITY_FAILURE",
    )?;
    strict(&bytes, TOTAL)
}
/// Private custody snapshot. Rust callers are trusted; native IPC exposes only typed coordinators.
pub struct Snapshot {
    pub revision: u64,
    pub source_digest: String,
    pub data: Option<Value>,
}
impl Vault {
    pub fn content_read(&self, cap: &Capability, id: &str, kind: &str) -> Result<Snapshot> {
        check(
            KINDS.contains(&kind) && kind != "content-part",
            "INVALID_CONTENT_RECORD",
        )?;
        let mut inner = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let state = self.authorize(&mut inner, cap)?;
        let key = &inner.secrets.as_ref().unwrap().key;
        let exists: bool = db(inner.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE id=?1)",
            [id],
            |r| r.get(0),
        ))?;
        let data = if exists {
            let bytes = canonical(&frame(&inner.conn, id)?)?;
            if let Some(known) = inner.anchors.get(id) {
                check(*known == hash(&bytes), "ROLLBACK_QUARANTINE")?;
            }
            Some(read(&inner.conn, &self.scope, &state.pins, id, kind, key)?)
        } else {
            None
        };
        let control = note_local::control_id(&self.scope)?;
        let source: Option<Vec<u8>> = db(inner
            .conn
            .query_row("SELECT frame FROM records WHERE id=?1", [control], |r| {
                r.get(0)
            })
            .optional())?;
        self.authorize(&mut inner, cap)?;
        Ok(Snapshot {
            revision: state.revision,
            source_digest: hash(source.as_deref().unwrap_or_default()),
            data,
        })
    }
    /// Atomic CAS under L; retirement is restricted to derived search records.
    pub fn content_commit(
        &self,
        cap: &Capability,
        expected: u64,
        records: &[Record],
        retire: &[String],
    ) -> Result<()> {
        check(
            !records.is_empty() && records.len() <= 32 && retire.len() <= 32,
            "RESOURCE_LIMIT",
        )?;
        let fence = self.lease(cap)?;
        let mut inner = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let before = self.authorize(&mut inner, cap)?;
        check(
            before.revision == expected.checked_add(1).ok_or(Error("RESOURCE_LIMIT"))?,
            "STALE_WRITER",
        )?;
        let key = Zeroizing::new(inner.secrets.as_ref().unwrap().key.to_vec());
        let signing = Zeroizing::new(inner.secrets.as_ref().unwrap().signing.to_vec());
        let tx = db(inner
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut state = state(&tx, &self.codec, &self.scope)?;
        check(
            state.revision == expected.checked_add(1).ok_or(Error("RESOURCE_LIMIT"))?
                && state.epoch == before.epoch,
            "STALE_WRITER",
        )?;
        self.fence(&state, fence)?;
        let mut seen = std::collections::BTreeSet::new();
        for record in records {
            check(
                valid_id(&record.id)
                    && record.id != state.vault_id
                    && record.id != device_local::control_id(&self.scope)?
                    && record.id != note_local::control_id(&self.scope)?
                    && record.id != notes::files::control_id(&self.scope)?
                    && (record.id != control_id(&self.scope)? || record.kind == "content-control")
                    && KINDS.contains(&record.kind.as_str())
                    && record.kind != "content-part"
                    && seen.insert(&record.id),
                "INVALID_CONTENT_RECORD",
            )?;
            let existing: Option<Vec<u8>> = db(tx
                .query_row("SELECT frame FROM records WHERE id=?1", [&record.id], |r| {
                    r.get(0)
                })
                .optional())?;
            if let Some(bytes) = existing {
                let frame = strict(&bytes, 524288)?;
                check(
                    frame["contract"] == "p13-content-v1"
                        && frame["context"]["record_kind"] == record.kind,
                    "RESERVED_RECORD",
                )?;
                let manifest = refs(
                    &self.scope,
                    &state.pins,
                    &record.id,
                    &record.kind,
                    &frame,
                    &key,
                )?;
                for part in values(&manifest, "parts")? {
                    db(tx.execute(
                        "DELETE FROM records WHERE id=?1",
                        [text(&part["record_id"])?],
                    ))?;
                }
            }
            let bytes = Zeroizing::new(canonical(&record.data)?);
            check(!bytes.is_empty() && bytes.len() <= TOTAL, "RESOURCE_LIMIT")?;
            let mut parts = Vec::new();
            for (index, chunk) in bytes.chunks(PART).enumerate() {
                let id = random_id();
                let value = json!({"purpose":"protected-content-part","version":1,"root_id":record.id,"root_kind":record.kind,"index":index,"bytes":chunk.len(),"digest":hash(chunk),"record_bytes":b64(chunk)});
                let frame = seal(&self.scope, &state.pins, &id, "content-part", &value, &key)?;
                db(tx.execute(
                    "INSERT INTO records VALUES(?1,?2)",
                    params![id, canonical(&frame)?],
                ))?;
                parts.push(
                    json!({"record_id":id,"index":index,"bytes":chunk.len(),"digest":hash(chunk)}),
                );
            }
            let manifest = json!({"purpose":"protected-content-manifest","version":1,"kind":record.kind,"bytes":bytes.len(),"digest":hash(&bytes),"parts":parts});
            let frame = seal(
                &self.scope,
                &state.pins,
                &record.id,
                &record.kind,
                &manifest,
                &key,
            )?;
            db(tx.execute("INSERT INTO records VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET frame=excluded.frame",params![record.id,canonical(&frame)?]))?;
        }
        for id in retire {
            check(!seen.contains(id) && valid_id(id), "INVALID_CONTENT_RECORD")?;
            let frame = frame(&tx, id)?;
            let manifest = refs(&self.scope, &state.pins, id, "search-page", &frame, &key)?;
            for part in values(&manifest, "parts")? {
                db(tx.execute(
                    "DELETE FROM records WHERE id=?1",
                    [text(&part["record_id"])?],
                ))?;
            }
            db(tx.execute("DELETE FROM records WHERE id=?1", [id]))?;
        }
        state.content_profile = Some("p13-content-v1".into());
        let body = expected_manifest(&self.scope, &state);
        state.manifest = json!({"body":body,"signature":anynote_crypto_core::crypto::sign(&manifest_input(&body)?,&signing)?});
        state.revision += 1;
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        self.fence(&state, fence)?;
        put_state(&tx, &state)?;
        db(tx.commit())?;
        inner.observed_revision = state.revision;
        for record in records {
            let bytes = canonical(&frame(&inner.conn, &record.id)?)?;
            inner.anchors.insert(record.id.clone(), hash(&bytes));
        }
        for id in retire {
            inner.anchors.remove(id);
        }
        Ok(())
    }
}
