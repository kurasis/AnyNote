//! Native host library: no renderer key/token export, general SQL/path or HTTP API.
use anynote_crypto_core::{
    Error, Result,
    codec::{Codec, canonical, strict, text},
    crypto::{b64, hash, un64},
    local, objects,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};
#[cfg_attr(not(windows), allow(dead_code))]
mod custody;
mod device_groups;
mod device_local;
mod device_pairing;
mod device_roster;
mod devices;
mod dpapi;
pub mod ipc;
pub mod lifecycle;
pub mod native_hello;
mod note_local;
pub mod notes;
pub mod shared;
// The GPL provider/attestation/TPM/filesystem implementation is shared by source,
// preserving its independent manifest/lock and synthetic RP. Only for_rp is exposed
// within the native crate so product credentials have a different exact namespace.
include!(concat!(env!("OUT_DIR"), "/provider.rs"));

fn check(ok: bool, code: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(Error(code)) }
}
fn db<T>(r: rusqlite::Result<T>) -> Result<T> {
    r.map_err(|e| match e {
        rusqlite::Error::SqliteFailure(ref x, _) if x.code == rusqlite::ErrorCode::DiskFull => {
            Error("INSUFFICIENT_STORAGE")
        }
        rusqlite::Error::SqliteFailure(ref x, _) if x.code == rusqlite::ErrorCode::DatabaseBusy => {
            Error("WRITER_BUSY")
        }
        _ => Error("STORAGE_FAILURE"),
    })
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error("CLOCK"))?
        .as_millis()
        .try_into()
        .map_err(|_| Error("CLOCK"))
}
fn random_id() -> String {
    b64(&libsodium_rs::random::bytes(16))
}
fn valid_id(s: &str) -> bool {
    s.len() == 22 && un64(s).is_ok_and(|v| v.len() == 16)
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub service_id: String,
    pub account_id: String,
    pub device_id: String,
    pub profile_id: String,
}
impl Scope {
    fn validate(&self) -> Result<()> {
        check(
            [
                &self.service_id,
                &self.account_id,
                &self.device_id,
                &self.profile_id,
            ]
            .into_iter()
            .all(|v| valid_id(v)),
            "INVALID_PROFILE",
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    owner: String,
    fence: u64,
    issued: u64,
    expires: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rotation {
    record_id: String,
    owner: String,
    request_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    rotation: Option<Rotation>,
    schema: u32,
    scope: Scope,
    epoch: u64,
    revision: u64,
    vault_id: String,
    manifest: Value,
    wrappers: Vec<Value>,
    pins: Value,
    lease: Option<Lease>,
}
impl State {
    fn validate(&self, c: &Codec, s: &Scope) -> Result<()> {
        check(
            self.schema == 1
                && self.scope == *s
                && self.epoch > 0
                && self.revision > 0
                && valid_id(&self.vault_id)
                && !self.wrappers.is_empty()
                && self.wrappers.len() <= 20,
            "INTEGRITY_FAILURE",
        )?;
        for w in &self.wrappers {
            if w["purpose"] == "windows-phrase-custody" {
                dpapi::validate(c, s, w)?;
                continue;
            }
            if w["purpose"] == "windows-native-custody" {
                custody::validate(c, w, s)?;
                continue;
            }
            #[cfg(windows)]
            return Err(Error("OS_PROTECTION_REQUIRED"));
            #[cfg(not(windows))]
            let kind = match w["context"]["method"].as_str() {
                Some("argon2id13") => "phrase-wrapper",
                _ => return Err(Error("INVALID_WRAPPER")),
            };
            #[cfg(not(windows))]
            c.validate("p02-v1", kind, w)?;
            #[cfg(not(windows))]
            for (k, v) in serde_json::to_value(s).unwrap().as_object().unwrap() {
                check(w["context"][k] == *v, "LOCAL_CONTEXT_MISMATCH")?;
            }
        }
        check(
            self.pins["service_id"] == s.service_id
                && self.pins["account_id"] == s.account_id
                && un64(text(&self.pins["root_fingerprint"])?)?.len() == 32
                && self.pins.as_object().is_some_and(|p| p.len() == 3),
            "INTEGRITY_FAILURE",
        )?;
        if let Some(r) = &self.rotation {
            check(
                valid_id(&r.record_id) && valid_id(&r.owner) && valid_id(&r.request_id),
                "INTEGRITY_FAILURE",
            )?;
        }
        if let Some(l) = &self.lease {
            check(
                valid_id(&l.owner) && l.fence > 0 && l.expires.checked_sub(l.issued) == Some(10000),
                "INTEGRITY_FAILURE",
            )?;
        }
        Ok(())
    }
}
/// Opaque handle: random 256 bits, not serializable or debug-printable. The host
/// binds it to its main-window capability map, never accepts frontend origin claims.
pub struct Capability {
    value: String,
    generation: u64,
}
impl std::fmt::Debug for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Capability([REDACTED])")
    }
}
#[derive(Clone)]
pub struct LockSignal(
    Arc<AtomicU64>,
    std::sync::Weak<Mutex<Inner>>,
    Arc<AtomicBool>,
);
impl LockSignal {
    pub fn invalidate(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        if let Some(inner) = self.1.upgrade() {
            if let Ok(mut guard) = inner.try_lock() {
                guard.device_channels.clear();
                guard.secrets = None;
                return;
            }
            if !self.2.swap(true, Ordering::SeqCst) {
                let pending = self.2.clone();
                let generation = self.0.clone();
                std::thread::spawn(move || {
                    if let Ok(mut guard) = inner.lock()
                        && guard
                            .secrets
                            .as_ref()
                            .is_some_and(|s| s.generation != generation.load(Ordering::SeqCst))
                    {
                        guard.device_channels.clear();
                        guard.secrets = None;
                    }
                    pending.store(false, Ordering::SeqCst);
                });
            }
        }
    }
    pub fn generation(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Secrets {
    key: Zeroizing<Vec<u8>>,
    signing: Zeroizing<Vec<u8>>,
    encryption: Zeroizing<Vec<u8>>,
    cap: String,
    epoch: u64,
    generation: u64,
    last: u64,
}
impl Drop for Secrets {
    fn drop(&mut self) {
        self.cap.zeroize();
    }
}
struct Inner {
    device_anchor: Option<Value>,
    device_channels: std::collections::BTreeMap<String, device_pairing::Channel>,
    conn: Connection,
    secrets: Option<Secrets>,
    observed_revision: u64,
    anchors: std::collections::BTreeMap<String, String>,
}
pub struct Vault {
    scope: Scope,
    path: PathBuf,
    codec: Codec,
    signal: LockSignal,
    owner: String,
    inner: Arc<Mutex<Inner>>,
}
fn state(c: &Connection, codec: &Codec, s: &Scope) -> Result<State> {
    let bytes: String = db(c.query_row("SELECT value FROM meta WHERE id=1", [], |r| r.get(0)))?;
    let parsed = strict(bytes.as_bytes(), 65536)?;
    let st: State = serde_json::from_value(parsed).map_err(|_| Error("INTEGRITY_FAILURE"))?;
    st.validate(codec, s)?;
    Ok(st)
}
fn put_state(c: &Connection, s: &State) -> Result<()> {
    db(c.execute("INSERT INTO meta(id,value) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET value=excluded.value",[serde_json::to_string(s).map_err(|_|Error("INTEGRITY_FAILURE"))?]))?;
    Ok(())
}
fn frame(c: &Connection, id: &str) -> Result<Value> {
    let b: Vec<u8> = db(c.query_row("SELECT frame FROM records WHERE id=?1", [id], |r| r.get(0)))?;
    strict(&b, 8_388_608)
}
impl Vault {
    pub fn open(path: &Path, scope: Scope) -> Result<Self> {
        scope.validate()?;
        libsodium_rs::ensure_init().map_err(|_| Error("CRYPTO_UNAVAILABLE"))?;
        check(
            path.is_absolute() && path.parent().is_some(),
            "INVALID_STORAGE_PATH",
        )?;
        filesystem::reject_links(path).map_err(|_| Error("INVALID_STORAGE_PATH"))?;
        std::fs::create_dir_all(path.parent().unwrap()).map_err(|_| Error("STORAGE_FAILURE"))?;
        filesystem::secure_directory(path.parent().unwrap())
            .map_err(|_| Error("STORAGE_FAILURE"))?;
        let conn = db(Connection::open(path))?;
        db(conn.busy_timeout(std::time::Duration::from_secs(5)))?;
        db(conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA secure_delete=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;"))?;
        let version: u32 = db(conn.pragma_query_value(None, "user_version", |r| r.get(0)))?;
        check(version <= 1, "UNSUPPORTED_LOCAL_SCHEMA")?;
        if version == 0 {
            let has:i64=db(conn.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",[],|r|r.get(0)))?;
            check(has == 0, "UNKNOWN_LOCAL_STORE")?;
            db(conn.execute_batch("BEGIN IMMEDIATE; CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL); CREATE TABLE records(id TEXT PRIMARY KEY,frame BLOB NOT NULL CHECK(length(frame)<=8388608)); PRAGMA user_version=1; COMMIT;"))?;
        }
        let count: i64 = db(conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        ))?;
        check(count == 2, "UNSUPPORTED_LOCAL_SCHEMA")?;
        let inner = Arc::new(Mutex::new(Inner {
            device_anchor: None,
            device_channels: Default::default(),
            conn,
            secrets: None,
            observed_revision: 0,
            anchors: Default::default(),
        }));
        let signal = LockSignal(
            Arc::new(AtomicU64::new(1)),
            Arc::downgrade(&inner),
            Arc::new(AtomicBool::new(false)),
        );
        let weak = Arc::downgrade(&inner);
        let generation = signal.0.clone();
        std::thread::spawn(move || {
            loop {
                let Some(inner) = weak.upgrade() else { break };
                if let Ok(mut i) = inner.try_lock() {
                    let stale = i.secrets.as_ref().is_some_and(|s| {
                        now()
                            .ok()
                            .and_then(|t| t.checked_sub(s.last))
                            .is_none_or(|age| age >= 300000)
                            || s.generation != generation.load(Ordering::SeqCst)
                    });
                    if stale {
                        i.device_channels.clear();
                        i.secrets = None;
                        generation.fetch_add(1, Ordering::SeqCst);
                    }
                }
                drop(inner);
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        });
        Ok(Self {
            scope,
            path: path.into(),
            codec: Codec::new()?,
            signal,
            owner: random_id(),
            inner,
        })
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn lock_signal(&self) -> LockSignal {
        self.signal.clone()
    }
    pub fn lock(&self) {
        self.signal.invalidate();
        if let Ok(mut i) = self.inner.lock() {
            i.device_channels.clear();
            i.secrets = None;
        }
    }
    pub fn lock_all(&self) -> Result<()> {
        self.signal.invalidate();
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        i.device_channels.clear();
        i.secrets = None;
        let tx = db(i
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut s = state(&tx, &self.codec, &self.scope)?;
        s.epoch = s.epoch.checked_add(1).ok_or(Error("RESOURCE_LIMIT"))?;
        s.revision = s.revision.checked_add(1).ok_or(Error("RESOURCE_LIMIT"))?;
        s.lease = None;
        put_state(&tx, &s)?;
        db(tx.commit())
    }
    pub fn status(&self) -> Result<&'static str> {
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let n: i64 = db(i
            .conn
            .query_row("SELECT count(*) FROM meta", [], |r| r.get(0)))?;
        if n == 0 {
            return Ok("enrollment-required");
        }
        let st = state(&i.conn, &self.codec, &self.scope)?;
        if let Some(ref s) = i.secrets
            && s.generation == self.signal.generation()
            && s.epoch == st.epoch
            && now()?.checked_sub(s.last).is_some_and(|v| v < 300000)
        {
            return Ok("unlocked");
        }
        i.device_channels.clear();
        i.secrets = None;
        Ok("locked")
    }
    fn context(&self, kind: &str, id: &str) -> Result<Value> {
        check(valid_id(id), "INVALID_RECORD")?;
        Ok(
            json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"local-record","service_id":self.scope.service_id,"account_id":self.scope.account_id,"device_id":self.scope.device_id,"profile_id":self.scope.profile_id,"record_id":id,"record_kind":kind,"local_schema":1}),
        )
    }
    fn unlock_context(&self, method: &str) -> Value {
        json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"local-unlock","service_id":self.scope.service_id,"account_id":self.scope.account_id,"device_id":self.scope.device_id,"profile_id":self.scope.profile_id,"wrapper_id":random_id(),"method":method})
    }
    /// A phrase mode is explicitly selected by the native host; it is never an
    /// automatic fallback from a failed Hello attempt. All alternate paths limit security.
    pub fn initialize_phrase(
        &self,
        phrase: &str,
        secrets: &[u8],
        pins: Value,
        explicit_phrase_choice: bool,
    ) -> Result<()> {
        check(explicit_phrase_choice, "EXPLICIT_PHRASE_CHOICE_REQUIRED")?;
        let data = self.codec.decode("p02-v1", "vault-secrets", secrets)?;
        check(
            data["group_keys"].as_array().is_some_and(|a| a.is_empty()),
            "INITIAL_GROUP_KEYS_FORBIDDEN",
        )?;
        let key = Zeroizing::new(libsodium_rs::random::bytes(32));
        let parameters = json!({"algorithm":"argon2id13","salt":b64(&libsodium_rs::random::bytes(16)),"opslimit":3,"memlimit":67108864});
        let kek = local::phrase_kek(&self.codec, phrase, &canonical(&parameters)?)?;
        let wrapper = local::wrap(
            &self.codec,
            "phrase-wrapper",
            &canonical(
                &json!({"context":self.unlock_context("argon2id13"),"parameters":parameters}),
            )?,
            &key,
            &kek,
        )?;
        self.initialize(
            key,
            dpapi::protect(&self.codec, &self.scope, wrapper)?,
            data,
            pins,
        )
    }
    fn initialize(
        &self,
        key: Zeroizing<Vec<u8>>,
        wrapper: Value,
        data: Value,
        pins: Value,
    ) -> Result<()> {
        let vault_id = random_id();
        let ctx = self.context("vault-secrets", &vault_id)?;
        let plaintext = Zeroizing::new(canonical(
            &json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"local-record-plaintext","context":ctx,"data":data}),
        )?);
        let f = objects::seal_local(&self.codec, &plaintext, &key)?;
        let signing = Zeroizing::new(un64(text(&data["device_signing_secret"])?)?);
        let body = manifest_body(&self.scope, &pins, &vault_id);
        let manifest = json!({"signature":anynote_crypto_core::crypto::sign(&manifest_input(&body)?,&signing)?,"body":body});
        let s = State {
            rotation: None,
            manifest,
            schema: 1,
            scope: self.scope.clone(),
            epoch: 1,
            revision: 1,
            vault_id: vault_id.clone(),
            wrappers: vec![wrapper],
            pins,
            lease: None,
        };
        s.validate(&self.codec, &self.scope)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let tx = db(i
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let count: i64 = db(tx.query_row(
            "SELECT (SELECT count(*) FROM meta)+(SELECT count(*) FROM records)",
            [],
            |r| r.get(0),
        ))?;
        check(count == 0, "PROFILE_EXISTS")?;
        db(tx.execute(
            "INSERT INTO records VALUES(?1,?2)",
            params![vault_id, canonical(&f)?],
        ))?;
        put_state(&tx, &s)?;
        db(tx.commit())
    }
    pub fn unlock_phrase(&self, phrase: &str) -> Result<Capability> {
        let generation = self.signal.generation();
        let snapshot = {
            let i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
            state(&i.conn, &self.codec, &self.scope)?
        };
        let w = snapshot
            .wrappers
            .iter()
            .find(|w| w["context"]["method"] == "argon2id13")
            .ok_or(Error("PHRASE_UNAVAILABLE"))?;
        let w = dpapi::unprotect(&self.codec, &self.scope, w)?;
        let mut descriptor = w.clone();
        descriptor.as_object_mut().unwrap().remove("nonce");
        descriptor.as_object_mut().unwrap().remove("ciphertext");
        let kek = local::phrase_kek(&self.codec, phrase, &canonical(&w["parameters"])?)?;
        let key = local::unwrap(
            &self.codec,
            "phrase-wrapper",
            &canonical(&w)?,
            &canonical(&descriptor)?,
            &kek,
        )?;
        self.activate(key, snapshot.epoch, generation)
    }
    fn activate(&self, key: Zeroizing<Vec<u8>>, epoch: u64, generation: u64) -> Result<Capability> {
        check(self.signal.generation() == generation, "STALE_CAPABILITY")?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = state(&i.conn, &self.codec, &self.scope)?;
        check(
            s.epoch == epoch && s.revision >= i.observed_revision,
            "ROLLBACK_QUARANTINE",
        )?;
        let f = frame(&i.conn, &s.vault_id)?;
        let p = objects::open_local(
            &self.codec,
            &canonical(&f)?,
            &key,
            &canonical(&self.context("vault-secrets", &s.vault_id)?)?,
        )?;
        let data = &p["data"];
        self.codec.validate("p02-v1", "vault-secrets", data)?;
        let signing = Zeroizing::new(un64(text(&data["device_signing_secret"])?)?);
        let encryption = Zeroizing::new(un64(text(&data["device_encryption_secret"])?)?);
        let pair = libsodium_rs::crypto_sign::KeyPair::from_seed(&signing[..32])
            .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
        check(
            pair.secret_key.as_ref() == signing.as_slice(),
            "INTEGRITY_FAILURE",
        )?;
        check(
            s.manifest["body"] == manifest_body(&self.scope, &s.pins, &s.vault_id)
                && s.manifest.as_object().is_some_and(|o| o.len() == 2),
            "INTEGRITY_FAILURE",
        )?;
        anynote_crypto_core::crypto::verify(
            &manifest_input(&s.manifest["body"])?,
            text(&s.manifest["signature"])?,
            pair.public_key.as_ref(),
        )?;
        let cap = b64(&libsodium_rs::random::bytes(32));
        check(self.signal.generation() == generation, "STALE_CAPABILITY")?;
        i.observed_revision = s.revision;
        i.secrets = Some(Secrets {
            key,
            signing,
            encryption,
            cap: cap.clone(),
            epoch,
            generation,
            last: now()?,
        });
        Ok(Capability {
            value: cap,
            generation,
        })
    }
    fn authorize(&self, i: &mut Inner, cap: &Capability) -> Result<State> {
        let s = state(&i.conn, &self.codec, &self.scope)?;
        let secret = i.secrets.as_mut().ok_or(Error("VAULT_LOCKED"))?;
        let t = now()?;
        if secret.cap != cap.value
            || secret.generation != cap.generation
            || self.signal.generation() != cap.generation
            || s.epoch != secret.epoch
            || s.revision < i.observed_revision
            || !t.checked_sub(secret.last).is_some_and(|v| v < 300000)
        {
            i.device_channels.clear();
            i.secrets = None;
            return Err(Error("STALE_CAPABILITY"));
        }
        check(
            s.manifest["body"] == manifest_body(&self.scope, &s.pins, &s.vault_id)
                && s.manifest.as_object().is_some_and(|o| o.len() == 2),
            "INTEGRITY_FAILURE",
        )?;
        anynote_crypto_core::crypto::verify(
            &manifest_input(&s.manifest["body"])?,
            text(&s.manifest["signature"])?,
            &secret.signing[32..],
        )?;
        secret.last = t;
        i.observed_revision = s.revision;
        Ok(s)
    }
    pub fn lease(&self, cap: &Capability) -> Result<u64> {
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let expected = self.authorize(&mut i, cap)?;
        let tx = db(i
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut s = state(&tx, &self.codec, &self.scope)?;
        let t = now()?;
        check(
            s.epoch == expected.epoch && cap.generation == self.signal.generation(),
            "STALE_CAPABILITY",
        )?;
        if let Some(l) = &s.lease {
            check(
                t >= l.issued && (l.owner == self.owner || t >= l.expires),
                "WRITER_BUSY",
            )?;
        }
        let fence = s
            .lease
            .as_ref()
            .map_or(0, |l| l.fence)
            .checked_add(1)
            .ok_or(Error("RESOURCE_LIMIT"))?;
        s.lease = Some(Lease {
            owner: self.owner.clone(),
            fence,
            issued: t,
            expires: t + 10000,
        });
        s.revision += 1;
        put_state(&tx, &s)?;
        db(tx.commit())?;
        i.observed_revision = s.revision;
        Ok(fence)
    }
    fn fence(&self, s: &State, fence: u64) -> Result<()> {
        let l = s.lease.as_ref().ok_or(Error("STALE_WRITER"))?;
        let t = now()?;
        check(
            l.owner == self.owner && l.fence == fence && t >= l.issued && t < l.expires,
            "STALE_WRITER",
        )
    }
    pub fn save_batch(&self, cap: &Capability, fence: u64, records: &[Record]) -> Result<()> {
        check(!records.is_empty() && records.len() <= 16, "RESOURCE_LIMIT")?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let state_before = self.authorize(&mut i, cap)?;
        let key = i.secrets.as_ref().unwrap().key.to_vec();
        let key = Zeroizing::new(key);
        let mut frames = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for r in records {
            check(
                ids.insert(&r.id)
                    && valid_id(&r.id)
                    && ["cache", "search", "draft", "outbox", "transfer", "session"]
                        .contains(&r.kind.as_str()),
                "INVALID_RECORD",
            )?;
            self.codec.validate(
                "p02-v1",
                &r.kind.replace("session", "session-secret"),
                &r.data,
            )?;
            let ctx = self.context(&r.kind, &r.id)?;
            let plain = Zeroizing::new(canonical(
                &json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"local-record-plaintext","context":ctx,"data":r.data}),
            )?);
            let f = objects::seal_local(&self.codec, &plain, &key)?;
            frames.push((r, canonical(&f)?));
        }
        let anchors = i.anchors.clone();
        let tx = db(i
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut s = state(&tx, &self.codec, &self.scope)?;
        check(s.epoch == state_before.epoch, "STALE_CAPABILITY")?;
        self.fence(&s, fence)?;
        let note_owned = notes::protected_ids(&self.note_control(&tx, &s, &key)?)?;
        for (r, f) in &frames {
            check(
                r.id != s.vault_id
                    && r.id != device_local::control_id(&self.scope)?
                    && r.id != note_local::control_id(&self.scope)?
                    && !note_owned.contains_key(&r.id),
                "RESERVED_RECORD",
            )?;
            let old: Option<Vec<u8>> = db(tx
                .query_row("SELECT frame FROM records WHERE id=?1", [&r.id], |row| {
                    row.get(0)
                })
                .optional())?;
            if let Some(old) = old {
                if let Some(h) = anchors.get(&r.id) {
                    check(hash(&old) == *h, "ROLLBACK_QUARANTINE")?;
                }
                let v = strict(&old, 8_388_608)?;
                check(
                    v["context"] == self.context(&r.kind, &r.id)?,
                    "LOCAL_CONTEXT_MISMATCH",
                )?;
                if r.kind == "outbox" {
                    let p =
                        objects::open_local(&self.codec, &old, &key, &canonical(&v["context"])?)?;
                    for field in [
                        "draft_id",
                        "attempt_id",
                        "revision_id",
                        "attempt_digest",
                        "bundle",
                    ] {
                        check(p["data"][field] == r.data[field], "IMMUTABLE_ATTEMPT")?;
                    }
                    outbox_transition(text(&p["data"]["state"])?, text(&r.data["state"])?)?;
                }
            }
            db(tx.execute("INSERT INTO records VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET frame=excluded.frame",params![r.id,f]))?;
        }
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        self.fence(&s, fence)?;
        if frames.iter().any(|(r, _)| {
            r.kind == "session"
                && s.rotation
                    .as_ref()
                    .is_some_and(|pending| pending.record_id == r.id)
        }) {
            s.rotation = None;
        }
        s.revision += 1;
        put_state(&tx, &s)?;
        db(tx.commit())?;
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        i.observed_revision = s.revision;
        for (r, f) in frames {
            i.anchors.insert(r.id.clone(), hash(&f));
        }
        Ok(())
    }
    /// Display records only; secrets and native bearer material have no IPC read route.
    pub fn read(&self, cap: &Capability, id: &str, kind: &str) -> Result<Value> {
        check(
            ["cache", "search", "draft", "outbox", "transfer"].contains(&kind),
            "SECRET_EXPORT_FORBIDDEN",
        )?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        self.authorize(&mut i, cap)?;
        let f = frame(&i.conn, id)?;
        let bytes = canonical(&f)?;
        if let Some(h) = i.anchors.get(id) {
            check(*h == hash(&bytes), "ROLLBACK_QUARANTINE")?;
        }
        let p = objects::open_local(
            &self.codec,
            &bytes,
            &i.secrets.as_ref().unwrap().key,
            &canonical(&self.context(kind, id)?)?,
        )?;
        self.codec.validate("p02-v1", kind, &p["data"])?;
        self.authorize(&mut i, cap)?;
        i.anchors.insert(id.into(), hash(&bytes));
        Ok(p["data"].clone())
    }
    pub fn evict_cache(&self, cap: &Capability, fence: u64, id: &str) -> Result<()> {
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        self.fence(&s, fence)?;
        let owned = notes::protected_ids(&self.note_control(
            &i.conn,
            &s,
            &i.secrets.as_ref().unwrap().key,
        )?)?;
        check(
            id != s.vault_id
                && id != device_local::control_id(&self.scope)?
                && id != note_local::control_id(&self.scope)?
                && !owned.contains_key(id),
            "RESERVED_RECORD",
        )?;
        let f = frame(&i.conn, id)?;
        check(
            f["context"] == self.context("cache", id)?,
            "UNSYNCED_WORK_PROTECTED",
        )?;
        let tx = db(i
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut s = state(&tx, &self.codec, &self.scope)?;
        self.fence(&s, fence)?;
        db(tx.execute("DELETE FROM records WHERE id=?1", [id]))?;
        s.revision += 1;
        put_state(&tx, &s)?;
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        db(tx.commit())?;
        i.anchors.remove(id);
        Ok(())
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Revoke every alternate unlock path by rotating L, not just deleting wrapper
    /// metadata. One streamed SQLite transaction preserves all drafts/outbox/sessions.
    pub fn rotate_to_phrase(
        &self,
        cap: &Capability,
        phrase: &str,
        explicit_phrase_choice: bool,
    ) -> Result<()> {
        check(explicit_phrase_choice, "EXPLICIT_PHRASE_CHOICE_REQUIRED")?;
        let before = {
            let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
            self.authorize(&mut i, cap)?
        };
        let key = Zeroizing::new(libsodium_rs::random::bytes(32));
        let parameters = json!({"algorithm":"argon2id13","salt":b64(&libsodium_rs::random::bytes(16)),"opslimit":3,"memlimit":67108864});
        let kek = local::phrase_kek(&self.codec, phrase, &canonical(&parameters)?)?;
        let wrapper = local::wrap(
            &self.codec,
            "phrase-wrapper",
            &canonical(
                &json!({"context":self.unlock_context("argon2id13"),"parameters":parameters}),
            )?,
            &key,
            &kek,
        )?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        self.authorize(&mut i, cap)?;
        let old_key = Zeroizing::new(i.secrets.as_ref().unwrap().key.to_vec());
        let tx = db(i
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut s = state(&tx, &self.codec, &self.scope)?;
        check(
            s.epoch == before.epoch && s.revision == before.revision,
            "STALE_WRITER",
        )?;
        {
            let mut statement = db(tx.prepare("SELECT id,frame FROM records ORDER BY id"))?;
            let mut rows = db(statement.query([]))?;
            while let Some(row) = db(rows.next())? {
                let id: String = db(row.get(0))?;
                let bytes: Vec<u8> = db(row.get(1))?;
                let f = strict(&bytes, 8_388_608)?;
                let kind = text(&f["context"]["record_kind"])?;
                let note = f["contract"] == "p09-local-v1";
                let additive = f["contract"] == "p08-local-v1";
                let mut p = if note {
                    note_local::open(&self.scope, &s.pins, &id, kind, &f, &old_key)?
                } else if additive {
                    device_local::open(&self.scope, &s.pins, &id, kind, &f, &old_key)?
                } else {
                    objects::open_local(
                        &self.codec,
                        &bytes,
                        &old_key,
                        &canonical(&self.context(kind, &id)?)?,
                    )?
                };
                let new = if note {
                    note_local::seal(&self.scope, &s.pins, &id, kind, &p, &key)
                } else if additive {
                    device_local::seal(&self.scope, &s.pins, &id, kind, &p, &key)
                } else {
                    objects::seal_local(&self.codec, &canonical(&p)?, &key)
                };
                wipe_value(&mut p);
                let new = new?;
                check(
                    self.signal.generation() == cap.generation,
                    "STALE_CAPABILITY",
                )?;
                db(tx.execute(
                    "UPDATE records SET frame=?1 WHERE id=?2",
                    params![canonical(&new)?, id],
                ))?;
            }
        }
        s.wrappers = vec![dpapi::protect(&self.codec, &self.scope, wrapper)?];
        s.epoch += 1;
        s.revision += 1;
        s.lease = None;
        put_state(&tx, &s)?;
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        db(tx.commit())?;
        i.device_channels.clear();
        i.secrets = None;
        i.anchors.clear();
        i.observed_revision = s.revision;
        self.signal.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    /// Native-only P06 credential adoption. There is deliberately no renderer route
    /// that reads/adopts bearer credentials. SQLite receives only the encrypted frame.
    pub fn store_credentials(
        &self,
        cap: &Capability,
        record_id: &str,
        credentials: &anynote_auth_native::Credentials,
    ) -> Result<()> {
        check(
            valid_id(&credentials.session_id)
                && ["restricted", "trusted"].contains(&credentials.state.as_str()),
            "INVALID_SESSION",
        )?;
        let r = Record {
            id: record_id.into(),
            kind: "session".into(),
            data: json!({"session_id":credentials.session_id,"access_credential":credentials.access.as_str(),"refresh_credential":credentials.refresh.as_str(),"expires_at":(now()?+900000).to_string()}),
        };
        let fence = self.lease(cap)?;
        self.save_batch(cap, fence, &[r])
    }
    /// A durable, nonsecret marker admits exactly one refresh request. A crash or
    /// unknown response requires fresh login; no old refresh is automatically replayed.
    pub fn rotate_credentials(
        &self,
        cap: &Capability,
        record_id: &str,
        adapter: &anynote_auth_native::Adapter,
    ) -> Result<()> {
        let fence = self.lease(cap)?;
        let request_id = random_id();
        let credentials = {
            let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
            let before = self.authorize(&mut i, cap)?;
            self.fence(&before, fence)?;
            let f = frame(&i.conn, record_id)?;
            let mut p = objects::open_local(
                &self.codec,
                &canonical(&f)?,
                &i.secrets.as_ref().unwrap().key,
                &canonical(&self.context("session", record_id)?)?,
            )?;
            let result = anynote_auth_native::Credentials {
                access: Zeroizing::new(text(&p["data"]["access_credential"])?.into()),
                refresh: Zeroizing::new(text(&p["data"]["refresh_credential"])?.into()),
                session_id: text(&p["data"]["session_id"])?.into(),
                state: "restricted".into(),
            };
            wipe_value(&mut p);
            let tx = db(i
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate))?;
            let mut s = state(&tx, &self.codec, &self.scope)?;
            check(
                s.epoch == before.epoch && s.rotation.is_none(),
                "REAUTH_REQUIRED",
            )?;
            self.fence(&s, fence)?;
            s.rotation = Some(Rotation {
                record_id: record_id.into(),
                owner: self.owner.clone(),
                request_id: request_id.clone(),
            });
            s.revision += 1;
            put_state(&tx, &s)?;
            db(tx.commit())?;
            result
        };
        let next = adapter
            .refresh(&credentials)
            .map_err(|_| Error("REAUTH_REQUIRED"))?;
        check(next.session_id == credentials.session_id, "INVALID_SESSION")?;
        {
            let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
            let s = self.authorize(&mut i, cap)?;
            check(
                s.rotation.as_ref().is_some_and(|r| {
                    r.owner == self.owner && r.record_id == record_id && r.request_id == request_id
                }),
                "REAUTH_REQUIRED",
            )?;
        }
        self.store_credentials(cap, record_id, &next)
    }
    pub fn clear_session(&self, cap: &Capability, record_id: &str) -> Result<()> {
        let fence = self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let before = self.authorize(&mut i, cap)?;
        let f = frame(&i.conn, record_id)?;
        check(
            f["context"] == self.context("session", record_id)?,
            "UNSYNCED_WORK_PROTECTED",
        )?;
        let tx = db(i
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut s = state(&tx, &self.codec, &self.scope)?;
        check(s.epoch == before.epoch, "STALE_CAPABILITY")?;
        self.fence(&s, fence)?;
        db(tx.execute("DELETE FROM records WHERE id=?1", [record_id]))?;
        if s.rotation
            .as_ref()
            .is_some_and(|r| r.record_id == record_id)
        {
            s.rotation = None;
        }
        s.revision += 1;
        put_state(&tx, &s)?;
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        db(tx.commit())
    }
    /// Only a frozen P06 challenge can be signed, with the current installation's
    /// independently pinned service/account/root, device and exact session binding.
    pub fn device_proof(
        &self,
        cap: &Capability,
        challenge: &[u8],
        session_id: &str,
    ) -> Result<Value> {
        check(valid_id(session_id), "INVALID_SESSION")?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let c = self.codec.decode("p02-state-c1", "challenge", challenge)?;
        let context = &c["context"];
        let secret = i.secrets.as_ref().unwrap();
        let signing_pair = libsodium_rs::crypto_sign::KeyPair::from_seed(&secret.signing[..32])
            .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
        check(
            signing_pair.secret_key.as_ref() == secret.signing.as_slice(),
            "INVALID_KEY_LENGTH",
        )?;
        let signing_public = signing_pair.public_key;
        let encryption_public =
            libsodium_rs::crypto_scalarmult::curve25519::scalarmult_base(&secret.encryption)
                .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
        for field in ["service_id", "account_id", "root_fingerprint"] {
            check(
                context[field] == s.pins[field],
                "CHALLENGE_CONTEXT_MISMATCH",
            )?;
        }
        let expiry = text(&context["expires_at"])?
            .parse::<u64>()
            .map_err(|_| Error("INVALID_CHALLENGE"))?;
        let t = now()?;
        check(
            context["intent"] == "device-proof"
                && context["device"]["device_id"] == self.scope.device_id
                && context["device"]["signing_key"] == b64(signing_public.as_bytes())
                && context["device"]["encryption_key"] == b64(&encryption_public)
                && expiry > t
                && expiry <= t + 125000,
            "CHALLENGE_CONTEXT_MISMATCH",
        )?;
        check(
            context["session_binding"]
                == hash(format!("AnyNote/P06/session-binding\0{session_id}").as_bytes()),
            "SESSION_BINDING_MISMATCH",
        )?;
        let pk = libsodium_rs::crypto_box::PublicKey::from_bytes(&encryption_public)
            .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
        let sk = libsodium_rs::crypto_box::SecretKey::from_bytes(&secret.encryption)
            .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
        let plain = Zeroizing::new(
            libsodium_rs::crypto_box::open_sealed_box(
                &un64(text(&c["sealed_challenge"])?)?,
                &pk,
                &sk,
            )
            .map_err(|_| Error("INTEGRITY_FAILURE"))?,
        );
        let p = self
            .codec
            .decode("p02-state-c1", "challenge-plaintext", &plain)?;
        check(
            p["context"] == *context
                && hash(&anynote_crypto_core::codec::domain(
                    "p02-state-c1",
                    "hash",
                    "challenge-plaintext",
                    &canonical(&p)?,
                )) == c["challenge_digest"],
            "INNER_CONTEXT_MISMATCH",
        )?;
        let body = json!({"purpose":"device-possession-proof","contract":"p02-state-c1","protocol":"anynote","protocol_version":1,"service_id":self.scope.service_id,"account_id":self.scope.account_id,"root_fingerprint":s.pins["root_fingerprint"],"challenge_digest":hash(&anynote_crypto_core::codec::domain("p02-state-c1","hash","challenge",&canonical(&c)?)),"device_id":self.scope.device_id,"session_binding":context["session_binding"],"challenge_response":p["secret"]});
        self.codec
            .validate("p02-state-c1", "possession-body", &body)?;
        let signature = anynote_crypto_core::crypto::sign(
            &self
                .codec
                .signing("p02-state-c1", "possession-body", &body)?,
            &secret.signing,
        )?;
        self.authorize(&mut i, cap)?;
        Ok(json!({"body":body,"signature":signature}))
    }
}

fn manifest_body(scope: &Scope, pins: &Value, vault_id: &str) -> Value {
    json!({"contract":"p07-local-v1","protocol":"anynote","protocol_version":1,"purpose":"local-vault-manifest","scope":scope,"pins":pins,"vault_id":vault_id})
}
fn wipe_value(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe_value),
        Value::Object(o) => o.values_mut().for_each(wipe_value),
        _ => {}
    }
}
fn manifest_input(body: &Value) -> Result<Vec<u8>> {
    let mut result = b"AnyNote/P07/local-manifest\0".to_vec();
    result.extend(canonical(body)?);
    Ok(result)
}
fn outbox_transition(from: &str, to: &str) -> Result<()> {
    check(
        from == to
            || matches!(
                (from, to),
                (
                    "QUEUED",
                    "SENT_UNKNOWN" | "CONFLICT" | "REKEY_REQUIRED" | "ACCESS_LOST"
                ) | (
                    "SENT_UNKNOWN",
                    "COMMITTED" | "CONFLICT" | "REKEY_REQUIRED" | "ACCESS_LOST"
                )
            ),
        "INVALID_OUTBOX_TRANSITION",
    )
}
pub struct Record {
    pub id: String,
    pub kind: String,
    pub data: Value,
}
impl Drop for Record {
    fn drop(&mut self) {
        fn wipe(v: &mut Value) {
            match v {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(wipe),
                Value::Object(o) => o.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.data);
    }
}
