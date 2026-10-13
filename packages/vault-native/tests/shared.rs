//! P10 actual SQLite security journal, fault atomicity, restart and closed IPC.
use anynote_crypto_core::{
    codec::{Codec, canonical},
    crypto::{b64, hash, sign},
    objects,
};
use anynote_local_vault::{
    Scope, Vault,
    ipc::{Endpoint, HostBinding, WindowRole},
};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
const PHRASE: &str = "public synthetic purple harbor paper lantern";
fn id() -> String {
    b64(&libsodium_rs::random::bytes(16))
}
fn digest(p: &str, k: &str, v: &Value) -> String {
    let mut bytes = format!("AnyNote/{p}/hash/{k}\0").into_bytes();
    bytes.extend(canonical(v).unwrap());
    hash(&bytes)
}
fn signed(codec: &Codec, p: &str, k: &str, b: Value, secret: &[u8]) -> Value {
    json!({"signature":sign(&codec.signing(p,&format!("{k}-body"),&b).unwrap(),secret).unwrap(),"body":b})
}
struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        for _ in 0..80 {
            if std::fs::remove_dir_all(&self.0).is_ok() || !self.0.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!("Synthetic native fixture cleanup failed");
    }
}
struct Fixture {
    scope: Scope,
    pins: Value,
    kit: Value,
    signing: libsodium_rs::crypto_sign::KeyPair,
    vault: Arc<Vault>,
    snapshot: Value,
    _cleanup: Cleanup,
}
impl Fixture {
    fn new() -> Self {
        libsodium_rs::ensure_init().unwrap();
        let c = Codec::new().unwrap();
        let scope = Scope {
            service_id: id(),
            account_id: id(),
            device_id: id(),
            profile_id: id(),
        };
        let r = libsodium_rs::random::bytes(32);
        let ctx = json!({"purpose":"account-root-derivation","contract":"p02-identity-c1","protocol":"anynote","protocol_version":1,"service_id":scope.service_id,"account_id":scope.account_id});
        let identity = objects::create_identity(&c, &r, &canonical(&ctx).unwrap()).unwrap();
        let (root_key, _) = objects::derive_root(&c, &r, &canonical(&ctx).unwrap()).unwrap();
        let pins = json!({"service_id":scope.service_id,"account_id":scope.account_id,"root_fingerprint":digest("p02-identity-c1","account-root-identity",&identity["body"])});
        let kit = json!({"purpose":"account-recovery-kit","contract":"p02-identity-c1","protocol":"anynote","protocol_version":1,"service_id":scope.service_id,"account_id":scope.account_id,"root_fingerprint":pins["root_fingerprint"],"identity":identity,"recovery_secret":objects::recovery_encode(&r).unwrap()});
        let signing = libsodium_rs::crypto_sign::KeyPair::generate().unwrap();
        let encryption = libsodium_rs::crypto_box::KeyPair::generate();
        let root = std::env::temp_dir().join(format!("anynote-p08-native-{}", id()));
        let vault = Arc::new(Vault::open(&root.join("vault.sqlite"), scope.clone()).unwrap());
        let secrets = json!({"device_signing_secret":b64(signing.secret_key.as_ref()),"device_encryption_secret":b64(encryption.secret_key.as_ref()),"group_keys":[]});
        vault
            .initialize_phrase(PHRASE, &canonical(&secrets).unwrap(), pins.clone(), true)
            .unwrap();
        let cap = vault.unlock_phrase(PHRASE).unwrap();
        let device = vault.device_public(&cap).unwrap();
        let session = id();
        let context = json!({"purpose":"device-possession-challenge","contract":"p02-state-c1","protocol":"anynote","protocol_version":1,"service_id":scope.service_id,"account_id":scope.account_id,"root_fingerprint":pins["root_fingerprint"],"intent":"register","challenge_id":id(),"session_binding":hash(format!("AnyNote/P06/session-binding\0{session}").as_bytes()),"generation":"0","roster":null,"nonce":b64(&libsodium_rs::random::bytes(32)),"device":device,"expires_at":(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()+50000).to_string()});
        let plain = json!({"purpose":"device-encryption-proof","context":context,"secret":b64(&libsodium_rs::random::bytes(32))});
        let challenge = json!({"context":context,"sealed_challenge":b64(&libsodium_rs::crypto_box::seal_box(&canonical(&plain).unwrap(),&encryption.public_key).unwrap()),"challenge_digest":digest("p02-state-c1","challenge-plaintext",&plain)});
        let proof = signed(
            &c,
            "p02-state-c1",
            "possession",
            json!({"purpose":"device-possession-proof","contract":"p02-state-c1","protocol":"anynote","protocol_version":1,"service_id":scope.service_id,"account_id":scope.account_id,"root_fingerprint":pins["root_fingerprint"],"challenge_digest":digest("p02-state-c1","challenge",&challenge),"device_id":scope.device_id,"session_binding":context["session_binding"],"challenge_response":plain["secret"]}),
            signing.secret_key.as_ref(),
        );
        let certificate = signed(
            &c,
            "p02-identity-c1",
            "certificate",
            json!({"purpose":"provisional-device-certificate","contract":"p02-identity-c1","protocol":"anynote","protocol_version":1,"service_id":scope.service_id,"account_id":scope.account_id,"root_fingerprint":pins["root_fingerprint"],"recovery_generation":"0","predecessor_roster":null,"issuer":{"kind":"root","root_fingerprint":pins["root_fingerprint"]},"device_id":scope.device_id,"device_signing_key":device["signing_key"],"device_encryption_key":device["encryption_key"],"capabilities":device["capabilities"],"pairing_transcript_digest":digest("p02-state-c1","challenge",&challenge)}),
            root_key.secret_key.as_ref(),
        );
        let event = signed(
            &c,
            "p02-state-c1",
            "event",
            json!({"purpose":"device-roster-event","contract":"p02-state-c1","protocol":"anynote","protocol_version":1,"service_id":scope.service_id,"account_id":scope.account_id,"root_fingerprint":pins["root_fingerprint"],"kind":"register","signer":"root","operation_id":id(),"generation":"0","version":"0","predecessor":null,"payload":{"challenge":challenge,"certificate":certificate,"confirmation":proof,"active_device_limit":"5"}}),
            root_key.secret_key.as_ref(),
        );
        let snapshot = json!({"identity":identity,"events":[event],"head":{"version":"0","digest":digest("p02-state-c1","event",&event)},"generation":"0"});
        vault.record_device_snapshot(&cap, &snapshot).unwrap();
        Self {
            _cleanup: Cleanup(root.clone()),
            scope,
            pins,
            kit,
            signing,
            vault,
            snapshot,
        }
    }
}
use std::time::{SystemTime, UNIX_EPOCH};
impl Drop for Fixture {
    fn drop(&mut self) {
        self.vault.lock();
        self.kit["recovery_secret"] = json!("");
    }
}

use anynote_local_vault::{Capability, notes::NotesRequest};
fn command(f: &Fixture, cap: &Capability, v: Value) -> Value {
    let request: NotesRequest = serde_json::from_value(v).unwrap();
    f.vault.notes_command(cap, request).unwrap()
}
fn private_status(f: &Fixture, made: &Value) -> Value {
    let r = &made["request"];
    let commit = &r["commit"];
    json!({"version":1,"group_id":made["group_id"],"kind":"private","owner_account_id":f.scope.account_id,"state":"active","membership":commit["body"]["intent"]["body"]["membership"],"key_epoch":"0","epoch_digest":digest("p02-group-c2","epoch-intent",&commit["body"]["intent"]),"history_checkpoint_digest":null,"rekey_required":false,"history_closure_required":false,"restore_quarantined":false,"settings":false,"genesis":{"version":1,"group_id":made["group_id"],"commit":commit,"pages":r["pages"]}})
}
fn shared_group(f: &Fixture, cap: &Capability) -> Value {
    let made = command(f, cap, json!({"action":"prepare-shared"}));
    let mut status = private_status(f, &made);
    status["kind"] = json!("shared");
    assert_eq!(
        made["request"]["commit"]["body"]["policy"]["body"]["members"][0]["root_fingerprint"],
        f.pins["root_fingerprint"]
    );
    assert_eq!(
        made["request"]["commit"]["body"]["intent"]["body"]["rosters"][0]["roster"],
        f.snapshot["head"]
    );
    command(f, cap, json!({"action":"group","status":status}));
    made
}
fn shared(f: &Fixture, cap: &Capability, r: Value) -> Value {
    command(f, cap, json!({"action":"shared","request":r}))
}
#[test]
fn native_shared_attempt_restart_and_ciphertext_privacy() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = shared_group(&f, &cap);
    let a = shared(
        &f,
        &cap,
        json!({"action":"history","group_id":g["group_id"]}),
    );
    f.vault.lock();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let sent = shared(&f, &cap, json!({"action":"retry","group_id":g["group_id"]}));
    assert_eq!(a["body"], sent["body"]);
    let db = rusqlite::Connection::open(f.vault.path()).unwrap();
    let rows = db
        .prepare("SELECT frame FROM records")
        .unwrap()
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    let raw = rows.concat();
    assert!(!raw.windows(64).any(|b| b == f.signing.secret_key.as_ref()));
    assert!(!String::from_utf8_lossy(&raw).contains("p10-group-proof"));
    let path = f.vault.path().to_owned();
    f.vault.lock();
    let other = Vault::open(&path, f.scope.clone()).unwrap();
    let cap2 = other.unlock_phrase(PHRASE).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10500));
    let req: NotesRequest = serde_json::from_value(
        json!({"action":"shared","request":{"action":"retry","group_id":g["group_id"]}}),
    )
    .unwrap();
    let resumed = other.notes_command(&cap2, req).unwrap();
    assert_eq!(resumed["body"], a["body"]);
}
#[test]
fn native_shared_sql_fault_keeps_previous_security_journal() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = shared_group(&f, &cap);
    let db = rusqlite::Connection::open(f.vault.path()).unwrap();
    let before: Vec<(String, Vec<u8>)> = db
        .prepare("SELECT id,frame FROM records ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    db.execute_batch("CREATE TRIGGER p10_fault BEFORE UPDATE ON records BEGIN SELECT RAISE(ABORT,'Synthetic atomic journal fault'); END;").unwrap();
    let req: NotesRequest = serde_json::from_value(
        json!({"action":"shared","request":{"action":"history","group_id":g["group_id"]}}),
    )
    .unwrap();
    assert!(f.vault.notes_command(&cap, req).is_err());
    db.execute_batch("DROP TRIGGER p10_fault;").unwrap();
    let after: Vec<(String, Vec<u8>)> = db
        .prepare("SELECT id,frame FROM records ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    assert_eq!(before, after);
    let a = shared(
        &f,
        &cap,
        json!({"action":"history","group_id":g["group_id"]}),
    );
    assert_eq!(a["family"], "history");
}
#[test]
fn native_shared_closed_commands_and_main_window_fences() {
    let f = Fixture::new();
    let endpoint = Endpoint::new(f.vault.clone());
    let host = HostBinding::from_native_window(WindowRole::Main, "tauri://localhost");
    let unlock = endpoint
        .invoke(
            &host,
            &canonical(&json!({"operation":"unlock-phrase","phrase":PHRASE})).unwrap(),
        )
        .unwrap();
    let handle = unlock["capability"].clone();
    let made=endpoint.invoke(&host,&canonical(&json!({"operation":"notes","capability":handle,"request":{"action":"prepare-shared"}})).unwrap()).unwrap();
    let frame = json!({"operation":"notes","capability":handle,"request":{"action":"shared","request":{"action":"details","group_id":made["group_id"]}}});
    let preview = HostBinding::from_native_window(WindowRole::Preview, "tauri://localhost");
    assert!(
        endpoint
            .invoke(&preview, &canonical(&frame).unwrap())
            .is_err()
    );
    let mut extra = frame.clone();
    extra["request"]["request"]["signing_key"] = json!(b64(f.signing.secret_key.as_ref()));
    assert!(endpoint.invoke(&host, &canonical(&extra).unwrap()).is_err());
    let mut sql = frame.clone();
    sql["request"]["request"]["action"] = json!("execute-sql");
    assert!(endpoint.invoke(&host, &canonical(&sql).unwrap()).is_err());
    endpoint
        .invoke(&host, &canonical(&json!({"operation":"lock"})).unwrap())
        .unwrap();
    assert!(endpoint.invoke(&host, &canonical(&frame).unwrap()).is_err());
}
