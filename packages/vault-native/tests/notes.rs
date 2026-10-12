//! P09 actual encrypted SQLite, lifecycle, fault and closed IPC tests; no hardware claim.
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
    fn fresh(&self) -> (Arc<Vault>, PathBuf) {
        let root = std::env::temp_dir().join(format!("anynote-p08-new-{}", id()));
        let scope = Scope {
            device_id: id(),
            profile_id: id(),
            ..self.scope.clone()
        };
        let vault = Arc::new(Vault::open(&root.join("vault.sqlite"), scope).unwrap());
        vault
            .initialize_device_phrase(PHRASE, self.pins.clone(), true)
            .unwrap();
        let cap = vault.unlock_phrase(PHRASE).unwrap();
        vault.record_device_snapshot(&cap, &self.snapshot).unwrap();
        (vault, root)
    }
}
use std::time::{SystemTime, UNIX_EPOCH};
impl Drop for Fixture {
    fn drop(&mut self) {
        self.vault.lock();
        self.kit["recovery_secret"] = json!("");
    }
}

use anynote_local_vault::{Capability, Record, notes::NotesRequest};
fn command(f: &Fixture, cap: &Capability, v: Value) -> Value {
    let request: NotesRequest = serde_json::from_value(v).unwrap();
    f.vault.notes_command(cap, request).unwrap()
}
fn group_status(f: &Fixture, made: &Value) -> Value {
    let r = &made["request"];
    let commit = &r["commit"];
    json!({"version":1,"group_id":made["group_id"],"kind":"private","owner_account_id":f.scope.account_id,"state":"active","membership":commit["body"]["intent"]["body"]["membership"],"key_epoch":"0","epoch_digest":digest("p02-group-c2","epoch-intent",&commit["body"]["intent"]),"history_checkpoint_digest":null,"rekey_required":false,"history_closure_required":false,"restore_quarantined":false,"settings":false,"genesis":{"version":1,"group_id":made["group_id"],"commit":commit,"pages":r["pages"]}})
}
fn group(f: &Fixture, cap: &Capability) -> Value {
    let made = command(f, cap, json!({"action":"prepare-group"}));
    command(
        f,
        cap,
        json!({"action":"group","status":group_status(f,&made)}),
    );
    made
}
fn edit(group: &Value, title: &str) -> Value {
    json!({"draft_id":null,"group_id":group["group_id"],"object_id":null,"object_kind":"thread","thread_id":null,"action":"create","parents":[],"archived":false,"content":{"title":title,"markdown":"","metadata_kind":"content","tags":[],"checklist":[],"summary_entry_id":null,"preferences":[]}})
}
fn attempt(f: &Fixture, cap: &Capability, group: &Value) -> (Value, Value, Value) {
    let saved = command(
        f,
        cap,
        json!({"action":"save","edit":edit(group,"PUBLIC native persistent title")}),
    );
    let queued = command(
        f,
        cap,
        json!({"action":"queue","draft_id":saved["draft_id"]}),
    );
    let sent = command(
        f,
        cap,
        json!({"action":"send","attempt_id":queued["attempt_id"]}),
    );
    (saved, queued, sent)
}
fn receipt(request: &Value) -> Value {
    let c = &request["bundle"]["envelope"]["header"]["context"];
    let ed = digest("p02-v1", "envelope", &request["bundle"]["envelope"]);
    json!({"receipt":{"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"mutation-receipt","operation_id":c["operation_id"],"revision_id":c["revision_id"],"envelope_digest":ed,"status":"COMMITTED","cursor":{"generation":c["service_id"],"sequence":"1"}},"heads":[{"revision_id":c["revision_id"],"envelope_digest":ed}]})
}
#[test]
fn native_note_restart_and_encrypted_sqlite_wal_inspection() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let (saved, queued, sent) = attempt(&f, &cap, &g);
    for path in [
        f.vault.path().to_path_buf(),
        PathBuf::from(format!("{}-wal", f.vault.path().display())),
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            for marker in [
                "PUBLIC native persistent title",
                b64(f.signing.secret_key.as_ref()).as_str(),
                f.kit["recovery_secret"].as_str().unwrap(),
            ] {
                assert!(!bytes.windows(marker.len()).any(|x| x == marker.as_bytes()));
            }
        }
    }
    f.vault.lock_all().unwrap();
    assert!(
        f.vault
            .notes_command(&cap, NotesRequest::Summary {})
            .is_err()
    );
    let reopened = Vault::open(f.vault.path(), f.scope.clone()).unwrap();
    let c = reopened.unlock_phrase(PHRASE).unwrap();
    let loaded = reopened
        .notes_command(
            &c,
            NotesRequest::Draft {
                draft_id: saved["draft_id"].as_str().unwrap().into(),
            },
        )
        .unwrap();
    assert_eq!(loaded["payload"]["title"], "PUBLIC native persistent title");
    let retry = reopened
        .notes_command(
            &c,
            NotesRequest::Send {
                attempt_id: queued["attempt_id"].as_str().unwrap().into(),
            },
        )
        .unwrap();
    assert_eq!(retry["request"], sent["request"]);
    let ack = reopened
        .notes_command(
            &c,
            NotesRequest::Ack {
                attempt_id: queued["attempt_id"].as_str().unwrap().into(),
                result: receipt(&sent["request"]),
            },
        )
        .unwrap();
    assert_eq!(ack["draft_retired"], true);
    assert_eq!(
        reopened
            .notes_command(&c, NotesRequest::Summary {})
            .unwrap()["drafts"],
        json!([])
    );
    assert_eq!(
        reopened
            .notes_command(
                &c,
                NotesRequest::Cached {
                    revision_id: ack["revision_id"].as_str().unwrap().into()
                }
            )
            .unwrap()["payload"]["title"],
        "PUBLIC native persistent title"
    );
    drop(reopened);
}
#[test]
fn native_receipt_fault_rolls_back_retirement_and_preserves_the_acknowledged_draft() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let (saved, queued, sent) = attempt(&f, &cap, &g);
    let connection = rusqlite::Connection::open(f.vault.path()).unwrap();
    connection.execute_batch("CREATE TRIGGER p09_abort_retire BEFORE DELETE ON records BEGIN SELECT RAISE(ABORT,'PUBLIC_SYNTHETIC_FAULT'); END;").unwrap();
    let before = connection
        .query_row("SELECT count(*) FROM records", [], |r| r.get::<_, i64>(0))
        .unwrap();
    assert!(
        f.vault
            .notes_command(
                &cap,
                NotesRequest::Ack {
                    attempt_id: queued["attempt_id"].as_str().unwrap().into(),
                    result: receipt(&sent["request"])
                }
            )
            .is_err()
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM records", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        before
    );
    assert_eq!(
        command(
            &f,
            &cap,
            json!({"action":"draft","draft_id":saved["draft_id"]})
        )["payload"]["title"],
        "PUBLIC native persistent title"
    );
    assert_eq!(
        command(&f, &cap, json!({"action":"summary"}))["drafts"][0]["state"],
        "SENT_UNKNOWN"
    );
    connection
        .execute_batch("DROP TRIGGER p09_abort_retire;")
        .unwrap();
    assert_eq!(
        command(
            &f,
            &cap,
            json!({"action":"ack","attempt_id":queued["attempt_id"],"result":receipt(&sent["request"])})
        )["draft_retired"],
        true
    );
}
#[test]
fn native_pending_attempt_protects_newer_text_and_a_different_receipt_cannot_retire_it() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let (saved, queued, sent) = attempt(&f, &cap, &g);
    let mut next = edit(&g, "PUBLIC newer unsent text");
    next["draft_id"] = saved["draft_id"].clone();
    next["object_id"] = saved["object_id"].clone();
    command(&f, &cap, json!({"action":"save","edit":next}));
    assert_eq!(
        f.vault
            .notes_command(
                &cap,
                NotesRequest::Queue {
                    draft_id: saved["draft_id"].as_str().unwrap().into()
                }
            )
            .unwrap_err()
            .0,
        "PUBLICATION_PENDING"
    );
    let mut bad = receipt(&sent["request"]);
    bad["receipt"]["revision_id"] = json!(id());
    assert!(
        f.vault
            .notes_command(
                &cap,
                NotesRequest::Ack {
                    attempt_id: queued["attempt_id"].as_str().unwrap().into(),
                    result: bad
                }
            )
            .is_err()
    );
    let good = receipt(&sent["request"]);
    assert_eq!(
        command(
            &f,
            &cap,
            json!({"action":"ack","attempt_id":queued["attempt_id"],"result":good})
        )["draft_retired"],
        false
    );
    assert_eq!(
        command(
            &f,
            &cap,
            json!({"action":"draft","draft_id":saved["draft_id"]})
        )["payload"]["title"],
        "PUBLIC newer unsent text"
    );
    assert_eq!(
        command(
            &f,
            &cap,
            json!({"action":"draft","draft_id":saved["draft_id"]})
        )["payload"]["context"]["action"],
        "update"
    );
}
#[test]
fn native_note_catalog_is_not_generic_mutable_and_rotation_preserves_pending_work() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let (saved, _, _) = attempt(&f, &cap, &g);
    let summary = command(&f, &cap, json!({"action":"summary"}));
    let record_id = summary["drafts"][0]["record_id"].as_str().unwrap();
    let payload = command(
        &f,
        &cap,
        json!({"action":"draft","draft_id":saved["draft_id"]}),
    )["payload"]
        .clone();
    let fence = f.vault.lease(&cap).unwrap();
    let r = Record {
        id: record_id.into(),
        kind: "draft".into(),
        data: json!({"draft_id":saved["draft_id"],"context":payload["context"],"payload":payload}),
    };
    assert_eq!(
        f.vault.save_batch(&cap, fence, &[r]).unwrap_err().0,
        "RESERVED_RECORD"
    );
    let fence = f.vault.lease(&cap).unwrap();
    assert_eq!(
        f.vault.evict_cache(&cap, fence, record_id).unwrap_err().0,
        "RESERVED_RECORD"
    );
    f.vault
        .rotate_to_phrase(&cap, "public synthetic second strong phrase words", true)
        .unwrap();
    let cap = f
        .vault
        .unlock_phrase("public synthetic second strong phrase words")
        .unwrap();
    assert_eq!(
        command(
            &f,
            &cap,
            json!({"action":"draft","draft_id":saved["draft_id"]})
        )["payload"]["title"],
        "PUBLIC native persistent title"
    );
}
#[test]
fn native_main_ipc_refuses_foreign_preview_stale_and_unknown_note_commands() {
    let f = Fixture::new();
    let endpoint = Endpoint::new(f.vault.clone());
    let host = HostBinding::from_native_window(WindowRole::Main, "tauri://localhost");
    let unlock = endpoint
        .invoke(
            &host,
            &canonical(&json!({"operation":"unlock-phrase","phrase":PHRASE})).unwrap(),
        )
        .unwrap();
    let body=canonical(&json!({"operation":"notes","capability":unlock["capability"],"request":{"action":"summary"}})).unwrap();
    assert!(
        endpoint
            .invoke(
                &HostBinding::from_native_window(WindowRole::Preview, "tauri://localhost"),
                &body
            )
            .is_err()
    );
    assert!(
        endpoint
            .invoke(
                &HostBinding::from_native_window(WindowRole::Main, "https://foreign.invalid"),
                &body
            )
            .is_err()
    );
    assert!(endpoint.invoke(&host,&canonical(&json!({"operation":"notes","capability":unlock["capability"],"request":{"action":"sql","query":"SELECT secret"}})).unwrap()).is_err());
    f.vault.lock_signal().invalidate();
    assert!(endpoint.invoke(&host, &body).is_err());
    let (_fresh, root) = f.fresh();
    drop(_fresh);
    let _cleanup = Cleanup(root);
}
