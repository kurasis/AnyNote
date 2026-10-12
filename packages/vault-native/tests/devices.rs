//! Actual native SQLite/DPAPI/software lifecycle checks; no Hello/TPM objects created.
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
#[test]
fn actual_native_signed_chain_and_encrypted_inspector() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let summary = f.vault.record_device_snapshot(&cap, &f.snapshot).unwrap();
    assert_eq!(summary["generation"], "0");
    let genesis = f.vault.device_settings_genesis(&cap).unwrap();
    assert_eq!(genesis, f.vault.device_settings_genesis(&cap).unwrap());
    let bytes = std::fs::read(f.vault.path()).unwrap();
    for marker in [
        f.kit["recovery_secret"].as_str().unwrap(),
        b64(f.signing.secret_key.as_ref()).as_str(),
        "group_secret",
    ] {
        assert!(!bytes.windows(marker.len()).any(|w| w == marker.as_bytes()));
    }
}
#[test]
fn native_independent_generation_and_both_key_enrollment() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let (new, root) = f.fresh();
    let newcap = new.unlock_phrase(PHRASE).unwrap();
    let invite = f.vault.device_invitation(&cap).unwrap();
    let session = id();
    let offer = new.device_offer(&newcap, &session, Some(&invite)).unwrap();
    let response = f
        .vault
        .device_response(&cap, &offer, Some(&invite))
        .unwrap();
    assert_ne!(
        f.vault.device_public(&cap).unwrap()["signing_key"],
        new.device_public(&newcap).unwrap()["signing_key"]
    );
    let approval = f
        .vault
        .device_approval(&cap, &response["transcript"], true)
        .unwrap();
    let event = new
        .device_confirmation(&newcap, &response["transcript"], &approval, &session, true)
        .unwrap();
    assert_eq!(new.device_retry(&newcap, true).unwrap(), event);
    let snapshot = json!({"identity":f.snapshot["identity"],"events":[f.snapshot["events"][0],event],"head":{"version":"1","digest":digest("p02-state-c1","event",&event)},"generation":"0"});
    new.record_device_snapshot(&newcap, &snapshot).unwrap();
    assert_eq!(
        f.vault.record_device_snapshot(&cap, &snapshot).unwrap()["devices"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    new.lock();
    drop(new);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn native_qr_secretstream_direction_replay_and_lock() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let (new, root) = f.fresh();
    let newcap = new.unlock_phrase(PHRASE).unwrap();
    let invite = f.vault.device_invitation(&cap).unwrap();
    let qr = f
        .vault
        .native_pairing_qr(&cap, &invite, "existing-device-invitation")
        .unwrap();
    let scan = new.native_pairing_scan(&newcap, &qr["qr"], true).unwrap();
    let offer = new.device_offer(&newcap, &id(), Some(&invite)).unwrap();
    let anchor = digest("p02-state-c1", "invitation", &invite);
    let frame = new
        .native_pairing_frame(
            &newcap,
            scan["handle"].as_str().unwrap(),
            "new-device-offer",
            &offer,
            &anchor,
            true,
        )
        .unwrap();
    assert_eq!(
        f.vault
            .native_pairing_frame(
                &cap,
                qr["handle"].as_str().unwrap(),
                "new-device-offer",
                &frame,
                &anchor,
                false
            )
            .unwrap(),
        offer
    );
    assert!(
        f.vault
            .native_pairing_frame(
                &cap,
                qr["handle"].as_str().unwrap(),
                "new-device-offer",
                &frame,
                &anchor,
                false
            )
            .is_err()
    );
    f.vault.lock_all().unwrap();
    assert!(
        f.vault
            .native_pairing_frame(
                &cap,
                qr["handle"].as_str().unwrap(),
                "new-device-offer",
                &frame,
                &anchor,
                false
            )
            .is_err()
    );
    new.lock();
    drop(new);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn native_manifest_pin_and_roster_signature_substitution_fail() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let mut wrong = f.snapshot.clone();
    wrong["identity"]["body"]["account_id"] = json!(id());
    assert!(f.vault.record_device_snapshot(&cap, &wrong).is_err());
    wrong = f.snapshot.clone();
    wrong["events"][0]["signature"] = json!(b64(&[0; 64]));
    assert!(f.vault.record_device_snapshot(&cap, &wrong).is_err());
    assert_eq!(
        f.vault.record_device_snapshot(&cap, &f.snapshot).unwrap()["generation"],
        "0"
    );
}
#[test]
fn native_typed_boundary_denies_preview_foreign_stale_and_raw_keys() {
    let f = Fixture::new();
    let endpoint = Endpoint::new(f.vault.clone());
    let main = HostBinding::from_native_window(WindowRole::Main, "tauri://localhost");
    let unlock = endpoint
        .invoke(
            &main,
            &canonical(&json!({"operation":"unlock-phrase","phrase":PHRASE})).unwrap(),
        )
        .unwrap();
    let request = json!({"operation":"device-public","capability":unlock["capability"]});
    assert!(
        endpoint
            .invoke(
                &HostBinding::from_native_window(WindowRole::Preview, "tauri://localhost"),
                &canonical(&request).unwrap()
            )
            .is_err()
    );
    assert!(
        endpoint
            .invoke(
                &HostBinding::from_native_window(WindowRole::Main, "https://example.invalid"),
                &canonical(&request).unwrap()
            )
            .is_err()
    );
    assert!(
        endpoint
            .invoke(&main, br#"{"operation":"raw-keys"}"#)
            .is_err()
    );
    endpoint.lock();
    assert!(
        endpoint
            .invoke(&main, &canonical(&request).unwrap())
            .is_err()
    );
}
#[test]
fn native_local_l_rotation_keeps_additive_control_and_frozen_secret_frames() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let request = f.vault.device_settings_genesis(&cap).unwrap();
    f.vault
        .rotate_to_phrase(&cap, "public synthetic sunset cloud stone meadow", true)
        .unwrap();
    assert!(f.vault.unlock_phrase(PHRASE).is_err());
    let new = f
        .vault
        .unlock_phrase("public synthetic sunset cloud stone meadow")
        .unwrap();
    assert_eq!(f.vault.device_settings_genesis(&new).unwrap(), request);
}
fn reset_challenge(
    f: &Fixture,
    new: &Vault,
    cap: &anynote_local_vault::Capability,
    session: &str,
) -> Value {
    let device = new.device_public(cap).unwrap();
    let context = json!({"purpose":"device-possession-challenge","contract":"p02-state-c1","protocol":"anynote","protocol_version":1,"service_id":f.scope.service_id,"account_id":f.scope.account_id,"root_fingerprint":f.pins["root_fingerprint"],"intent":"reset","challenge_id":id(),"session_binding":hash(format!("AnyNote/P06/session-binding\0{session}").as_bytes()),"generation":f.snapshot["generation"],"roster":f.snapshot["head"],"nonce":b64(&libsodium_rs::random::bytes(32)),"device":device,"expires_at":(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()+50000).to_string()});
    let plain = json!({"purpose":"device-encryption-proof","context":context,"secret":b64(&libsodium_rs::random::bytes(32))});
    let public = libsodium_rs::crypto_box::PublicKey::from_bytes(
        &anynote_crypto_core::crypto::un64(device["encryption_key"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    json!({"context":context,"sealed_challenge":b64(&libsodium_rs::crypto_box::seal_box(&canonical(&plain).unwrap(),&public).unwrap()),"challenge_digest":digest("p02-state-c1","challenge-plaintext",&plain)})
}
#[test]
fn native_fresh_recovery_rejects_substituted_root_and_recovers_keys_only_after_activation() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let genesis = f.vault.device_settings_genesis(&cap).unwrap();
    let (new, root) = f.fresh();
    let nc = new.unlock_phrase(PHRASE).unwrap();
    let session = id();
    let challenge = reset_challenge(&f, &new, &nc, &session);
    let mut wrong = f.kit.clone();
    wrong["root_fingerprint"] = json!(hash(b"different root"));
    assert!(
        new.device_recovery_reset(&nc, &wrong, &challenge, &session, true)
            .is_err()
    );
    let records = genesis["pages"][0]["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["body"]["context"]["recipient"]["kind"] == "account-recovery")
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    assert!(
        new.device_group_keys(&nc, &genesis, &records, Some(&f.kit), None)
            .is_err()
    );
    let event = new
        .device_recovery_reset(&nc, &f.kit, &challenge, &session, true)
        .unwrap();
    assert_eq!(event, new.device_retry(&nc, true).unwrap());
    let snapshot = json!({"identity":f.snapshot["identity"],"events":[f.snapshot["events"][0],event],"head":{"version":"1","digest":digest("p02-state-c1","event",&event)},"generation":"1"});
    new.record_device_snapshot(&nc, &snapshot).unwrap();
    let result = new
        .device_group_keys(&nc, &genesis, &records, Some(&f.kit), None)
        .unwrap();
    assert_eq!(result["records"].as_array().unwrap().len(), 1);
    assert!(
        new.device_group_keys(&nc, &genesis, &[], None, Some(&f.scope.device_id))
            .is_err()
    );
    let bytes = std::fs::read(new.path()).unwrap();
    assert!(
        !bytes
            .windows(f.kit["recovery_secret"].as_str().unwrap().len())
            .any(|x| x == f.kit["recovery_secret"].as_str().unwrap().as_bytes())
    );
    new.lock();
    drop(new);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn native_known_checkpoint_and_descendant_revocation_reject_rollback_and_self_revoke() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let (new, root) = f.fresh();
    let nc = new.unlock_phrase(PHRASE).unwrap();
    let invite = f.vault.device_invitation(&cap).unwrap();
    let session = id();
    let offer = new.device_offer(&nc, &session, Some(&invite)).unwrap();
    let response = f
        .vault
        .device_response(&cap, &offer, Some(&invite))
        .unwrap();
    let approval = f
        .vault
        .device_approval(&cap, &response["transcript"], true)
        .unwrap();
    let event = new
        .device_confirmation(&nc, &response["transcript"], &approval, &session, true)
        .unwrap();
    let snapshot = json!({"identity":f.snapshot["identity"],"events":[f.snapshot["events"][0],event],"head":{"version":"1","digest":digest("p02-state-c1","event",&event)},"generation":"0"});
    f.vault.record_device_snapshot(&cap, &snapshot).unwrap();
    assert!(f.vault.record_device_snapshot(&cap, &f.snapshot).is_err());
    assert!(
        f.vault
            .device_revoke(&cap, std::slice::from_ref(&f.scope.device_id), true)
            .is_err()
    );
    let target = offer["body"]["device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let revoke = f
        .vault
        .device_revoke(&cap, std::slice::from_ref(&target), true)
        .unwrap();
    assert_eq!(
        revoke["body"]["payload"]["affected_devices"],
        json!([target])
    );
    let revoked = json!({"identity":f.snapshot["identity"],"events":[f.snapshot["events"][0],event,revoke],"head":{"version":"2","digest":digest("p02-state-c1","event",&revoke)},"generation":"0"});
    new.record_device_snapshot(&nc, &revoked).unwrap();
    assert!(new.device_invitation(&nc).is_err());
    new.lock();
    drop(new);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn native_two_connections_and_aborted_sql_write_preserve_acknowledged_control() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let other = Vault::open(f.vault.path(), f.scope.clone()).unwrap();
    let oc = other.unlock_phrase(PHRASE).unwrap();
    assert!(other.record_device_snapshot(&oc, &f.snapshot).is_err());
    let connection = rusqlite::Connection::open(f.vault.path()).unwrap();
    connection.execute_batch("CREATE TRIGGER p08_fault BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT, 'synthetic storage failure'); END;").unwrap();
    assert!(f.vault.device_settings_genesis(&cap).is_err());
    connection.execute_batch("DROP TRIGGER p08_fault;").unwrap();
    assert_eq!(
        f.vault.record_device_snapshot(&cap, &f.snapshot).unwrap()["head"],
        f.snapshot["head"]
    );
    assert!(f.vault.device_settings_genesis(&cap).is_ok());
    drop(connection);
    drop(other);
}
