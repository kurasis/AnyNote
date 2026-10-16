use anynote_crypto_core::{
    codec::{canonical, strict},
    crypto::{b64, hash},
};
use anynote_local_vault::{
    Record, Scope, Vault,
    ipc::{Endpoint, HostBinding, WindowRole},
    lifecycle::{Boundary, invalidate},
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
const PHRASE: &str = "public synthetic purple harbor paper lantern";
fn id() -> String {
    b64(&libsodium_rs::random::bytes(16))
}
fn fixture(kind: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../fixtures/protocol/p02/v1/bytes/{kind}-0000.hex"
    ));
    let s = std::fs::read_to_string(path).unwrap();
    let raw = (0..s.trim().len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s.trim()[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    strict(&raw, 8_388_608).unwrap()
}
struct TestVault {
    vault: Arc<Vault>,
    scope: Scope,
    root: PathBuf,
    secrets: Value,
    pins: Value,
}
impl TestVault {
    fn new() -> Self {
        libsodium_rs::ensure_init().unwrap();
        let d = fixture("draft");
        let scope = Scope {
            service_id: d["context"]["service_id"].as_str().unwrap().into(),
            account_id: d["context"]["author"]["account_id"]
                .as_str()
                .unwrap()
                .into(),
            device_id: d["context"]["author"]["device_id"].as_str().unwrap().into(),
            profile_id: id(),
        };
        let root = std::env::temp_dir().join(format!("anynote-p07-{}", id()));
        let vault = Arc::new(Vault::open(&root.join("vault.sqlite"), scope.clone()).unwrap());
        let s = libsodium_rs::crypto_sign::KeyPair::generate().unwrap();
        let e = libsodium_rs::crypto_box::KeyPair::generate();
        let secrets = json!({"device_signing_secret":b64(s.secret_key.as_ref()),"device_encryption_secret":b64(e.secret_key.as_ref()),"group_keys":[]});
        let pins = json!({"service_id":scope.service_id,"account_id":scope.account_id,"root_fingerprint":hash(&libsodium_rs::random::bytes(32))});
        vault
            .initialize_phrase(PHRASE, &canonical(&secrets).unwrap(), pins.clone(), true)
            .unwrap();
        Self {
            vault,
            scope,
            root,
            secrets,
            pins,
        }
    }
    fn db(&self) -> Connection {
        Connection::open(self.vault.path()).unwrap()
    }
    fn inspector(&self, forbidden: &[&str]) {
        for entry in std::fs::read_dir(&self.root).unwrap() {
            let p = entry.unwrap().path();
            if p.is_file() {
                let bytes = std::fs::read(p).unwrap();
                for secret in forbidden {
                    assert!(
                        !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                        "plaintext in owned SQLite/WAL"
                    );
                    assert!(
                        !bytes
                            .windows(b64(secret.as_bytes()).len())
                            .any(|w| w == b64(secret.as_bytes()).as_bytes()),
                        "encoded plaintext in owned SQLite/WAL"
                    );
                }
            }
        }
    }
}
#[test]
fn restart_ciphertext_and_secret_export_denial() {
    let f = TestVault::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let record = id();
    let d = fixture("draft");
    f.vault
        .save_batch(
            &cap,
            f.vault.lease(&cap).unwrap(),
            &[Record {
                id: record.clone(),
                kind: "draft".into(),
                data: d.clone(),
            }],
        )
        .unwrap();
    f.inspector(&[
        f.secrets["device_signing_secret"].as_str().unwrap(),
        f.secrets["device_encryption_secret"].as_str().unwrap(),
        d["payload"]["markdown"].as_str().unwrap(),
    ]);
    let state: Value = serde_json::from_str(
        &f.db()
            .query_row("SELECT value FROM meta", [], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        f.vault
            .read(&cap, state["vault_id"].as_str().unwrap(), "vault-secrets")
            .unwrap_err()
            .0,
        "SECRET_EXPORT_FORBIDDEN"
    );
    f.vault.lock_all().unwrap();
    assert!(f.vault.read(&cap, &record, "draft").is_err());
    let reopened = Vault::open(f.vault.path(), f.scope.clone()).unwrap();
    assert_eq!(reopened.status().unwrap(), "locked");
    let fresh = reopened.unlock_phrase(PHRASE).unwrap();
    assert_eq!(reopened.read(&fresh, &record, "draft").unwrap(), d);
}
#[test]
fn real_sqlite_atomic_batch_fault() {
    let f = TestVault::new();
    let c = f.vault.unlock_phrase(PHRASE).unwrap();
    let a = id();
    let b = id();
    let d = fixture("draft");
    let connection = f.db();
    connection.execute_batch(&format!("CREATE TRIGGER injected BEFORE INSERT ON records WHEN NEW.id='{b}' BEGIN SELECT RAISE(ABORT,'synthetic fault'); END;")).unwrap();
    let count: i64 = connection
        .query_row("SELECT count(*) FROM records", [], |r| r.get(0))
        .unwrap();
    let records = [
        Record {
            id: a.clone(),
            kind: "draft".into(),
            data: d.clone(),
        },
        Record {
            id: b.clone(),
            kind: "draft".into(),
            data: d,
        },
    ];
    let fence = f.vault.lease(&c).unwrap();
    assert!(f.vault.save_batch(&c, fence, &records).is_err());
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM records", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        count
    );
    connection.execute_batch("DROP TRIGGER injected;").unwrap();
    f.vault.save_batch(&c, fence, &records).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM records", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        count + 2
    );
}
#[test]
fn cross_connection_leader_and_stale_fence() {
    let f = TestVault::new();
    let other = Vault::open(f.vault.path(), f.scope.clone()).unwrap();
    let a = f.vault.unlock_phrase(PHRASE).unwrap();
    let b = other.unlock_phrase(PHRASE).unwrap();
    let l1 = f.vault.lease(&a).unwrap();
    assert_eq!(other.lease(&b).unwrap_err().0, "WRITER_BUSY");
    let connection = f.db();
    let mut state: Value = serde_json::from_str(
        &connection
            .query_row("SELECT value FROM meta", [], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    state["lease"]["issued"] = json!(0);
    state["lease"]["expires"] = json!(10000);
    connection
        .execute("UPDATE meta SET value=?1", [state.to_string()])
        .unwrap();
    let l2 = other.lease(&b).unwrap();
    assert!(l2 > l1);
    assert_eq!(
        f.vault
            .save_batch(
                &a,
                l1,
                &[Record {
                    id: id(),
                    kind: "draft".into(),
                    data: fixture("draft")
                }]
            )
            .unwrap_err()
            .0,
        "STALE_WRITER"
    );
    other.lock_all().unwrap();
    assert!(f.vault.lease(&a).is_err());
}
#[test]
fn host_writer_readiness_does_not_invalidate_content_cas() {
    let f = TestVault::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let fence = f.vault.writer_ready(&cap).unwrap();
    let root = anynote_local_vault::content::control_id(&f.scope).unwrap();
    let before = f
        .vault
        .content_read(&cap, &root, "content-control")
        .unwrap();
    let metadata: String = f
        .db()
        .query_row("SELECT value FROM meta", [], |r| r.get(0))
        .unwrap();
    // Actual host status/transfer polls may interleave between the protected
    // helper's read and commit. They must not manufacture a concurrent writer.
    let mut observed_fence = fence;
    for _ in 0..16 {
        observed_fence = f.vault.writer_ready(&cap).unwrap();
        assert!(f.vault.file_transfers(&cap).unwrap().is_array());
    }
    let after_polls = f
        .db()
        .query_row("SELECT value FROM meta", [], |r| r.get::<_, String>(0))
        .unwrap();
    let record = Record {
        id: root.clone(),
        kind: "content-control".into(),
        data: json!({"purpose":"P15 public CAS regression","version":1}),
    };
    f.vault
        .content_commit(&cap, before.revision, std::slice::from_ref(&record), &[])
        .unwrap();
    assert_eq!(observed_fence, fence);
    assert_eq!(metadata, after_polls);
    // A real intervening commit still invalidates the old snapshot.
    assert_eq!(
        f.vault
            .content_commit(&cap, before.revision, std::slice::from_ref(&record), &[])
            .unwrap_err()
            .0,
        "STALE_WRITER"
    );
    assert_eq!(
        f.vault
            .content_read(&cap, &root, "content-control")
            .unwrap()
            .data
            .unwrap(),
        record.data
    );
    f.vault.lock();
    assert!(f.vault.file_transfers(&cap).is_err());
}

#[test]
fn host_writer_readiness_preserves_owner_expiry_and_generation_fences() {
    let f = TestVault::new();
    let other = Vault::open(f.vault.path(), f.scope.clone()).unwrap();
    let a = f.vault.unlock_phrase(PHRASE).unwrap();
    let b = other.unlock_phrase(PHRASE).unwrap();
    let first = f.vault.writer_ready(&a).unwrap();
    assert_eq!(other.writer_ready(&b).unwrap_err().0, "WRITER_BUSY");
    let connection = f.db();
    let mut state: Value = serde_json::from_str(
        &connection
            .query_row("SELECT value FROM meta", [], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    state["lease"]["issued"] = json!(0);
    state["lease"]["expires"] = json!(10000);
    connection
        .execute("UPDATE meta SET value=?1", [state.to_string()])
        .unwrap();
    let next = other.writer_ready(&b).unwrap();
    assert!(next > first);
    assert_eq!(f.vault.writer_ready(&a).unwrap_err().0, "WRITER_BUSY");
    assert_eq!(
        f.vault
            .save_batch(
                &a,
                first,
                &[Record {
                    id: id(),
                    kind: "draft".into(),
                    data: fixture("draft")
                }]
            )
            .unwrap_err()
            .0,
        "STALE_WRITER"
    );
    other.lock_all().unwrap();
    assert!(other.writer_ready(&b).is_err());
}
#[test]
fn known_record_rollback_and_nonce_after_unknown_full_restart() {
    let f = TestVault::new();
    let c = f.vault.unlock_phrase(PHRASE).unwrap();
    let record = id();
    let d = fixture("draft");
    let fence = f.vault.lease(&c).unwrap();
    let records = [Record {
        id: record.clone(),
        kind: "draft".into(),
        data: d,
    }];
    f.vault.save_batch(&c, fence, &records).unwrap();
    let connection = f.db();
    let old: Vec<u8> = connection
        .query_row("SELECT frame FROM records WHERE id=?1", [&record], |r| {
            r.get(0)
        })
        .unwrap();
    f.vault.save_batch(&c, fence, &records).unwrap();
    let new: Vec<u8> = connection
        .query_row("SELECT frame FROM records WHERE id=?1", [&record], |r| {
            r.get(0)
        })
        .unwrap();
    assert_ne!(
        strict(&old, 8_388_608).unwrap()["nonce"],
        strict(&new, 8_388_608).unwrap()["nonce"]
    );
    connection
        .execute(
            "UPDATE records SET frame=?1 WHERE id=?2",
            params![old, record],
        )
        .unwrap();
    assert_eq!(
        f.vault.read(&c, &record, "draft").unwrap_err().0,
        "ROLLBACK_QUARANTINE"
    );
    f.vault.lock_all().unwrap();
    let fresh = Vault::open(f.vault.path(), f.scope.clone()).unwrap();
    let c = fresh.unlock_phrase(PHRASE).unwrap();
    fresh
        .save_batch(&c, fresh.lease(&c).unwrap(), &records)
        .unwrap();
    let after: Vec<u8> = connection
        .query_row("SELECT frame FROM records WHERE id=?1", [&record], |r| {
            r.get(0)
        })
        .unwrap();
    assert_ne!(
        strict(&old, 8_388_608).unwrap()["nonce"],
        strict(&after, 8_388_608).unwrap()["nonce"]
    );
}
#[test]
fn wrong_phrase_and_excessive_kdf_reject_before_unlock() {
    let f = TestVault::new();
    assert!(
        f.vault
            .unlock_phrase("other synthetic purple harbor paper lantern")
            .is_err()
    );
    assert_eq!(f.vault.status().unwrap(), "locked");
    let connection = f.db();
    let mut state: Value = serde_json::from_str(
        &connection
            .query_row("SELECT value FROM meta", [], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    state["wrappers"][0]["parameters"]["memlimit"] = json!(1073741824);
    connection
        .execute("UPDATE meta SET value=?1", [state.to_string()])
        .unwrap();
    assert!(f.vault.unlock_phrase(PHRASE).is_err());
}
#[test]
fn signed_manifest_rejects_root_pin_substitution() {
    let f = TestVault::new();
    let connection = f.db();
    let mut state: Value = serde_json::from_str(
        &connection
            .query_row("SELECT value FROM meta", [], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    state["pins"]["root_fingerprint"] = json!(hash(&libsodium_rs::random::bytes(32)));
    connection
        .execute("UPDATE meta SET value=?1", [state.to_string()])
        .unwrap();
    assert_eq!(
        f.vault.unlock_phrase(PHRASE).unwrap_err().0,
        "INTEGRITY_FAILURE"
    );
}
#[test]
fn all_lifecycle_events_reject_old_capabilities() {
    let f = TestVault::new();
    for reason in [
        Boundary::SessionLock,
        Boundary::Suspend,
        Boundary::Background,
        Boundary::Logout,
        Boundary::Close,
        Boundary::Idle,
    ] {
        let cap = f.vault.unlock_phrase(PHRASE).unwrap();
        invalidate(&f.vault.lock_signal(), reason);
        assert!(f.vault.lease(&cap).is_err());
        assert_eq!(f.vault.status().unwrap(), "locked");
    }
}
#[test]
fn real_rust_ipc_main_scope_and_lock_boundary() {
    let f = TestVault::new();
    let endpoint = Endpoint::new(f.vault.clone());
    let main = HostBinding::from_native_window(WindowRole::Main, "http://tauri.localhost");
    let preview = HostBinding::from_native_window(WindowRole::Preview, "http://tauri.localhost");
    let remote = HostBinding::from_native_window(WindowRole::Main, "https://attacker.invalid");
    let request = json!({"operation":"unlock-phrase","phrase":PHRASE}).to_string();
    assert_eq!(
        endpoint.invoke(&preview, request.as_bytes()).unwrap_err().0,
        "IPC_SCOPE_DENIED"
    );
    assert_eq!(
        endpoint.invoke(&remote, request.as_bytes()).unwrap_err().0,
        "IPC_SCOPE_DENIED"
    );
    let result = endpoint.invoke(&main, request.as_bytes()).unwrap();
    let cap = result["capability"].as_str().unwrap();
    assert!(
        !result
            .to_string()
            .contains(f.secrets["device_signing_secret"].as_str().unwrap())
    );
    assert!(
        endpoint
            .invoke(
                &main,
                json!({"operation":"read","capability":cap,"id":id(),"kind":"session"})
                    .to_string()
                    .as_bytes()
            )
            .is_err()
    );
    endpoint.lock();
    assert!(
        endpoint
            .invoke(
                &main,
                json!({"operation":"read","capability":cap,"id":id(),"kind":"draft"})
                    .to_string()
                    .as_bytes()
            )
            .is_err()
    );
    assert!(
        endpoint
            .invoke(&main, b"{\"operation\":\"status\",\"path\":\"/tmp\"}")
            .is_err()
    );
    assert!(
        endpoint
            .invoke(&main, b"{\"operation\":\"get-private-key\"}")
            .is_err()
    );
}
#[test]
fn native_session_tokens_are_encrypted_and_not_ipc_readable() {
    let f = TestVault::new();
    let c = f.vault.unlock_phrase(PHRASE).unwrap();
    let record = id();
    let access = format!("synthetic-p07-access-{}", id());
    let refresh = format!("synthetic-p07-refresh-{}", id());
    let credentials = anynote_auth_native::Credentials {
        access: zeroize::Zeroizing::new(access.clone()),
        refresh: zeroize::Zeroizing::new(refresh.clone()),
        session_id: id(),
        state: "restricted".into(),
    };
    f.vault
        .store_credentials(&c, &record, &credentials)
        .unwrap();
    f.inspector(&[&access, &refresh]);
    assert_eq!(
        f.vault.read(&c, &record, "session").unwrap_err().0,
        "SECRET_EXPORT_FORBIDDEN"
    );
    f.vault.clear_session(&c, &record).unwrap();
    assert_eq!(
        f.db()
            .query_row("SELECT count(*) FROM records WHERE id=?1", [record], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
}
#[test]
fn draft_never_evicted_and_phrase_choice_is_explicit() {
    let f = TestVault::new();
    let c = f.vault.unlock_phrase(PHRASE).unwrap();
    let record = id();
    let fence = f.vault.lease(&c).unwrap();
    f.vault
        .save_batch(
            &c,
            fence,
            &[Record {
                id: record.clone(),
                kind: "draft".into(),
                data: fixture("draft"),
            }],
        )
        .unwrap();
    assert_eq!(
        f.vault.evict_cache(&c, fence, &record).unwrap_err().0,
        "UNSYNCED_WORK_PROTECTED"
    );
    let empty = Vault::open(
        &f.root.join("other.sqlite"),
        Scope {
            profile_id: id(),
            ..f.scope.clone()
        },
    )
    .unwrap();
    assert_eq!(
        empty
            .initialize_phrase(PHRASE, &canonical(&f.secrets).unwrap(), f.pins, true)
            .unwrap(),
        ()
    );
    let denied = Vault::open(
        &f.root.join("denied.sqlite"),
        Scope {
            profile_id: id(),
            ..f.scope.clone()
        },
    )
    .unwrap();
    assert_eq!(
        denied
            .initialize_phrase(PHRASE, &canonical(&f.secrets).unwrap(), json!({}), false)
            .unwrap_err()
            .0,
        "EXPLICIT_PHRASE_CHOICE_REQUIRED"
    );
}
#[test]
fn empty_store_reenrollment_and_unknown_schema_preserve_bytes() {
    let f = TestVault::new();
    let path = f.root.join("empty.sqlite");
    let empty = Vault::open(
        &path,
        Scope {
            profile_id: id(),
            ..f.scope.clone()
        },
    )
    .unwrap();
    assert_eq!(empty.status().unwrap(), "enrollment-required");
    drop(empty);
    let connection = Connection::open(&path).unwrap();
    connection.pragma_update(None, "user_version", 7).unwrap();
    drop(connection);
    let before = std::fs::read(&path).unwrap();
    assert!(Vault::open(&path, f.scope.clone()).is_err());
    assert_eq!(std::fs::read(path).unwrap(), before);
}
#[test]
fn cross_account_namespace_is_denied() {
    let f = TestVault::new();
    let other = Vault::open(
        f.vault.path(),
        Scope {
            account_id: id(),
            ..f.scope.clone()
        },
    )
    .unwrap();
    assert!(other.unlock_phrase(PHRASE).is_err());
}

#[test]
fn wrapper_revocation_rotates_l_and_preserves_all_local_work() {
    let f = TestVault::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let record = id();
    let d = fixture("draft");
    f.vault
        .save_batch(
            &cap,
            f.vault.lease(&cap).unwrap(),
            &[Record {
                id: record.clone(),
                kind: "draft".into(),
                data: d.clone(),
            }],
        )
        .unwrap();
    let conn = f.db();
    let old: Value = serde_json::from_str(
        &conn
            .query_row("SELECT value FROM meta", [], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    let old_frame: Vec<u8> = conn
        .query_row("SELECT frame FROM records WHERE id=?1", [&record], |r| {
            r.get(0)
        })
        .unwrap();
    let next_phrase = "alternate synthetic orange ocean willow horizon";
    f.vault.rotate_to_phrase(&cap, next_phrase, true).unwrap();
    assert_eq!(f.vault.status().unwrap(), "locked");
    assert!(f.vault.unlock_phrase(PHRASE).is_err());
    let fresh = f.vault.unlock_phrase(next_phrase).unwrap();
    assert_eq!(f.vault.read(&fresh, &record, "draft").unwrap(), d);
    let current: Value = serde_json::from_str(
        &conn
            .query_row("SELECT value FROM meta", [], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    assert_ne!(old["wrappers"][0], current["wrappers"][0]);
    let new_frame: Vec<u8> = conn
        .query_row("SELECT frame FROM records WHERE id=?1", [&record], |r| {
            r.get(0)
        })
        .unwrap();
    assert_ne!(old_frame, new_frame);
    assert!(f.vault.lease(&cap).is_err());
}
#[test]
fn interrupted_l_rotation_keeps_prior_key_and_ciphertext() {
    let f = TestVault::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let record = id();
    f.vault
        .save_batch(
            &cap,
            f.vault.lease(&cap).unwrap(),
            &[Record {
                id: record.clone(),
                kind: "draft".into(),
                data: fixture("draft"),
            }],
        )
        .unwrap();
    let conn = f.db();
    let old: Vec<u8> = conn
        .query_row("SELECT frame FROM records WHERE id=?1", [&record], |r| {
            r.get(0)
        })
        .unwrap();
    conn.execute_batch(&format!("CREATE TRIGGER rotation_fault BEFORE UPDATE ON records WHEN NEW.id='{record}' BEGIN SELECT RAISE(ABORT,'synthetic fault'); END;")).unwrap();
    assert!(
        f.vault
            .rotate_to_phrase(
                &cap,
                "alternate synthetic orange ocean willow horizon",
                true
            )
            .is_err()
    );
    let after: Vec<u8> = conn
        .query_row("SELECT frame FROM records WHERE id=?1", [&record], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(old, after);
    assert_eq!(
        f.vault.read(&cap, &record, "draft").unwrap(),
        fixture("draft")
    );
}

#[cfg(windows)]
#[test]
fn actual_windows_wts_registration_and_message_fences_without_hello_objects() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{WTS_SESSION_LOCK, WTS_SESSION_UNLOCK};
    use windows_sys::{
        Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, PBT_APMSUSPEND, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE,
        },
        core::w,
    };
    let f = TestVault::new();
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            w!("STATIC"),
            w!("AnyNote P07 software hook"),
            0,
            0,
            0,
            32,
            32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    assert!(!hwnd.is_null());
    let hook =
        anynote_local_vault::lifecycle::WindowsHook::attach(hwnd as usize, f.vault.lock_signal())
            .unwrap();
    let before = f.vault.lock_signal().generation();
    hook.message(WM_WTSSESSION_CHANGE, WTS_SESSION_UNLOCK as usize);
    assert_eq!(before, f.vault.lock_signal().generation());
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    hook.message(WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK as usize);
    assert!(f.vault.lease(&cap).is_err());
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    hook.message(WM_POWERBROADCAST, PBT_APMSUSPEND as usize);
    assert!(f.vault.lease(&cap).is_err());
    drop(hook);
    unsafe {
        DestroyWindow(hwnd);
    }
}
#[cfg(not(windows))]
#[test]
fn non_windows_hello_has_no_software_fallback() {
    let f = TestVault::new();
    assert_eq!(
        f.vault.unlock_hello(0).unwrap_err().0,
        "WINDOWS_PROVIDER_REQUIRED"
    );
    assert_eq!(f.vault.status().unwrap(), "locked");
}

#[test]
fn p13_multipart_custody_reserves_namespace_rotates_and_rejects_downgrade() {
    let f = TestVault::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let root = anynote_local_vault::content::control_id(&f.scope).unwrap();
    let data = json!({"purpose":"p13-native-search","version":1,"private_title":"P13 PRIVATE NATIVE SEARCH TOKEN","body":"x".repeat(300000)});
    let before = f
        .vault
        .content_read(&cap, &root, "content-control")
        .unwrap();
    f.vault
        .content_commit(
            &cap,
            before.revision,
            &[Record {
                id: root.clone(),
                kind: "content-control".into(),
                data: data.clone(),
            }],
            &[],
        )
        .unwrap();
    assert_eq!(
        f.vault
            .content_read(&cap, &root, "content-control")
            .unwrap()
            .data
            .unwrap(),
        data
    );
    f.inspector(&["P13 PRIVATE NATIVE SEARCH TOKEN"]);
    let fence = f.vault.lease(&cap).unwrap();
    assert_eq!(
        f.vault.evict_cache(&cap, fence, &root).unwrap_err().0,
        "RESERVED_RECORD"
    );
    assert_eq!(
        f.vault
            .content_commit(
                &cap,
                before.revision,
                &[Record {
                    id: root.clone(),
                    kind: "content-control".into(),
                    data: data.clone()
                }],
                &[]
            )
            .unwrap_err()
            .0,
        "STALE_WRITER"
    );
    f.vault
        .rotate_to_phrase(&cap, "public synthetic p13 rotated phrase", true)
        .unwrap();
    let next = f
        .vault
        .unlock_phrase("public synthetic p13 rotated phrase")
        .unwrap();
    assert_eq!(
        f.vault
            .content_read(&next, &root, "content-control")
            .unwrap()
            .data
            .unwrap(),
        data
    );
    f.vault.lock();
    let db = f.db();
    let raw: String = db
        .query_row("SELECT value FROM meta", [], |r| r.get(0))
        .unwrap();
    let mut state: Value = serde_json::from_str(&raw).unwrap();
    state.as_object_mut().unwrap().remove("content_profile");
    db.execute("UPDATE meta SET value=?1", [state.to_string()])
        .unwrap();
    assert_eq!(
        f.vault
            .unlock_phrase("public synthetic p13 rotated phrase")
            .unwrap_err()
            .0,
        "INTEGRITY_FAILURE"
    );
}
