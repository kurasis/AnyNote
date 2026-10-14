include!("../../vault-native/tests/common/notes_fixture.rs");
use anynote_windows_native::{
    host::{Binding, Host, Profile, Request, Service},
    jobs::Jobs,
    selection::{Destination, Selections, Source},
};
use std::io::Write;
fn host(f: &Fixture) -> Host {
    let h = Host::from_parts(
        f.vault.path().parent().unwrap(),
        Profile {
            version: 1,
            scope: f.scope.clone(),
            service: Service {
                issuer: "https://synthetic.example".into(),
                app: "https://synthetic-app.example".into(),
                pins: f.pins.clone(),
            },
            credential_id: id(),
        },
        f.vault.clone(),
        anynote_auth_native::Adapter::new(
            "https://synthetic.example",
            "https://synthetic-app.example",
        )
        .unwrap(),
    );
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    h.bind_new_service(&cap).unwrap();
    h
}
fn binding() -> Binding {
    Binding {
        label: "main".into(),
        origin: "http://tauri.localhost".into(),
        hwnd: 0,
    }
}
#[test]
fn native_host_rejects_foreign_preview_unknown_fields_and_stale_generations() {
    let f = Fixture::new();
    let h = host(&f);
    let mut b = binding();
    b.label = "preview".into();
    assert_eq!(
        h.execute(&b, 0, Request::Status {}).unwrap_err().0,
        "IPC_SCOPE_DENIED"
    );
    b.label = "main".into();
    b.origin = "https://synthetic.example".into();
    assert_eq!(
        h.execute(
            &b,
            0,
            Request::Unlock {
                phrase: PHRASE.into()
            }
        )
        .unwrap_err()
        .0,
        "IPC_SCOPE_DENIED"
    );
    for request in [
        json!({"operation":"status","path":"vault.sqlite"}),
        json!({"operation":"http","url":"https://synthetic.example"}),
        json!({"operation":"sign","bytes":"abc"}),
        json!({"operation":"save","edit":{},"publish":false,"group_key":"abc"}),
    ] {
        assert!(serde_json::from_value::<Request>(request).is_err());
    }
    h.execute(
        &binding(),
        0,
        Request::Unlock {
            phrase: PHRASE.into(),
        },
    )
    .unwrap();
    let job = h.jobs.start(0).unwrap();
    h.lock();
    assert!(job.cancelled());
    assert_eq!(h.capability(0).err().unwrap().0, "STALE_CAPABILITY");
    assert_eq!(h.capability(h.current()).err().unwrap().0, "VAULT_LOCKED");
    h.execute(
        &binding(),
        h.current(),
        Request::Unlock {
            phrase: PHRASE.into(),
        },
    )
    .unwrap();
    assert_eq!(
        h.execute(&binding(), 0, Request::Summary {}).unwrap_err().0,
        "STALE_CAPABILITY"
    );
}
#[test]
fn selected_handles_are_single_use_generation_bound_and_destinations_never_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("selected.txt");
    std::fs::write(&path, b"public synthetic source").unwrap();
    let selections = Selections::default();
    let handle = selections
        .insert(4, Source::open(&path, 128).unwrap())
        .unwrap();
    assert_eq!(
        selections.take(5, &handle).err().unwrap().0,
        "STALE_CAPABILITY"
    );
    assert_eq!(
        selections.take(4, &handle).err().unwrap().0,
        "SOURCE_RESELECT_REQUIRED"
    );
    let source = Source::open(&path, 128).unwrap();
    assert_eq!(source.size, 23);
    assert_eq!(
        Source::open(&path, 1).err().unwrap().0,
        "FILE_LIMIT_EXCEEDED"
    );
    let target = dir.path().join("explicit.txt");
    {
        let mut out = Destination::create(&target).unwrap();
        out.write_all(b"authenticated only").unwrap();
        assert!(!target.exists());
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    let mut out = Destination::create(&target).unwrap();
    out.write_all(b"complete authenticated data").unwrap();
    out.finish().unwrap();
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"complete authenticated data"
    );
    assert_eq!(
        Destination::create(&target).err().unwrap().0,
        "DESTINATION_EXISTS"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"public synthetic source");
}
#[test]
fn native_jobs_are_bounded_cancelled_and_do_not_expose_paths() {
    let jobs = Jobs::default();
    let a = jobs.start(7).unwrap();
    let b = jobs.start(7).unwrap();
    assert_eq!(jobs.start(7).err().unwrap().0, "HOST_BUSY");
    jobs.pause_all();
    assert_eq!(a.check(7).unwrap_err().0, "RESUME_REQUIRED");
    b.finish(Err(anynote_crypto_core::Error("INSUFFICIENT_STORAGE")));
    let summary = jobs.summary(7).unwrap();
    assert!(
        !canonical(&summary)
            .unwrap()
            .windows(4)
            .any(|w| w == b"path")
    );
    assert!(
        jobs.summary(8).unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
#[test]
fn recovered_file_parts_use_fresh_keys_protected_checkpoints_and_reject_different_source() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let bytes = b"synthetic recovery has no plaintext staging";
    let proof = json!({"size":bytes.len(),"parts":[hash(bytes)],"digest":hash(bytes)});
    let a = f
        .vault
        .prepare_recovered_file(
            &cap,
            g["group_id"].as_str().unwrap(),
            &proof,
            "recovered.txt",
            "text/plain",
        )
        .unwrap();
    let b = f
        .vault
        .prepare_recovered_file(
            &cap,
            g["group_id"].as_str().unwrap(),
            &proof,
            "recovered.txt",
            "text/plain",
        )
        .unwrap();
    assert_ne!(a["request"]["context"], b["request"]["context"]);
    let draft = a["draft_id"].as_str().unwrap();
    assert_eq!(
        f.vault
            .recovered_file_part(&cap, draft, 0, b"bad")
            .unwrap_err()
            .0,
        "SOURCE_CHANGED"
    );
    let cipher = f.vault.recovered_file_part(&cap, draft, 0, bytes).unwrap();
    assert_ne!(cipher, bytes);
    assert_eq!(
        f.vault.recovered_file_part(&cap, draft, 0, bytes).unwrap(),
        cipher
    );
    f.vault.lock();
    assert_eq!(
        f.vault
            .recovered_file_part(&cap, draft, 0, bytes)
            .unwrap_err()
            .0,
        "VAULT_LOCKED"
    );
    for e in std::fs::read_dir(f.vault.path().parent().unwrap()).unwrap() {
        let e = e.unwrap();
        if e.path().is_file() {
            let data = std::fs::read(e.path()).unwrap();
            assert!(!data.windows(bytes.len()).any(|w| w == bytes));
            assert!(!data.windows(13).any(|w| w == b"recovered.txt"));
        }
    }
}

#[test]
fn native_private_portable_proof_and_selected_keys_match_authenticated_source() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let (_, queue, sent) = attempt(&f, &cap, &g);
    command(
        &f,
        &cap,
        json!({"action":"ack","attempt_id":queue["attempt_id"],"result":receipt(&sent["request"])}),
    );
    let record = &sent["request"]["bundle"];
    let c = &record["envelope"]["header"]["context"];
    let item = json!({"group_id":g["group_id"],"object_id":c["object_id"],"revision_id":c["revision_id"],"object_kind":c["object_kind"],"payload_status":"retained","envelope_digest":digest("p02-v1","envelope",&record["envelope"])});
    let proof = f
        .vault
        .portable_public(&cap, &[g["group_id"].as_str().unwrap().into()])
        .unwrap();
    assert_eq!(proof["pins"].as_array().unwrap().len(), 1);
    assert!(proof["pins"][0]["history"].is_object());
    assert_eq!(proof["document"]["profile"], "p13-public-proof-v1");
    let selected = f.vault.portable_selected_key(&cap, &item, record).unwrap();
    assert_eq!(selected["key_kind"], "object-dek");
    assert_eq!(selected["revision_id"], c["revision_id"]);
    assert!(selected["file_data_dek"].is_null());
    let mut wrong = item.clone();
    wrong["revision_id"] = json!(id());
    assert_eq!(
        f.vault
            .portable_selected_key(&cap, &wrong, record)
            .unwrap_err()
            .0,
        "EXPORT_SOURCE_MISMATCH"
    );
    let mut header = json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"export-footer","export_id":id(),"header_digest":hash(b"synthetic verified header"),"inventory_digest":hash(b"synthetic inventory"),"page_count":"0","item_count":"0","total_item_bytes":"0","signer":proof["signer"]});
    let expected = header.clone();
    header["item_count"] = json!("1");
    assert_eq!(
        f.vault
            .sign_portable_footer(&cap, &header, &expected)
            .unwrap_err()
            .0,
        "EXPORT_SOURCE_MISMATCH"
    );
}

#[test]
fn tampered_public_profile_cannot_retarget_native_credentials() {
    let f = Fixture::new();
    let mut h = host(&f);
    h.execute(
        &binding(),
        0,
        Request::Unlock {
            phrase: PHRASE.into(),
        },
    )
    .unwrap();
    h.profile.service.issuer = "https://attacker.example".into();
    assert_eq!(
        h.capability(0).err().unwrap().0,
        "SERVICE_CONFIGURATION_CHANGED"
    );
    assert_eq!(
        h.execute(&binding(), 0, Request::Login {}).unwrap_err().0,
        "SERVICE_CONFIGURATION_CHANGED"
    );
}

#[test]
fn actual_filesystem_space_estimate_fails_closed_before_creating_output() {
    let d = tempfile::tempdir().unwrap();
    let output = d.path().join("explicit.age");
    anynote_windows_native::selection::ensure_space(&output, 1).unwrap();
    assert_eq!(
        anynote_windows_native::selection::ensure_space(&output, u64::MAX)
            .unwrap_err()
            .0,
        "INSUFFICIENT_STORAGE"
    );
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
}
