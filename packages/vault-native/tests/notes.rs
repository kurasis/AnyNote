include!("common/notes_fixture.rs");
use anynote_local_vault::{
    Record,
    ipc::{Endpoint, HostBinding, WindowRole},
};

#[test]
fn staged_sync_cursor_is_atomic_and_restore_regression_keeps_drafts() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let (_, _, sent) = attempt(&f, &cap, &g);
    let bundle = &sent["request"]["bundle"];
    let x = &bundle["envelope"]["header"]["context"];
    let ed = digest("p02-v1", "envelope", &bundle["envelope"]);
    let item = json!({"group_id":g["group_id"],"object_kind":"thread","object_id":x["object_id"],"revision_id":x["revision_id"],"envelope_digest":ed,"payload_status":"retained"});
    let snapshot_id = id();
    let page = json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"snapshot-page","snapshot_id":snapshot_id,"page_index":"0","items":[item]});
    let status = group_status(&f, &g);
    let mut catalog_bytes = b"AnyNote/P11/catalog\0".to_vec();
    catalog_bytes.extend(1u32.to_be_bytes());
    let b = canonical(&status).unwrap();
    catalog_bytes.extend((b.len() as u32).to_be_bytes());
    catalog_bytes.extend(b);
    let mut inventory = b"AnyNote/p02-v1/hash/snapshot-inventory\0".to_vec();
    inventory.extend(1u32.to_be_bytes());
    inventory.extend(1u64.to_be_bytes());
    for n in [0, 1, canonical(&page).unwrap().len() as u32] {
        inventory.extend(n.to_be_bytes());
    }
    inventory.extend(
        anynote_crypto_core::crypto::un64(&digest("p02-v1", "snapshot-page", &page)).unwrap(),
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let cursor = json!({"generation":id(),"sequence":"3"});
    let scope = json!({"service_id":f.scope.service_id,"account_id":f.scope.account_id,"root_fingerprint":f.pins["root_fingerprint"],"group_id":g["group_id"]});
    let result = json!({"version":1,"scope":scope,"descriptor":{"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"snapshot-descriptor","snapshot_id":snapshot_id,"account_id":f.scope.account_id,"device_id":f.scope.device_id,"snapshot_purpose":"resync","watermark":cursor,"created_at":now.to_string(),"expires_at":(now+1800000).to_string(),"page_count":"1","item_count":"1","inventory_digest":hash(&inventory)},"catalog_count":"1","catalog_digest":hash(&catalog_bytes)});
    command(
        &f,
        &cap,
        json!({"action":"sync","request":{"action":"snapshot-start","result":result}}),
    );
    command(
        &f,
        &cap,
        json!({"action":"sync","request":{"action":"catalog","page":{"version":1,"snapshot_id":snapshot_id,"start":"0","groups":[status],"next":null}}}),
    );
    command(
        &f,
        &cap,
        json!({"action":"sync","request":{"action":"snapshot-page","result":{"version":1,"scope":scope,"page":page}}}),
    );
    let finish: NotesRequest =
        serde_json::from_value(json!({"action":"sync","request":{"action":"snapshot-finish"}}))
            .unwrap();
    assert_eq!(
        f.vault.notes_command(&cap, finish).unwrap_err().0,
        "SYNC_GAP"
    );
    command(
        &f,
        &cap,
        json!({"action":"sync","request":{"action":"snapshot-item","result":{"version":1,"snapshot_id":snapshot_id,"item":item,"bundle":bundle,"reference":{"object_id":x["object_id"],"object_kind":"thread","thread_id":null,"archived":false,"tombstoned":false,"created_sequence":"3","updated_sequence":"3","heads":[{"revision_id":x["revision_id"],"envelope_digest":ed}]}}}}),
    );
    let foreground = command(
        &f,
        &cap,
        json!({"action":"open","request":{"group_id":g["group_id"],"object_id":x["object_id"],"revision_id":x["revision_id"],"object_kind":"thread","thread_id":null,"bundle":bundle}}),
    );
    assert_eq!(foreground["envelope_digest"], ed);
    assert!(
        command(
            &f,
            &cap,
            json!({"action":"sync","request":{"action":"status"}})
        )["cursor"]
            .is_null()
    );
    f.vault.lock_all().unwrap();
    let reopened = Vault::open(f.vault.path(), f.scope.clone()).unwrap();
    let c = reopened.unlock_phrase(PHRASE).unwrap();
    let finish: NotesRequest =
        serde_json::from_value(json!({"action":"sync","request":{"action":"snapshot-finish"}}))
            .unwrap();
    let done = reopened.notes_command(&c, finish).unwrap();
    assert_eq!(done["cursor"], cursor);
    assert_eq!(
        reopened
            .notes_command(&c, NotesRequest::Summary {})
            .unwrap()["drafts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let run = |request: Value| {
        reopened
            .notes_command(&c, serde_json::from_value(request).unwrap())
            .unwrap()
    };
    let mut update = edit(&g, "PUBLIC native current after sync");
    update["object_id"] = x["object_id"].clone();
    update["action"] = json!("update");
    update["parents"] = json!([{"revision_id":x["revision_id"],"envelope_digest":ed}]);
    let saved = run(json!({"action":"save","edit":update}));
    let queued = run(json!({"action":"queue","draft_id":saved["draft_id"]}));
    let sent2 = run(json!({"action":"send","attempt_id":queued["attempt_id"]}));
    let b2 = &sent2["request"]["bundle"];
    let c2 = &b2["envelope"]["header"]["context"];
    let ed2 = digest("p02-v1", "envelope", &b2["envelope"]);
    run(
        json!({"action":"ack","attempt_id":queued["attempt_id"],"result":receipt(&sent2["request"])}),
    );
    let next = json!({"generation":cursor["generation"],"sequence":"4"});
    run(
        json!({"action":"sync","request":{"action":"delta-start","page":{"version":1,"scope":scope,"from_cursor":cursor,"next_cursor":next,"watermark":next,"scanned_count":"1","complete":true,"events":[{"event_id":id(),"sequence":"4","group_id":g["group_id"],"object_id":x["object_id"],"revision_id":c2["revision_id"],"digest":ed2,"kind":"object-commit"}]}}}),
    );
    run(
        json!({"action":"sync","request":{"action":"delta-item","result":{"version":1,"item":{"group_id":g["group_id"],"object_kind":"thread","object_id":x["object_id"],"revision_id":c2["revision_id"],"envelope_digest":ed2,"payload_status":"retained"},"bundle":b2,"reference":{"object_id":x["object_id"],"object_kind":"thread","thread_id":null,"archived":false,"tombstoned":false,"created_sequence":"3","updated_sequence":"4","heads":[{"revision_id":c2["revision_id"],"envelope_digest":ed2}]}}}}),
    );
    run(json!({"action":"sync","request":{"action":"delta-finish"}}));
    let connection = rusqlite::Connection::open(reopened.path()).unwrap();
    connection.execute_batch("CREATE TRIGGER p11_compact_fault BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT,'PUBLIC_SYNTHETIC_COMPACT_FAULT'); END;").unwrap();
    let compact: NotesRequest =
        serde_json::from_value(json!({"action":"sync","request":{"action":"compact","limit":1}}))
            .unwrap();
    assert!(reopened.notes_command(&c, compact).is_err());
    connection
        .execute_batch("DROP TRIGGER p11_compact_fault")
        .unwrap();
    assert_eq!(
        run(json!({"action":"sync","request":{"action":"compact","limit":1}}))["compacted"],
        1
    );
    let cached: NotesRequest =
        serde_json::from_value(json!({"action":"cached","revision_id":x["revision_id"]})).unwrap();
    assert_eq!(
        reopened.notes_command(&c, cached).unwrap_err().0,
        "PAYLOAD_UNAVAILABLE"
    );
    assert_eq!(
        run(json!({"action":"cached","revision_id":c2["revision_id"]}))["payload"]["title"],
        "PUBLIC native current after sync"
    );
    assert_eq!(
        run(json!({"action":"summary"}))["drafts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    run(
        json!({"action":"open","request":{"group_id":g["group_id"],"object_kind":"thread","object_id":x["object_id"],"thread_id":null,"revision_id":x["revision_id"],"bundle":bundle}}),
    );
    assert_eq!(
        run(json!({"action":"sync","request":{"action":"status"}}))["cursor"],
        next
    );
    let mut local_entry = edit(&g, "PUBLIC native owned recovery");
    local_entry["object_kind"] = json!("entry");
    local_entry["thread_id"] = x["object_id"].clone();
    local_entry["content"]["markdown"] = json!("PUBLIC preserve native source draft");
    let source = run(json!({"action":"save","edit":local_entry}));
    let queue = run(json!({"action":"queue","draft_id":source["draft_id"]}));
    let first = run(json!({"action":"send","attempt_id":queue["attempt_id"]}));
    let copy = run(
        json!({"action":"recover-draft","draft_id":source["draft_id"],"destination_group":g["group_id"],"destination_thread":x["object_id"],"confirmed":true}),
    );
    assert_ne!(copy["draft_id"], source["draft_id"]);
    assert_ne!(copy["object_id"], source["object_id"]);
    assert_eq!(copy["source_draft_retained"], true);
    assert_eq!(
        run(json!({"action":"draft","draft_id":source["draft_id"]}))["payload"]["markdown"],
        "PUBLIC preserve native source draft"
    );
    assert_eq!(
        run(json!({"action":"send","attempt_id":queue["attempt_id"]}))["request"],
        first["request"]
    );
    let mut old = result.clone();
    old["descriptor"]["watermark"]["sequence"] = json!("2");
    let start: NotesRequest = serde_json::from_value(
        json!({"action":"sync","request":{"action":"snapshot-start","result":old}}),
    )
    .unwrap();
    let blocked = reopened.notes_command(&c, start).unwrap();
    assert_eq!(blocked["state"], "RESTORE_QUARANTINE");
    assert_eq!(blocked["cursor"], next);
    reopened.lock_all().unwrap();
}
#[test]
fn native_note_restart_and_encrypted_sqlite_wal_inspection() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let mut wrong_summary = edit(&g, "PUBLIC refused unverified summary");
    wrong_summary["content"]["summary_entry_id"] = json!(id());
    let request: NotesRequest =
        serde_json::from_value(json!({"action":"save","edit":wrong_summary})).unwrap();
    assert_eq!(
        f.vault.notes_command(&cap, request).unwrap_err().0,
        "CONTEXT_MISMATCH"
    );
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

#[test]
fn native_verified_revoke_blocks_old_epoch_even_if_service_flags_are_false() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let (peer, root) = f.fresh();
    let cleanup = Cleanup(root);
    let peer_cap = peer.unlock_phrase(PHRASE).unwrap();
    let invitation = f.vault.device_invitation(&cap).unwrap();
    let session = id();
    let offer = peer
        .device_offer(&peer_cap, &session, Some(&invitation))
        .unwrap();
    let response = f
        .vault
        .device_response(&cap, &offer, Some(&invitation))
        .unwrap();
    let approval = f
        .vault
        .device_approval(&cap, &response["transcript"], true)
        .unwrap();
    let enrolled = peer
        .device_confirmation(
            &peer_cap,
            &response["transcript"],
            &approval,
            &session,
            true,
        )
        .unwrap();
    let snapshot = json!({"identity":f.snapshot["identity"],"events":[f.snapshot["events"][0],enrolled],"head":{"version":"1","digest":digest("p02-state-c1","event",&enrolled)},"generation":"0"});
    f.vault.record_device_snapshot(&cap, &snapshot).unwrap();
    let g = group(&f, &cap);
    let saved = command(
        &f,
        &cap,
        json!({"action":"save","edit":edit(&g,"PUBLIC draft kept after peer revoke")}),
    );
    let target = peer.device_public(&peer_cap).unwrap()["device_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let revoke = f.vault.device_revoke(&cap, &[target], true).unwrap();
    let event = &revoke;
    let current = json!({"identity":snapshot["identity"],"events":[snapshot["events"][0],snapshot["events"][1],event],"head":{"version":event["body"]["version"],"digest":digest("p02-state-c1","event",event)},"generation":"0"});
    f.vault.record_device_snapshot(&cap, &current).unwrap();
    let malicious_status = group_status(&f, &g);
    assert_eq!(malicious_status["rekey_required"], false);
    command(
        &f,
        &cap,
        json!({"action":"group","status":malicious_status}),
    );
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
        "REKEY_REQUIRED"
    );
    assert_eq!(
        command(
            &f,
            &cap,
            json!({"action":"draft","draft_id":saved["draft_id"]})
        )["payload"]["title"],
        "PUBLIC draft kept after peer revoke"
    );
    peer.lock();
    drop(peer);
    drop(cleanup);
}

#[test]
fn p12_native_incompressible_gigabyte_durable_resume_and_export() {
    use sha2::{Digest, Sha256};
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    let f = Fixture::new();
    let mut cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let root = f.vault.path().parent().unwrap();
    eprintln!("P12_FILE_MEMORY_BEGIN");
    let source_path = root.join("explicit-synthetic-source.bin");
    let mut source = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&source_path)
        .unwrap();
    let mut expected = Sha256::new();
    let mut left = 1_000_000_000usize;
    while left > 0 {
        let bytes = libsodium_rs::random::bytes(left.min(8_388_608));
        source.write_all(&bytes).unwrap();
        expected.update(&bytes);
        left -= bytes.len();
    }
    source.sync_all().unwrap();
    let made = f
        .vault
        .prepare_file(
            &cap,
            g["group_id"].as_str().unwrap(),
            &mut source,
            "P12 SECRET WINDOWS NAME.txt",
            "application/octet-stream",
        )
        .unwrap();
    let draft = made["draft_id"].as_str().unwrap();
    let mut acknowledgements = Vec::new();
    for index in 0..120usize {
        let cipher = f.vault.file_part(&cap, draft, &mut source, index).unwrap();
        if index == 0 {
            assert_eq!(
                cipher,
                f.vault.file_part(&cap, draft, &mut source, index).unwrap()
            );
            source.seek(SeekFrom::Start(0)).unwrap();
            let mut original = [0u8];
            source.read_exact(&mut original).unwrap();
            source.seek(SeekFrom::Start(0)).unwrap();
            source.write_all(&[original[0] ^ 1]).unwrap();
            assert_eq!(
                f.vault
                    .file_part(&cap, draft, &mut source, index)
                    .unwrap_err()
                    .0,
                "SOURCE_CHANGED"
            );
            source.seek(SeekFrom::Start(0)).unwrap();
            source.write_all(&original).unwrap();
        }
        if index == 53 {
            f.vault.lock_all().unwrap();
            assert!(f.vault.file_part(&cap, draft, &mut source, index).is_err());
            cap = f.vault.unlock_phrase(PHRASE).unwrap();
            assert_eq!(
                cipher,
                f.vault.file_part(&cap, draft, &mut source, index).unwrap()
            );
        }
        File::create(root.join(format!("encrypted-part-{index}")))
            .unwrap()
            .write_all(&cipher)
            .unwrap();
        acknowledgements.push(json!({"index":index.to_string(),"ciphertext_bytes":cipher.len().to_string(),"ciphertext_digest":hash(&cipher)}));
    }
    assert_eq!(acknowledgements[119]["ciphertext_bytes"], "1755664");
    let finish = f.vault.file_finish(&cap, draft, &acknowledgements).unwrap();
    assert_eq!(
        finish,
        f.vault.file_finish(&cap, draft, &acknowledgements).unwrap()
    );
    let record = &finish["request"]["record"];
    assert_eq!(
        record["envelope"]["header"]["framing"]["plaintext_bytes"],
        "1000000000"
    );
    let mut parts = (0..120).map(|index| {
        std::fs::read(root.join(format!("encrypted-part-{index}")))
            .map_err(|_| anynote_crypto_core::Error("STORAGE_UNAVAILABLE"))
    });
    let output_path = root.join("explicit-synthetic-export.incomplete");
    let mut output = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&output_path)
        .unwrap();
    let exported = f
        .vault
        .export_file(&cap, record, &mut parts, &mut output)
        .unwrap();
    assert_eq!(exported["complete"], true);
    output.seek(SeekFrom::Start(0)).unwrap();
    let mut observed = Sha256::new();
    let mut buffer = vec![0u8; 65536];
    loop {
        let n = output.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        observed.update(&buffer[..n]);
    }
    assert_eq!(expected.finalize(), observed.finalize());
    let disk = std::fs::read(f.vault.path()).unwrap();
    assert!(
        !disk
            .windows(b"P12 SECRET WINDOWS NAME".len())
            .any(|w| w == b"P12 SECRET WINDOWS NAME")
    );
    let wal = f.vault.path().with_extension("sqlite-wal");
    if wal.exists() {
        let bytes = std::fs::read(wal).unwrap();
        assert!(
            !bytes
                .windows(b"P12 SECRET WINDOWS NAME".len())
                .any(|w| w == b"P12 SECRET WINDOWS NAME")
        );
    }
    eprintln!("P12_FILE_MEMORY_END");
}

#[test]
fn p12_native_ciphertext_cache_verifies_bytes_and_refuses_corruption() {
    use anynote_local_vault::notes::file_cache::CipherCache;
    use std::fs::OpenOptions;
    use std::io::Write;
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let root = f.vault.path().parent().unwrap();
    let path = root.join("explicit-cache-test-source.bin");
    let mut source = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    source
        .write_all(b"public synthetic encrypted cache fixture")
        .unwrap();
    let made = f
        .vault
        .prepare_file(
            &cap,
            g["group_id"].as_str().unwrap(),
            &mut source,
            "PRIVATE CACHE NAME.txt",
            "application/octet-stream",
        )
        .unwrap();
    let draft = made["draft_id"].as_str().unwrap();
    let cipher = f.vault.file_part(&cap, draft, &mut source, 0).unwrap();
    let part = json!({"index":"0","ciphertext_bytes":cipher.len().to_string(),"ciphertext_digest":hash(&cipher)});
    let finished = f.vault.file_finish(&cap, draft, &[part]).unwrap();
    let record = &finished["request"]["record"];
    let cache = CipherCache::for_vault(&f.vault).unwrap();
    let mut job = cache.begin(&Codec::new().unwrap(), record).unwrap();
    cache.put(&mut job, 0, &cipher).unwrap();
    assert_eq!(
        cache.begin(&Codec::new().unwrap(), record).err().unwrap().0,
        "VAULT_BUSY"
    );
    job.pin(1048576, true).unwrap();
    cache.finish(&mut job).unwrap();
    drop(job);
    let mut replacement = cache.begin(&Codec::new().unwrap(), record).unwrap();
    cache.put(&mut replacement, 0, &cipher).unwrap();
    cache.finish(&mut replacement).unwrap();
    drop(replacement);
    let version = record["envelope"]["header"]["context"]["file_version_id"]
        .as_str()
        .unwrap();
    cache
        .verify(&f.vault, &cap, g["group_id"].as_str().unwrap(), version)
        .unwrap();
    let directory = root
        .join(format!("p12-downloaded-ciphertext-{}", f.scope.profile_id))
        .join(format!("{}_{version}", g["group_id"].as_str().unwrap()));
    let manifest = std::fs::read(directory.join("manifest.json")).unwrap();
    let meta: Value = serde_json::from_slice(&manifest).unwrap();
    assert_eq!(meta["pinned"], true);
    assert_eq!(meta["additional_budget"], 1048576);
    assert!(
        !manifest
            .windows(b"PRIVATE CACHE NAME".len())
            .any(|w| w == b"PRIVATE CACHE NAME")
    );
    let offline_destination = root.join("explicit-offline-export.bin");
    cache
        .atomic_export(
            &f.vault,
            &cap,
            g["group_id"].as_str().unwrap(),
            version,
            &offline_destination,
            false,
        )
        .unwrap();
    assert_eq!(
        std::fs::read(&offline_destination).unwrap(),
        b"public synthetic encrypted cache fixture"
    );
    let mut corrupt_size = meta.clone();
    corrupt_size["bytes"] = json!(u64::MAX);
    std::fs::write(
        directory.join("manifest.json"),
        serde_json::to_vec(&corrupt_size).unwrap(),
    )
    .unwrap();
    assert_eq!(
        cache.begin(&Codec::new().unwrap(), record).err().unwrap().0,
        "INTEGRITY_FAILURE"
    );
    std::fs::write(directory.join("manifest.json"), manifest).unwrap();
    let mut wrong = cipher.clone();
    wrong[0] ^= 1;
    std::fs::write(directory.join("0"), wrong).unwrap();
    assert_eq!(
        cache
            .verify(&f.vault, &cap, g["group_id"].as_str().unwrap(), version)
            .unwrap_err()
            .0,
        "CHUNK_DIGEST_MISMATCH"
    );
}

#[test]
fn p12_native_copy_burn_and_atomic_export_keep_original_recoverable() {
    use std::fs::OpenOptions;
    use std::io::Write;
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let group_id = g["group_id"].as_str().unwrap();
    let root = f.vault.path().parent().unwrap();
    let mut source = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.join("explicit-copy-source.bin"))
        .unwrap();
    source.write_all(b"public source for native copy").unwrap();
    let original = f
        .vault
        .prepare_file(
            &cap,
            group_id,
            &mut source,
            "copy.bin",
            "application/octet-stream",
        )
        .unwrap();
    let draft = original["draft_id"].as_str().unwrap();
    let cipher = f.vault.file_part(&cap, draft, &mut source, 0).unwrap();
    let preview = f.vault.file_copy_preview(&cap, draft, group_id).unwrap();
    assert!(
        f.vault
            .copy_selected_file(&cap, draft, group_id, &mut source, "wrong", true)
            .is_err()
    );
    let copy = f
        .vault
        .copy_selected_file(
            &cap,
            draft,
            group_id,
            &mut source,
            preview["digest"].as_str().unwrap(),
            true,
        )
        .unwrap();
    assert_ne!(
        copy["request"]["context"]["file_version_id"],
        original["request"]["context"]["file_version_id"]
    );
    assert_ne!(
        cipher,
        f.vault
            .file_part(&cap, copy["draft_id"].as_str().unwrap(), &mut source, 0)
            .unwrap()
    );
    let part = json!({"index":"0","ciphertext_bytes":cipher.len().to_string(),"ciphertext_digest":hash(&cipher)});
    let finished = f.vault.file_finish(&cap, draft, &[part]).unwrap();
    let record = &finished["request"]["record"];
    let destination = root.join("explicit-verified-export.bin");
    let mut parts = std::iter::once(Ok(cipher.clone()));
    assert_eq!(
        f.vault
            .atomic_export_file(&cap, record, &mut parts, &destination, false)
            .unwrap()["complete"],
        true
    );
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        b"public source for native copy"
    );
    let wrong_destination = root.join("wrong.incomplete");
    let mut bad = cipher.clone();
    bad[0] ^= 1;
    let mut parts = std::iter::once(Ok(bad));
    assert!(
        f.vault
            .atomic_export_file(&cap, record, &mut parts, &wrong_destination, false)
            .is_err()
    );
    assert!(!wrong_destination.exists());
    f.vault
        .burn_file_attempt(
            &cap,
            draft,
            &json!({"upload_id":original["request"]["upload_id"],"state":"EXPIRED"}),
            true,
        )
        .unwrap();
    assert_eq!(
        f.vault.file_request(&cap, draft).unwrap_err().0,
        "IMMUTABLE_ATTEMPT"
    );
    assert_eq!(
        f.vault
            .file_part(&cap, draft, &mut source, 0)
            .unwrap_err()
            .0,
        "IMMUTABLE_ATTEMPT"
    );
    assert_eq!(
        f.vault
            .file_transfers(&cap)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
}
