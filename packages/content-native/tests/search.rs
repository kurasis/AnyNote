include!("../../vault-native/tests/common/notes_fixture.rs");
use anynote_content_native::Search;
#[test]
fn real_native_search_verifies_signed_content_encrypts_tokens_and_fences_lock_and_source_change() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let (_, queued, sent) = attempt(&f, &cap, &g);
    let ack = receipt(&sent["request"]);
    command(
        &f,
        &cap,
        json!({"action":"ack","attempt_id":queued["attempt_id"],"result":ack}),
    );
    let revision = sent["request"]["bundle"]["envelope"]["header"]["context"]["revision_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let search = Search::new(&f.vault, &cap, &f.scope).unwrap();
    assert_eq!(
        search.index(std::slice::from_ref(&revision)).unwrap()["indexed"],
        1
    );
    let result = search
        .search(
            "ＰＥＲＳＩＳＴＥＮＴ",
            Some(g["group_id"].as_str().unwrap()),
        )
        .unwrap();
    assert_eq!(result["results"].as_array().unwrap().len(), 1);
    for entry in std::fs::read_dir(f.vault.path().parent().unwrap()).unwrap() {
        let entry = entry.unwrap();
        if entry.path().is_file() {
            let bytes = std::fs::read(entry.path()).unwrap();
            assert!(
                !bytes
                    .windows("persistent".len())
                    .any(|w| w == b"persistent")
            );
        }
    }
    let (_, second, sent2) = attempt(&f, &cap, &g);
    command(
        &f,
        &cap,
        json!({"action":"ack","attempt_id":second["attempt_id"],"result":receipt(&sent2["request"])}),
    );
    assert_eq!(
        search.search("persistent", None).unwrap()["rebuild_required"],
        true
    );
    assert!(search.index(&[revision]).is_err());
    search.clear(true).unwrap();
    assert!(
        search.search("persistent", None).unwrap()["results"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    f.vault.lock();
    assert!(search.search("persistent", None).is_err());
}

#[test]
fn authenticated_native_filename_index_never_exports_keys_and_survives_reopen() {
    let f = Fixture::new();
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    let g = group(&f, &cap);
    let mut source = tempfile::tempfile().unwrap();
    let made = f
        .vault
        .prepare_file(
            &cap,
            g["group_id"].as_str().unwrap(),
            &mut source,
            "P13 NATIVE CONFIDENTIAL FILENAME.pdf",
            "application/pdf",
        )
        .unwrap();
    let finished = f
        .vault
        .file_finish(&cap, made["draft_id"].as_str().unwrap(), &[])
        .unwrap();
    let record = &finished["request"]["record"];
    let metadata = f.vault.file_metadata(&cap, record).unwrap();
    assert_eq!(metadata["name"], "P13 NATIVE CONFIDENTIAL FILENAME.pdf");
    assert_eq!(metadata.as_object().unwrap().len(), 4);
    assert!(metadata.get("file_data_key").is_none());
    let search = Search::new(&f.vault, &cap, &f.scope).unwrap();
    search.observe_file(record).unwrap();
    search.observe_file(record).unwrap();
    let catalog = search.catalog().unwrap();
    assert_eq!(catalog["items"].as_array().unwrap().len(), 1);
    let revision = record["envelope"]["header"]["context"]["file_version_id"]
        .as_str()
        .unwrap()
        .to_owned();
    search.index(&[revision]).unwrap();
    assert_eq!(
        search.search("native confidential", None).unwrap()["results"][0]["object_kind"],
        "file-manifest"
    );
    let mut bad = record.clone();
    bad["manifest_ciphertext"] = json!("AAAA");
    assert!(search.observe_file(&bad).is_err());
    assert_eq!(
        search.catalog().unwrap()["items"].as_array().unwrap().len(),
        1
    );
    for entry in std::fs::read_dir(f.vault.path().parent().unwrap()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(path).unwrap();
            assert!(
                !bytes
                    .windows(b"NATIVE CONFIDENTIAL FILENAME".len())
                    .any(|v| v == b"NATIVE CONFIDENTIAL FILENAME")
            );
        }
    }
    f.vault.lock();
    assert!(search.search("confidential", None).is_err());
    let cap = f.vault.unlock_phrase(PHRASE).unwrap();
    assert_eq!(
        Search::new(&f.vault, &cap, &f.scope)
            .unwrap()
            .search("confidential", None)
            .unwrap()["results"][0]["title"],
        "P13 NATIVE CONFIDENTIAL FILENAME.pdf"
    );
}
