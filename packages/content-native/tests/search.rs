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
