use anynote_crypto_core::{
    codec::{canonical, strict},
    crypto::b64,
};
use anynote_windows_native::{
    bridge::{Assets, Bridge},
    selection::Source,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn sha(p: &Path) -> String {
    b64(&Sha256::digest(std::fs::read(p).unwrap()))
}
#[test]
fn trusted_native_pipe_reads_frozen_archive_offline_and_recovers_authenticated_bytes() {
    let root = root();
    let node = std::env::var_os("ANYNOTE_NATIVE_NODE")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("apps/desktop/src-tauri/resources/node.exe"));
    let script = root.join("apps/desktop/src-tauri/resources/custody.mjs");
    let node_sha = sha(&node);
    let script_sha = sha(&script);
    let assets = Assets {
        node: &node,
        script: &script,
        node_sha: &node_sha,
        script_sha: &script_sha,
    };
    let fixture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("fixtures/protocol/p02/v1/crypto.json")).unwrap(),
    )
    .unwrap();
    let mut source = Source::open(
        &root.join("fixtures/protocol/p02/v1/rust.age"),
        116010000000,
    )
    .unwrap();
    let mut bridge = Bridge::spawn(&assets, || false).unwrap();
    bridge
        .json(
            1,
            &json!({"mode":"inspect","kit":fixture["objects"]["kit"]}),
        )
        .unwrap();
    let mut validated = false;
    let mut plain = Vec::new();
    let mut notes = 0;
    loop {
        let (kind, data) = bridge.receive().unwrap();
        match kind {
            13 => {
                let request = strict(&data, 4096).unwrap();
                let offset = request["offset"].as_str().unwrap().parse().unwrap();
                source.file.seek(SeekFrom::Start(offset)).unwrap();
                let mut bytes = vec![0; 65536];
                let n = source.file.read(&mut bytes).unwrap();
                bridge
                    .send(if n == 0 { 4 } else { 3 }, &bytes[..n])
                    .unwrap();
            }
            8 => {
                let report = strict(&data, 16777216).unwrap();
                assert_eq!(report["status"], "VERIFIED_OFFLINE");
                assert_eq!(report["live_destination_mutations"], 0);
                validated = true;
                bridge.ack().unwrap();
            }
            14 => {
                assert!(validated);
                let note = strict(&data, 16777216).unwrap();
                assert_eq!(
                    note["payload"]["title"],
                    fixture["objects"]["payload"]["title"]
                );
                notes += 1;
                bridge.ack().unwrap();
            }
            15 | 17 => {
                assert!(validated);
                bridge.ack().unwrap();
            }
            16 => {
                assert!(validated);
                let (kind, data) = bridge.receive().unwrap();
                assert_eq!(kind, 3);
                plain.extend_from_slice(&data);
                bridge.ack().unwrap();
            }
            18 => break,
            _ => panic!("unexpected bounded frame {kind}"),
        }
    }
    assert_eq!(notes, 1);
    let expected = fixture["objects"]["file_plain_hex"].as_str().unwrap();
    assert_eq!(
        plain.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        expected
    );
    let invalid = Assets {
        node: &node,
        script: &script,
        node_sha: "not-the-pinned-runtime",
        script_sha: &script_sha,
    };
    assert_eq!(
        Bridge::spawn(&invalid, || false).err().unwrap().0,
        "RUNTIME_INTEGRITY_FAILURE"
    );
    assert!(canonical(&fixture["objects"]["kit"]).unwrap().len() < 65536);
}
