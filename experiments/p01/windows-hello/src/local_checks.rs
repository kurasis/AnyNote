//! SPDX-License-Identifier: GPL-3.0-only
//! Bounded local synthetic checks bundled into the one executable.
use libsodium_rs::{crypto_aead::xchacha20poly1305 as aead, crypto_pwhash::argon2id, random};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const CHUNK: usize = 8_388_608;
const MAX: usize = 1_000_000_000;

fn decode(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.len() > 131072 {
        return Err("Invalid public fixture".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn primitives() -> Result<Value> {
    libsodium_rs::ensure_init()?;
    let mut checks = 0;
    for text in [
        include_str!("../../fixtures/rust.json"),
        include_str!("../../fixtures/node.json"),
        include_str!("../../fixtures/browser-worker.json"),
    ] {
        let fixture: Value = serde_json::from_str(text)?;
        for item in fixture["aead"].as_array().ok_or("Missing corpus")? {
            let field = |name: &str| decode(item[name].as_str().ok_or("Missing field")?);
            let key = aead::Key::from_bytes(&field("key")?)?;
            let nonce: [u8; 24] = field("nonce")?.try_into().map_err(|_| "Invalid nonce")?;
            let nonce = aead::Nonce::from_bytes(nonce);
            let (aad, message, cipher) = (field("aad")?, field("message")?, field("ciphertext")?);
            if aead::decrypt(&cipher, Some(&aad), &nonce, &key)? != message
                || aead::encrypt(&message, Some(&aad), &nonce, &key)? != cipher
            {
                return Err("Frozen AEAD mismatch".into());
            }
            let mut corrupt = cipher.clone();
            corrupt[0] ^= 1;
            if aead::decrypt(&corrupt, Some(&aad), &nonce, &key).is_ok()
                || aead::decrypt(&cipher[..cipher.len() - 1], Some(&aad), &nonce, &key).is_ok()
            {
                return Err("Invalid ciphertext accepted".into());
            }
            checks += 4;
        }
    }
    let fixtures: Value = serde_json::from_str(include_str!("../../fixtures/argon2id.json"))?;
    for case in fixtures["cases"].as_array().ok_or("Missing KDF corpus")? {
        let request = &case["request"];
        let key = Zeroizing::new(argon2id::pwhash(
            32,
            request["phrase"]
                .as_str()
                .ok_or("Missing phrase")?
                .as_bytes(),
            &decode(request["salt_hex"].as_str().ok_or("Missing salt")?)?,
            3,
            67_108_864,
        )?);
        if hex(&key) != case["derived_hex"].as_str().ok_or("Missing digest")? {
            return Err("Frozen Argon2id mismatch".into());
        }
        checks += 1;
    }
    Ok(
        json!({"status":"PASS","checks":checks,"scope":"Frozen XChaCha20-Poly1305 corpora and three public 64 MiB Argon2id vectors"}),
    )
}

pub fn file_roundtrip(directory: &Path, size: usize) -> Result<Value> {
    if size > MAX {
        return Err("Oversize rejected before any disk write".into());
    }
    std::fs::create_dir(directory)?;
    crate::filesystem::secure_directory(directory).map_err(|_| "Synthetic ACL unavailable")?;
    let _pins = crate::filesystem::pin_directory(directory)
        .map_err(|_| "Cannot pin synthetic directory")?;
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK]);
    let source_path = directory.join("synthetic-source.bin");
    let mut source = File::create_new(&source_path)?;
    let mut generated_hash = Sha256::new();
    for offset in (0..size).step_by(CHUNK) {
        let bytes = &mut buffer[..(size - offset).min(CHUNK)];
        random::fill_bytes(bytes);
        source.write_all(bytes)?;
        generated_hash.update(bytes);
    }
    source.sync_all()?;
    drop(source);
    let (key, prefix, count) = (
        aead::Key::generate(),
        random::bytes(16),
        size.div_ceil(CHUNK),
    );
    let nonce_for = |index: usize| {
        let mut bytes = [0u8; 24];
        bytes[..16].copy_from_slice(&prefix);
        bytes[16..].copy_from_slice(&(index as u64).to_le_bytes());
        aead::Nonce::from_bytes(bytes)
    };
    let (mut input, mut inventory) = (File::open(&source_path)?, Vec::new());
    for index in 0..count {
        let length = (size - index * CHUNK).min(CHUNK);
        let bytes = &mut buffer[..length];
        input.read_exact(bytes)?;
        let aad = format!("AnyNote.P01.DeviceKit/{index}/{count}/{size}/{length}");
        let cipher = aead::encrypt(bytes, Some(aad.as_bytes()), &nonce_for(index), &key)?;
        bytes.fill(0);
        inventory.push(Sha256::digest(&cipher));
        let mut file = File::create_new(directory.join(format!("{index}.ciphertext")))?;
        file.write_all(&cipher)?;
        file.sync_all()?;
    }
    let output_path = directory.join("explicit-synthetic-export.bin");
    let mut output = File::create_new(&output_path)?;
    for (index, digest) in inventory.iter().enumerate() {
        let length = (size - index * CHUNK).min(CHUNK);
        let mut file = File::open(directory.join(format!("{index}.ciphertext")))?;
        if file.metadata()?.len() != (length + 16) as u64 {
            return Err("Invalid bounded stored part".into());
        }
        let mut cipher = vec![0u8; length + 16];
        file.read_exact(&mut cipher)?;
        if &Sha256::digest(&cipher) != digest {
            return Err("Stored part digest mismatch".into());
        }
        let aad = format!("AnyNote.P01.DeviceKit/{index}/{count}/{size}/{length}");
        let clear = Zeroizing::new(aead::decrypt(
            &cipher,
            Some(aad.as_bytes()),
            &nonce_for(index),
            &key,
        )?);
        output.write_all(&clear)?;
    }
    output.sync_all()?;
    drop(output);
    let (mut output, mut saved_hash) = (File::open(output_path)?, Sha256::new());
    loop {
        let count = output.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        saved_hash.update(&buffer[..count]);
        buffer[..count].fill(0);
    }
    let expected = generated_hash.finalize();
    if expected != saved_hash.finalize() || output.metadata()?.len() != size as u64 {
        return Err("Actual saved output mismatch".into());
    }
    Ok(
        json!({"status":"PASS","bytes":size,"chunks":count,"sha256":hex(&expected),
        "transport":"Local disk ciphertext only; network and WebView2 not tested", "memory":"NOT MEASURED"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_boundary_output_and_oversize_guard() {
        libsodium_rs::ensure_init().unwrap();
        let root = tempfile::tempdir().unwrap();
        let result = file_roundtrip(&root.path().join("boundary"), CHUNK + 1).unwrap();
        assert_eq!(result["bytes"], CHUNK + 1);
        assert_eq!(result["chunks"], 2);
        let oversized = root.path().join("oversized");
        assert!(file_roundtrip(&oversized, MAX + 1).is_err());
        assert!(!oversized.exists());
    }
    #[test]
    fn frozen_native_corpora_and_argon_profiles_execute() {
        assert_eq!(primitives().unwrap()["checks"], 51);
    }
}
