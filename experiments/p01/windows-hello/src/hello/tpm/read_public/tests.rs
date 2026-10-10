use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // Independently generated public-only synthetic RSA fixture; not hardware evidence.
    let value: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/hello/tpm-certification.json"
    )))
    .unwrap();
    let area = STANDARD
        .decode(value["publicArea"].as_str().unwrap())
        .unwrap();
    let public = STANDARD
        .decode(value["cngSubject"].as_str().unwrap())
        .unwrap();
    let mut name = vec![0, 0x0b];
    name.extend(Sha256::digest(&area));
    let mut response = vec![0x80, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    for field in [&area, &name, &name] {
        response.extend((field.len() as u16).to_be_bytes());
        response.extend(field);
    }
    let length = response.len() as u32;
    response[2..6].copy_from_slice(&length.to_be_bytes());
    (response, public, name)
}
#[test]
fn fixed_read_only_command_and_exact_fixture_binding() {
    assert_eq!(
        command(0x80000001),
        [0x80, 1, 0, 0, 0, 14, 0, 0, 1, 0x73, 0x80, 0, 0, 1]
    );
    let (response, public, name) = fixture();
    let attributes = inspect(&response, &public, &name).unwrap();
    assert_eq!(attributes & 0x00020032, 0x00020032);
    assert_eq!(crate::hello::readiness()["available"], false);
}
#[test]
fn every_truncation_oversized_extra_bytes_and_forged_lengths_fail() {
    let (response, public, name) = fixture();
    for length in 0..response.len() {
        assert!(inspect(&response[..length], &public, &name).is_err());
    }
    for length in [0, 9, 10, response.len() - 1, response.len() + 1, usize::MAX] {
        let mut changed = response.clone();
        changed[2..6].copy_from_slice(&(length as u32).to_be_bytes());
        assert!(inspect(&changed, &public, &name).is_err());
    }
    let mut extra = response.clone();
    extra.push(0);
    let len = extra.len() as u32;
    extra[2..6].copy_from_slice(&len.to_be_bytes());
    assert!(inspect(&extra, &public, &name).is_err());
    assert!(inspect(&vec![0; MAX_RESPONSE + 1], &public, &name).is_err());
    for size in [0u16, 1, 277, u16::MAX] {
        let mut changed = response.clone();
        changed[10..12].copy_from_slice(&size.to_be_bytes());
        assert!(inspect(&changed, &public, &name).is_err());
    }
}
#[test]
fn exact_native_tpm_error_is_reported_without_success() {
    let mut response = vec![0x80, 1, 0, 0, 0, 10, 0, 0, 1, 0x8b];
    let error = inspect(&response, &[], &[]).unwrap_err();
    assert_eq!(error.code, Some(0x18b));
    assert_eq!(error.operation, Some("tpm-read-public-response"));
    response[1] = 2;
    assert_eq!(
        inspect(&response, &[], &[]).unwrap_err().operation,
        Some("tpm-read-public-response-tag")
    );
}
#[test]
fn another_public_key_and_every_changed_name_byte_are_rejected() {
    let (response, mut public, name) = fixture();
    public[100] ^= 1;
    assert_eq!(
        inspect(&response, &public, &name).unwrap_err().operation,
        Some("tpm-read-public-key-mismatch")
    );
    public[100] ^= 1;
    for index in 0..name.len() {
        let mut changed = name.clone();
        changed[index] ^= 1;
        assert_eq!(
            inspect(&response, &public, &changed).unwrap_err().operation,
            Some("tpm-read-public-name-mismatch")
        );
    }
    for index in 0..public.len() {
        let mut changed = public.clone();
        changed[index] ^= 1;
        assert!(inspect(&response, &changed, &name).is_err());
    }
}
#[test]
fn missing_nonduplicable_attributes_and_broader_templates_fail() {
    let (response, public, name) = fixture();
    let attributes = u32::from_be_bytes(response[16..20].try_into().unwrap());
    for bit in [1u32, 4, 5, 17] {
        let mut changed = response.clone();
        changed[16..20].copy_from_slice(&(attributes & !(1 << bit)).to_be_bytes());
        assert_eq!(
            inspect(&changed, &public, &name).unwrap_err().operation,
            Some("tpm-read-public-template-unsupported")
        );
    }
    for bit in [16u32, 18, 31] {
        let mut changed = response.clone();
        changed[16..20].copy_from_slice(&(attributes | (1 << bit)).to_be_bytes());
        assert!(inspect(&changed, &public, &name).is_err());
    }
}
#[test]
fn public_area_hash_and_response_names_are_bound_not_just_lengths() {
    let (response, public, name) = fixture();
    let area_len = u16::from_be_bytes(response[10..12].try_into().unwrap()) as usize;
    for index in 12..12 + area_len + 2 + 34 {
        let mut changed = response.clone();
        changed[index] ^= 1;
        assert!(inspect(&changed, &public, &name).is_err(), "byte {index}");
    }
    // Qualified Name is shape-checked only: no parent-chain attestation claim.
    let mut changed = response.clone();
    changed[12 + area_len + 2 + 34 + 2] ^= 1;
    assert!(inspect(&changed, &public, &name).is_err());
}
