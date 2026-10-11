//! Public-signature primitive adapter. The caller must provide validated canonical
//! public DTO bytes. General native JSON/AEAD/custody adapters remain P05/P07.
use libsodium_rs::crypto_sign::{self, PublicKey, SecretKey};

pub fn object_signing_input(canonical_header: &[u8]) -> Vec<u8> {
    let mut input = b"AnyNote/p02-v1/sign/object-revision\0".to_vec();
    input.extend_from_slice(canonical_header);
    input
}

pub fn sign_object(canonical_header: &[u8], key: &SecretKey) -> libsodium_rs::Result<[u8; 64]> {
    crypto_sign::sign_detached(&object_signing_input(canonical_header), key)
}

pub fn verify_object(canonical_header: &[u8], signature: &[u8; 64], key: &PublicKey) -> bool {
    crypto_sign::verify_detached(signature, &object_signing_input(canonical_header), key)
}
