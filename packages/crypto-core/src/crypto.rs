use crate::{Error, Result, require};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use libsodium_rs::{crypto_aead::xchacha20poly1305 as aead, crypto_box, crypto_sign};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn un64(s: &str) -> Result<Vec<u8>> {
    require(s.len() <= 16_777_216, "RESOURCE_LIMIT")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error("INVALID_BINARY"))?;
    require(b64(&bytes) == s, "INVALID_BINARY")?;
    Ok(bytes)
}
pub fn hash(bytes: &[u8]) -> String {
    b64(&Sha256::digest(bytes))
}
pub fn hkdf(secret: &[u8], salt: &[u8], info: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    require(secret.len() == 32, "INVALID_KEY_LENGTH")?;
    let mut result = Zeroizing::new(vec![0; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(salt), secret)
        .expand(info, &mut result)
        .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    Ok(result)
}
pub(crate) fn encrypt(plain: &[u8], aad: &[u8], nonce: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    libsodium_rs::ensure_init().map_err(|_| Error("CRYPTO_UNAVAILABLE"))?;
    require(
        plain.len() <= 8_388_608 && aad.len() <= 1_048_576,
        "RESOURCE_LIMIT",
    )?;
    let key = aead::Key::from_bytes(key).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    let nonce = aead::Nonce::try_from(nonce).map_err(|_| Error("INVALID_NONCE"))?;
    aead::encrypt(plain, Some(aad), &nonce, &key).map_err(|_| Error("CRYPTO_FAILURE"))
}
pub(crate) fn decrypt(
    cipher: &[u8],
    aad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    libsodium_rs::ensure_init().map_err(|_| Error("CRYPTO_UNAVAILABLE"))?;
    require(
        (16..=8_388_624).contains(&cipher.len()) && aad.len() <= 1_048_576,
        "RESOURCE_LIMIT",
    )?;
    let key = aead::Key::from_bytes(key).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    let nonce = aead::Nonce::try_from(nonce).map_err(|_| Error("INVALID_NONCE"))?;
    aead::decrypt(cipher, Some(aad), &nonce, &key)
        .map(Zeroizing::new)
        .map_err(|_| Error("INTEGRITY_FAILURE"))
}
pub fn sign(bytes: &[u8], secret: &[u8]) -> Result<String> {
    libsodium_rs::ensure_init().map_err(|_| Error("CRYPTO_UNAVAILABLE"))?;
    let key =
        crypto_sign::SecretKey::from_bytes(secret).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    crypto_sign::sign_detached(bytes, &key)
        .map(|s| b64(&s))
        .map_err(|_| Error("CRYPTO_FAILURE"))
}
pub fn verify(bytes: &[u8], signature: &str, public: &[u8]) -> Result<()> {
    libsodium_rs::ensure_init().map_err(|_| Error("CRYPTO_UNAVAILABLE"))?;
    let key =
        crypto_sign::PublicKey::from_bytes(public).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    let signature: [u8; 64] = un64(signature)?
        .try_into()
        .map_err(|_| Error("INVALID_SIGNATURE"))?;
    require(
        crypto_sign::verify_detached(&signature, bytes, &key),
        "INVALID_SIGNATURE",
    )
}
pub fn random_key() -> Result<Zeroizing<Vec<u8>>> {
    libsodium_rs::ensure_init().map_err(|_| Error("CRYPTO_UNAVAILABLE"))?;
    Ok(Zeroizing::new(libsodium_rs::random::bytes(32)))
}
pub fn device_keys() -> Result<(crypto_sign::KeyPair, crypto_box::KeyPair)> {
    libsodium_rs::ensure_init().map_err(|_| Error("CRYPTO_UNAVAILABLE"))?;
    Ok((
        crypto_sign::KeyPair::generate().map_err(|_| Error("CRYPTO_FAILURE"))?,
        crypto_box::KeyPair::generate(),
    ))
}
