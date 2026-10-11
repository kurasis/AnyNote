use crate::{Result, require};
use crate::{
    codec::{Codec, canonical, domain, text},
    crypto::*,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub fn aad(purpose: &str, v: &Value) -> Result<Vec<u8>> {
    Ok(domain("p02-v1", "aad", purpose, &canonical(v)?))
}
pub fn verify_object(c: &Codec, bytes: &[u8], public: &[u8], expected: &[u8]) -> Result<Value> {
    let b = c.decode("p02-v1", "bundle", bytes)?;
    let h = &b["envelope"]["header"];
    require(
        h["context"] == c.decode("p02-v1", "context", expected)?,
        "CONTEXT_MISMATCH",
    )?;
    verify(
        &c.signing("p02-v1", "header", h)?,
        text(&b["envelope"]["signature"])?,
        public,
    )?;
    let cipher = un64(text(&b["ciphertext"])?)?;
    require(
        cipher.len() as u64 == crate::codec::num(&h["ciphertext_bytes"])?
            && hash(&cipher) == h["ciphertext_digest"],
        "CIPHERTEXT_MISMATCH",
    )?;
    require(
        hash(&domain("p02-v1", "hash", "wrap", &canonical(&b["wrap"])?)) == h["key_wrap_digest"],
        "KEY_WRAP_MISMATCH",
    )?;
    Ok(b)
}
pub fn open_object(
    c: &Codec,
    bytes: &[u8],
    group: &[u8],
    public: &[u8],
    expected: &[u8],
) -> Result<Value> {
    let b = verify_object(c, bytes, public, expected)?;
    let context = &b["envelope"]["header"]["context"];
    let wrap = &b["wrap"];
    let dek = decrypt(
        &un64(text(&wrap["ciphertext"])?)?,
        &aad("object-key-wrap", &json!({"context":context}))?,
        &un64(text(&wrap["nonce"])?)?,
        group,
    )?;
    require(dek.len() == 32, "INVALID_KEY_LENGTH")?;
    let plain = decrypt(
        &un64(text(&b["ciphertext"])?)?,
        &aad("object-payload", &json!({"context":context}))?,
        &un64(text(&b["envelope"]["header"]["nonce"])?)?,
        &dek,
    )?;
    let p = c.decode("p02-v1", "payload", &plain)?;
    require(p["context"] == *context, "CONTEXT_MISMATCH")?;
    Ok(p)
}
pub fn seal_object(c: &Codec, bytes: &[u8], group: &[u8], signing: &[u8]) -> Result<Value> {
    let p = c.decode("p02-v1", "payload", bytes)?;
    let context = &p["context"];
    let dek = random_key()?;
    let n = libsodium_rs::random::bytes(24);
    let wn = libsodium_rs::random::bytes(24);
    let wrap = json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"object-key-wrap","context":context,"nonce":b64(&wn),"ciphertext":b64(&encrypt(&dek,&aad("object-key-wrap",&json!({"context":context}))?,&wn,group)?)});
    let cipher = encrypt(
        &Zeroizing::new(canonical(&p)?),
        &aad("object-payload", &json!({"context":context}))?,
        &n,
        &dek,
    )?;
    let header = json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"object-revision","context":context,"nonce":b64(&n),"ciphertext_bytes":cipher.len().to_string(),"ciphertext_digest":hash(&cipher),"key_wrap_digest":hash(&domain("p02-v1","hash","wrap",&canonical(&wrap)?))});
    let b = json!({"envelope":{"signature":sign(&c.signing("p02-v1","header",&header)?,signing)?,"header":header},"wrap":wrap,"ciphertext":b64(&cipher)});
    c.validate("p02-v1", "bundle", &b)?;
    Ok(b)
}
pub fn seal_local(c: &Codec, bytes: &[u8], key: &[u8]) -> Result<Value> {
    let p = c.decode("p02-v1", "local-plaintext", bytes)?;
    let n = libsodium_rs::random::bytes(24);
    let context = &p["context"];
    Ok(
        json!({"context":context,"nonce":b64(&n),"ciphertext":b64(&encrypt(&canonical(&p)?,&aad("local-record",context)?,&n,key)?)}),
    )
}
pub fn open_local(c: &Codec, bytes: &[u8], key: &[u8], expected: &[u8]) -> Result<Value> {
    let e = c.decode("p02-v1", "local-envelope", bytes)?;
    let context = c.decode("p02-v1", "local-context", expected)?;
    require(e["context"] == context, "LOCAL_CONTEXT_MISMATCH")?;
    let p = decrypt(
        &un64(text(&e["ciphertext"])?)?,
        &aad("local-record", &context)?,
        &un64(text(&e["nonce"])?)?,
        key,
    )?;
    let v = c.decode("p02-v1", "local-plaintext", &p)?;
    require(v["context"] == context, "LOCAL_CONTEXT_MISMATCH")?;
    Ok(v)
}

pub fn derive_root(
    c: &Codec,
    secret: &[u8],
    context: &[u8],
) -> Result<(
    libsodium_rs::crypto_sign::KeyPair,
    libsodium_rs::crypto_box::KeyPair,
)> {
    let context = c.encode("p02-identity-c1", "derivation-context", context)?;
    let salt = un64(&hash(&domain(
        "p02-identity-c1",
        "hkdf",
        "extract-salt",
        &context,
    )))?;
    let s = hkdf(
        secret,
        &salt,
        &domain("p02-identity-c1", "hkdf", "root-signing-seed", &context),
    )?;
    let e = hkdf(
        secret,
        &salt,
        &domain(
            "p02-identity-c1",
            "hkdf",
            "recovery-encryption-seed",
            &context,
        ),
    )?;
    let signing = libsodium_rs::crypto_sign::KeyPair::from_seed(&s)
        .map_err(|_| crate::Error("CRYPTO_FAILURE"))?;
    let recovery = libsodium_rs::crypto_box::KeyPair::from_seed(&e)
        .map_err(|_| crate::Error("CRYPTO_FAILURE"))?;
    Ok((signing, recovery))
}
pub fn recovery_encode(secret: &[u8]) -> Result<String> {
    require(secret.len() == 32, "INVALID_KEY_LENGTH")?;
    let mut bytes = Zeroizing::new(vec![1]);
    bytes.extend_from_slice(secret);
    bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse("anr").unwrap(), &bytes)
        .map_err(|_| crate::Error("INVALID_RECOVERY_ENCODING"))
}
pub fn recovery_decode(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    require(
        s.len() == 63
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
        "INVALID_RECOVERY_ENCODING",
    )?;
    let checked = bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32m>(s)
        .map_err(|_| crate::Error("INVALID_RECOVERY_ENCODING"))?;
    let bytes = Zeroizing::new(checked.byte_iter().collect::<Vec<u8>>());
    require(
        checked.hrp().as_str() == "anr" && bytes.len() == 33 && bytes[0] == 1,
        "INVALID_RECOVERY_ENCODING",
    )?;
    require(
        recovery_encode(&bytes[1..])? == s,
        "INVALID_RECOVERY_ENCODING",
    )?;
    Ok(Zeroizing::new(bytes[1..].to_vec()))
}
pub fn create_identity(c: &Codec, secret: &[u8], context: &[u8]) -> Result<Value> {
    let v = c.decode("p02-identity-c1", "derivation-context", context)?;
    let (signing, recovery) = derive_root(c, secret, context)?;
    let body = serde_json::json!({"purpose":"account-root-identity","contract":"p02-identity-c1","protocol":"anynote","protocol_version":1,"derivation":"hkdf-sha256-c1","service_id":v["service_id"],"account_id":v["account_id"],"root_signing_key":b64(signing.public_key.as_ref()),"recovery_encryption_key":b64(recovery.public_key.as_ref())});
    let i = serde_json::json!({"signature":sign(&c.signing("p02-identity-c1","identity-body",&body)?,signing.secret_key.as_ref())?,"body":body});
    c.validate("p02-identity-c1", "identity", &i)?;
    Ok(i)
}
pub fn recover_root(
    c: &Codec,
    bytes: &[u8],
    pin: &[u8],
) -> Result<(
    libsodium_rs::crypto_sign::KeyPair,
    libsodium_rs::crypto_box::KeyPair,
)> {
    let kit = c.decode("p02-identity-c1", "kit", bytes)?;
    let pin_value = c.decode("p02-identity-c1", "identity-pin", pin)?;
    require(
        kit["service_id"] == pin_value["service_id"]
            && kit["account_id"] == pin_value["account_id"]
            && kit["root_fingerprint"] == pin_value["root_fingerprint"],
        "ROOT_PIN_MISMATCH",
    )?;
    verify_identity(c, &canonical(&kit["identity"])?, pin)?;
    let secret = recovery_decode(text(&kit["recovery_secret"])?)?;
    let context = json!({"purpose":"account-root-derivation","contract":"p02-identity-c1","protocol":"anynote","protocol_version":1,"service_id":kit["service_id"],"account_id":kit["account_id"]});
    let context = canonical(&context)?;
    require(
        create_identity(c, &secret, &context)? == kit["identity"],
        "RECOVERY_IDENTITY_MISMATCH",
    )?;
    derive_root(c, &secret, &context)
}
pub fn verify_identity(c: &Codec, bytes: &[u8], pin: &[u8]) -> Result<Value> {
    let i = c.decode("p02-identity-c1", "identity", bytes)?;
    let pin = c.decode("p02-identity-c1", "identity-pin", pin)?;
    require(
        i["body"]["account_id"] == pin["account_id"]
            && i["body"]["service_id"] == pin["service_id"]
            && hash(&domain(
                "p02-identity-c1",
                "hash",
                "account-root-identity",
                &canonical(&i["body"])?,
            )) == pin["root_fingerprint"],
        "ROOT_PIN_MISMATCH",
    )?;
    verify(
        &c.signing("p02-identity-c1", "identity-body", &i["body"])?,
        text(&i["signature"])?,
        &un64(text(&i["body"]["root_signing_key"])?)?,
    )?;
    Ok(i)
}
pub fn open_grant(
    c: &Codec,
    bytes: &[u8],
    expected: &[u8],
    issuer: &[u8],
    public: &[u8],
    secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let record = c.decode("p02-identity-c1", "grant", bytes)?;
    let context = c.decode("p02-identity-c1", "grant-context", expected)?;
    require(
        record["body"]["context"] == context,
        "GRANT_CONTEXT_MISMATCH",
    )?;
    verify(
        &c.signing("p02-identity-c1", "grant-body", &record["body"])?,
        text(&record["signature"])?,
        issuer,
    )?;
    require(
        hash(&domain(
            "p02-identity-c1",
            "hash",
            "x25519-public-key",
            public,
        )) == context["recipient"]["encryption_key_fingerprint"],
        "RECIPIENT_KEY_MISMATCH",
    )?;
    let pk = libsodium_rs::crypto_box::PublicKey::from_bytes(public)
        .map_err(|_| crate::Error("INVALID_KEY_LENGTH"))?;
    let sk = libsodium_rs::crypto_box::SecretKey::from_bytes(secret)
        .map_err(|_| crate::Error("INVALID_KEY_LENGTH"))?;
    require(
        libsodium_rs::crypto_scalarmult::curve25519::scalarmult_base(secret)
            .map_err(|_| crate::Error("INVALID_KEY_LENGTH"))?
            .as_slice()
            == public,
        "RECIPIENT_KEY_MISMATCH",
    )?;
    let plain = Zeroizing::new(
        libsodium_rs::crypto_box::open_sealed_box(
            &un64(text(&record["body"]["sealed_ciphertext"])?)?,
            &pk,
            &sk,
        )
        .map_err(|_| crate::Error("INTEGRITY_FAILURE"))?,
    );
    let v = c.decode("p02-identity-c1", "grant-plaintext", &plain)?;
    require(v["context"] == context, "INNER_CONTEXT_MISMATCH")?;
    Ok(Zeroizing::new(un64(text(&v["group_key"])?)?))
}

/// Expected recipient/issuer authority is supplied by independently verified policy.
pub fn seal_grant(
    c: &Codec,
    context: &[u8],
    group: &[u8],
    recipient: &[u8],
    signing: &[u8],
) -> Result<Value> {
    require(group.len() == 32, "INVALID_KEY_LENGTH")?;
    let context = c.decode("p02-identity-c1", "grant-context", context)?;
    let pk = libsodium_rs::crypto_box::PublicKey::from_bytes(recipient)
        .map_err(|_| crate::Error("INVALID_KEY_LENGTH"))?;
    require(
        hash(&domain(
            "p02-identity-c1",
            "hash",
            "x25519-public-key",
            recipient,
        )) == context["recipient"]["encryption_key_fingerprint"],
        "RECIPIENT_KEY_MISMATCH",
    )?;
    let plain = Zeroizing::new(canonical(
        &json!({"purpose":"group-key-plaintext", "context": context, "group_key":b64(group)}),
    )?);
    c.decode("p02-identity-c1", "grant-plaintext", &plain)?;
    let body = json!({"context":context,"sealed_ciphertext":b64(&libsodium_rs::crypto_box::seal_box(&plain,&pk).map_err(|_|crate::Error("CRYPTO_FAILURE"))?)});
    let result = json!({"signature":sign(&c.signing("p02-identity-c1", "grant-body", &body)?,signing)?, "body":body});
    c.validate("p02-identity-c1", "grant", &result)?;
    Ok(result)
}
