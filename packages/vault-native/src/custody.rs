//! Additive P07 custody container. Its encrypted payload is the unchanged P02
//! native-wrapper; the outer key is recoverable only through the actual TPM key.
use super::*;
use libsodium_rs::crypto_aead::xchacha20poly1305 as aead;
pub(crate) fn validate(c: &Codec, w: &Value, scope: &Scope) -> Result<()> {
    check(
        w.as_object().is_some_and(|o| o.len() == 9)
            && w["contract"] == "p07-local-v1"
            && w["protocol"] == "anynote"
            && w["protocol_version"] == 1
            && w["purpose"] == "windows-native-custody"
            && w["scope"] == serde_json::to_value(scope).unwrap(),
        "INVALID_NATIVE_CONTAINER",
    )?;
    let d = &w["descriptor"];
    let mut f = d.clone();
    check(
        f.get("nonce").is_none() && f.get("ciphertext").is_none(),
        "INVALID_NATIVE_CONTAINER",
    )?;
    f["nonce"] = json!(b64(&[0; 12]));
    f["ciphertext"] = json!(b64(&[0; 48]));
    c.validate("p02-v1", "native-wrapper", &f)?;
    for (k, v) in serde_json::to_value(scope).unwrap().as_object().unwrap() {
        check(d["context"][k] == *v, "LOCAL_CONTEXT_MISMATCH")?;
    }
    check(
        d["context"]["method"] == "windows-webauthn-prf"
            && un64(text(&w["nonce"])?)?.len() == 24
            && (256..=1024).contains(&un64(text(&w["tpm_ciphertext"])?)?.len())
            && (16..=16384).contains(&un64(text(&w["ciphertext"])?)?.len()),
        "INVALID_NATIVE_CONTAINER",
    )
}
fn aad(w: &Value) -> Result<Vec<u8>> {
    let mut body = w.clone();
    body.as_object_mut().unwrap().remove("nonce");
    body.as_object_mut().unwrap().remove("ciphertext");
    let mut out = b"AnyNote/P07/windows-native-custody\0".to_vec();
    out.extend(canonical(&body)?);
    Ok(out)
}
pub(crate) fn seal(
    c: &Codec,
    scope: &Scope,
    descriptor: &Value,
    inner: &Value,
    tpm_ciphertext: &[u8],
    key: &[u8],
) -> Result<Value> {
    let mut w = json!({"contract":"p07-local-v1","protocol":"anynote","protocol_version":1,"purpose":"windows-native-custody","scope":scope,"descriptor":descriptor,"tpm_ciphertext":b64(tpm_ciphertext),"nonce":b64(&libsodium_rs::random::bytes(24)),"ciphertext":b64(&[0;16])});
    validate(c, &w, scope)?;
    let nonce = aead::Nonce::try_from(un64(text(&w["nonce"])?)?.as_slice())
        .map_err(|_| Error("INVALID_NONCE"))?;
    let key = aead::Key::from_bytes(key).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    w["ciphertext"] = json!(b64(&aead::encrypt(
        &canonical(inner)?,
        Some(&aad(&w)?),
        &nonce,
        &key
    )
    .map_err(|_| Error("CRYPTO_FAILURE"))?));
    validate(c, &w, scope)?;
    Ok(w)
}
pub(crate) fn open(c: &Codec, scope: &Scope, w: &Value, key: &[u8]) -> Result<Value> {
    validate(c, w, scope)?;
    let nonce = aead::Nonce::try_from(un64(text(&w["nonce"])?)?.as_slice())
        .map_err(|_| Error("INVALID_NONCE"))?;
    let key = aead::Key::from_bytes(key).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    let plain = Zeroizing::new(
        aead::decrypt(
            &un64(text(&w["ciphertext"])?)?,
            Some(&aad(w)?),
            &nonce,
            &key,
        )
        .map_err(|_| Error("INTEGRITY_FAILURE"))?,
    );
    let inner = c.decode("p02-v1", "native-wrapper", &plain)?;
    let mut d = inner.clone();
    d.as_object_mut().unwrap().remove("nonce");
    d.as_object_mut().unwrap().remove("ciphertext");
    check(d == w["descriptor"], "LOCAL_CONTEXT_MISMATCH")?;
    Ok(inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn portable_compound_bytes_require_both_keys_and_exact_descriptor() {
        let c = Codec::new().unwrap();
        let scope = Scope {
            service_id: random_id(),
            account_id: random_id(),
            device_id: random_id(),
            profile_id: random_id(),
        };
        let mut name = vec![0, 11];
        name.extend(libsodium_rs::random::bytes(32));
        let d = json!({"context":{"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"local-unlock","service_id":scope.service_id,"account_id":scope.account_id,"device_id":scope.device_id,"profile_id":scope.profile_id,"wrapper_id":random_id(),"method":"windows-webauthn-prf"},"provider":"windows-hello-webauthn-prf-tpm","provider_format":1,"credential_id":b64(&libsodium_rs::random::bytes(32)),"prf_salt":b64(&libsodium_rs::random::bytes(32)),"tpm_name":b64(&name),"tpm_public_sha256":hash(&libsodium_rs::random::bytes(32)),"machine_binding_id":random_id()});
        // PUBLIC test inputs exercise AEAD, not an eligibility/provider substitute.
        let key = libsodium_rs::random::bytes(32);
        let prf = libsodium_rs::random::bytes(32);
        let outer = libsodium_rs::random::bytes(32);
        let tpm = libsodium_rs::random::bytes(256);
        let inner = local::wrap_native(&c, &canonical(&d).unwrap(), &key, &prf).unwrap();
        let w = seal(&c, &scope, &d, &inner, &tpm, &outer).unwrap();
        let recovered = open(&c, &scope, &w, &outer).unwrap();
        assert_eq!(
            *local::unwrap_native(
                &c,
                &canonical(&recovered).unwrap(),
                &canonical(&d).unwrap(),
                &prf
            )
            .unwrap(),
            key
        );
        assert!(open(&c, &scope, &w, &libsodium_rs::random::bytes(32)).is_err());
        assert!(
            local::unwrap_native(
                &c,
                &canonical(&recovered).unwrap(),
                &canonical(&d).unwrap(),
                &libsodium_rs::random::bytes(32)
            )
            .is_err()
        );
        let mut changed = w.clone();
        changed["descriptor"]["machine_binding_id"] = json!(random_id());
        assert!(open(&c, &scope, &changed, &outer).is_err());
        let mut changed = w.clone();
        changed["tpm_ciphertext"] = json!(b64(&libsodium_rs::random::bytes(256)));
        assert!(open(&c, &scope, &changed, &outer).is_err());
        let mut changed = w;
        changed["extra"] = json!(true);
        assert!(validate(&c, &changed, &scope).is_err());
    }
}
