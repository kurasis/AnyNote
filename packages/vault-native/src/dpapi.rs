//! Current-user DPAPI is an extra outer layer for the explicit phrase mode.
//! It is not physical user presence. The inner frozen phrase wrapper is unchanged.
use super::*;
#[cfg(windows)]
fn entropy(scope: &Scope, context: &Value) -> Result<Vec<u8>> {
    let mut e = b"AnyNote/P07/windows-phrase-custody\0".to_vec();
    e.extend(canonical(&json!({"scope":scope,"context":context}))?);
    Ok(e)
}
#[cfg(windows)]
fn crypt(input: &[u8], extra: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    };
    check(
        input.len() <= 65536 && extra.len() <= 16384,
        "RESOURCE_LIMIT",
    )?;
    let source = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr() as *mut u8,
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: extra.len() as u32,
        pbData: extra.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let result = unsafe {
        if protect {
            CryptProtectData(
                &source,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        } else {
            CryptUnprotectData(
                &source,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
    };
    if result == 0 {
        return Err(Error("OS_PROTECTION_FAILURE"));
    }
    let output = if out.cbData <= 65536 && !out.pbData.is_null() {
        Ok(Zeroizing::new(
            unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec(),
        ))
    } else {
        Err(Error("RESOURCE_LIMIT"))
    };
    unsafe {
        if !out.pbData.is_null() {
            for i in 0..out.cbData as usize {
                out.pbData.add(i).write_volatile(0);
            }
            LocalFree(out.pbData as _);
        }
    }
    output
}
pub(crate) fn protect(c: &Codec, scope: &Scope, wrapper: Value) -> Result<Value> {
    c.validate("p02-v1", "phrase-wrapper", &wrapper)?;
    #[cfg(windows)]
    {
        let context = wrapper["context"].clone();
        let blob = crypt(&canonical(&wrapper)?, &entropy(scope, &context)?, true)?;
        Ok(
            json!({"contract":"p07-local-v1","protocol":"anynote","protocol_version":1,"purpose":"windows-phrase-custody","scope":scope,"context":context,"blob":b64(&blob)}),
        )
    }
    #[cfg(not(windows))]
    {
        let _ = scope;
        Ok(wrapper)
    }
}
pub(crate) fn validate(c: &Codec, scope: &Scope, w: &Value) -> Result<()> {
    check(
        w.as_object().is_some_and(|o| o.len() == 7)
            && w["contract"] == "p07-local-v1"
            && w["protocol"] == "anynote"
            && w["protocol_version"] == 1
            && w["purpose"] == "windows-phrase-custody"
            && w["scope"] == serde_json::to_value(scope).unwrap()
            && un64(text(&w["blob"])?)?.len() <= 65536,
        "INVALID_OS_WRAPPER",
    )?;
    c.validate("p02-v1", "unlock-context", &w["context"])?;
    check(w["context"]["method"] == "argon2id13", "INVALID_OS_WRAPPER")
}
pub(crate) fn unprotect(c: &Codec, scope: &Scope, w: &Value) -> Result<Value> {
    if w["purpose"] != "windows-phrase-custody" {
        #[cfg(windows)]
        return Err(Error("OS_PROTECTION_REQUIRED"));
        #[cfg(not(windows))]
        return Ok(w.clone());
    }
    validate(c, scope, w)?;
    #[cfg(windows)]
    {
        let bytes = crypt(
            &un64(text(&w["blob"])?)?,
            &entropy(scope, &w["context"])?,
            false,
        )?;
        let wrapper = c.decode("p02-v1", "phrase-wrapper", &bytes)?;
        check(wrapper["context"] == w["context"], "LOCAL_CONTEXT_MISMATCH")?;
        Ok(wrapper)
    }
    #[cfg(not(windows))]
    Err(Error("WINDOWS_PROVIDER_REQUIRED"))
}
