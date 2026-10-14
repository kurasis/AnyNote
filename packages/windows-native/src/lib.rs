//! Trusted native Windows application coordinator, usable without a WebView in tests.
pub mod bridge;
pub mod host;
pub mod imports;
pub mod jobs;
pub mod portable;
pub mod selection;
pub mod sync;
pub mod transfers;
pub mod updates;
pub use anynote_crypto_core::{Error, Result};
use serde_json::Value;
fn check(ok: bool, code: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(Error(code)) }
}
fn id(v: &str) -> Result<&str> {
    check(
        v.len() == 22
            && v.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)),
        "INVALID_ID",
    )?;
    Ok(v)
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().ok_or(Error("INVALID_REQUEST"))
}
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => {
            use zeroize::Zeroize;
            s.zeroize()
        }
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}
fn random_id() -> String {
    anynote_crypto_core::crypto::b64(&libsodium_rs::random::bytes(16))
}
