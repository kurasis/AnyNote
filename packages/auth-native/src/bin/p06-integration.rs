//! Explicit test-only executable. Uses actual API/OAuth/callback; emits no reusable credentials.
use anynote_auth_native::{Adapter, Error};
use serde::Deserialize;
use std::io::{Read, Write};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    issuer: String,
    app: String,
    ca_path: String,
    device_commitment: String,
}
fn main() -> Result<(), Error> {
    let mut input = String::new();
    std::io::stdin()
        .take(8193)
        .read_to_string(&mut input)
        .map_err(|_| Error::Configuration)?;
    if input.len() > 8192 {
        return Err(Error::Configuration);
    }
    let config: Input = serde_json::from_str(&input).map_err(|_| Error::Configuration)?;
    let ca = std::fs::read(config.ca_path).map_err(|_| Error::Configuration)?;
    let adapter = Adapter::synthetic_local(&config.issuer, &config.app, &ca)?;
    let pending = adapter.begin(&config.device_commitment, false)?;
    println!(
        "{}",
        serde_json::json!({"version":1,"consent_url":pending.consent_url().as_str()})
    );
    std::io::stdout().flush().map_err(|_| Error::Transport)?;
    let old = adapter.complete(pending)?;
    if old.state != "restricted" {
        return Err(Error::Denied);
    }
    let next = adapter.refresh(&old)?;
    if next.session_id != old.session_id
        || next.state != "restricted"
        || adapter.refresh(&old).err() != Some(Error::Denied)
    {
        return Err(Error::Denied);
    }
    println!(
        "{}",
        serde_json::json!({"status":"PASS","native_oauth_transport":"actual fixed-issuer HTTPS + PKCE + TCP callback + refresh/reuse","state":"restricted"})
    );
    Ok(())
}
