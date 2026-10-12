//! Feature-gated synthetic process harness. Uses the real vault and typed host boundary.
//! Private inputs stay in bounded/zeroized stdin; only public outputs/ciphertext leave it.
use anynote_crypto_core::{
    codec::{canonical, strict},
    crypto::b64,
};
use anynote_local_vault::{
    Scope, Vault,
    ipc::{Endpoint, HostBinding, WindowRole},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{BufRead, Write},
    path::PathBuf,
    sync::Arc,
};
use zeroize::Zeroizing;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Init {
    scope: Scope,
    pins: Value,
    phrase: String,
    secrets: Option<Value>,
}
struct Owned(PathBuf);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn line(
    input: &mut impl BufRead,
) -> Result<Option<Zeroizing<Vec<u8>>>, Box<dyn std::error::Error>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut limited = std::io::Read::take(input, 16_781_313);
    let n = limited.read_until(b'\n', &mut bytes)?;
    if n == 0 {
        return Ok(None);
    }
    if n > 16_781_312 {
        return Err("RESOURCE_LIMIT".into());
    }
    Ok(Some(bytes))
}
fn emit(v: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", v)?;
    out.flush()?;
    Ok(())
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = std::io::stdin().lock();
    let bytes = line(&mut input)?.ok_or("INIT_REQUIRED")?;
    let init: Init = serde_json::from_value(strict(&bytes, 4_194_304)?)?;
    let owned = Owned(std::env::temp_dir().join(format!(
        "anynote-p08-process-{}",
        b64(&libsodium_rs::random::bytes(16))
    )));
    let vault = Arc::new(Vault::open(&owned.0.join("vault.sqlite"), init.scope)?);
    let phrase = Zeroizing::new(init.phrase);
    if let Some(secrets) = init.secrets {
        vault.initialize_phrase(
            &phrase,
            &Zeroizing::new(canonical(&secrets)?),
            init.pins,
            true,
        )?;
    } else {
        vault.initialize_device_phrase(&phrase, init.pins, true)?;
    }
    let endpoint = Endpoint::new(vault.clone());
    let host = HostBinding::from_native_window(WindowRole::Main, "tauri://localhost");
    let mut handle = endpoint.invoke(
        &host,
        &Zeroizing::new(canonical(
            &json!({"operation":"unlock-phrase","phrase":*phrase}),
        )?),
    )?["capability"]
        .clone();
    emit(&endpoint.invoke(
        &host,
        &canonical(&json!({"operation":"device-public","capability":handle}))?,
    )?)?;
    while let Some(bytes) = line(&mut input)? {
        let mut request = strict(&bytes, 16_781_312)?;
        if request["operation"] == "test-inspect-ciphertext" {
            let conn = rusqlite::Connection::open(vault.path())?;
            let state: Value =
                serde_json::from_str(
                    &conn.query_row("SELECT value FROM meta", [], |r| r.get::<_, String>(0))?,
                )?;
            let rows = conn
                .prepare("SELECT id,frame FROM records ORDER BY id")?
                .query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                })?
                .map(|r| {
                    let (id, bytes) = r?;
                    Ok::<_, Box<dyn std::error::Error>>(
                        json!({"id":id,"frame":strict(&bytes,1_048_576)?}),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            emit(&json!({"state":state,"rows":rows}))?;
            continue;
        }
        if request["operation"] == "unlock-phrase" {
            request["phrase"] = json!(*phrase);
        } else if request["operation"] != "lock" && request["operation"] != "status" {
            request["capability"] = handle.clone();
        }
        match endpoint.invoke(&host, &Zeroizing::new(canonical(&request)?)) {
            Ok(value) => {
                if request["operation"] == "unlock-phrase" {
                    handle = value["capability"].clone();
                    emit(&json!({"state":"unlocked"}))?;
                } else {
                    emit(&value)?;
                }
            }
            Err(e) => emit(&json!({"error":e.0}))?,
        }
    }
    vault.lock();
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("P08_INTEGRATION_FAILED");
        std::process::exit(1);
    }
}
