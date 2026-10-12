//! Explicit test-only executable. Stdin is bounded/zeroized; no production IPC,
//! caller-selected path, key export, eligibility mock or token issuer exists.
use anynote_crypto_core::{
    codec::{canonical, strict},
    crypto::b64,
};
use anynote_local_vault::{Record, Scope, Vault};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{Read, Write};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    native_transport: Option<NativeTransport>,
    scope: Scope,
    phrase: String,
    pins: Option<Value>,
    secrets: Option<Value>,
    records: Vec<Row>,
    snapshot: Option<Snapshot>,
    challenge: Option<Value>,
    session_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeTransport {
    issuer: String,
    app: String,
    ca_path: String,
    credentials: Tokens,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tokens {
    access: String,
    refresh: String,
    session_id: String,
    state: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    id: String,
    kind: String,
    data: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    state: Value,
    rows: Vec<CipherRow>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CipherRow {
    id: String,
    frame: Value,
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin().take(8_388_609).read_to_end(&mut bytes)?;
    let parsed = strict(&bytes, 8_388_608)?;
    let input: Input = serde_json::from_value(parsed)?;
    let root = std::env::temp_dir().join(format!(
        "anynote-p07-integration-{}",
        b64(&libsodium_rs::random::bytes(16))
    ));
    let path = root.join("vault.sqlite");
    let vault = Vault::open(&path, input.scope)?;
    if let Some(snapshot) = input.snapshot {
        let mut conn = rusqlite::Connection::open(&path)?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO meta VALUES(1,?1)",
            [snapshot.state.to_string()],
        )?;
        for row in snapshot.rows {
            tx.execute(
                "INSERT INTO records VALUES(?1,?2)",
                rusqlite::params![row.id, canonical(&row.frame)?],
            )?;
        }
        tx.commit()?;
    } else {
        vault.initialize_phrase(
            &input.phrase,
            &canonical(&input.secrets.ok_or("SECRETS_REQUIRED")?)?,
            input.pins.ok_or("PINS_REQUIRED")?,
            true,
        )?;
    }
    let cap = vault.unlock_phrase(&input.phrase)?;
    if let Some(transport) = input.native_transport {
        let adapter = anynote_auth_native::Adapter::synthetic_local(
            &transport.issuer,
            &transport.app,
            &std::fs::read(&transport.ca_path)?,
        )?;
        let credentials = anynote_auth_native::Credentials {
            access: zeroize::Zeroizing::new(transport.credentials.access),
            refresh: zeroize::Zeroizing::new(transport.credentials.refresh),
            session_id: transport.credentials.session_id,
            state: transport.credentials.state,
        };
        let id = b64(&libsodium_rs::random::bytes(16));
        vault.store_credentials(&cap, &id, &credentials)?;
        vault.rotate_credentials(&cap, &id, &adapter)?;
    }

    if let Some(challenge) = input.challenge {
        let proof = vault.device_proof(
            &cap,
            &canonical(&challenge)?,
            &input.session_id.ok_or("SESSION_REQUIRED")?,
        )?;
        println!("{}", json!({"status":"PASS","proof":proof}));
        return Ok(());
    }
    let records = input
        .records
        .into_iter()
        .map(|r| Record {
            id: r.id,
            kind: r.kind,
            data: r.data,
        })
        .collect::<Vec<_>>();
    if !records.is_empty() {
        vault.save_batch(&cap, vault.lease(&cap)?, &records)?;
    }
    let mut visible = Vec::new();
    for r in &records {
        visible.push(json!({"id":r.id,"kind":r.kind,"data":vault.read(&cap,&r.id,&r.kind)?}));
    }
    vault.lock_all()?;
    let conn = rusqlite::Connection::open(&path)?;
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
            Ok::<_, Box<dyn std::error::Error>>(json!({"id":id,"frame":strict(&bytes,8_388_608)?}))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "{}",
        json!({"status":"PASS","snapshot":{"state":state,"rows":rows},"visible":visible})
    )?;
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("P07_INTEGRATION_FAILED");
        std::process::exit(1);
    }
}
