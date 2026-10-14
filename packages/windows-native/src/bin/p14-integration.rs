//! Feature-only owned synthetic acceptance driver. Never shipped in the installer.
use anynote_crypto_core::{
    codec::{canonical, strict},
    crypto::b64,
};
use anynote_local_vault::{Scope, Vault};
use anynote_windows_native::{
    bridge::Assets,
    host::{Binding, Host, Profile, Request, Service},
    selection::Source,
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, Write},
    path::PathBuf,
    sync::Arc,
};
use zeroize::{Zeroize, Zeroizing};
struct Owned {
    path: PathBuf,
    cleanup: bool,
}
impl Drop for Owned {
    fn drop(&mut self) {
        if self.cleanup {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
fn line(
    input: &mut impl BufRead,
) -> Result<Option<Zeroizing<Vec<u8>>>, Box<dyn std::error::Error>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let n = std::io::Read::take(input, 33558529).read_until(b'\n', &mut bytes)?;
    if n == 0 {
        return Ok(None);
    }
    if n > 33558528 {
        return Err("RESOURCE_LIMIT".into());
    }
    Ok(Some(bytes))
}
fn emit(v: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{v}")?;
    out.flush()?;
    Ok(())
}
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Object(o) => o.values_mut().for_each(wipe),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        _ => (),
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = std::io::stdin().lock();
    let mut init = strict(&line(&mut input)?.ok_or("INIT_REQUIRED")?, 4194304)?;
    let scope: Scope = serde_json::from_value(init["scope"].clone())?;
    let mut owned = Owned {
        path: std::env::temp_dir().join(format!(
            "anynote-p14-synthetic-{}",
            b64(&anynote_crypto_core::crypto::random_key()?[..16])
        )),
        cleanup: true,
    };
    if let Some(path) = init["fixture_root"].as_str() {
        if !cfg!(windows) || std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
            return Err("Owned Windows Actions fixture required".into());
        }
        let target = PathBuf::from(path);
        if target.exists() {
            return Err("Refusing existing fixture root".into());
        }
        std::fs::create_dir_all(&target)?;
        std::fs::write(
            target.join("owner.json"),
            canonical(&json!({"purpose":"p14-owned-installed-application","scope":scope}))?,
        )?;
        owned.path = target;
    }
    let vault = Arc::new(Vault::open(
        &owned.path.join("vault.sqlite"),
        scope.clone(),
    )?);
    let phrase = Zeroizing::new(init["phrase"].as_str().ok_or("PHRASE_REQUIRED")?.to_owned());
    vault.initialize_phrase(
        &phrase,
        &Zeroizing::new(canonical(&init["secrets"])?),
        init["pins"].clone(),
        true,
    )?;
    let cap = vault.unlock_phrase(&phrase)?;
    vault.record_device_snapshot(&cap, &init["snapshot"])?;
    let ca = std::fs::read(init["ca"].as_str().ok_or("CA_REQUIRED")?)?;
    let issuer = "https://api.anynote.test:18443";
    let app = "https://app.anynote.test:18443";
    let adapter = anynote_auth_native::Adapter::synthetic_local(issuer, app, &ca)?;
    let profile = Profile {
        version: 1,
        scope,
        service: Service {
            issuer: issuer.into(),
            app: app.into(),
            pins: init["pins"].clone(),
        },
        credential_id: b64(&anynote_crypto_core::crypto::random_key()?[..16]),
    };
    let host = Arc::new(Host::from_parts(&owned.path, profile, vault, adapter));
    let binding = Binding {
        label: "main".into(),
        origin: "http://tauri.localhost".into(),
        hwnd: 0,
    };
    host.bind_new_service(&cap)?;
    host.execute(
        &binding,
        0,
        Request::Unlock {
            phrase: phrase.to_string(),
        },
    )?;
    wipe(&mut init);
    let cap = host.capability(0)?;
    emit(&host.vault.device_public(&cap)?)?;
    while let Some(bytes) = line(&mut input)? {
        let mut command = strict(&bytes, 33558528)?;
        let result = (|| -> anynote_crypto_core::Result<Value> {
            match command["driver"].as_str() {
                Some("login") => {
                    let cap = host.capability(host.current())?;
                    let public = host.vault.device_public(&cap)?;
                    let pending = host
                        .adapter
                        .begin(
                            &anynote_windows_native::host::native_commitment(&public)?,
                            false,
                        )
                        .map_err(|_| anynote_crypto_core::Error("AUTH_BEGIN_FAILED"))?;
                    emit(&json!({"consent_url":pending.consent_url()}))
                        .map_err(|_| anynote_crypto_core::Error("PIPE_FAILED"))?;
                    let credentials = host
                        .adapter
                        .complete(pending)
                        .map_err(|_| anynote_crypto_core::Error("AUTH_COMPLETE_FAILED"))?;
                    host.vault.store_credentials(
                        &cap,
                        &host.profile.credential_id,
                        &credentials,
                    )?;
                    Ok(json!({"state":credentials.state}))
                }
                Some("persist") => {
                    if init["fixture_root"].is_null() && !owned.path.join("owner.json").exists() {
                        return Err(anynote_crypto_core::Error("FIXTURE_OWNERSHIP_REQUIRED"));
                    }
                    std::fs::write(
                        owned.path.join("profile.json"),
                        canonical(&json!(host.profile))?,
                    )
                    .map_err(|_| anynote_crypto_core::Error("STORAGE_UNAVAILABLE"))?;
                    host.lock();
                    owned.cleanup = false;
                    Ok(json!({"state":"PERSISTED","physical_acceptance":false}))
                }
                Some("prepare-group-creation") => {
                    let cap = host.capability(host.current())?;
                    host.prepare_group_creation(
                        &cap,
                        command["title"]
                            .as_str()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                        command["shared"]
                            .as_bool()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    )
                }
                Some("account-card") => host.account_card(host.current()),
                Some("group-card") => host.group_card(
                    host.current(),
                    command["group_id"]
                        .as_str()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                ),
                Some("adopt-card") => host.adopt_group_card(
                    host.current(),
                    command["proof"].clone(),
                    command["accept"]
                        .as_bool()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                ),
                Some("invite-card") => host.invite_account_card(
                    host.current(),
                    command["group_id"]
                        .as_str()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    &command["card"],
                    command["role"]
                        .as_str()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                ),
                Some("ownership-proposal") => host.ownership_proposal(
                    host.current(),
                    command["group_id"]
                        .as_str()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    command["account_id"]
                        .as_str()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    command["device_id"]
                        .as_str()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                ),
                Some("ownership-step") => host.ownership_step(
                    host.current(),
                    command["group_id"]
                        .as_str()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    &command["policy"],
                    command["cosign"]
                        .as_bool()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                ),
                Some("saved-ownership") => host.saved_ownership_policy(
                    host.current(),
                    command["group_id"]
                        .as_str()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                ),
                Some("product") => {
                    let request: Request = serde_json::from_value(command["request"].clone())
                        .map_err(|_| anynote_crypto_core::Error("INVALID_REQUEST"))?;
                    host.execute(&binding, host.current(), request)
                }
                Some("upload") => Ok(
                    json!({"job_id":host.start_upload(host.current(),command["group_id"].as_str().ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?.into(),Source::open(&PathBuf::from(command["source"].as_str().ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?),1000000000)?,None)?}),
                ),
                Some("download") => Ok(
                    json!({"job_id":host.start_download(host.current(),command["group_id"].as_str().ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?.into(),command["file_version_id"].as_str().ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?.into(),&PathBuf::from(command["target"].as_str().ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?),false)?}),
                ),
                Some("export") => {
                    let group = command["group_id"]
                        .as_str()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?;
                    let plan =
                        host.prepare_export(host.current(), &[group.into()], true, true, 1048576)?;
                    let target = PathBuf::from(
                        command["target"]
                            .as_str()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    );
                    let node = PathBuf::from(
                        command["node"]
                            .as_str()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    );
                    let script = PathBuf::from(
                        command["script"]
                            .as_str()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    );
                    let a = Assets {
                        node: &node,
                        script: &script,
                        node_sha: command["node_sha"]
                            .as_str()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                        script_sha: command["script_sha"]
                            .as_str()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    };
                    let job = host.jobs.start(host.current())?;
                    let result =
                        host.export_archive(host.current(), plan, &target, &a, job.clone());
                    job.finish(result.clone());
                    result
                }
                Some("file-status") => {
                    let cap = host.capability(host.current())?;
                    let request = host.vault.file_request(
                        cap.as_ref(),
                        command["draft_id"]
                            .as_str()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    )?;
                    let result = host.vault.file_http(
                        cap.as_ref(),
                        &host.profile.credential_id,
                        &host.adapter,
                        anynote_auth_native::FileOperation::Status {
                            upload: request["upload_id"]
                                .as_str()
                                .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                        },
                    )?;
                    Ok(json!({"status":result.status}))
                }
                Some("session-expiry") => {
                    let cap = host.capability(host.current())?;
                    Ok(
                        json!({"expires_at":host.vault.native_credentials_expires_at(cap.as_ref(),&host.profile.credential_id)?}),
                    )
                }
                Some("expire-session") => {
                    let cap = host.capability(host.current())?;
                    Ok(
                        json!({"prior_expires_at":host.vault.synthetic_expire_native_session(cap.as_ref(),&host.profile.credential_id)?}),
                    )
                }
                Some("prepare-note-attempt") => {
                    let cap = host.capability(host.current())?;
                    let queued = host.vault.notes_command(
                        cap.as_ref(),
                        anynote_local_vault::notes::NotesRequest::Queue {
                            draft_id: command["draft_id"]
                                .as_str()
                                .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?
                                .to_owned(),
                        },
                    )?;
                    let sent = host.vault.notes_command(
                        cap.as_ref(),
                        anynote_local_vault::notes::NotesRequest::Send {
                            attempt_id: queued["attempt_id"]
                                .as_str()
                                .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?
                                .to_owned(),
                        },
                    )?;
                    Ok(
                        json!({"attempt_id":queued["attempt_id"],"request_sha256":anynote_crypto_core::crypto::hash(&canonical(&sent["request"])?),"request":sent["request"] }),
                    )
                }
                Some("copy-file") => {
                    let draft = command["draft_id"]
                        .as_str()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?;
                    let destination = command["destination_group"]
                        .as_str()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?;
                    let preview =
                        host.selected_file_copy_preview(host.current(), draft, destination)?;
                    let source = Source::open(
                        std::path::Path::new(
                            command["source"]
                                .as_str()
                                .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                        ),
                        1000000000,
                    )?;
                    Ok(
                        json!({"job_id":host.start_selected_file_copy(host.current(),draft,destination,source,preview["digest"].as_str().ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?)?}),
                    )
                }
                Some("kit") => host.save_kit(
                    host.current(),
                    command["export_id"]
                        .as_str()
                        .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    &PathBuf::from(
                        command["target"]
                            .as_str()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    ),
                ),
                Some("inspect") => {
                    let node = PathBuf::from(
                        command["node"]
                            .as_str()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    );
                    let script = PathBuf::from(
                        command["script"]
                            .as_str()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    );
                    let a = Assets {
                        node: &node,
                        script: &script,
                        node_sha: command["node_sha"]
                            .as_str()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                        script_sha: command["script_sha"]
                            .as_str()
                            .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                    };
                    host.inspect_import(
                        host.current(),
                        Source::open(
                            &PathBuf::from(
                                command["source"]
                                    .as_str()
                                    .ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,
                            ),
                            116010000000,
                        )?,
                        command["kit"].clone(),
                        command["destination"].as_str(),
                        command["resume"].as_str(),
                        &a,
                    )
                }
                Some("confirm") => Ok(
                    json!({"job_id":host.start_import(host.current(),command["import_id"].as_str().ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?,command["audience_digest"].as_str().ok_or(anynote_crypto_core::Error("INVALID_REQUEST"))?)?}),
                ),
                _ => Err(anynote_crypto_core::Error("INVALID_DRIVER")),
            }
        })();
        wipe(&mut command);
        match result {
            Ok(v) => emit(&v)?,
            Err(e) => emit(&json!({"error":e.0}))?,
        }
    }
    host.lock();
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("P14_INTEGRATION_FAILED");
        std::process::exit(1);
    }
}
