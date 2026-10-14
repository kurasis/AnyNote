//! Fully authenticated native immutable-input import. All journals are encrypted under L.
use crate::*;
use crate::{
    bridge::{Assets, Bridge},
    host::Host,
    jobs::Job,
    selection::Source,
};
use anynote_auth_native::FileOperation;
use anynote_crypto_core::{
    codec::{canonical, strict},
    crypto::hash,
};
use anynote_local_vault::Capability;
use serde_json::json;
use std::{
    io::{Read, Seek, SeekFrom},
    sync::Arc,
};
pub struct ValidatedImport {
    bridge: Bridge,
    source: Source,
    pub report: Value,
    state: Value,
    generation: u64,
}
impl Drop for ValidatedImport {
    fn drop(&mut self) {
        wipe(&mut self.state);
    }
}
fn feed(source: &mut Source, bridge: &mut Bridge, data: &[u8]) -> Result<()> {
    let request = strict(data, 4096)?;
    let offset = string(&request, "offset")?
        .parse::<u64>()
        .map_err(|_| Error("INVALID_BRIDGE_FRAME"))?;
    check(
        request["bytes"] == 65536 && offset <= source.size,
        "INVALID_BRIDGE_FRAME",
    )?;
    source.check()?;
    source
        .file
        .seek(SeekFrom::Start(offset))
        .map_err(|_| Error("SOURCE_UNAVAILABLE"))?;
    let mut bytes = zeroize::Zeroizing::new(vec![0u8; 65536]);
    let n = source
        .file
        .read(&mut bytes)
        .map_err(|_| Error("SOURCE_UNAVAILABLE"))?;
    if n == 0 {
        bridge.send(4, &[])
    } else {
        bridge.send(3, &bytes[..n])
    }
}
impl Host {
    pub fn inspect_import(
        self: &Arc<Self>,
        g: u64,
        mut source: Source,
        kit: Value,
        destination: Option<&str>,
        resume: Option<&str>,
        assets: &Assets,
    ) -> Result<Value> {
        let cap = self.capability(g)?;
        if let Some(d) = destination {
            id(d)?;
        }
        let own = self.clone();
        let mut bridge = Bridge::spawn(assets, move || own.current() != g)?;
        bridge.json(1, &json!({"mode":"inspect","kit":kit}))?;
        let report = loop {
            check(self.current() == g, "STALE_CAPABILITY")?;
            let (kind, data) = bridge.receive()?;
            match kind {
                13 => feed(&mut source, &mut bridge, &data)?,
                8 => break strict(&data, 16777216)?,
                _ => return Err(Error("INVALID_BRIDGE_FRAME")),
            }
        };
        check(
            report["status"] == "VERIFIED_OFFLINE" && report["live_destination_mutations"] == 0,
            "OFFLINE_INTEGRITY_FAILURE",
        )?;
        let import_id = resume.map(str::to_owned).unwrap_or_else(random_id);
        let previous = if resume.is_some() {
            Some(
                self.vault
                    .content_read(&cap, id(&import_id)?, "import-state")?
                    .data
                    .ok_or(Error("NOT_FOUND"))?,
            )
        } else {
            None
        };
        let prior_group = previous
            .as_ref()
            .and_then(|s| s["destination"]["group_id"].as_str());
        if let (Some(requested), Some(prior)) = (destination, prior_group) {
            check(requested == prior, "IDEMPOTENCY_MISMATCH")?;
        }
        let destination = destination.or(prior_group);
        let context = if let Some(d) = destination {
            self.prove(&cap)?;
            let status = self.group(&cap, d)?;
            json!({"group_id":d,"status":status})
        } else {
            json!({"group_id":null,"kind":"new-private-group","account_id":self.profile.scope.account_id})
        };
        let audience = hash(&canonical(&context)?);
        let mut state=previous.unwrap_or(json!({"purpose":"p14-native-import","version":1,"import_id":import_id,"archive_sha256":kit["archive_sha256"],"export_id":kit["export_id"],"destination":context,"notes":[],"files":[],"state":"READY","group_request":null,"selected_notes":[]}));
        check(
            state["archive_sha256"] == kit["archive_sha256"]
                && state["export_id"] == kit["export_id"]
                && !matches!(state["state"].as_str(), Some("COMPLETE" | "CANCELLED")),
            "IDEMPOTENCY_MISMATCH",
        )?;
        let notes = report["notes"]
            .as_array()
            .ok_or(Error("INVALID_BRIDGE_FRAME"))?;
        let parents = notes
            .iter()
            .flat_map(|n| n["context"]["parents"].as_array().into_iter().flatten())
            .filter_map(|p| p["revision_id"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        state["selected_notes"] = json!(
            notes
                .iter()
                .filter(|n| n["payload_status"] == "retained"
                    && n["context"]["action"] != "soft-delete"
                    && !parents.contains(n["context"]["revision_id"].as_str().unwrap_or("")))
                .map(|n| n["context"]["revision_id"].clone())
                .collect::<Vec<_>>()
        );
        state["state"] = json!("READY");
        state["audience_digest"] = json!(audience);
        state["destination"] = context.clone();
        self.save_native_job(&cap, &import_id, &state)?;
        let result = json!({"import_id":import_id,"audience_digest":audience,"preview":{"source_root":report["header"]["root_fingerprint"],"source_service":report["header"]["service_id"],"destination":context,"notes":state["selected_notes"].as_array().unwrap().len(),"files":report["files"].as_array().ok_or(Error("INVALID_BRIDGE_FRAME"))?.len(),"history":"original-archive-provenance-only"},"live_destination_mutations":0});
        let mut imports = self.imports.lock().map_err(|_| Error("HOST_BUSY"))?;
        check(imports.is_empty(), "HOST_BUSY")?;
        imports.insert(
            import_id,
            ValidatedImport {
                bridge,
                source,
                report,
                state,
                generation: g,
            },
        );
        Ok(result)
    }
    pub fn start_import(self: &Arc<Self>, g: u64, import: &str, audience: &str) -> Result<String> {
        let cap = self.capability(g)?;
        let mut input = self
            .imports
            .lock()
            .map_err(|_| Error("HOST_BUSY"))?
            .remove(id(import)?)
            .ok_or(Error("SOURCE_RESELECT_REQUIRED"))?;
        check(
            input.generation == g && input.state["audience_digest"] == audience,
            "COPY_CONFIRMATION_REQUIRED",
        )?;
        if let Some(group) = input.state["destination"]["group_id"].as_str() {
            self.prove(&cap)?;
            let status = self.group(&cap, group)?;
            check(
                input.state["destination"]["status"] == status,
                "COPY_CONFIRMATION_REQUIRED",
            )?;
        }
        let job = self.jobs.start(g)?;
        let jid = job.id.clone();
        let own = self.clone();
        std::thread::spawn(move || {
            let result = own.import_validated(&cap, &mut input, &job);
            if result.is_err() {
                input.state["state"] = json!("PAUSED");
                let _ = own.save_native_job(
                    &cap,
                    string(&input.state, "import_id").unwrap_or(""),
                    &input.state,
                );
            }
            job.finish(result);
        });
        Ok(jid)
    }
    fn import_validated(
        &self,
        cap: &Capability,
        input: &mut ValidatedImport,
        job: &Job,
    ) -> Result<Value> {
        let iid = string(&input.state, "import_id")?.to_owned();
        self.prove(cap)?;
        job.check(self.current())?;
        if input.state["destination"]["group_id"].is_null() {
            if input.state["group_request"].is_null() {
                let prepared = self.notes(cap, json!({"action":"prepare-group"}))?;
                input.state["group_request"] = prepared["request"].clone();
                self.save_native_job(cap, &iid, &input.state)?;
            }
            let result = self.api(
                cap,
                anynote_auth_native::control::Route::CreateGroup,
                None,
                None,
                &[],
                Some(&input.state["group_request"]),
            )?;
            self.notes(cap, json!({"action":"group","status":result}))?;
            input.state["destination"] = json!({"group_id":result["group_id"],"status":result});
            self.save_native_job(cap, &iid, &input.state)?;
        }
        let group = string(&input.state["destination"], "group_id")?.to_owned();
        self.group(cap, &group)?;
        input.state["state"] = json!("IMPORTING");
        self.save_native_job(cap, &iid, &input.state)?;
        input.bridge.ack()?;
        let mut file = None::<String>;
        let mut acknowledgements = Vec::new();
        let mut committed_file = false;
        loop {
            job.check(self.current())?;
            let (kind, data) = input.bridge.receive()?;
            match kind {
                13 => feed(&mut input.source, &mut input.bridge, &data)?,
                14 => {
                    let mut event = strict(&data, 16777216)?;
                    let revision = string(&event, "revision")?.to_owned();
                    if input.state["selected_notes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|r| r == &revision)
                        && !input.state["notes"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|n| n["source_revision"] == revision)
                    {
                        input.state["notes"].as_array_mut().unwrap().push(json!({"source_revision":revision,"source_context":event["payload"]["context"],"payload":event["payload"],"object_id":random_id(),"draft_id":null,"complete":false}));
                        self.save_native_job(cap, &iid, &input.state)?;
                    }
                    wipe(&mut event);
                    input.bridge.ack()?;
                }
                15 => {
                    let event = strict(&data, 65536)?;
                    let version = string(&event, "version")?.to_owned();
                    if let Some(existing) = input.state["files"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|f| f["source_version"] == version)
                    {
                        file = Some(string(existing, "draft_id")?.into());
                    } else {
                        let prepared = self.vault.prepare_recovered_file(
                            cap,
                            &group,
                            &event["source"],
                            string(&event["metadata"], "name")?,
                            "application/octet-stream",
                        )?;
                        file = Some(string(&prepared, "draft_id")?.into());
                        input.state["files"].as_array_mut().unwrap().push(json!({"source_version":version,"draft_id":file,"attached":false,"attachment_draft":null}));
                        self.save_native_job(cap, &iid, &input.state)?;
                    }
                    acknowledgements.clear();
                    committed_file = false;
                    let request = self.vault.file_request(cap, file.as_deref().unwrap())?;
                    let upload = string(&request, "upload_id")?;
                    let status = self.vault.file_http(
                        cap,
                        &self.profile.credential_id,
                        &self.adapter,
                        FileOperation::Status { upload },
                    )?;
                    if status.status == 404 {
                        self.file_response(
                            cap,
                            FileOperation::Reserve {
                                group: &group,
                                body: &request,
                            },
                        )?;
                    } else {
                        check(status.status == 200, "API_DENIED")?;
                        let status = strict(&status.bytes, 1048576)?;
                        committed_file = status["state"] == "COMMITTED";
                    }
                    input.bridge.ack()?;
                }
                16 => {
                    let meta = strict(&data, 4096)?;
                    let index = meta["index"]
                        .as_u64()
                        .ok_or(Error("INVALID_BRIDGE_FRAME"))?
                        as usize;
                    let (k, plain) = input.bridge.receive()?;
                    check(
                        k == 3
                            && plain.len()
                                == meta["bytes"]
                                    .as_u64()
                                    .ok_or(Error("INVALID_BRIDGE_FRAME"))?
                                    as usize,
                        "INVALID_BRIDGE_FRAME",
                    )?;
                    job.check(self.current())?;
                    let draft = file.as_deref().ok_or(Error("INCOMPLETE_FILE"))?;
                    if !committed_file {
                        let cipher = self.vault.recovered_file_part(cap, draft, index, &plain)?;
                        let request = self.vault.file_request(cap, draft)?;
                        acknowledgements.push(self.file_response(
                            cap,
                            FileOperation::Part {
                                upload: string(&request, "upload_id")?,
                                index: index as u8,
                                ciphertext: &cipher,
                            },
                        )?);
                    }
                    job.progress(index as u64 * 8388608, 0);
                    input.bridge.ack()?;
                }
                17 => {
                    let event = strict(&data, 4096)?;
                    let version = string(&event, "version")?;
                    let draft = file.take().ok_or(Error("INCOMPLETE_FILE"))?;
                    let request = self.vault.file_request(cap, &draft)?;
                    let upload = string(&request, "upload_id")?;
                    let status = self.file_response(cap, FileOperation::Status { upload })?;
                    let receipt = if status["state"] == "COMMITTED" {
                        status["receipt"].clone()
                    } else {
                        let finished = self.vault.file_finish(cap, &draft, &acknowledgements)?;
                        self.file_response(
                            cap,
                            FileOperation::Commit {
                                upload,
                                body: &finished["request"],
                            },
                        )?
                    };
                    self.vault.file_committed(cap, &draft, &receipt)?;
                    self.file_reference(cap, &group, string(&receipt, "file_version_id")?)?;
                    let pos = input.state["files"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .position(|f| f["source_version"] == version)
                        .ok_or(Error("INTEGRITY_FAILURE"))?;
                    if input.state["files"][pos]["attached"] != true {
                        self.attach_uploaded_file(
                            cap,
                            &group,
                            string(&receipt, "file_version_id")?,
                            &draft,
                            "Recovered file",
                        )?;
                        input.state["files"][pos]["attached"] = json!(true);
                        self.save_native_job(cap, &iid, &input.state)?;
                    }
                    input.bridge.ack()?;
                }
                18 => break,
                _ => return Err(Error("INVALID_BRIDGE_FRAME")),
            }
        }
        // Files are attached immediately. Notes publish after the complete recovery pass,
        // so source archive order cannot turn an entry into an orphan destination object.
        for kind in ["group-metadata", "thread", "entry"] {
            let len = input.state["notes"].as_array().unwrap().len();
            for n in 0..len {
                job.check(self.current())?;
                let note = input.state["notes"][n].clone();
                let c = &note["source_context"];
                if c["object_kind"] != kind || note["complete"] == true {
                    continue;
                }
                if kind == "group-metadata" {
                    input.state["notes"][n]["complete"] = json!(true);
                    self.save_native_job(cap, &iid, &input.state)?;
                    continue;
                }
                let thread = if kind == "entry" {
                    input.state["notes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|t| {
                            t["source_context"]["object_kind"] == "thread"
                                && t["source_context"]["object_id"] == c["thread_id"]
                                && t["source_context"]["group_id"] == c["group_id"]
                        })
                        .and_then(|t| t["object_id"].as_str())
                        .map(str::to_owned)
                        .ok_or(Error("IMPORT_THREAD_UNAVAILABLE"))?
                } else {
                    String::new()
                };
                if note["draft_id"].is_null() {
                    let mut content = note["payload"].clone();
                    content["summary_entry_id"] = Value::Null;
                    content["preferences"] = json!([]);
                    let edit = Self::edit(
                        &group,
                        kind,
                        note["object_id"].as_str(),
                        if kind == "entry" { Some(&thread) } else { None },
                        &content,
                        json!([]),
                        "create",
                    );
                    let saved = self.notes(cap, json!({"action":"save","edit":edit}))?;
                    input.state["notes"][n]["draft_id"] = saved["draft_id"].clone();
                    self.save_native_job(cap, &iid, &input.state)?;
                }
                self.publish(cap, string(&input.state["notes"][n], "draft_id")?)?;
                input.state["notes"][n]["complete"] = json!(true);
                wipe(&mut input.state["notes"][n]["payload"]);
                self.save_native_job(cap, &iid, &input.state)?;
            }
        }
        input.state["state"] = json!("COMPLETE");
        self.save_native_job(cap, &iid, &input.state)?;
        Ok(json!({"import_id":iid,"state":"COMPLETE","group_id":group}))
    }
    fn file_response(&self, cap: &Capability, operation: FileOperation<'_>) -> Result<Value> {
        let response =
            self.vault
                .file_http(cap, &self.profile.credential_id, &self.adapter, operation)?;
        check((200..300).contains(&response.status), "API_DENIED")?;
        strict(&response.bytes, 1048576)
    }
}
