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
use anynote_local_vault::{Capability, Record};
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
fn recovered_part_bytes(
    source: &mut Source,
    bridge: &mut Bridge,
    expected: u64,
    mut authorize: impl FnMut() -> Result<()>,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    loop {
        authorize()?;
        let (kind, bytes) = bridge.receive()?;
        if kind == 13 {
            // The authenticated reader may prefetch archive input while its
            // visitor sends this plaintext part. Service only that bounded
            // selected-source request; it is not part of the plaintext frame.
            feed(source, bridge, &bytes)?;
            continue;
        }
        check(
            kind == 3 && bytes.len() as u64 == expected,
            "INVALID_BRIDGE_FRAME",
        )?;
        return Ok(bytes);
    }
}
impl Host {
    /// Each selected note has an independently protected payload. The small root journal
    /// contains aliases and receipts only, so total archive plaintext is never materialized.
    fn import_payload_id(import: &str, revision: &str) -> Result<String> {
        let mut bytes = b"AnyNote/P14/import-note\0".to_vec();
        bytes.extend(canonical(&json!([id(import)?, id(revision)?]))?);
        Ok(anynote_crypto_core::crypto::b64(
            &anynote_crypto_core::crypto::un64(&hash(&bytes))?[..16],
        ))
    }
    fn store_import_payload(
        &self,
        cap: &Capability,
        import: &str,
        revision: &str,
        payload: &Value,
    ) -> Result<String> {
        let record_id = Self::import_payload_id(import, revision)?;
        let data = json!({"purpose":"p14-import-note","version":1,"import_id":import,"source_revision":revision,"payload":payload});
        for _ in 0..16 {
            let previous = self.vault.content_read(cap, &record_id, "import-state")?;
            if let Some(mut stored) = previous.data {
                let same = stored == data;
                wipe(&mut stored);
                check(same, "IDEMPOTENCY_MISMATCH")?;
                return Ok(record_id);
            }
            let result = self.vault.content_commit(
                cap,
                previous.revision,
                &[Record {
                    id: record_id.clone(),
                    kind: "import-state".into(),
                    data: data.clone(),
                }],
                &[],
            );
            match result {
                Ok(()) => return Ok(record_id),
                Err(Error("STALE_WRITER")) => (),
                Err(e) => return Err(e),
            }
        }
        Err(Error("STALE_WRITER"))
    }
    fn load_import_payload(&self, cap: &Capability, import: &str, note: &Value) -> Result<Value> {
        // Read older in-progress development journals without replacing their stable aliases.
        if note["payload"].is_object() {
            return Ok(note["payload"].clone());
        }
        let revision = string(note, "source_revision")?;
        let record_id = Self::import_payload_id(import, revision)?;
        check(note["payload_id"] == record_id, "INTEGRITY_FAILURE")?;
        let mut record = self
            .vault
            .content_read(cap, &record_id, "import-state")?
            .data
            .ok_or(Error("INTEGRITY_FAILURE"))?;
        check(
            record["purpose"] == "p14-import-note"
                && record["import_id"] == import
                && record["source_revision"] == revision,
            "INTEGRITY_FAILURE",
        )?;
        let payload = record["payload"].take();
        wipe(&mut record);
        Ok(payload)
    }
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
        if input.state["group_request"].is_object()
            && input.state["destination_metadata_published"] != true
        {
            if input.state["destination_metadata_draft"].is_null() {
                let summary = self.notes(cap, json!({"action":"summary"}))?;
                let existing = summary["drafts"]
                    .as_array()
                    .ok_or(Error("INTEGRITY_FAILURE"))?
                    .iter()
                    .find(|d| {
                        d["group_id"] == group
                            && d["object_id"] == group
                            && d["object_kind"] == "group-metadata"
                    });
                let draft = if let Some(existing) = existing {
                    existing["draft_id"].clone()
                } else {
                    let export = string(&input.state, "export_id")?;
                    let content = json!({"title":format!("Recovered archive {}",&export[..8.min(export.len())]),"markdown":"","metadata_kind":"content","tags":[],"checklist":[],"summary_entry_id":null,"preferences":[]});
                    self.notes(cap,json!({"action":"save","edit":Self::edit(&group,"group-metadata",Some(&group),None,&content,json!([]),"create")}))?["draft_id"].clone()
                };
                input.state["destination_metadata_draft"] = draft;
                self.save_native_job(cap, &iid, &input.state)?;
            }
            self.publish(cap, string(&input.state, "destination_metadata_draft")?)?;
            input.state["destination_metadata_published"] = json!(true);
            self.save_native_job(cap, &iid, &input.state)?;
        }
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
                    if event["payload"]["metadata_kind"] != "account-preferences"
                        && input.state["selected_notes"]
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
                        let payload_id =
                            self.store_import_payload(cap, &iid, &revision, &event["payload"])?;
                        input.state["notes"].as_array_mut().unwrap().push(json!({"source_revision":revision,"source_context":event["payload"]["context"],"payload_id":payload_id,"object_id":random_id(),"draft_id":null,"complete":false}));
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
                        input.state["files"].as_array_mut().unwrap().push(json!({"source_version":version,"draft_id":file,"attached":false,"attachment_draft":null,"reference":null}));
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
                        if !committed_file {
                            let old = file.as_ref().unwrap().clone();
                            let preview = self.vault.file_copy_preview(cap, &old, &group)?;
                            if matches!(status["state"].as_str(), Some("EXPIRED" | "CANCELLED"))
                                || preview["preview"]["policy"] != request["context"]["policy"]
                            {
                                // Reconcile the old immutable operation before preparing new
                                // IDs/DEKs. A committed operation is never burned or resent.
                                let closed = if matches!(
                                    status["state"].as_str(),
                                    Some("EXPIRED" | "CANCELLED")
                                ) {
                                    status
                                } else {
                                    self.file_response(cap, FileOperation::Cancel { upload })?
                                };
                                self.vault.burn_file_attempt(cap, &old, &closed, true)?;
                                let prepared = self.vault.prepare_recovered_file(
                                    cap,
                                    &group,
                                    &event["source"],
                                    string(&event["metadata"], "name")?,
                                    "application/octet-stream",
                                )?;
                                let pos = input.state["files"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .position(|f| f["source_version"] == version)
                                    .ok_or(Error("INTEGRITY_FAILURE"))?;
                                if !input.state["files"][pos]["superseded_drafts"].is_array() {
                                    input.state["files"][pos]["superseded_drafts"] = json!([]);
                                }
                                input.state["files"][pos]["superseded_drafts"]
                                    .as_array_mut()
                                    .unwrap()
                                    .push(json!(old));
                                input.state["files"][pos]["draft_id"] =
                                    prepared["draft_id"].clone();
                                file = Some(string(&prepared, "draft_id")?.to_owned());
                                self.save_native_job(cap, &iid, &input.state)?;
                                let request =
                                    self.vault.file_request(cap, file.as_deref().unwrap())?;
                                self.file_response(
                                    cap,
                                    FileOperation::Reserve {
                                        group: &group,
                                        body: &request,
                                    },
                                )?;
                            }
                        }
                    }
                    input.bridge.ack()?;
                }
                16 => {
                    let meta = strict(&data, 4096)?;
                    let index = meta["index"]
                        .as_u64()
                        .ok_or(Error("INVALID_BRIDGE_FRAME"))?
                        as usize;
                    let plain = recovered_part_bytes(
                        &mut input.source,
                        &mut input.bridge,
                        meta["bytes"]
                            .as_u64()
                            .ok_or(Error("INVALID_BRIDGE_FRAME"))?,
                        || job.check(self.current()),
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
                    job.progress((index as u64 + 1) * 8388608, 0);
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
                    input.state["files"][pos]["reference"] =
                        self.file_reference(cap, &group, string(&receipt, "file_version_id")?)?;
                    self.save_native_job(cap, &iid, &input.state)?;
                    let referenced = input.report["notes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|note| {
                            input.state["selected_notes"]
                                .as_array()
                                .unwrap()
                                .contains(&note["context"]["revision_id"])
                                && note["context"]["attachments"].as_array().is_some_and(|a| {
                                    a.iter().any(|a| a["file_version_id"] == version)
                                })
                        });
                    if !referenced && input.state["files"][pos]["attached"] != true {
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
        // Pruned/deleted source threads must not strand retained entries. Persist one
        // stable placeholder alias and payload before publishing anything from that branch.
        let entries = input.state["notes"].as_array().unwrap().clone();
        for entry in entries
            .iter()
            .filter(|n| n["source_context"]["object_kind"] == "entry")
        {
            let context = &entry["source_context"];
            let exists = input.state["notes"].as_array().unwrap().iter().any(|n| {
                n["source_context"]["object_kind"] == "thread"
                    && n["source_context"]["object_id"] == context["thread_id"]
                    && n["source_context"]["group_id"] == context["group_id"]
            });
            if !exists {
                let revision = random_id();
                let payload = json!({"title":"Recovered thread","markdown":"","metadata_kind":"content","tags":[],"checklist":[],"summary_entry_id":null,"preferences":[]});
                let payload_id = self.store_import_payload(cap, &iid, &revision, &payload)?;
                input.state["notes"].as_array_mut().unwrap().push(json!({"source_revision":revision,"source_context":{"object_kind":"thread","object_id":context["thread_id"],"group_id":context["group_id"],"attachments":[]},"payload_id":payload_id,"object_id":random_id(),"draft_id":null,"complete":false}));
                self.save_native_job(cap, &iid, &input.state)?;
            }
        }
        // Keep each source group's metadata as a named thread instead of replacing
        // an existing destination's metadata or discarding multi-group provenance.
        for kind in ["group-metadata", "thread", "entry"] {
            let len = input.state["notes"].as_array().unwrap().len();
            for n in 0..len {
                job.check(self.current())?;
                let note = input.state["notes"][n].clone();
                let c = &note["source_context"];
                if c["object_kind"] != kind || note["complete"] == true {
                    continue;
                }
                let destination_kind = if kind == "group-metadata" {
                    "thread"
                } else {
                    kind
                };
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
                    // A saved draft may precede its journal acknowledgement after a crash.
                    // Reuse its immutable object alias instead of creating a second draft.
                    let drafts = self.notes(cap, json!({"action":"summary"}))?;
                    if let Some(existing) = drafts["drafts"]
                        .as_array()
                        .ok_or(Error("INTEGRITY_FAILURE"))?
                        .iter()
                        .find(|d| d["object_id"] == note["object_id"] && d["group_id"] == group)
                    {
                        input.state["notes"][n]["draft_id"] = existing["draft_id"].clone();
                        self.save_native_job(cap, &iid, &input.state)?;
                    } else {
                        let mut content = self.load_import_payload(cap, &iid, &note)?;
                        content["summary_entry_id"] = Value::Null;
                        content["preferences"] = json!([]);
                        let mut edit = Self::edit(
                            &group,
                            destination_kind,
                            note["object_id"].as_str(),
                            if kind == "entry" { Some(&thread) } else { None },
                            &content,
                            json!([]),
                            "create",
                        );
                        let mut attachments = Vec::new();
                        for source in c["attachments"].as_array().into_iter().flatten() {
                            let mapped = input.state["files"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .find(|f| f["source_version"] == source["file_version_id"])
                                .ok_or(Error("IMPORT_ATTACHMENT_UNAVAILABLE"))?;
                            check(
                                mapped["reference"].is_object(),
                                "IMPORT_ATTACHMENT_UNAVAILABLE",
                            )?;
                            attachments.push(mapped["reference"].clone());
                        }
                        attachments.sort_by_key(|a| {
                            format!(
                                "{}/{}",
                                a["file_id"].as_str().unwrap_or(""),
                                a["file_version_id"].as_str().unwrap_or("")
                            )
                        });
                        edit["attachments"] = json!(attachments);
                        edit["archived"] = json!(c["archived"] == true);
                        let saved = self.notes(cap, json!({"action":"save","edit":edit}))?;
                        input.state["notes"][n]["draft_id"] = saved["draft_id"].clone();
                        self.save_native_job(cap, &iid, &input.state)?;
                        wipe(&mut content);
                    }
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

#[cfg(test)]
#[allow(dead_code)]
mod payload_tests {
    include!("../../vault-native/tests/common/notes_fixture.rs");
    use crate::host::{Host, Profile, Service};
    #[test]
    fn archive_notes_exceed_one_record_without_plaintext_staging_or_cross_job_reuse() {
        let f = Fixture::new();
        let cap = f.vault.unlock_phrase(PHRASE).unwrap();
        let h = Host::from_parts(
            f.vault.path().parent().unwrap(),
            Profile {
                version: 1,
                scope: f.scope.clone(),
                credential_id: id(),
                service: Service {
                    issuer: "https://synthetic.example".into(),
                    app: "https://synthetic-app.example".into(),
                    pins: f.pins.clone(),
                },
            },
            f.vault.clone(),
            anynote_auth_native::Adapter::new(
                "https://synthetic.example",
                "https://synthetic-app.example",
            )
            .unwrap(),
        );
        let job = id();
        let mut root = json!({"notes":[]});
        for n in 0..12 {
            let revision = id();
            let payload = json!({"title":format!("SYNTHETIC private imported note {n}"),"markdown":"x".repeat(1500000)});
            let record = h
                .store_import_payload(&cap, &job, &revision, &payload)
                .unwrap();
            assert_eq!(
                h.store_import_payload(&cap, &job, &revision, &payload)
                    .unwrap(),
                record
            );
            root["notes"]
                .as_array_mut()
                .unwrap()
                .push(json!({"source_revision":revision,"payload_id":record}));
            assert_eq!(
                h.load_import_payload(&cap, &job, &root["notes"][n])
                    .unwrap(),
                payload
            );
        }
        assert!(canonical(&root).unwrap().len() < 4096);
        assert_eq!(
            h.load_import_payload(&cap, &id(), &root["notes"][0])
                .unwrap_err()
                .0,
            "INTEGRITY_FAILURE"
        );
        let row = &root["notes"][0];
        assert_eq!(
            h.store_import_payload(
                &cap,
                &job,
                row["source_revision"].as_str().unwrap(),
                &json!({"markdown":"tampered"})
            )
            .unwrap_err()
            .0,
            "IDEMPOTENCY_MISMATCH"
        );
        f.vault.lock_all().unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let path = std::path::PathBuf::from(format!("{}{}", f.vault.path().display(), suffix));
            if let Ok(bytes) = std::fs::read(path) {
                assert!(
                    !bytes
                        .windows(31)
                        .any(|w| w == b"SYNTHETIC private imported note ")
                );
            }
        }
    }
}

#[cfg(test)]
mod pipe_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};
    fn sha(path: &Path) -> String {
        anynote_crypto_core::crypto::b64(&Sha256::digest(std::fs::read(path).unwrap()))
    }
    #[test]
    fn pending_plaintext_services_only_bounded_archive_prefetch_and_rejects_other_frames() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let node = std::env::var_os("ANYNOTE_NATIVE_NODE")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("apps/desktop/src-tauri/resources/node.exe"));
        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("public-source.bin");
        let script = work.path().join("public-peer.mjs");
        std::fs::write(&source, b"PUBLIC_ARCHIVE_BYTES").unwrap();
        // Public synthetic peer forces a source read between metadata and data.
        // It never receives vault/archive keys or filesystem paths over the pipe.
        std::fs::write(&script, r#"import {write} from 'node:fs';
let buffered=Buffer.alloc(0),wake;process.stdin.on('data',b=>{buffered=Buffer.concat([buffered,b]);wake?.();});
async function frame(){for(;;){if(buffered.length>=8){const k=buffered.readUInt32BE(0),n=buffered.readUInt32BE(4);if(buffered.length>=n+8){const b=Buffer.from(buffered.subarray(8,8+n));buffered=buffered.subarray(8+n);return {k,b};}}await new Promise(r=>wake=r);}}
async function send(k,b){const h=Buffer.alloc(8);h.writeUInt32BE(k);h.writeUInt32BE(b.length,4);const v=Buffer.concat([h,b]);await new Promise((r,j)=>write(1,v,e=>e?j(e):r()));}
const mode=JSON.parse((await frame()).b).mode;
if(mode==='unexpected'){await send(7,Buffer.from('PUBLIC_OTHER'));}
else{await send(13,Buffer.from(JSON.stringify({offset:mode==='invalid-offset'?'21':'0',bytes:65536})));const source=await frame();if(source.k!==3||source.b.toString()!=='PUBLIC_ARCHIVE_BYTES')throw Error('PUBLIC_SOURCE_MISMATCH');await send(3,Buffer.from('PUBLIC_PART'));}
process.stdin.destroy();
"#).unwrap();
        let node_sha = sha(&node);
        let script_sha = sha(&script);
        let assets = Assets {
            node: &node,
            script: &script,
            node_sha: &node_sha,
            script_sha: &script_sha,
        };
        for (mode, succeeds, expected) in [
            ("interleave", true, 11),
            ("invalid-offset", false, 11),
            ("unexpected", false, 11),
            ("wrong-size", false, 12),
        ] {
            let mut input = Source::open(&source, 65536).unwrap();
            let mut bridge = Bridge::spawn(&assets, || false).unwrap();
            bridge.json(1, &json!({"mode":mode})).unwrap();
            let result = recovered_part_bytes(&mut input, &mut bridge, expected, || Ok(()));
            if succeeds {
                assert_eq!(&*result.unwrap(), b"PUBLIC_PART");
            } else {
                assert_eq!(result.unwrap_err().0, "INVALID_BRIDGE_FRAME");
            }
        }
    }
}
