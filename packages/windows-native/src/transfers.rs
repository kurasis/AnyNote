//! Real native selected-handle jobs; only counters cross the renderer boundary.
use crate::*;
use crate::{
    host::Host,
    selection::{Destination, Source},
};
use anynote_local_vault::notes::{
    file_cache::CipherCache,
    files::{Network, SelectedSource},
};
use std::{path::Path, sync::Arc};
impl Host {
    /// Stable encrypted publication state makes file attachment retry safe across ACK crashes.
    pub fn attach_uploaded_file(
        &self,
        cap: &anynote_local_vault::Capability,
        group: &str,
        version: &str,
        draft: &str,
        name: &str,
    ) -> Result<Value> {
        use anynote_local_vault::{Record, notes::NotesRequest};
        use serde_json::json;
        let id = anynote_crypto_core::crypto::b64(
            &anynote_crypto_core::crypto::un64(&anynote_crypto_core::crypto::hash(
                &anynote_crypto_core::codec::canonical(
                    &json!({"purpose":"AnyNote/P14/file-publication","scope":self.profile.scope,"draft_id":draft}),
                )?,
            ))?[..16],
        );
        let mut snapshot = self.vault.content_read(cap, &id, "import-state")?;
        let mut state=snapshot.data.take().unwrap_or(json!({"purpose":"p14-file-publication","version":1,"group_id":group,"file_version_id":version,"thread_id":null,"thread_draft":null,"entry_id":null,"entry_draft":null,"state":"READY"}));
        check(
            state["purpose"] == "p14-file-publication"
                && state["version"] == 1
                && state["group_id"] == group
                && state["file_version_id"] == version,
            "LOCAL_CONTEXT_MISMATCH",
        )?;
        if state["state"] == "COMPLETE" {
            return Ok(json!({"state":"COMPLETE","entry_id":state["entry_id"]}));
        }
        let save = |value: &Value, revision: u64| {
            self.vault.content_commit(
                cap,
                revision,
                &[Record {
                    id: id.clone(),
                    kind: "import-state".into(),
                    data: value.clone(),
                }],
                &[],
            )
        };
        let content = json!({"title":name,"markdown":"","metadata_kind":"content","tags":[],"checklist":[],"summary_entry_id":null,"preferences":[]});
        if state["thread_draft"].is_null() {
            let edit = Self::edit(group, "thread", None, None, &content, json!([]), "create");
            let saved = self.vault.notes_command(cap, NotesRequest::Save { edit })?;
            state["thread_draft"] = saved["draft_id"].clone();
            state["thread_id"] = saved["object_id"].clone();
            save(&state, snapshot.revision)?;
        }
        self.publish(cap, string(&state, "thread_draft")?)?;
        if state["entry_draft"].is_null() {
            let reference = self.file_reference(cap, group, version)?;
            let mut edit = Self::edit(
                group,
                "entry",
                None,
                Some(string(&state, "thread_id")?),
                &content,
                json!([]),
                "create",
            );
            edit["attachments"] = json!([reference]);
            let saved = self.vault.notes_command(cap, NotesRequest::Save { edit })?;
            state["entry_draft"] = saved["draft_id"].clone();
            state["entry_id"] = saved["object_id"].clone();
            save(
                &state,
                self.vault.content_read(cap, &id, "import-state")?.revision,
            )?;
        }
        self.publish(cap, string(&state, "entry_draft")?)?;
        state["state"] = json!("COMPLETE");
        save(
            &state,
            self.vault.content_read(cap, &id, "import-state")?.revision,
        )?;
        Ok(json!({"state":"COMPLETE","entry_id":state["entry_id"]}))
    }
    pub fn file_reference(
        &self,
        cap: &anynote_local_vault::Capability,
        group: &str,
        version: &str,
    ) -> Result<Value> {
        use anynote_auth_native::FileOperation;
        let response = self.vault.file_http(
            cap,
            &self.profile.credential_id,
            &self.adapter,
            FileOperation::Manifest { version },
        )?;
        check(response.status == 200, "API_DENIED")?;
        let record = anynote_crypto_core::codec::strict(&response.bytes, 1048576)?;
        self.vault.observe_file(cap, group, version, &record)?;
        let metadata = self.vault.file_metadata(cap, &record)?;
        let c = &record["envelope"]["header"]["context"];
        Ok(
            serde_json::json!({"file_id":c["file_id"],"file_version_id":version,"envelope_digest":metadata["envelope_digest"]}),
        )
    }
    pub fn start_upload(
        self: &Arc<Self>,
        g: u64,
        group: String,
        source: Source,
        resume: Option<String>,
    ) -> Result<String> {
        id(&group)?;
        if let Some(ref id) = resume {
            crate::id(id)?;
        }
        let cap = self.capability(g)?;
        let job = self.jobs.start(g)?;
        let jid = job.id.clone();
        let host = self.clone();
        std::thread::spawn(move || {
            let mut source = source;
            let result = (|| {
                host.prove(&cap)?;
                host.group(&cap, &group)?;
                job.check(host.current())?;
                source.check()?;
                let uploaded = host.vault.upload_file_with_progress(
                    &cap,
                    Network {
                        credential_id: &host.profile.credential_id,
                        adapter: &host.adapter,
                    },
                    SelectedSource {
                        group: &group,
                        file: &mut source.file,
                        name: &source.name,
                        media: "application/octet-stream",
                        resume: resume.as_deref(),
                    },
                    |bytes, total| {
                        job.check(host.current())?;
                        job.progress(bytes, total);
                        Ok(())
                    },
                )?;
                job.check(host.current())?;
                let receipt = &uploaded["receipt"];
                let attachment = host.attach_uploaded_file(
                    &cap,
                    &group,
                    string(receipt, "file_version_id")?,
                    string(&uploaded, "draft_id")?,
                    &source.name,
                )?;
                Ok(
                    serde_json::json!({"draft_id":uploaded["draft_id"],"receipt":receipt,"attachment_object_id":attachment["entry_id"]}),
                )
            })();
            job.finish(result);
        });
        Ok(jid)
    }
    pub fn start_download(
        self: &Arc<Self>,
        g: u64,
        group: String,
        version: String,
        path: &Path,
        offline: bool,
    ) -> Result<String> {
        id(&group)?;
        id(&version)?;
        let cap = self.capability(g)?;
        crate::selection::ensure_space(path, 1000000000)?;
        let mut destination = Destination::create(path)?;
        let job = self.jobs.start(g)?;
        let jid = job.id.clone();
        let host = self.clone();
        let output = path.to_owned();
        std::thread::spawn(move || {
            let result = (|| {
                job.check(host.current())?;
                if offline {
                    drop(destination);
                    CipherCache::for_vault(&host.vault)?.atomic_export(
                        &host.vault,
                        &cap,
                        &group,
                        &version,
                        &output,
                        false,
                    )?;
                } else {
                    host.prove(&cap)?;
                    host.group(&cap, &group)?;
                    let result = host.vault.download_file(
                        &cap,
                        Network {
                            credential_id: &host.profile.credential_id,
                            adapter: &host.adapter,
                        },
                        &group,
                        &version,
                        destination.writer()?,
                    )?;
                    job.check(host.current())?;
                    destination.finish()?;
                    return Ok(result);
                }
                Ok(serde_json::json!({"state":"COMPLETE"}))
            })();
            job.finish(result);
        });
        Ok(jid)
    }
    pub fn read_preview(&self, g: u64, group: &str, version: &str) -> Result<Vec<u8>> {
        use anynote_auth_native::FileOperation;
        let cap = self.capability(g)?;
        self.group(&cap, group)?;
        let response = self.vault.file_http(
            &cap,
            &self.profile.credential_id,
            &self.adapter,
            FileOperation::Manifest { version },
        )?;
        check(response.status == 200, "API_DENIED")?;
        let record = anynote_crypto_core::codec::strict(&response.bytes, 1048576)?;
        let metadata = self.vault.file_metadata(&cap, &record)?;
        let size = record["envelope"]["header"]["framing"]["plaintext_bytes"]
            .as_str()
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or(Error("INVALID_REQUEST"))?;
        check(size <= 16777216, "SAFE_DOWNLOAD_REQUIRED")?;
        let mut parts = (0..size.div_ceil(8388608)).map(|i| {
            self.vault
                .file_http(
                    &cap,
                    &self.profile.credential_id,
                    &self.adapter,
                    FileOperation::Chunk {
                        version,
                        index: i as u8,
                    },
                )
                .and_then(|r| {
                    check(r.status == 200, "API_DENIED")?;
                    Ok(r.bytes)
                })
        });
        let mut sink = Vec::with_capacity(size);
        let mut reader = self.vault.file_reader(&cap, &record)?;
        for part in &mut parts {
            check(self.current() == g, "STALE_CAPABILITY")?;
            let plain = zeroize::Zeroizing::new(reader.decrypt_next(&part?)?);
            sink.extend_from_slice(&plain);
        }
        reader.finish()?;
        let _ = metadata;
        check(self.current() == g, "STALE_CAPABILITY")?;
        Ok(sink)
    }
}
