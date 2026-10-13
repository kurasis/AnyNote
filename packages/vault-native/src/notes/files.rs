//! Host-selected handles only; renderer never supplies an arbitrary path or receives keys.
use super::*;
use anynote_crypto_core::files::{FileReader, FileWriter};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write as IoWrite};

pub const CHUNK: usize = 8388608;
pub struct Network<'a> {
    pub credential_id: &'a str,
    pub adapter: &'a anynote_auth_native::Adapter,
}
pub struct SelectedSource<'a> {
    pub group: &'a str,
    pub file: &'a mut File,
    pub name: &'a str,
    pub media: &'a str,
    pub resume: Option<&'a str>,
}
fn response(value: anynote_auth_native::FileResponse) -> Result<Value> {
    let parsed = strict(&value.bytes, 1048576)?;
    if value.status != 200 {
        return Err(Error(match parsed["error"]["code"].as_str() {
            Some("NOT_FOUND") => "NOT_FOUND",
            Some("UPLOAD_EXPIRED") => "UPLOAD_EXPIRED",
            Some("REKEY_RESTART_REQUIRED") => "REKEY_RESTART_REQUIRED",
            Some("QUOTA_EXCEEDED") => "QUOTA_EXCEEDED",
            Some("DEVICE_REVOKED") => "DEVICE_REVOKED",
            Some("ROLE_FORBIDDEN") => "ROLE_FORBIDDEN",
            Some("ROSTER_CHANGED") => "ROSTER_CHANGED",
            Some("POLICY_CHANGED") => "POLICY_CHANGED",
            Some("STALE_REVISION") => "STALE_REVISION",
            Some("IDEMPOTENCY_MISMATCH") => "IDEMPOTENCY_MISMATCH",
            Some("INSUFFICIENT_STORAGE") => "INSUFFICIENT_STORAGE",
            _ => "FILE_TRANSPORT_DENIED",
        }));
    }
    Ok(parsed)
}
pub(crate) fn control_id(scope: &Scope) -> Result<String> {
    Ok(b64(&libsodium_rs::crypto_generichash::hash(
        &canonical(&json!({"purpose":"AnyNote/P12/file-control","scope":scope}))?,
        16,
    )))
}
fn identity(file: &mut File, signal: &LockSignal, generation: u64) -> Result<Value> {
    let before = file.metadata().map_err(|_| Error("SOURCE_CHANGED"))?;
    let size = before.len();
    let modified = before.modified().map_err(|_| Error("SOURCE_CHANGED"))?;
    check(size <= 1000000000, "RESOURCE_LIMIT")?;
    let mut digest = Sha256::new();
    let mut parts = Vec::new();
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK]);
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error("SOURCE_CHANGED"))?;
    let mut left = size;
    while left > 0 {
        check(signal.generation() == generation, "STALE_CAPABILITY")?;
        let n = left.min(CHUNK as u64) as usize;
        file.read_exact(&mut buffer[..n])
            .map_err(|_| Error("SOURCE_CHANGED"))?;
        digest.update(&buffer[..n]);
        parts.push(hash(&buffer[..n]));
        left -= n as u64;
    }
    check(
        file.metadata().map_err(|_| Error("SOURCE_CHANGED"))?.len() == size
            && file
                .metadata()
                .map_err(|_| Error("SOURCE_CHANGED"))?
                .modified()
                .map_err(|_| Error("SOURCE_CHANGED"))?
                == modified,
        "SOURCE_CHANGED",
    )?;
    Ok(json!({"size":size,"parts":parts,"digest":b64(&digest.finalize())}))
}
impl Vault {
    pub fn file_copy_preview(
        &self,
        cap: &Capability,
        draft: &str,
        destination_group: &str,
    ) -> Result<Value> {
        self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let control = self.file_control(&i, &s)?;
        let (reference, mut data) = self.file_read(&i, &s, &control, draft)?;
        let result = (|| {
            let (_, policy, _key) = self.file_authority(&mut i, &s, destination_group)?;
            let notes = self.note_control(&i.conn, &s, &i.secrets.as_ref().unwrap().key)?;
            let snapshot = self.snapshot_for_groups(&mut i, &s)?;
            let (_, _, info) = self.note_info(&mut i, &s, &notes, &snapshot, destination_group)?;
            let audience = if info["members"].is_array() {
                info["members"].clone()
            } else {
                json!([{"account_id":self.scope.account_id,"root_fingerprint":s.pins["root_fingerprint"],"role":"owner"}])
            };
            let preview = json!({"source_group":reference["group_id"],"source_version":data["context"]["file_version_id"],"destination_group":destination_group,"audience":audience,"policy":policy,"scope":"selected-file-only-with-fresh-encryption"});
            Ok(json!({"digest":hash(&canonical(&preview)?),"preview":preview}))
        })();
        wipe_value(&mut data);
        result
    }
    pub fn copy_selected_file(
        &self,
        cap: &Capability,
        draft: &str,
        destination_group: &str,
        source: &mut File,
        preview_digest: &str,
        confirmed: bool,
    ) -> Result<Value> {
        check(confirmed, "COPY_CONFIRMATION_REQUIRED")?;
        let preview = self.file_copy_preview(cap, draft, destination_group)?;
        check(
            preview["digest"] == preview_digest,
            "COPY_CONFIRMATION_REQUIRED",
        )?;
        let proven = identity(source, &self.signal, cap.generation)?;
        let mut data = {
            let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
            let s = self.authorize(&mut i, cap)?;
            let control = self.file_control(&i, &s)?;
            self.file_read(&i, &s, &control, draft)?.1
        };
        let result = (|| {
            check(proven == data["source"], "SOURCE_CHANGED")?;
            let current = self.file_copy_preview(cap, draft, destination_group)?;
            check(
                current["digest"] == preview_digest,
                "COPY_CONFIRMATION_REQUIRED",
            )?;
            self.prepare_file_bound(
                cap,
                destination_group,
                source,
                text(&data["name"])?,
                text(&data["media"])?,
                Some(&preview["preview"]["policy"]),
            )
        })();
        wipe_value(&mut data);
        result
    }
    /// Trusted host dialog result only. No renderer command accepts this path.
    pub fn atomic_export_file(
        &self,
        cap: &Capability,
        record: &Value,
        parts: &mut dyn Iterator<Item = Result<Vec<u8>>>,
        destination: &std::path::Path,
        overwrite: bool,
    ) -> Result<Value> {
        let parent = destination.parent().ok_or(Error("INVALID_FILENAME"))?;
        check(
            destination.is_absolute() && parent.is_dir() && destination.file_name().is_some(),
            "INVALID_FILENAME",
        )?;
        check(
            overwrite || !destination.exists(),
            "EXPORT_DESTINATION_EXISTS",
        )?;
        let temporary = parent.join(format!(".anynote-export-{}.incomplete", random_id()));
        let result = (|| {
            let mut sink = std::fs::OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&temporary)
                .map_err(|_| Error("INSUFFICIENT_STORAGE"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
                    .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
            }
            let result = self.export_file(cap, record, parts, &mut sink)?;
            drop(sink);
            check(
                self.signal.generation() == cap.generation,
                "STALE_CAPABILITY",
            )?;
            if !overwrite {
                std::fs::hard_link(&temporary, destination)
                    .map_err(|_| Error("EXPORT_DESTINATION_EXISTS"))?;
                std::fs::remove_file(&temporary).map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
            } else {
                #[cfg(windows)]
                {
                    use std::os::windows::ffi::OsStrExt;
                    use windows_sys::Win32::Storage::FileSystem::{
                        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
                    };
                    let source: Vec<u16> =
                        temporary.as_os_str().encode_wide().chain(Some(0)).collect();
                    let target: Vec<u16> = destination
                        .as_os_str()
                        .encode_wide()
                        .chain(Some(0))
                        .collect();
                    // SAFETY: owned NUL-terminated buffers remain live for the synchronous call.
                    check(
                        unsafe {
                            MoveFileExW(
                                source.as_ptr(),
                                target.as_ptr(),
                                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                            )
                        } != 0,
                        "STORAGE_UNAVAILABLE",
                    )?;
                }
                #[cfg(not(windows))]
                std::fs::rename(&temporary, destination)
                    .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
            }
            #[cfg(unix)]
            File::open(parent)
                .map_err(|_| Error("STORAGE_UNAVAILABLE"))?
                .sync_all()
                .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
            Ok(result)
        })();
        if temporary.exists() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }
    pub fn file_request(&self, cap: &Capability, draft: &str) -> Result<Value> {
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let control = self.file_control(&i, &s)?;
        let (_, mut data) = self.file_read(&i, &s, &control, draft)?;
        let result = json!({"version":1,"upload_id":data["upload_id"],"context":data["context"],"plaintext_bytes":data["source"]["size"].as_u64().ok_or(Error("INTEGRITY_FAILURE"))?.to_string()});
        wipe_value(&mut data);
        Ok(result)
    }
    pub fn reselect_file(&self, cap: &Capability, draft: &str, source: &mut File) -> Result<()> {
        let proven = identity(source, &self.signal, cap.generation)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let control = self.file_control(&i, &s)?;
        let (_, mut data) = self.file_read(&i, &s, &control, draft)?;
        let result = (|| {
            let (_, policy, _) =
                self.file_authority(&mut i, &s, text(&data["context"]["group_id"])?)?;
            check(
                policy == data["context"]["policy"],
                "REKEY_RESTART_REQUIRED",
            )?;
            check(proven == data["source"], "SOURCE_CHANGED")
        })();
        wipe_value(&mut data);
        result
    }
    pub fn upload_file(
        &self,
        cap: &Capability,
        network: Network<'_>,
        selected: SelectedSource<'_>,
    ) -> Result<Value> {
        use anynote_auth_native::FileOperation;
        let draft = if let Some(draft) = selected.resume {
            draft.to_owned()
        } else {
            text(
                &self.prepare_file(
                    cap,
                    selected.group,
                    selected.file,
                    selected.name,
                    selected.media,
                )?["draft_id"],
            )?
            .to_owned()
        };
        let request = self.file_request(cap, &draft)?;
        check(
            request["context"]["group_id"] == selected.group,
            "CONTEXT_MISMATCH",
        )?;
        let upload = text(&request["upload_id"])?;
        let status_response = self.file_http(
            cap,
            network.credential_id,
            network.adapter,
            FileOperation::Status { upload },
        )?;
        let status = if status_response.status == 404 {
            response(self.file_http(
                cap,
                network.credential_id,
                network.adapter,
                FileOperation::Reserve {
                    group: selected.group,
                    body: &request,
                },
            )?)?
        } else {
            response(status_response)?
        };
        check(
            status["upload_id"] == upload
                && status["group_id"] == selected.group
                && status["file_version_id"] == request["context"]["file_version_id"],
            "CONTEXT_MISMATCH",
        )?;
        if status["state"] == "COMMITTED" {
            self.file_committed(cap, &draft, &status["receipt"])?;
            return Ok(json!({"draft_id":draft,"receipt":status["receipt"]}));
        }
        check(
            status["state"] != "EXPIRED" && status["state"] != "CANCELLED",
            "UPLOAD_EXPIRED",
        )?;
        let transfer = self
            .file_transfers(cap)?
            .as_array()
            .ok_or(Error("INTEGRITY_FAILURE"))?
            .iter()
            .find(|t| t["draft_id"] == draft)
            .cloned()
            .ok_or(Error("TRANSFER_NOT_FOUND"))?;
        let mut acknowledged = Vec::new();
        if transfer["state"] != "COMMIT_UNKNOWN" {
            self.reselect_file(cap, &draft, selected.file)?;
            for index in 0..selected
                .file
                .metadata()
                .map_err(|_| Error("SOURCE_CHANGED"))?
                .len()
                .div_ceil(CHUNK as u64)
            {
                let cipher = self.file_part(cap, &draft, selected.file, index as usize)?;
                acknowledged.push(response(self.file_http(
                    cap,
                    network.credential_id,
                    network.adapter,
                    FileOperation::Part {
                        upload,
                        index: index as u8,
                        ciphertext: &cipher,
                    },
                )?)?);
            }
        }
        let finished = self.file_finish(cap, &draft, &acknowledged)?;
        let receipt = response(self.file_http(
            cap,
            network.credential_id,
            network.adapter,
            FileOperation::Commit {
                upload,
                body: &finished["request"],
            },
        )?)?;
        self.file_committed(cap, &draft, &receipt)?;
        Ok(json!({"draft_id":draft,"receipt":receipt}))
    }
    pub fn download_file(
        &self,
        cap: &Capability,
        network: Network<'_>,
        group: &str,
        version: &str,
        sink: &mut File,
    ) -> Result<Value> {
        use anynote_auth_native::FileOperation;
        let record = response(self.file_http(
            cap,
            network.credential_id,
            network.adapter,
            FileOperation::Manifest { version },
        )?)?;
        check(
            record["envelope"]["header"]["context"]["group_id"] == group
                && record["envelope"]["header"]["context"]["file_version_id"] == version,
            "CONTEXT_MISMATCH",
        )?;
        self.observe_file(cap, group, version, &record)?;
        let count = text(&record["envelope"]["header"]["framing"]["chunk_count"])?
            .parse::<u8>()
            .map_err(|_| Error("INTEGRITY_FAILURE"))?;
        let cache = super::file_cache::CipherCache::for_vault(self).ok();
        let mut cache_job = cache
            .as_ref()
            .and_then(|c| c.begin(&self.codec, &record).ok());
        let mut parts = (0..count).map(|index| {
            let response = self.file_http(
                cap,
                network.credential_id,
                network.adapter,
                FileOperation::Chunk { version, index },
            )?;
            check(response.status == 200, "FILE_TRANSPORT_DENIED")?;
            if let (Some(cache), Some(job)) = (&cache, &mut cache_job)
                && cache.put(job, index as usize, &response.bytes).is_err()
            {
                cache_job = None;
            }
            Ok(response.bytes)
        });
        let result = self.export_file(cap, &record, &mut parts, sink)?;
        drop(parts);
        if let (Some(cache), Some(job)) = (&cache, &mut cache_job) {
            let _ = cache.finish(job);
        }
        Ok(result)
    }
    pub fn file_http(
        &self,
        cap: &Capability,
        credential_id: &str,
        adapter: &anynote_auth_native::Adapter,
        operation: anynote_auth_native::FileOperation<'_>,
    ) -> Result<anynote_auth_native::FileResponse> {
        check(valid_id(credential_id), "INVALID_SESSION")?;
        let credentials = {
            let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
            let s = self.authorize(&mut i, cap)?;
            check(s.rotation.is_none(), "REAUTH_REQUIRED")?;
            let f = frame(&i.conn, credential_id)?;
            let mut p = objects::open_local(
                &self.codec,
                &canonical(&f)?,
                &i.secrets.as_ref().unwrap().key,
                &canonical(&self.context("session", credential_id)?)?,
            )?;
            let result = anynote_auth_native::Credentials {
                access: Zeroizing::new(text(&p["data"]["access_credential"])?.into()),
                refresh: Zeroizing::new(text(&p["data"]["refresh_credential"])?.into()),
                session_id: text(&p["data"]["session_id"])?.into(),
                state: "trusted".into(),
            };
            wipe_value(&mut p);
            result
        };
        let result = adapter
            .file(&credentials, operation)
            .map_err(|_| Error("FILE_TRANSPORT_UNAVAILABLE"))?;
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        self.authorize(&mut i, cap)?;
        Ok(result)
    }
    pub(super) fn file_control(&self, i: &Inner, s: &State) -> Result<Value> {
        let id = control_id(&self.scope)?;
        let exists: bool = db(i.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE id=?1)",
            [&id],
            |r| r.get(0),
        ))?;
        if !exists {
            return Ok(json!({"purpose":"p12-file-control","version":1,"id":id,"transfers":[]}));
        }
        let value = paged_local::open(
            &self.codec,
            &i.conn,
            &self.scope,
            &s.pins,
            (&id, "file-control"),
            &frame(&i.conn, &id)?,
            &i.secrets.as_ref().ok_or(Error("VAULT_LOCKED"))?.key,
        )?;
        check(
            value["id"] == id && values(&value, "transfers")?.len() <= 512,
            "INTEGRITY_FAILURE",
        )?;
        self.codec.validate("p12-files", "file-control", &value)?;
        Ok(value)
    }
    pub(super) fn file_read(
        &self,
        i: &Inner,
        s: &State,
        control: &Value,
        draft: &str,
    ) -> Result<(Value, Value)> {
        let reference = find(control, "transfers", "draft_id", draft)?;
        let id = text(&reference["record_id"])?;
        let data = paged_local::open(
            &self.codec,
            &i.conn,
            &self.scope,
            &s.pins,
            (id, "file-transfer"),
            &frame(&i.conn, id)?,
            &i.secrets.as_ref().ok_or(Error("VAULT_LOCKED"))?.key,
        )?;
        check(
            data["draft_id"] == draft && data["context"]["group_id"] == reference["group_id"],
            "LOCAL_CONTEXT_MISMATCH",
        )?;
        self.codec.validate("p12-files", "file-transfer", &data)?;
        Ok((reference, data))
    }
    fn file_authority(
        &self,
        i: &mut Inner,
        s: &State,
        group: &str,
    ) -> Result<(Value, Value, Zeroizing<Vec<u8>>)> {
        let notes = self.note_control(
            &i.conn,
            s,
            &i.secrets.as_ref().ok_or(Error("VAULT_LOCKED"))?.key,
        )?;
        check(
            notes["sync"]["state"] != "RESTORE_QUARANTINE",
            "RESTORE_QUARANTINE",
        )?;
        let snapshot = self.snapshot_for_groups(i, s)?;
        let roster = Roster::replay(&self.codec, &snapshot, &s.pins, i.device_anchor.as_ref())?;
        let (reference, _, info) = self.note_info(i, s, &notes, &snapshot, group)?;
        writable(
            &reference,
            &info,
            &roster,
            &self.scope,
            &i.secrets.as_ref().unwrap().signing,
        )?;
        Ok((
            author(&roster, &self.scope, &i.secrets.as_ref().unwrap().signing)?,
            policy(&info),
            self.note_key(i, s, group, &info)?,
        ))
    }
    fn file_write(
        &self,
        i: &mut Inner,
        cap: &Capability,
        before: &State,
        control: &Value,
        reference: &Value,
        data: &Value,
    ) -> Result<()> {
        check(
            values(control, "transfers")?.len() <= 512 && canonical(data)?.len() <= 262144,
            "RESOURCE_LIMIT",
        )?;
        let kind = if data["purpose"] == "p12-file-evidence" {
            "file-evidence"
        } else {
            "file-transfer"
        };
        self.codec.validate("p12-files", "file-control", control)?;
        self.codec.validate("p12-files", kind, data)?;
        let key = Zeroizing::new(
            i.secrets
                .as_ref()
                .ok_or(Error("VAULT_LOCKED"))?
                .key
                .to_vec(),
        );
        let signing = Zeroizing::new(
            i.secrets
                .as_ref()
                .ok_or(Error("VAULT_LOCKED"))?
                .signing
                .to_vec(),
        );
        let roots = [
            (text(&reference["record_id"])?, kind, data),
            (text(&control["id"])?, "file-control", control),
        ];
        self.fence(
            before,
            before.lease.as_ref().ok_or(Error("STALE_WRITER"))?.fence,
        )?;
        let tx = db(i
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut current = state(&tx, &self.codec, &self.scope)?;
        check(
            current.epoch == before.epoch
                && current.revision == before.revision
                && self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        for (id, kind, value) in roots {
            let exists: bool = db(tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM records WHERE id=?1)",
                [id],
                |r| r.get(0),
            ))?;
            if exists {
                let old = frame(&tx, id)?;
                let mut manifest = paged_local::manifest(
                    &self.codec,
                    &self.scope,
                    &current.pins,
                    id,
                    kind,
                    &old,
                    &key,
                )?;
                for p in values(&manifest, "parts")? {
                    db(tx.execute("DELETE FROM records WHERE id=?1", [text(&p["record_id"])?]))?;
                }
                wipe_value(&mut manifest);
            }
            let (root, parts) = paged_local::prepare(
                &self.codec,
                &self.scope,
                &current.pins,
                id,
                kind,
                value,
                &key,
            )?;
            for (part, bytes) in parts {
                db(tx.execute("INSERT INTO records VALUES(?1,?2)", params![part, bytes]))?;
            }
            db(tx.execute("INSERT INTO records VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET frame=excluded.frame",params![id,canonical(&root)?]))?;
        }
        self.fence(
            &current,
            before.lease.as_ref().ok_or(Error("STALE_WRITER"))?.fence,
        )?;
        current.file_profile = Some("p12-files-v1".into());
        let body = expected_manifest(&self.scope, &current);
        current.manifest = json!({"signature":anynote_crypto_core::crypto::sign(&manifest_input(&body)?,&signing)?,"body":body});
        current.revision += 1;
        put_state(&tx, &current)?;
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        db(tx.commit())?;
        i.observed_revision = current.revision;
        Ok(())
    }
    pub fn prepare_file(
        &self,
        cap: &Capability,
        group: &str,
        file: &mut File,
        name: &str,
        media: &str,
    ) -> Result<Value> {
        self.prepare_file_bound(cap, group, file, name, media, None)
    }
    fn prepare_file_bound(
        &self,
        cap: &Capability,
        group: &str,
        file: &mut File,
        name: &str,
        media: &str,
        expected_policy: Option<&Value>,
    ) -> Result<Value> {
        // Hash before selecting keys; each later read must match the encrypted commitment.
        {
            self.lease(cap)?;
            let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
            let s = self.authorize(&mut i, cap)?;
            self.file_authority(&mut i, &s, group)?;
        }
        let proof = identity(file, &self.signal, cap.generation)?;
        self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (author, policy, _key) = self.file_authority(&mut i, &s, group)?;
        check(
            expected_policy.is_none_or(|p| p == &policy),
            "COPY_CONFIRMATION_REQUIRED",
        )?;
        let context = json!({"contract":"p02-file-c1","protocol":"anynote","protocol_version":1,"service_id":self.scope.service_id,"group_id":group,"file_id":random_id(),"file_version_id":random_id(),"operation_id":random_id(),"author":author,"policy":policy,"parents":[],"file_format":"xchacha20poly1305-chunks-c1","manifest_schema":1});
        let writer = FileWriter::new(
            &self.codec,
            &canonical(&context)?,
            proof["size"].as_u64().ok_or(Error("RESOURCE_LIMIT"))?,
        )?;
        let draft = random_id();
        let reference = json!({"draft_id":draft,"record_id":random_id(),"group_id":group,"state":"NEEDS_SOURCE","file_version_id":context["file_version_id"]});
        let mut data = json!({"purpose":"p12-file-transfer","version":1,"draft_id":draft,"upload_id":random_id(),"context":context,"source":proof,"name":name,"media":media,"writer":writer.checkpoint(text(&proof["digest"])?)?,"acknowledged":[],"record":null,"receipt":null,"state":"NEEDS_SOURCE"});
        let mut control = self.file_control(&i, &s)?;
        list(&mut control, "transfers")?.push(reference.clone());
        let result = json!({"draft_id":draft,"request":{"version":1,"upload_id":data["upload_id"],"context":context,"plaintext_bytes":proof["size"].as_u64().unwrap().to_string()}});
        let saved = self.file_write(&mut i, cap, &s, &control, &reference, &data);
        wipe_value(&mut data);
        saved?;
        Ok(result)
    }
    pub fn file_part(
        &self,
        cap: &Capability,
        draft: &str,
        source: &mut File,
        index: usize,
    ) -> Result<Vec<u8>> {
        self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let mut control = self.file_control(&i, &s)?;
        let (mut reference, mut data) = self.file_read(&i, &s, &control, draft)?;
        let result = (|| {
            let (_, policy, _) = self.file_authority(&mut i, &s, text(&reference["group_id"])?)?;
            check(
                policy == data["context"]["policy"],
                "REKEY_RESTART_REQUIRED",
            )?;
            let size = data["source"]["size"]
                .as_u64()
                .ok_or(Error("INTEGRITY_FAILURE"))?;
            let next = data["writer"]["next"]
                .as_u64()
                .ok_or(Error("INTEGRITY_FAILURE"))? as usize;
            check(
                index <= next
                    && index < (size.div_ceil(CHUNK as u64) as usize)
                    && source
                        .metadata()
                        .map_err(|_| Error("SOURCE_CHANGED"))?
                        .len()
                        == size,
                "SOURCE_CHANGED",
            )?;
            let n = (size - index as u64 * CHUNK as u64).min(CHUNK as u64) as usize;
            let mut plain = Zeroizing::new(vec![0u8; n]);
            source
                .seek(SeekFrom::Start(index as u64 * CHUNK as u64))
                .map_err(|_| Error("SOURCE_CHANGED"))?;
            source
                .read_exact(&mut plain)
                .map_err(|_| Error("SOURCE_CHANGED"))?;
            check(
                hash(&plain) == data["source"]["parts"][index],
                "SOURCE_CHANGED",
            )?;
            let mut checkpoint = data["writer"].clone();
            checkpoint["next"] = json!(index);
            checkpoint["parts"]
                .as_array_mut()
                .ok_or(Error("INTEGRITY_FAILURE"))?
                .truncate(index);
            let mut writer = FileWriter::resume(&self.codec, &checkpoint)?;
            wipe_value(&mut checkpoint);
            let cipher = writer.encrypt_next(&plain)?;
            if index < next {
                check(
                    hash(&cipher) == data["writer"]["parts"][index]["ciphertext_digest"],
                    "INTEGRITY_FAILURE",
                )?;
            } else {
                data["writer"] = writer.checkpoint(text(&data["source"]["digest"])?)?;
                data["state"] = json!("UPLOADING");
                reference["state"] = json!("UPLOADING");
                let position = super::index(&control, "transfers", "draft_id", draft)?;
                control["transfers"][position] = reference.clone();
                self.file_write(&mut i, cap, &s, &control, &reference, &data)?;
            }
            check(
                self.signal.generation() == cap.generation,
                "STALE_CAPABILITY",
            )?;
            Ok(cipher)
        })();
        wipe_value(&mut data);
        result
    }
    pub fn file_finish(
        &self,
        cap: &Capability,
        draft: &str,
        acknowledged: &[Value],
    ) -> Result<Value> {
        self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let mut control = self.file_control(&i, &s)?;
        let (mut reference, mut data) = self.file_read(&i, &s, &control, draft)?;
        let result = (|| {
            let (_, policy, key) =
                self.file_authority(&mut i, &s, text(&reference["group_id"])?)?;
            check(
                policy == data["context"]["policy"],
                "REKEY_RESTART_REQUIRED",
            )?;
            if data["record"].is_null() {
                check(
                    data["writer"]["parts"]
                        .as_array()
                        .ok_or(Error("INTEGRITY_FAILURE"))?
                        == acknowledged,
                    "INCOMPLETE_FILE",
                )?;
                let writer = FileWriter::resume(&self.codec, &data["writer"])?;
                data["record"] = writer.finish(
                    &self.codec,
                    text(&data["name"])?,
                    text(&data["media"])?,
                    &key,
                    &i.secrets.as_ref().unwrap().signing,
                )?;
                data["state"] = json!("COMMIT_UNKNOWN");
                reference["state"] = json!("COMMIT_UNKNOWN");
                let pos = index(&control, "transfers", "draft_id", draft)?;
                control["transfers"][pos] = reference.clone();
                self.file_write(&mut i, cap, &s, &control, &reference, &data)?;
            }
            Ok(
                json!({"upload_id":data["upload_id"],"request":{"version":1,"record":data["record"]}}),
            )
        })();
        wipe_value(&mut data);
        result
    }
    pub fn file_committed(&self, cap: &Capability, draft: &str, receipt: &Value) -> Result<Value> {
        self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let mut control = self.file_control(&i, &s)?;
        let (mut reference, mut data) = self.file_read(&i, &s, &control, draft)?;
        let result = (|| {
            let c = &data["context"];
            check(
                !data["record"].is_null()
                    && receipt["state"] == "COMMITTED"
                    && receipt["upload_id"] == data["upload_id"]
                    && receipt["group_id"] == c["group_id"]
                    && receipt["file_id"] == c["file_id"]
                    && receipt["file_version_id"] == c["file_version_id"]
                    && receipt["operation_id"] == c["operation_id"]
                    && receipt["envelope_digest"]
                        == digest("p02-file-c1", "file-envelope", &data["record"]["envelope"])?,
                "CIPHERTEXT_MISMATCH",
            )?;
            check(
                data["receipt"].is_null() || data["receipt"] == *receipt,
                "IDEMPOTENCY_MISMATCH",
            )?;
            data["receipt"] = receipt.clone();
            data["state"] = json!("UNATTACHED");
            reference["state"] = json!("UNATTACHED");
            let pos = index(&control, "transfers", "draft_id", draft)?;
            control["transfers"][pos] = reference.clone();
            self.file_write(&mut i, cap, &s, &control, &reference, &data)?;
            Ok(json!({"state":"UNATTACHED"}))
        })();
        wipe_value(&mut data);
        result
    }
    pub fn file_transfers(&self, cap: &Capability) -> Result<Value> {
        self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        Ok(self.file_control(&i, &s)?["transfers"].clone())
    }
    /// Verified own-current manifest; historical/shared authority is checked by the caller's signed group workflow.
    pub fn observe_file(
        &self,
        cap: &Capability,
        group: &str,
        version: &str,
        record: &Value,
    ) -> Result<Value> {
        check(
            record["envelope"]["header"]["context"]["group_id"] == group
                && record["envelope"]["header"]["context"]["file_version_id"] == version,
            "CONTEXT_MISMATCH",
        )?;
        let _verified = self.file_reader(cap, record)?;
        self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let mut control = self.file_control(&i, &s)?;
        let digest = digest("p02-file-c1", "file-envelope", &record["envelope"])?;
        if control["witnesses"].is_null() {
            control["witnesses"] = json!([]);
        }
        if let Some(old) = values(&control, "witnesses")?
            .iter()
            .find(|w| w["file_version_id"] == version)
        {
            check(old["envelope_digest"] == digest, "ROLLBACK_QUARANTINE")?;
            return Ok(
                json!({"state":"VERIFIED","file_version_id":version,"envelope_digest":digest}),
            );
        }
        check(
            values(&control, "witnesses")?.len() < 1000,
            "RESOURCE_LIMIT",
        )?;
        let reference = json!({"record_id":random_id(),"group_id":group,"file_version_id":version,"envelope_digest":digest});
        list(&mut control, "witnesses")?.push(reference.clone());
        self.file_write(
            &mut i,
            cap,
            &s,
            &control,
            &reference,
            &json!({"purpose":"p12-file-evidence","version":1,"envelope":record["envelope"]}),
        )?;
        Ok(json!({"state":"VERIFIED","file_version_id":version,"envelope_digest":digest}))
    }
    pub(super) fn file_evidence(&self, i: &Inner, s: &State, witness: &Value) -> Result<Value> {
        let id = text(&witness["record_id"])?;
        let data = paged_local::open(
            &self.codec,
            &i.conn,
            &self.scope,
            &s.pins,
            (id, "file-evidence"),
            &frame(&i.conn, id)?,
            &i.secrets.as_ref().ok_or(Error("VAULT_LOCKED"))?.key,
        )?;
        self.codec.validate("p12-files", "file-evidence", &data)?;
        check(
            digest("p02-file-c1", "file-envelope", &data["envelope"])?
                == witness["envelope_digest"],
            "INTEGRITY_FAILURE",
        )?;
        Ok(data)
    }
    pub(super) fn file_reader(&self, cap: &Capability, record: &Value) -> Result<FileReader> {
        self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let c = &record["envelope"]["header"]["context"];
        let group = text(&c["group_id"])?;
        let notes = self.note_control(
            &i.conn,
            &s,
            &i.secrets.as_ref().ok_or(Error("VAULT_LOCKED"))?.key,
        )?;
        let snapshot = self.snapshot_for_groups(&mut i, &s)?;
        let (reference, _, info) = self.note_info(&mut i, &s, &notes, &snapshot, group)?;
        let public = if info["policy"].is_object() {
            let data = self.note_read(
                &mut i,
                &s,
                &notes,
                text(&reference["record_id"])?,
                "group-evidence",
            )?;
            let (proof, verified) = self.note_shared_proof(&mut i, &s, &notes, &snapshot, &data)?;
            let certificate =
                crate::shared::object_author(&self.codec, &proof, &verified, record, &self.scope)?;
            un64(text(&certificate["body"]["device_signing_key"])?)?
        } else {
            check(
                c["policy"] == policy(&info)
                    && c["author"]["account_id"] == self.scope.account_id
                    && c["author"]["root_fingerprint"] == s.pins["root_fingerprint"],
                "CONTEXT_MISMATCH",
            )?;
            let past = historical(&self.codec, &snapshot, &s.pins, &c["author"]["roster"])?;
            let certificate =
                past.active(text(&c["author"]["device_id"])?, Some("sign-content"))?;
            let current =
                Roster::replay(&self.codec, &snapshot, &s.pins, i.device_anchor.as_ref())?;
            let control = self.file_control(&i, &s)?;
            let known = values(&control, "transfers")?.iter().any(|t| {
                t["file_version_id"] == c["file_version_id"] && t["state"] == "UNATTACHED"
            });
            check(
                current
                    .devices
                    .get(text(&c["author"]["device_id"])?)
                    .is_some_and(|d| d.active)
                    || known,
                "UNANCHORED_HISTORY",
            )?;
            un64(text(
                &certificate.certificate["body"]["device_signing_key"],
            )?)?
        };
        let mut key_info = info.clone();
        key_info["policy"] = c["policy"].clone();
        key_info["epoch_digest"] = c["policy"]["epoch_digest"].clone();
        let key = self.note_key(&i, &s, group, &key_info)?;
        if info["policy"].is_object() {
            let epoch = info["epochs"]
                .as_array()
                .ok_or(Error("KEYS_PENDING"))?
                .iter()
                .find(|e| e["key_epoch"] == c["policy"]["key_epoch"])
                .ok_or(Error("KEYS_PENDING"))?;
            check(
                crate::device_groups::key_commitment(
                    &json!({"service_id":self.scope.service_id,"group_id":group}),
                    &key,
                )? == epoch["key_commitment"],
                "KEY_REPAIR_REQUIRED",
            )?;
        }
        let reader = FileReader::open(
            &self.codec,
            &canonical(record)?,
            &key,
            &public,
            &canonical(c)?,
        )?;
        Ok(reader)
    }
    pub fn export_file(
        &self,
        cap: &Capability,
        record: &Value,
        parts: &mut dyn Iterator<Item = Result<Vec<u8>>>,
        sink: &mut File,
    ) -> Result<Value> {
        let mut reader = self.file_reader(cap, record)?;
        for cipher in parts {
            check(
                self.signal.generation() == cap.generation,
                "STALE_CAPABILITY",
            )?;
            let plain = Zeroizing::new(reader.decrypt_next(&cipher?)?);
            check(
                self.signal.generation() == cap.generation,
                "STALE_CAPABILITY",
            )?;
            sink.write_all(&plain)
                .map_err(|_| Error("INSUFFICIENT_STORAGE"))?;
        }
        reader.finish()?;
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        sink.sync_all().map_err(|_| Error("INSUFFICIENT_STORAGE"))?;
        Ok(
            json!({"complete":true,"plaintext_bytes":record["envelope"]["header"]["framing"]["plaintext_bytes"]}),
        )
    }
}
