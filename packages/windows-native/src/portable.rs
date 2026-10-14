//! Native standard-age jobs. Original frames/DEKs are sent only to the trusted bounded helper.
use crate::*;
use crate::{
    bridge::{Assets, Bridge},
    host::Host,
    jobs::Job,
    selection::Destination,
};
use anynote_auth_native::control::Route;
use anynote_crypto_core::{
    codec::{Codec, canonical, domain, strict},
    crypto::{b64, hash, un64},
};
use anynote_local_vault::{Capability, Record};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path, sync::Arc};
use zeroize::Zeroizing;
fn common(purpose: &str) -> Value {
    json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":purpose})
}
fn digest(kind: &str, v: &Value) -> Result<String> {
    Ok(hash(&domain("p02-v1", "hash", kind, &canonical(v)?)))
}
fn commitment(codec: &Codec, pages: &[Value], family: &str) -> Result<Value> {
    let total = pages
        .iter()
        .map(|p| p["items"].as_array().map_or(0, Vec::len))
        .sum::<usize>();
    let mut h = Sha256::new();
    h.update(domain(
        "p02-v1",
        "hash",
        &format!("{family}-inventory"),
        &[],
    ));
    h.update((pages.len() as u32).to_be_bytes());
    h.update((total as u64).to_be_bytes());
    for (i, p) in pages.iter().enumerate() {
        let b = codec.encode("p02-v1", &format!("{family}-page"), &canonical(p)?)?;
        h.update((i as u32).to_be_bytes());
        h.update((p["items"].as_array().unwrap().len() as u32).to_be_bytes());
        h.update((b.len() as u32).to_be_bytes());
        h.update(un64(&digest(&format!("{family}-page"), p)?)?);
    }
    Ok(
        json!({"inventory_digest":b64(&h.finalize()),"item_count":total.to_string(),"page_count":pages.len().to_string()}),
    )
}
struct Inventory {
    rows: Vec<Value>,
    pages: Vec<Value>,
    total: u64,
    export_id: String,
}
impl Inventory {
    fn add(&mut self, path: &str, bytes: &[u8]) -> Result<()> {
        let kind = if path.starts_with("files/") {
            "chunk"
        } else if path.starts_with("identity/") {
            "identity"
        } else if path.starts_with("keys/") {
            "key"
        } else if path.starts_with("records/") {
            "record"
        } else {
            "source-snapshot"
        };
        self.rows.push(
            json!({"path":path,"kind":kind,"size":bytes.len().to_string(),"digest":hash(bytes)}),
        );
        self.total += bytes.len() as u64;
        if self.rows.len() == 500 {
            self.flush();
        }
        check(
            canonical(&json!(self.pages))?.len() <= 67108864,
            "RESOURCE_LIMIT",
        )
    }
    fn flush(&mut self) {
        if self.rows.is_empty() {
            return;
        }
        let mut page = common("export-inventory-page");
        page["export_id"] = json!(self.export_id);
        page["page_index"] = json!(self.pages.len().to_string());
        page["items"] = json!(std::mem::take(&mut self.rows));
        self.pages.push(page);
    }
    fn footer(&mut self, codec: &Codec, header: &Value, signer: &Value) -> Result<Value> {
        self.flush();
        let mut body = common("export-footer");
        body["export_id"] = json!(self.export_id);
        body["header_digest"] = json!(digest("export-header", header)?);
        body["total_item_bytes"] = json!(self.total.to_string());
        body["signer"] = signer.clone();
        let counts = commitment(codec, &self.pages, "export")?;
        for k in ["inventory_digest", "item_count", "page_count"] {
            body[k] = counts[k].clone();
        }
        Ok(body)
    }
}
pub struct Plan {
    pub lease: Value,
    pub deadline: u64,
    pub seconds: u64,
}
fn millis() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error("CLOCK_REGRESSION"))?
        .as_millis() as u64)
}
impl Host {
    pub fn prepare_export(
        &self,
        g: u64,
        groups: &[String],
        history: bool,
        trash: bool,
        kib: u64,
    ) -> Result<Plan> {
        let cap = self.capability(g)?;
        check(
            groups.len() <= 200 && (1..=1048576).contains(&kib),
            "RESOURCE_LIMIT",
        )?;
        for x in groups {
            id(x)?;
        }
        self.prove(&cap)?;
        self.resync(&cap)?;
        let mut selected = groups.to_vec();
        selected.sort();
        selected.dedup();
        let lease=self.api(&cap,Route::ExportStart,None,None,&[],Some(&json!({"version":1,"operation_id":random_id(),"group_ids":selected,"include_history":history,"include_trash":trash})))?;
        let deadline = string(&lease, "maximum_expires_at_ms")?
            .parse::<u64>()
            .map_err(|_| Error("INVALID_EXPORT_LEASE"))?;
        let estimate = string(&lease, "estimated_archive_bytes")?
            .parse::<u64>()
            .map_err(|_| Error("INVALID_EXPORT_LEASE"))?;
        let seconds = estimate.div_ceil(kib * 1024);
        check(
            deadline > millis()? && deadline - millis()? <= 86400000,
            "INVALID_EXPORT_LEASE",
        )?;
        if millis()? + seconds * 1000 + 300000 >= deadline {
            let _ = self.api(
                &cap,
                Route::ExportCancel,
                lease["descriptor"]["snapshot_id"].as_str(),
                None,
                &[],
                None,
            );
            return Err(Error("EXPORT_SELECTION_TOO_LARGE"));
        }
        Ok(Plan {
            lease,
            deadline,
            seconds,
        })
    }
    fn export_tick(
        &self,
        cap: &Capability,
        job: &Job,
        lease: &mut Value,
        deadline: u64,
    ) -> Result<()> {
        job.check(self.current())?;
        check(millis()? < deadline, "SYNC_CURSOR_EXPIRED")?;
        if millis()? + 120000
            >= string(lease, "lease_expires_at_ms")?
                .parse::<u64>()
                .map_err(|_| Error("INVALID_EXPORT_LEASE"))?
        {
            let next = self.api(
                cap,
                Route::ExportRenew,
                lease["descriptor"]["snapshot_id"].as_str(),
                None,
                &[],
                Some(&json!({"version":1})),
            )?;
            check(
                next["descriptor"] == lease["descriptor"] && next["scope"] == lease["scope"],
                "EXPORT_SOURCE_MISMATCH",
            )?;
            *lease = next;
        }
        Ok(())
    }
    pub fn export_archive(
        self: &Arc<Self>,
        g: u64,
        plan: Plan,
        target: &Path,
        assets: &Assets,
        job: Arc<Job>,
    ) -> Result<Value> {
        let cap = self.capability(g)?;
        let mut destination = Some(Destination::create(target)?);
        let mut lease = plan.lease;
        let snapshot = string(&lease["descriptor"], "snapshot_id")?.to_owned();
        let codec = Codec::new()?;
        let result = (|| {
            check(
                lease["scope"]["account_id"] == self.profile.scope.account_id
                    && lease["scope"]["service_id"] == self.profile.scope.service_id
                    && lease["scope"]["root_fingerprint"]
                        == self.profile.service.pins["root_fingerprint"],
                "LOCAL_CONTEXT_MISMATCH",
            )?;
            let mut groups = Vec::new();
            let mut start = "0".to_owned();
            loop {
                self.export_tick(&cap, &job, &mut lease, plan.deadline)?;
                let page = self.api(
                    &cap,
                    Route::ExportCatalog,
                    Some(&snapshot),
                    None,
                    &[("start", &start)],
                    None,
                )?;
                groups.extend(
                    page["groups"]
                        .as_array()
                        .ok_or(Error("INVALID_PAGE"))?
                        .iter()
                        .cloned(),
                );
                check(groups.len() <= 200, "RESOURCE_LIMIT")?;
                if page["next"].is_null() {
                    break;
                }
                let next = string(&page, "next")?.to_owned();
                check(next != start, "INVALID_PAGE_ORDER")?;
                start = next;
            }
            let mut catalog = b"AnyNote/P11/catalog\0".to_vec();
            catalog.extend((groups.len() as u32).to_be_bytes());
            for group in &groups {
                let b = canonical(group)?;
                catalog.extend((b.len() as u32).to_be_bytes());
                catalog.extend(b);
                self.group(&cap, string(group, "group_id")?)?;
            }
            check(
                hash(&catalog) == lease["catalog_digest"],
                "EXPORT_SOURCE_MISMATCH",
            )?;
            let mut pages = Vec::new();
            let count = string(&lease["descriptor"], "page_count")?
                .parse::<usize>()
                .map_err(|_| Error("INVALID_PAGE"))?;
            check(count <= 8000, "RESOURCE_LIMIT")?;
            for n in 0..count {
                self.export_tick(&cap, &job, &mut lease, plan.deadline)?;
                let page = self.api(
                    &cap,
                    Route::ExportPage,
                    Some(&snapshot),
                    None,
                    &[("index", &n.to_string())],
                    None,
                )?;
                check(page["scope"] == lease["scope"], "EXPORT_SOURCE_MISMATCH")?;
                pages.push(page["page"].clone());
            }
            let counts = commitment(&codec, &pages, "snapshot")?;
            for k in ["page_count", "item_count", "inventory_digest"] {
                check(
                    counts[k] == lease["descriptor"][k],
                    "EXPORT_SOURCE_MISMATCH",
                )?;
            }
            let mut items = pages
                .iter()
                .flat_map(|p| p["items"].as_array().unwrap().iter().cloned())
                .collect::<Vec<_>>();
            check(items.len() <= 51000, "RESOURCE_LIMIT")?;
            items.sort_by_key(|i| i["revision_id"].as_str().unwrap_or("").to_owned());
            let group_ids = groups
                .iter()
                .map(|v| string(v, "group_id").map(str::to_owned))
                .collect::<Result<Vec<_>>>()?;
            // Current accessible records are authenticated before selected-key preparation.
            for item in &items {
                if item["payload_status"] == "pruned" {
                    continue;
                }
                let record = self.api(
                    &cap,
                    Route::ExportRecord,
                    Some(&snapshot),
                    item["revision_id"].as_str(),
                    &[],
                    None,
                )?;
                check(record["item"] == *item, "EXPORT_SOURCE_MISMATCH")?;
                if item["object_kind"] == "file-manifest" {
                    self.vault.observe_file(
                        &cap,
                        string(item, "group_id")?,
                        string(item, "revision_id")?,
                        &record["record"],
                    )?;
                } else {
                    let c = &record["record"]["envelope"]["header"]["context"];
                    self.vault.notes_command(&cap,anynote_local_vault::notes::NotesRequest::Open{request:json!({"group_id":c["group_id"],"object_id":c["object_id"],"revision_id":c["revision_id"],"object_kind":c["object_kind"],"thread_id":c["thread_id"],"bundle":record["record"]})})?;
                }
            }
            let public = self.vault.portable_public(&cap, &group_ids)?;
            let export_id = random_id();
            let mut header = common("export-header");
            header["export_id"] = json!(export_id);
            header["service_id"] = json!(self.profile.scope.service_id);
            header["account_id"] = json!(self.profile.scope.account_id);
            header["root_fingerprint"] = public["root_fingerprint"].clone();
            header["snapshot"] = lease["descriptor"].clone();
            header["selection"] = json!({"group_ids":group_ids,"include_history":lease["selection"]["include_history"],"include_trash":lease["selection"]["include_trash"]});
            header["created_at"] = lease["descriptor"]["created_at"].clone();
            header["outer_format"] = json!("age-v1-X25519");
            header["archive_format"] = json!("ustar-anynote-v1");
            codec.validate("p02-v1", "export-header", &header)?;
            let own = self.clone();
            let cancelled = job.clone();
            let mut bridge =
                Bridge::spawn(assets, move || own.current() != g || cancelled.cancelled())?;
            bridge.json(1,&json!({"mode":"export","header":header,"signer":public["signer"],"kit":{"exporter_root_fingerprint":public["root_fingerprint"],"exporter_roster":public["signer"]["roster"],"independent_group_pins":public["pins"]}}))?;
            let mut entries = Vec::new();
            for item in items
                .iter()
                .filter(|i| i["object_kind"] == "file-manifest" && i["payload_status"] != "pruned")
            {
                let r = self.api(
                    &cap,
                    Route::ExportRecord,
                    Some(&snapshot),
                    item["revision_id"].as_str(),
                    &[],
                    None,
                )?;
                let n = string(&r["record"]["envelope"]["header"]["framing"], "chunk_count")?
                    .parse::<usize>()
                    .map_err(|_| Error("INVALID_PAGE"))?;
                for index in 0..n {
                    entries.push((
                        format!("files/{}/{index:08}.bin", string(item, "revision_id")?),
                        json!({"kind":"chunk","item":item,"index":index}),
                    ));
                }
            }
            entries.push(("identity/evidence.json".into(), json!({"kind":"public"})));
            for item in items.iter().filter(|i| i["payload_status"] != "pruned") {
                entries.push((
                    format!("keys/{}.json", string(item, "revision_id")?),
                    json!({"kind":"key","item":item}),
                ));
            }
            for item in &items {
                entries.push((
                    format!("records/{}.json", string(item, "revision_id")?),
                    json!({"kind":"record","item":item}),
                ));
            }
            for (n, page) in pages.iter().enumerate() {
                entries.push((
                    format!("snapshots/{n:08}.json"),
                    json!({"kind":"page","page":page}),
                ));
            }
            let mut inventory = Inventory {
                rows: Vec::new(),
                pages: Vec::new(),
                total: 0,
                export_id: export_id.clone(),
            };
            let mut next = 0;
            let mut digest = Sha256::new();
            let mut bytes = 0u64;
            let mut durable = false;
            let mut reader = None::<anynote_crypto_core::files::FileReader>;
            loop {
                self.export_tick(&cap, &job, &mut lease, plan.deadline)?;
                let (kind, data) = bridge.receive()?;
                match kind {
                    11 => {
                        if next == entries.len() {
                            bridge.send(4, &[])?;
                            continue;
                        }
                        let (path, description) = &entries[next];
                        let mut body = Zeroizing::new(match description["kind"].as_str() {
                            Some("public") => canonical(&public["document"])?,
                            Some("page") => canonical(&description["page"])?,
                            Some("chunk") => {
                                let item = &description["item"];
                                let response = self.vault.export_chunk_http(
                                    &cap,
                                    &self.profile.credential_id,
                                    &self.adapter,
                                    &snapshot,
                                    string(item, "revision_id")?,
                                    description["index"].as_u64().unwrap() as u8,
                                )?;
                                check(response.status == 200, "API_DENIED")?;
                                let index = description["index"].as_u64().unwrap();
                                if index == 0 {
                                    let r = self.api(
                                        &cap,
                                        Route::ExportRecord,
                                        Some(&snapshot),
                                        item["revision_id"].as_str(),
                                        &[],
                                        None,
                                    )?;
                                    reader = Some(self.vault.file_reader(&cap, &r["record"])?);
                                }
                                let _plain = reader
                                    .as_mut()
                                    .ok_or(Error("INCOMPLETE_FILE"))?
                                    .decrypt_next(&response.bytes)?;
                                if response.bytes.is_empty() {
                                    return Err(Error("INVALID_CHUNK"));
                                }
                                let r = self.api(
                                    &cap,
                                    Route::ExportRecord,
                                    Some(&snapshot),
                                    item["revision_id"].as_str(),
                                    &[],
                                    None,
                                )?;
                                if index + 1
                                    == string(
                                        &r["record"]["envelope"]["header"]["framing"],
                                        "chunk_count",
                                    )?
                                    .parse::<u64>()
                                    .map_err(|_| Error("INVALID_PAGE"))?
                                {
                                    reader.take().unwrap().finish()?;
                                }
                                response.bytes
                            }
                            Some("key" | "record") => {
                                let item = &description["item"];
                                let response = self.api(
                                    &cap,
                                    Route::ExportRecord,
                                    Some(&snapshot),
                                    item["revision_id"].as_str(),
                                    &[],
                                    None,
                                )?;
                                check(response["item"] == *item, "EXPORT_SOURCE_MISMATCH")?;
                                if description["kind"] == "key" {
                                    let mut key = self.vault.portable_selected_key(
                                        &cap,
                                        item,
                                        &response["record"],
                                    )?;
                                    let b =
                                        codec.encode("p02-v1", "export-key", &canonical(&key)?)?;
                                    wipe(&mut key);
                                    b
                                } else {
                                    codec.encode(
                                        "p02-v1",
                                        if item["payload_status"] == "pruned" {
                                            "export-pruned-record"
                                        } else if item["object_kind"] == "file-manifest" {
                                            "export-file-record"
                                        } else {
                                            "bundle"
                                        },
                                        &canonical(&response["record"])?,
                                    )?
                                }
                            }
                            _ => return Err(Error("INVALID_BRIDGE_FRAME")),
                        });
                        self.export_tick(&cap, &job, &mut lease, plan.deadline)?;
                        inventory.add(path, &body)?;
                        bridge.json(2, &json!({"path":path,"bytes":body.len()}))?;
                        bridge.send(3, &body)?;
                        use zeroize::Zeroize;
                        body.zeroize();
                        next += 1;
                    }
                    7 => {
                        check(bytes + data.len() as u64 <= 116010000000, "RESOURCE_LIMIT")?;
                        destination
                            .as_mut()
                            .ok_or(Error("EXPORT_CLOSED"))?
                            .write_all(&data)
                            .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
                        digest.update(&*data);
                        bytes += data.len() as u64;
                        job.progress(bytes, 0);
                        bridge.ack()?;
                    }
                    5 => {
                        let prefix = domain("p02-v1", "sign", "export-footer-body", &[]);
                        check(data.starts_with(&prefix), "EXPORT_SOURCE_MISMATCH")?;
                        let body = strict(&data[prefix.len()..], 1048576)?;
                        let expected = inventory.footer(&codec, &header, &public["signer"])?;
                        self.api(&cap, Route::ExportStatus, Some(&snapshot), None, &[], None)?;
                        let signature = self.vault.sign_portable_footer(&cap, &body, &expected)?;
                        bridge.send(6, &signature)?;
                    }
                    12 => {
                        destination
                            .as_mut()
                            .ok_or(Error("EXPORT_CLOSED"))?
                            .writer()?
                            .sync_all()
                            .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
                        durable = true;
                        bridge.ack()?;
                    }
                    8 => {
                        check(durable && next == entries.len(), "INCOMPLETE_EXPORT")?;
                        let mut result = strict(&data, 65536)?;
                        check(
                            result["kit"]["archive_sha256"] == b64(&digest.finalize())
                                && result["kit"]["export_id"] == export_id,
                            "EXPORT_SOURCE_MISMATCH",
                        )?;
                        self.save_native_job(&cap,&export_id,&json!({"purpose":"p14-native-export","version":1,"state":"OUTPUT_PENDING","kit":result["kit"],"target":target,"partial":destination.as_ref().unwrap().encrypted_path()}))?;
                        job.check(self.current())?;
                        destination.take().unwrap().finish()?;
                        self.save_native_job(&cap,&export_id,&json!({"purpose":"p14-native-export","version":1,"state":"COMPLETE","kit":result["kit"]}))?;
                        wipe(&mut result);
                        return Ok(
                            json!({"export_id":export_id,"archive_bytes":bytes.to_string(),"state":"COMPLETE","kit_saved_separately":false}),
                        );
                    }
                    _ => return Err(Error("INVALID_BRIDGE_FRAME")),
                }
            }
        })();
        let _ = self.api(&cap, Route::ExportCancel, Some(&snapshot), None, &[], None);
        result
    }
    pub fn native_job_id(&self) -> String {
        let b = canonical(&json!({"purpose":"AnyNote/P14/native-jobs","scope":self.profile.scope}))
            .unwrap();
        b64(&un64(&hash(&b)).unwrap()[..16])
    }
    pub fn save_native_job(&self, cap: &Capability, id: &str, data: &Value) -> Result<()> {
        crate::id(id)?;
        let root = self.native_job_id();
        let snapshot = self.vault.content_read(cap, &root, "content-control")?;
        let mut control = snapshot
            .data
            .unwrap_or(json!({"purpose":"p14-native-jobs","version":1,"items":[]}));
        let rows = control["items"]
            .as_array_mut()
            .ok_or(Error("INTEGRITY_FAILURE"))?;
        if !rows.iter().any(|r| r["job_id"] == id) {
            check(rows.len() < 512, "RESOURCE_LIMIT")?;
            rows.push(json!({"job_id":id,"kind":if data["purpose"]=="p14-native-export"{"export-state"}else{"import-state"}}));
        }
        let kind = if data["purpose"] == "p14-native-export" {
            "export-state"
        } else {
            "import-state"
        };
        self.vault.content_commit(
            cap,
            snapshot.revision,
            &[
                Record {
                    id: root,
                    kind: "content-control".into(),
                    data: control,
                },
                Record {
                    id: id.into(),
                    kind: kind.into(),
                    data: data.clone(),
                },
            ],
            &[],
        )
    }
    pub fn save_kit(&self, g: u64, export: &str, path: &Path) -> Result<Value> {
        let cap = self.capability(g)?;
        let state = self
            .vault
            .content_read(&cap, id(export)?, "export-state")?
            .data
            .ok_or(Error("NOT_FOUND"))?;
        check(state["state"] == "COMPLETE", "EXPORT_NOT_COMPLETE")?;
        let mut out = Destination::create(path)?;
        out.write_all(&canonical(&state["kit"])?)
            .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        check(g == self.current(), "STALE_CAPABILITY")?;
        out.finish()?;
        Ok(json!({"state":"SAVED_SEPARATELY"}))
    }
}
