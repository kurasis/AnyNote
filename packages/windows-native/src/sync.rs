//! Actual captured native resync, published atomically by the existing P11 verifier.
use crate::host::Host;
use crate::*;
use anynote_auth_native::control::Route;
use anynote_local_vault::Capability;
use serde_json::json;
impl Host {
    pub fn catch_up(&self, cap: &Capability) -> Result<Value> {
        let result = self.catch_up_inner(cap);
        if let Err(Error(
            code @ ("RESTORE_QUARANTINE"
            | "CIPHERTEXT_MISMATCH"
            | "INVALID_SIGNATURE"
            | "CONTEXT_MISMATCH"
            | "ROOT_PIN_MISMATCH"
            | "SYNC_GAP"
            | "INVALID_SYNC_DTO"
            | "INTEGRITY_FAILURE"),
        )) = &result
        {
            let digest = anynote_crypto_core::crypto::hash(&anynote_crypto_core::codec::canonical(
                &json!({"code":code}),
            )?);
            let _=self.notes(cap,json!({"action":"sync","request":{"action":"quarantine","state":if *code=="RESTORE_QUARANTINE"{"RESTORE_QUARANTINE"}else{"QUARANTINED"},"digest":digest}}));
        }
        result
    }
    fn catch_up_inner(&self, cap: &Capability) -> Result<Value> {
        let mut state = self.notes(cap, json!({"action":"sync","request":{"action":"status"}}))?;
        check(state["state"] != "RESTORE_QUARANTINE", "RESTORE_QUARANTINE")?;
        check(state["state"] != "QUARANTINED", "SYNC_QUARANTINE")?;
        if state["cursor"].is_null() || !state["stage"].is_null() {
            state = self.resync(cap)?;
        }
        for _ in 0..100 {
            let cursor = &state["cursor"];
            let page = if state["pending"].is_null() {
                match self.api(
                    cap,
                    Route::Sync,
                    None,
                    None,
                    &[
                        ("generation", string(cursor, "generation")?),
                        ("sequence", string(cursor, "sequence")?),
                    ],
                    None,
                ) {
                    Ok(page) => page,
                    Err(Error("SYNC_CURSOR_EXPIRED")) => return self.resync(cap),
                    Err(e) => return Err(e),
                }
            } else {
                state["pending"]["page"].clone()
            };
            let events = page["events"].as_array().ok_or(Error("INVALID_PAGE"))?;
            // Security/file changes require a complete captured inventory and refreshed signed
            // authority. An unsigned event is only a hint to refresh, never a new permission.
            if events
                .iter()
                .any(|e| e["revision_id"].is_null() || e["kind"] == "file")
            {
                self.notes(
                    cap,
                    json!({"action":"sync","request":{"action":"delta-cancel"}}),
                )?;
                state = self.resync(cap)?;
                continue;
            }
            self.notes(
                cap,
                json!({"action":"sync","request":{"action":"delta-start","page":page}}),
            )?;
            for event in events {
                let group = string(event, "group_id")?;
                let object = string(event, "object_id")?;
                let revision = string(event, "revision_id")?;
                self.group(cap, group)?;
                let reference = self.api(cap, Route::Object, Some(object), None, &[], None)?;
                let result = self.api(
                    cap,
                    Route::Revision,
                    Some(object),
                    Some(revision),
                    &[],
                    None,
                )?;
                let context = &result["bundle"]["envelope"]["header"]["context"];
                let item = json!({"group_id":group,"object_id":object,"object_kind":context["object_kind"],"revision_id":revision,"envelope_digest":event["digest"],"payload_status":if context["action"]=="soft-delete"{"tombstone"}else{"retained"}});
                self.notes(cap,json!({"action":"sync","request":{"action":"delta-item","result":{"version":1,"item":item,"reference":reference["object"],"bundle":result["bundle"]}}}))?;
            }
            state = self.notes(
                cap,
                json!({"action":"sync","request":{"action":"delta-finish"}}),
            )?;
            self.api(cap,Route::SyncAck,None,None,&[],Some(&json!({"version":1,"cursor":state["cursor"],"group_id":state["scope"]["group_id"]})))?;
            if page["complete"] == true {
                return Ok(state);
            }
        }
        state["catch_up_pending"] = json!(true);
        Ok(state)
    }
    pub fn local_objects(
        &self,
        cap: &Capability,
        group: &str,
        thread: Option<&str>,
        after: Option<&str>,
    ) -> Result<Value> {
        id(group)?;
        if let Some(t) = thread {
            id(t)?;
        }
        if let Some(a) = after {
            id(a)?;
        }
        let state = self.notes(cap, json!({"action":"sync","request":{"action":"status"}}))?;
        check(!state["cursor"].is_null(), "OFFLINE_UNAVAILABLE")?;
        let projection = state["projection"]
            .as_array()
            .ok_or(Error("INTEGRITY_FAILURE"))?;
        let mut references = projection
            .iter()
            .filter(|p| {
                p["group_id"] == group
                    && p["reference"]["object_kind"]
                        == if thread.is_some() { "entry" } else { "thread" }
                    && (thread.is_none() || p["reference"]["thread_id"] == thread.unwrap())
            })
            .map(|p| &p["reference"])
            .collect::<Vec<_>>();
        references.sort_by_key(|r| r["object_id"].as_str().unwrap_or(""));
        let eligible = references
            .into_iter()
            .filter(|r| after.is_none_or(|a| r["object_id"].as_str().is_some_and(|v| v > a)))
            .take(51)
            .collect::<Vec<_>>();
        let mut items = Vec::new();
        for object in eligible.iter().take(50) {
            let head = object["heads"]
                .as_array()
                .and_then(|h| h.first())
                .ok_or(Error("PAYLOAD_UNAVAILABLE"))?;
            let opened = self.notes(
                cap,
                json!({"action":"cached","revision_id":string(head,"revision_id")?}),
            )?;
            items.push(json!({"object":object,"payload":opened["payload"],"offline":true}));
        }
        Ok(
            json!({"items":items,"next":if eligible.len()>50{eligible[49]["object_id"].clone()}else{Value::Null},"state":"OFFLINE","freshness":"last-authenticated-local-view"}),
        )
    }
    pub fn local_groups(&self, cap: &Capability) -> Result<Value> {
        self.notes(cap, json!({"action":"sync","request":{"action":"offline"}}))?;
        let summary = self.notes(cap, json!({"action":"summary"}))?;
        let mut items = Vec::new();
        for reference in summary["groups"]
            .as_array()
            .ok_or(Error("INTEGRITY_FAILURE"))?
        {
            let status = &reference["status"];
            if status.is_null() {
                continue;
            }
            let group = string(reference, "group_id")?;
            let title=self.notes(cap,json!({"action":"sync","request":{"action":"status"}}))?["projection"].as_array().and_then(|rows|rows.iter().find(|p|p["group_id"]==group && p["reference"]["object_kind"]=="group-metadata")).and_then(|p|p["reference"]["heads"].as_array()).and_then(|h|h.first()).and_then(|h|h["revision_id"].as_str()).map(str::to_owned);
            let title = if let Some(revision) = title {
                self.notes(cap,json!({"action":"cached","revision_id":revision}))?["payload"]["title"].clone()
            } else {
                json!("Untitled")
            };
            items.push(json!({"group":status,"title":title,"offline":true}));
        }
        Ok(json!({"items":items,"state":"OFFLINE","freshness":"last-authenticated-local-view"}))
    }
    pub fn resync(&self, cap: &Capability) -> Result<Value> {
        let start = self.api(
            cap,
            Route::Snapshot,
            None,
            None,
            &[],
            Some(
                &json!({"version":1,"operation_id":random_id(),"purpose":"resync","group_id":null}),
            ),
        )?;
        let snapshot = string(&start["descriptor"], "snapshot_id")?.to_owned();
        let result = (|| {
            self.notes(
                cap,
                json!({"action":"sync","request":{"action":"snapshot-start","result":start}}),
            )?;
            let mut offset = "0".to_owned();
            loop {
                let page = self.api(
                    cap,
                    Route::SnapshotCatalog,
                    Some(&snapshot),
                    None,
                    &[("start", &offset)],
                    None,
                )?;
                for group in page["groups"].as_array().ok_or(Error("INVALID_PAGE"))? {
                    self.group(cap, string(group, "group_id")?)?;
                }
                self.notes(
                    cap,
                    json!({"action":"sync","request":{"action":"catalog","page":page}}),
                )?;
                if page["next"].is_null() {
                    break;
                }
                let next = string(&page, "next")?.to_owned();
                check(next != offset, "INVALID_PAGE_ORDER")?;
                offset = next;
            }
            let count = string(&start["descriptor"], "page_count")?
                .parse::<usize>()
                .map_err(|_| Error("INVALID_PAGE"))?;
            check(count <= 8000, "RESOURCE_LIMIT")?;
            for n in 0..count {
                let page = self.api(
                    cap,
                    Route::SnapshotPage,
                    Some(&snapshot),
                    None,
                    &[("index", &n.to_string())],
                    None,
                )?;
                self.notes(
                    cap,
                    json!({"action":"sync","request":{"action":"snapshot-page","result":page}}),
                )?;
                for item in page["page"]["items"]
                    .as_array()
                    .ok_or(Error("INVALID_PAGE"))?
                {
                    let record = self.api(
                        cap,
                        Route::SnapshotItem,
                        Some(&snapshot),
                        item["revision_id"].as_str(),
                        &[],
                        None,
                    )?;
                    self.notes(cap,json!({"action":"sync","request":{"action":"snapshot-item","result":record}}))?;
                }
            }
            if !start["files"].is_null() {
                let mut inventory = Vec::new();
                let mut offset = "0".to_owned();
                loop {
                    let page = self.api(
                        cap,
                        Route::SnapshotFiles,
                        Some(&snapshot),
                        None,
                        &[("start", &offset)],
                        None,
                    )?;
                    for item in page["files"]
                        .as_array()
                        .or_else(|| page["items"].as_array())
                        .ok_or(Error("INVALID_PAGE"))?
                    {
                        let c = &item["envelope"]["header"]["context"];
                        self.vault.observe_file(
                            cap,
                            string(c, "group_id")?,
                            string(c, "file_version_id")?,
                            item,
                        )?;
                        let bytes = anynote_crypto_core::codec::domain(
                            "p02-file-c1",
                            "hash",
                            "file-envelope",
                            &anynote_crypto_core::codec::canonical(&item["envelope"])?,
                        );
                        inventory.push(json!({"group_id":c["group_id"],"file_id":c["file_id"],"file_version_id":c["file_version_id"],"envelope_digest":anynote_crypto_core::crypto::hash(&bytes)}));
                    }
                    check(inventory.len() <= 1000, "RESOURCE_LIMIT")?;
                    if page["next"].is_null() {
                        break;
                    }
                    let next = string(&page, "next")?.to_owned();
                    check(next != offset, "INVALID_PAGE_ORDER")?;
                    offset = next;
                }
                self.notes(cap,json!({"action":"sync","request":{"action":"snapshot-files","inventory":inventory}}))?;
            }
            self.notes(
                cap,
                json!({"action":"sync","request":{"action":"snapshot-finish"}}),
            )
        })();
        if result.is_err() {
            let _ = self.notes(
                cap,
                json!({"action":"sync","request":{"action":"snapshot-cancel"}}),
            );
        }
        let _ = self.api(cap, Route::SnapshotCancel, Some(&snapshot), None, &[], None);
        result
    }
}
