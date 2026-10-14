//! Actual captured native resync, published atomically by the existing P11 verifier.
use crate::host::Host;
use crate::*;
use anynote_auth_native::control::Route;
use anynote_local_vault::Capability;
use serde_json::json;
impl Host {
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
