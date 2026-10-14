//! Staged encrypted synchronization; the existing content verifier remains authoritative.
use super::*;
use std::collections::BTreeSet;
struct Sensitive(Value);
impl Drop for Sensitive {
    fn drop(&mut self) {
        wipe_value(&mut self.0);
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Status {},
    Offline {},
    Compact { limit: u8 },
    Quarantine { state: String, digest: String },
    SnapshotStart { result: Value },
    Catalog { page: Value },
    SnapshotPage { result: Value },
    SnapshotItem { result: Value },
    SnapshotFiles { inventory: Value },
    SnapshotFinish {},
    SnapshotCancel {},
    DeltaStart { page: Value },
    DeltaItem { result: Value },
    DeltaFinish {},
    DeltaCancel {},
}
impl Request {
    pub(super) fn wipe(&mut self) {
        match self {
            Self::SnapshotStart { result }
            | Self::SnapshotPage { result }
            | Self::SnapshotItem { result }
            | Self::DeltaItem { result } => wipe_value(result),
            Self::SnapshotFiles { inventory } => wipe_value(inventory),
            Self::Catalog { page } | Self::DeltaStart { page } => wipe_value(page),
            _ => (),
        }
    }
}
fn number(v: &Value) -> Result<u64> {
    text(v)?.parse().map_err(|_| Error("INVALID_SYNC_DTO"))
}
fn order(v: &Value) -> Result<String> {
    Ok(format!(
        "{}/{}/{}/{}",
        text(&v["group_id"])?,
        text(&v["object_kind"])?,
        text(&v["object_id"])?,
        text(&v["revision_id"])?
    ))
}
fn catalog_hash(groups: &[Value]) -> Result<String> {
    let mut bytes = b"AnyNote/P11/catalog\0".to_vec();
    bytes.extend((groups.len() as u32).to_be_bytes());
    for g in groups {
        let b = canonical(g)?;
        bytes.extend((b.len() as u32).to_be_bytes());
        bytes.extend(b);
    }
    Ok(hash(&bytes))
}
fn inventory_hash(pages: &[Value]) -> Result<String> {
    let mut bytes = b"AnyNote/p02-v1/hash/snapshot-inventory\0".to_vec();
    bytes.extend((pages.len() as u32).to_be_bytes());
    let count = pages
        .iter()
        .try_fold(0u64, |n, p| Ok::<_, Error>(n + number(&p["items"])?))?;
    bytes.extend(count.to_be_bytes());
    for p in pages {
        for k in ["index", "items", "bytes"] {
            bytes.extend((number(&p[k])? as u32).to_be_bytes());
        }
        bytes.extend(un64(text(&p["hash"])?)?);
    }
    Ok(hash(&bytes))
}
impl Vault {
    fn sync_publish(
        &self,
        i: &mut Inner,
        state: &State,
        c: &mut Value,
        staged: &[Value],
        snapshot: bool,
    ) -> Result<()> {
        let mut witnesses = values(c, "witnesses")?.clone();
        for v in staged {
            if let Some(w) = witnesses
                .iter_mut()
                .find(|w| w["revision_id"] == v["witness"]["revision_id"])
            {
                let mut old_proof = w.as_object().ok_or(Error("INTEGRITY_FAILURE"))?.clone();
                let mut new_proof = v["witness"]
                    .as_object()
                    .ok_or(Error("INTEGRITY_FAILURE"))?
                    .clone();
                old_proof.remove("cache_id");
                new_proof.remove("cache_id");
                check(old_proof == new_proof, "ROLLBACK_QUARANTINE")?;
                *w = v["witness"].clone();
            } else {
                witnesses.push(v["witness"].clone());
            }
        }
        for v in staged {
            let data = self.note_read(i, state, c, text(&v["cache_id"])?, "cache")?;
            let envelope = if data["purpose"] == "p11-header-evidence" {
                data["envelope"].clone()
            } else {
                self.codec
                    .decode("p02-v1", "bundle", &un64(text(&data["record_bytes"])?)?)?["envelope"]
                    .clone()
            };
            check(
                digest("p02-v1", "envelope", &envelope)? == v["item"]["envelope_digest"],
                "INTEGRITY_FAILURE",
            )?;
            for p in values(&envelope["header"]["context"], "parents")? {
                check(
                    witnesses.iter().any(|w| {
                        w["revision_id"] == p["revision_id"]
                            && w["envelope_digest"] == p["envelope_digest"]
                            && w["group_id"] == v["item"]["group_id"]
                            && w["object_id"] == v["item"]["object_id"]
                    }),
                    "UNANCHORED_HISTORY",
                )?;
            }
        }
        let group = c["sync"]["scope"]["group_id"].clone();
        let mut refs = values(&c["sync"], "projection")?
            .iter()
            .filter(|p| !snapshot || (!group.is_null() && p["group_id"] != group))
            .cloned()
            .collect::<Vec<_>>();
        for v in staged {
            for h in values(&v["reference"], "heads")? {
                check(
                    witnesses.iter().any(|w| {
                        w["group_id"] == v["item"]["group_id"]
                            && w["object_id"] == v["item"]["object_id"]
                            && w["revision_id"] == h["revision_id"]
                            && w["envelope_digest"] == h["envelope_digest"]
                    }),
                    "UNANCHORED_HISTORY",
                )?;
            }
            refs.retain(|p| {
                !(p["group_id"] == v["item"]["group_id"]
                    && p["reference"]["object_id"] == v["item"]["object_id"])
            });
            refs.push(json!({"group_id":v["item"]["group_id"],"reference":v["reference"]}));
        }
        refs.sort_by_key(|p| {
            format!(
                "{}/{}",
                p["group_id"].as_str().unwrap(),
                p["reference"]["object_id"].as_str().unwrap()
            )
        });
        c["witnesses"] = json!(witnesses);
        c["sync"]["projection"] = json!(refs);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn note_sync(
        &self,
        i: &mut Inner,
        cap: &Capability,
        state: &State,
        fence: u64,
        c: &mut Value,
        evidence: (&Value, &Roster),
        request: &Request,
    ) -> Result<Value> {
        if c["sync"].is_null() {
            c["sync"] = json!({"purpose":"p11-sync-control","version":1,"scope":{"service_id":self.scope.service_id,"account_id":self.scope.account_id,"root_fingerprint":state.pins["root_fingerprint"],"group_id":null},"cursor":null,"watermark":null,"stage":null,"groups":[],"pending":null,"retry":[],"projection":[],"state":"NEW","quarantine":null});
        }
        self.codec
            .validate("p11-sync", "sync-control", &c["sync"])?;
        check(
            c["sync"]["state"] != "RESTORE_QUARANTINE"
                || matches!(
                    request,
                    Request::Status {}
                        | Request::Offline {}
                        | Request::Quarantine { .. }
                        | Request::SnapshotCancel {}
                        | Request::DeltaCancel {}
                        | Request::SnapshotStart { .. }
                ),
            "RESTORE_QUARANTINE",
        )?;
        let mut writes = Vec::new();
        match request {
            Request::Status {} => return Ok(c["sync"].clone()),
            Request::Compact { limit } => {
                check(*limit >= 1 && *limit <= 16, "INVALID_REQUEST")?;
                check(
                    !c["sync"]["cursor"].is_null()
                        && c["sync"]["stage"].is_null()
                        && c["sync"]["pending"].is_null(),
                    "SYNC_GAP",
                )?;
                let mut keep = BTreeSet::new();
                for p in values(&c["sync"], "projection")? {
                    for h in values(&p["reference"], "heads")? {
                        keep.insert(text(&h["revision_id"])?.to_owned());
                    }
                }
                for d in values(c, "drafts")? {
                    let data =
                        Sensitive(self.note_read(i, state, c, text(&d["record_id"])?, "draft")?);
                    for p in values(&data.0["context"], "parents")? {
                        keep.insert(text(&p["revision_id"])?.to_owned());
                    }
                }
                for a in values(c, "attempts")? {
                    let data = self.note_read(i, state, c, text(&a["record_id"])?, "outbox")?;
                    if data["state"] != "COMMITTED" {
                        for p in
                            values(&data["bundle"]["envelope"]["header"]["context"], "parents")?
                        {
                            keep.insert(text(&p["revision_id"])?.to_owned());
                        }
                    }
                }
                for w in values(c, "witnesses")? {
                    if (!c["sync"]["scope"]["group_id"].is_null()
                        && w["group_id"] != c["sync"]["scope"]["group_id"])
                        || keep.contains(text(&w["revision_id"])?)
                    {
                        continue;
                    }
                    let data = self.note_read(i, state, c, text(&w["cache_id"])?, "cache")?;
                    if data["purpose"] == "p11-header-evidence" {
                        continue;
                    }
                    let b = self.codec.decode(
                        "p02-v1",
                        "bundle",
                        &un64(text(&data["record_bytes"])?)?,
                    )?;
                    check(
                        digest("p02-v1", "envelope", &b["envelope"])? == w["envelope_digest"],
                        "INTEGRITY_FAILURE",
                    )?;
                    writes.push(Write{id:text(&w["cache_id"])?.into(),kind:"cache".into(),data:json!({"purpose":"p11-header-evidence","version":1,"envelope":b["envelope"]})});
                    if writes.len() == *limit as usize {
                        break;
                    }
                }
                self.note_commit(i, cap, state, fence, c, &writes, None)?;
                return Ok(
                    json!({"compacted":writes.len(),"scope":"superseded-ciphertext-only","signed_headers_retained":true,"drafts_retained":true}),
                );
            }
            Request::Quarantine { state, digest } => {
                check(
                    ["QUARANTINED", "RESTORE_QUARANTINE"].contains(&state.as_str())
                        && un64(digest).is_ok_and(|b| b.len() == 32),
                    "INVALID_SYNC_DTO",
                )?;
                check(
                    c["sync"]["state"] != "RESTORE_QUARANTINE" || state == "RESTORE_QUARANTINE",
                    "RESTORE_QUARANTINE",
                )?;
                c["sync"]["state"] = json!(state);
                c["sync"]["quarantine"] = json!(digest);
            }
            Request::Offline {} => {
                if !matches!(
                    c["sync"]["state"].as_str(),
                    Some("QUARANTINED" | "RESTORE_QUARANTINE")
                ) {
                    c["sync"]["state"] = json!("OFFLINE");
                }
            }
            Request::SnapshotStart { result: r } => {
                self.codec.validate("p11-sync", "snapshot-result", r)?;
                let d = &r["descriptor"];
                check(
                    r["scope"]["service_id"] == self.scope.service_id
                        && r["scope"]["account_id"] == self.scope.account_id
                        && r["scope"]["root_fingerprint"] == state.pins["root_fingerprint"]
                        && d["account_id"] == self.scope.account_id
                        && d["device_id"] == self.scope.device_id
                        && d["snapshot_purpose"] == "resync",
                    "ROOT_PIN_MISMATCH",
                )?;
                let created = number(&d["created_at"])?;
                let expires = number(&d["expires_at"])?;
                check(
                    expires > created
                        && expires - created <= 1800000
                        && number(&d["page_count"])? <= 8000
                        && number(&d["item_count"])? <= 50000
                        && number(&r["catalog_count"])? <= 1000,
                    "CONTEXT_MISMATCH",
                )?;
                check(c["sync"]["pending"].is_null(), "PUBLICATION_PENDING")?;
                let cursor = &c["sync"]["cursor"];
                if !cursor.is_null() {
                    check(c["sync"]["scope"] == r["scope"], "LOCAL_CONTEXT_MISMATCH")?;
                }
                if !cursor.is_null()
                    && (cursor["generation"] != d["watermark"]["generation"]
                        || number(&cursor["sequence"])? > number(&d["watermark"]["sequence"])?)
                {
                    c["sync"]["state"] = json!("RESTORE_QUARANTINE");
                    c["sync"]["quarantine"] = json!(hash(&canonical(r)?));
                } else {
                    check(
                        c["sync"]["state"] != "RESTORE_QUARANTINE",
                        "RESTORE_QUARANTINE",
                    )?;
                    c["sync"]["scope"] = r["scope"].clone();
                    c["sync"]["stage"] = json!({"result":r,"catalog":[],"catalog_next":"0","pages":[],"items":[],"inventory":[],"last":null,"all_items":"0"});
                    c["sync"]["state"] = json!("STAGING");
                }
            }
            Request::SnapshotCancel {} => {
                c["sync"]["stage"] = Value::Null;
                if c["sync"]["state"] != "RESTORE_QUARANTINE" {
                    c["sync"]["state"] = json!(if c["sync"]["cursor"].is_null() {
                        "NEW"
                    } else {
                        "SYNCED"
                    });
                }
            }
            Request::Catalog { page: p } => {
                self.codec.validate("p11-sync", "catalog-page", p)?;
                let t = &mut c["sync"]["stage"];
                check(
                    t.is_object()
                        && p["snapshot_id"] == t["result"]["descriptor"]["snapshot_id"]
                        && p["start"] == t["catalog_next"],
                    "SYNC_GAP",
                )?;
                let total = values(t, "catalog")?.len() + values(p, "groups")?.len();
                let expected = number(&t["result"]["catalog_count"])? as usize;
                check(
                    total <= expected
                        && p["next"]
                            == if total < expected {
                                json!(total.to_string())
                            } else {
                                Value::Null
                            }
                        && (!values(p, "groups")?.is_empty() || total == expected),
                    "SYNC_GAP",
                )?;
                for g in values(p, "groups")? {
                    check(
                        values(t, "catalog")?
                            .last()
                            .is_none_or(|old| old["group_id"].as_str() < g["group_id"].as_str()),
                        "SYNC_GAP",
                    )?;
                    list(t, "catalog")?.push(g.clone());
                }
                t["catalog_next"] = json!(total.to_string());
                if p["next"].is_null() {
                    check(
                        catalog_hash(values(t, "catalog")?)? == t["result"]["catalog_digest"],
                        "CIPHERTEXT_MISMATCH",
                    )?;
                }
            }
            Request::SnapshotPage { result: r } => {
                self.codec.validate("p11-sync", "snapshot-page-result", r)?;
                check(r["scope"] == c["sync"]["scope"], "ROOT_PIN_MISMATCH")?;
                let t = &mut c["sync"]["stage"];
                let p = &r["page"];
                check(
                    t.is_object()
                        && t["catalog_next"] == t["result"]["catalog_count"]
                        && p["snapshot_id"] == t["result"]["descriptor"]["snapshot_id"]
                        && number(&p["page_index"])? == values(t, "pages")?.len() as u64
                        && values(t, "pages")?.len()
                            < (number(&t["result"]["descriptor"]["page_count"])? as usize)
                        && !values(p, "items")?.is_empty(),
                    "SYNC_GAP",
                )?;
                for item in values(p, "items")? {
                    let next = order(item)?;
                    check(
                        (t["last"].is_null() || text(&t["last"])? < next.as_str())
                            && values(t, "catalog")?
                                .iter()
                                .any(|g| g["group_id"] == item["group_id"]),
                        "SYNC_GAP",
                    )?;
                    t["last"] = json!(next);
                    list(t, "inventory")?.push(item.clone());
                }
                let count = values(t, "inventory")?.len();
                check(
                    count <= number(&t["result"]["descriptor"]["item_count"])? as usize,
                    "SYNC_GAP",
                )?;
                t["all_items"] = json!(count.to_string());
                list(t,"pages")?.push(json!({"index":p["page_index"],"items":values(p,"items")?.len().to_string(),"bytes":canonical(p)?.len().to_string(),"hash":digest("p02-v1","snapshot-page",p)?}));
            }
            Request::SnapshotItem { result: r } | Request::DeltaItem { result: r } => {
                let snapshot = matches!(request, Request::SnapshotItem { .. });
                self.codec.validate(
                    "p11-sync",
                    if snapshot {
                        "snapshot-bundle"
                    } else {
                        "delta-bundle"
                    },
                    r,
                )?;
                let slot = if snapshot { "stage" } else { "pending" };
                let t = &c["sync"][slot];
                check(t.is_object(), "SYNC_GAP")?;
                let item = &r["item"];
                if snapshot {
                    check(
                        r["snapshot_id"] == t["result"]["descriptor"]["snapshot_id"]
                            && values(t, "inventory")?.contains(item),
                        "CONTEXT_MISMATCH",
                    )?;
                } else {
                    check(
                        values(&t["page"], "events")?.iter().any(|e| {
                            e["revision_id"] == item["revision_id"]
                                && e["object_id"] == item["object_id"]
                                && e["group_id"] == item["group_id"]
                                && e["digest"] == item["envelope_digest"]
                        }),
                        "CONTEXT_MISMATCH",
                    )?;
                }
                if let Some(old) = values(t, "items")?
                    .iter()
                    .find(|old| old["item"]["revision_id"] == item["revision_id"])
                {
                    check(
                        old["item"] == *item && old["reference"] == r["reference"],
                        "ROLLBACK_QUARANTINE",
                    )?;
                    return Ok(c["sync"].clone());
                }
                let b = &r["bundle"];
                let x = &b["envelope"]["header"]["context"];
                for k in ["group_id", "object_kind", "object_id", "revision_id"] {
                    check(item[k] == x[k], "CONTEXT_MISMATCH")?;
                }
                check(
                    digest("p02-v1", "envelope", &b["envelope"])? == item["envelope_digest"]
                        && r["reference"]["object_id"] == item["object_id"]
                        && r["reference"]["object_kind"] == item["object_kind"]
                        && r["reference"]["thread_id"] == x["thread_id"]
                        && item["payload_status"]
                            == if x["action"] == "soft-delete" {
                                "tombstone"
                            } else {
                                "retained"
                            },
                    "CONTEXT_MISMATCH",
                )?;
                let mut temp = c.clone();
                for old in values(t, "items")? {
                    if !values(&temp, "witnesses")?
                        .iter()
                        .any(|w| w["revision_id"] == old["witness"]["revision_id"])
                    {
                        list(&mut temp, "witnesses")?.push(old["witness"].clone());
                    }
                }
                let open = json!({"group_id":x["group_id"],"object_id":x["object_id"],"revision_id":x["revision_id"],"object_kind":x["object_kind"],"thread_id":x["thread_id"],"bundle":b});
                let mut payload = self.note_verify(i, state, &temp, evidence, &open)?;
                wipe_value(&mut payload);
                let write = self.note_cache(&mut temp, b)?;
                let witness = values(&temp, "witnesses")?
                    .iter()
                    .find(|w| w["revision_id"] == item["revision_id"])
                    .ok_or(Error("INTEGRITY_FAILURE"))?
                    .clone();
                list(&mut c["sync"][slot],"items")?.push(json!({"item":item,"cache_id":write.id,"witness":witness,"reference":r["reference"]}));
                writes.push(write);
            }
            Request::SnapshotFiles { inventory } => {
                let t = &c["sync"]["stage"];
                let items = inventory.as_array().ok_or(Error("INVALID_REQUEST"))?;
                check(
                    t.is_object()
                        && items.len() <= 1000
                        && items.len().to_string() == text(&t["result"]["files"]["count"])?,
                    "SYNC_GAP",
                )?;
                let files = self.file_control(i, state)?;
                for item in items {
                    let witness = files["witnesses"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|w| {
                            w["group_id"] == item["group_id"]
                                && w["file_version_id"] == item["file_version_id"]
                                && w["envelope_digest"] == item["envelope_digest"]
                        })
                        .ok_or(Error("UNANCHORED_HISTORY"))?;
                    check(
                        self.file_evidence(i, state, witness)?["envelope"]["header"]["context"]["file_id"]
                            == item["file_id"],
                        "CONTEXT_MISMATCH",
                    )?;
                }
                let mut bytes = b"AnyNote/P12/snapshot-files\0".to_vec();
                bytes.extend(canonical(inventory)?);
                check(
                    hash(&bytes) == t["result"]["files"]["digest"],
                    "INTEGRITY_FAILURE",
                )?;
                c["sync"]["stage"]["files_verified"] = json!(true);
            }
            Request::SnapshotFinish {} => {
                let t = c["sync"]["stage"].clone();
                check(
                    t.is_object()
                        && t["catalog_next"] == t["result"]["catalog_count"]
                        && values(&t, "pages")?.len()
                            == number(&t["result"]["descriptor"]["page_count"])? as usize
                        && t["all_items"] == t["result"]["descriptor"]["item_count"]
                        && values(&t, "items")?.len() == values(&t, "inventory")?.len()
                        && (t["result"]["files"].is_null() || t["files_verified"] == true)
                        && inventory_hash(values(&t, "pages")?)?
                            == t["result"]["descriptor"]["inventory_digest"],
                    "SYNC_GAP",
                )?;
                self.sync_publish(i, state, c, values(&t, "items")?, true)?;
                c["sync"]["cursor"] = t["result"]["descriptor"]["watermark"].clone();
                c["sync"]["watermark"] = c["sync"]["cursor"].clone();
                c["sync"]["stage"] = Value::Null;
                c["sync"]["state"] = json!("SYNCED");
                c["sync"]["quarantine"] = Value::Null;
            }
            Request::DeltaStart { page: p } => {
                self.codec.validate("p11-sync", "delta-page", p)?;
                let s = &mut c["sync"];
                check(
                    !s["cursor"].is_null()
                        && s["stage"].is_null()
                        && p["scope"] == s["scope"]
                        && p["from_cursor"] == s["cursor"],
                    "SYNC_CURSOR_EXPIRED",
                )?;
                check(
                    s["pending"].is_null() || s["pending"]["page"] == *p,
                    "PUBLICATION_PENDING",
                )?;
                check(
                    p["next_cursor"]["generation"] == s["cursor"]["generation"]
                        && p["watermark"]["generation"] == s["cursor"]["generation"],
                    "RESTORE_QUARANTINE",
                )?;
                let from = number(&s["cursor"]["sequence"])?;
                let next = number(&p["next_cursor"]["sequence"])?;
                let high = number(&p["watermark"]["sequence"])?;
                check(
                    next >= from
                        && next <= high
                        && next - from == number(&p["scanned_count"])?
                        && next - from <= 1000
                        && p["complete"] == json!(next == high)
                        && (next > from || next == high),
                    "SYNC_GAP",
                )?;
                let mut last = from;
                let mut ids = BTreeSet::new();
                for e in values(p, "events")? {
                    let n = number(&e["sequence"])?;
                    check(
                        n > last
                            && n <= next
                            && ids.insert(text(&e["event_id"])?)
                            && (s["scope"]["group_id"].is_null()
                                || e["group_id"] == s["scope"]["group_id"]),
                        "SYNC_GAP",
                    )?;
                    last = n;
                }
                if s["pending"].is_null() {
                    s["pending"] = json!({"page":p,"items":[]});
                }
                s["state"] = json!("STAGING");
            }
            Request::DeltaCancel {} => {
                c["sync"]["pending"] = Value::Null;
                if c["sync"]["state"] != "RESTORE_QUARANTINE" {
                    c["sync"]["state"] = json!(if c["sync"]["cursor"].is_null() {
                        "NEW"
                    } else {
                        "SYNCED"
                    });
                }
            }
            Request::DeltaFinish {} => {
                let p = c["sync"]["pending"].clone();
                check(
                    p.is_object()
                        && values(&p["page"], "events")?.iter().all(|e| {
                            !e["revision_id"].is_null()
                                && p["items"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .any(|v| v["item"]["revision_id"] == e["revision_id"])
                        }),
                    "SYNC_GAP",
                )?;
                self.sync_publish(i, state, c, values(&p, "items")?, false)?;
                c["sync"]["cursor"] = p["page"]["next_cursor"].clone();
                c["sync"]["watermark"] = p["page"]["watermark"].clone();
                c["sync"]["pending"] = Value::Null;
                c["sync"]["state"] = json!("SYNCED");
            }
        }
        self.note_commit(i, cap, state, fence, c, &writes, None)?;
        Ok(c["sync"].clone())
    }
}
