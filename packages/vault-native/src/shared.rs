//! Closed independently pinned shared-group authority. Public evidence is not a signing capability.
use super::*;
use crate::device_groups::{
    common, historical, key_commitment, public_sign, recipient, signer, verify_genesis_kind,
};
use crate::device_roster::{Roster, digest, signed};
use anynote_crypto_core::crypto;
use anynote_crypto_core::history::HistoryAnchor;
use std::collections::{BTreeMap, BTreeSet};
fn array<'a>(v: &'a Value, k: &str) -> Result<&'a Vec<Value>> {
    v[k].as_array().ok_or(Error("SCHEMA_MISMATCH"))
}
fn number(v: &Value) -> Result<u64> {
    text(v)?.parse().map_err(|_| Error("SCHEMA_MISMATCH"))
}
fn policy_head(p: &Value) -> Result<Value> {
    Ok(json!({"version":p["body"]["version"],"digest":digest("p02-group-c2","policy",p)?}))
}
fn history_head(p: &Value) -> Result<Value> {
    Ok(json!({"version":p["body"]["sequence"],"digest":digest("p02-group-c2","history",p)?}))
}
fn anchor(proof: &Value, account: &Value) -> Result<Value> {
    array(proof, "accounts")?
        .iter()
        .find(|a| a["pins"]["account_id"] == *account)
        .cloned()
        .ok_or(Error("PINNED_ACCOUNT_REQUIRED"))
}
fn at(codec: &Codec, proof: &Value, sender: &Value) -> Result<Roster> {
    let a = anchor(proof, &sender["account_id"])?;
    historical(codec, &a["snapshot"], &a["pins"], &sender["roster_head"])
}
fn scope_check(proof: &Value, r: &Value) -> Result<()> {
    check(
        r["body"]["service_id"] == proof["pin"]["service_id"]
            && r["body"]["group_id"] == proof["pin"]["group_id"],
        "CONTEXT_MISMATCH",
    )
}
fn actor(codec: &Codec, proof: &Value, r: &Value, kind: &str, cap: &str) -> Result<Value> {
    scope_check(proof, r)?;
    let a = at(codec, proof, &r["body"]["signer"])?;
    let d = a.active(text(&r["body"]["signer"]["device_id"])?, Some(cap))?;
    check(
        signer(&a, text(&r["body"]["signer"]["device_id"])?)? == r["body"]["signer"],
        "ROSTER_CHANGED",
    )?;
    signed(
        codec,
        "p02-group-c2",
        kind,
        r,
        text(&d.certificate["body"]["device_signing_key"])?,
    )?;
    Ok(d.certificate.clone())
}
fn role(members: &Value, sender: &Value) -> Result<String> {
    let m = members
        .as_array()
        .ok_or(Error("SCHEMA_MISMATCH"))?
        .iter()
        .find(|m| {
            m["account_id"] == sender["account_id"]
                && m["root_fingerprint"] == sender["root_fingerprint"]
        })
        .ok_or(Error("ACCESS_REVOKED"))?;
    Ok(text(&m["role"])?.into())
}
fn verify_invite(
    codec: &Codec,
    proof: &Value,
    i: &Value,
    policy: &Value,
    members: &Value,
) -> Result<()> {
    actor(codec, proof, i, "invitation", "sign-content")?;
    check(
        role(members, &i["body"]["signer"])? == "owner" && i["body"]["policy"] == *policy,
        "OWNER_REQUIRED",
    )?;
    let a = anchor(proof, &i["body"]["target_account_id"])?;
    check(
        a["pins"]["root_fingerprint"] == i["body"]["target_root_fingerprint"]
            && !members
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["account_id"] == i["body"]["target_account_id"]),
        "TARGET_ROOT_MISMATCH",
    )
}
fn verify_accept(codec: &Codec, proof: &Value, i: &Value, a: &Value, policy: &Value) -> Result<()> {
    actor(codec, proof, a, "acceptance", "sign-content")?;
    check(
        a["body"]["operation_id"] == i["body"]["operation_id"]
            && a["body"]["invitation_digest"] == digest("p02-group-c2", "invitation", i)?
            && a["body"]["policy"] == *policy
            && a["body"]["signer"]["account_id"] == i["body"]["target_account_id"]
            && a["body"]["signer"]["root_fingerprint"] == i["body"]["target_root_fingerprint"],
        "INVITATION_CONTEXT_MISMATCH",
    )
}
#[allow(clippy::too_many_arguments)]
fn apply_policy(
    codec: &Codec,
    proof: &Value,
    p: &Value,
    current: &Value,
    members: &Value,
    kind: &str,
    archived: bool,
    admission: bool,
) -> Result<(Value, bool, bool)> {
    actor(codec, proof, p, "policy", "sign-content")?;
    let b = &p["body"];
    check(role(members, &b["signer"])? == "owner", "OWNER_REQUIRED")?;
    check(
        b["predecessor"] == *current && number(&b["version"])? == number(&current["version"])? + 1,
        "POLICY_CHANGED",
    )?;
    let mut next = members.as_array().unwrap().clone();
    let mut loss = false;
    let mut archived = archived;
    let target = &b["payload"]["target_account_id"];
    match text(&b["action"])? {
        "admit" => {
            check(
                admission && next.len() < 20,
                "ADMISSION_REQUIRES_COMPLETE_GRANTS",
            )?;
            let i = &b["payload"]["invitation"];
            verify_invite(codec, proof, i, current, members)?;
            verify_accept(codec, proof, i, &b["payload"]["acceptance"], current)?;
            check(
                b["operation_id"] == i["body"]["operation_id"],
                "INVITATION_CONTEXT_MISMATCH",
            )?;
            next.push(json!({"account_id":i["body"]["target_account_id"],"root_fingerprint":i["body"]["target_root_fingerprint"],"role":i["body"]["role"]}));
        }
        "remove" => {
            let old = next
                .iter()
                .find(|m| m["account_id"] == *target)
                .ok_or(Error("INVALID_MEMBER_REMOVAL"))?;
            check(old["role"] != "owner", "INVALID_MEMBER_REMOVAL")?;
            next.retain(|m| m["account_id"] != *target);
            loss = true;
        }
        "role" => {
            let m = next
                .iter_mut()
                .find(|m| m["account_id"] == *target)
                .ok_or(Error("INVALID_ROLE_CHANGE"))?;
            check(
                m["role"] != "owner" && m["role"] != b["payload"]["role"],
                "INVALID_ROLE_CHANGE",
            )?;
            loss = m["role"] == "editor" && b["payload"]["role"] == "reader";
            m["role"] = b["payload"]["role"].clone();
        }
        "archive" => {
            check(!archived, "ARCHIVE_STATE_MISMATCH")?;
            archived = true;
        }
        "unarchive" => {
            check(archived, "ARCHIVE_STATE_MISMATCH")?;
            archived = false;
        }
        "transfer" => {
            check(
                kind == "shared" && !p["cosignature"].is_null(),
                "PRIVATE_TRANSFER_FORBIDDEN",
            )?;
            let incoming = &b["payload"]["incoming_signer"];
            let r = at(codec, proof, incoming)?;
            let d = r.active(text(&incoming["device_id"])?, Some("sign-content"))?;
            check(
                signer(&r, text(&incoming["device_id"])?)? == *incoming
                    && role(members, incoming)? != "owner",
                "INCOMING_OWNER_REQUIRED",
            )?;
            crypto::verify(
                &codec.signing("p02-group-c2", "policy-body", b)?,
                text(&p["cosignature"])?,
                &un64(text(&d.certificate["body"]["device_signing_key"])?)?,
            )?;
            for m in &mut next {
                if m["role"] == "owner" {
                    m["role"] = json!("editor");
                }
                if m["account_id"] == incoming["account_id"] {
                    m["role"] = json!("owner");
                }
            }
        }
        _ => return Err(Error("INVALID_POLICY_ACTION")),
    }
    if b["action"] != "transfer" {
        check(p["cosignature"].is_null(), "UNEXPECTED_COSIGNATURE")?;
    }
    next.sort_by(|a, b| a["account_id"].as_str().cmp(&b["account_id"].as_str()));
    let next = json!(next);
    codec.validate("p02-group-c2", "members", &next)?;
    check(next == b["members"], "MEMBERSHIP_RESULT_MISMATCH")?;
    Ok((next, loss, archived))
}
fn grant_order(r: &Value) -> String {
    let c = &r["body"]["context"];
    let recipient = &c["recipient"];
    format!(
        "{:0>19}/{}/{}/{}",
        c["key_epoch"].as_str().unwrap(),
        recipient["account_id"].as_str().unwrap(),
        recipient["kind"].as_str().unwrap(),
        recipient["device_id"].as_str().unwrap_or("")
    )
}
fn grant_commitment(codec: &Codec, pages: &[Value]) -> Result<Value> {
    check(!pages.is_empty() && pages.len() <= 1000, "RESOURCE_LIMIT")?;
    let count = pages
        .iter()
        .map(|p| p["records"].as_array().map_or(0, Vec::len))
        .sum::<usize>();
    let mut b = b"AnyNote/p02-group-c2/hash/grant-inventory\0".to_vec();
    b.extend((pages.len() as u32).to_be_bytes());
    b.extend((count as u64).to_be_bytes());
    let mut last = None;
    for (n, p) in pages.iter().enumerate() {
        codec.validate("p02-group-c2", "grant-page", p)?;
        check(number(&p["page_index"])? == n as u64, "INVALID_PAGE_ORDER")?;
        let records = array(p, "records")?;
        if n + 1 < pages.len() && records.len() < 500 {
            let mut aug = p.clone();
            aug["records"]
                .as_array_mut()
                .unwrap()
                .push(pages[n + 1]["records"][0].clone());
            check(canonical(&aug)?.len() > 1048576, "INVALID_PAGE_PACKING")?;
        }
        b.extend((n as u32).to_be_bytes());
        b.extend((records.len() as u32).to_be_bytes());
        b.extend((canonical(p)?.len() as u32).to_be_bytes());
        b.extend(un64(&digest("p02-group-c2", "grant-page", p)?)?);
        for r in records {
            let order = grant_order(r);
            check(
                last.as_ref().is_none_or(|old| old < &order),
                "UNORDERED_OR_DUPLICATE",
            )?;
            last = Some(order);
        }
    }
    Ok(
        json!({"digest":hash(&b),"record_count":count.to_string(),"page_count":pages.len().to_string()}),
    )
}
pub(crate) struct Verified {
    pub policy: Value,
    pub members: Value,
    pub epochs: Vec<Value>,
    pub history: Value,
    pub records: BTreeMap<String, Value>,
    pub rosters: Value,
    pub write_state: &'static str,
    pub grants: Vec<Value>,
    pub issuer: Value,
    pub epoch_head: Value,
    pub kind: String,
}
impl Verified {
    pub fn reference(&self) -> Value {
        json!({"membership":self.policy,"key_epoch":self.epochs.last().unwrap()["key_epoch"],"epoch_digest":self.epochs.last().unwrap()["epoch_digest"],"history_checkpoint_digest":self.history})
    }
}
pub(crate) fn verify(
    codec: &Codec,
    proof: &Value,
    own: &Value,
    known: Option<&Value>,
    witnesses: &[Value],
    local_genesis: bool,
) -> Result<Verified> {
    codec.validate("p10-shared", "adopt-request", proof)?;
    let pin = &proof["pin"];
    let j = &proof["journal"];
    check(
        pin["group_id"] == j["group_id"] && pin["service_id"] == own["service_id"],
        "CONTEXT_MISMATCH",
    )?;
    let mut ids = BTreeSet::new();
    for a in array(proof, "accounts")? {
        check(
            ids.insert(text(&a["pins"]["account_id"])?),
            "DUPLICATE_ACCOUNT",
        )?;
        let prior = known
            .and_then(|k| {
                k["accounts"]
                    .as_array()?
                    .iter()
                    .find(|p| p["pins"] == a["pins"])
            })
            .map(|p| &p["snapshot"]["head"]);
        Roster::replay(codec, &a["snapshot"], &a["pins"], prior)?;
    }
    check(
        anchor(proof, &own["account_id"])?["pins"] == *own,
        "ROOT_PIN_MISMATCH",
    )?;
    let owner = anchor(proof, &pin["owner_account_id"])?;
    check(
        owner["pins"]["root_fingerprint"] == pin["owner_root_fingerprint"],
        "ROOT_PIN_MISMATCH",
    )?;
    let genesis = &j["genesis"];
    let g = &genesis["commit"]["body"]["policy"];
    check(
        digest("p02-group-c2", "policy", g)? == pin["genesis_digest"],
        "GENESIS_PIN_MISMATCH",
    )?;
    let kind = text(&g["body"]["payload"]["group_kind"])?.to_string();
    verify_genesis_kind(codec, genesis, &owner["snapshot"], &owner["pins"], &kind)?;
    if let Some(k) = known {
        check(
            k["pin"]["service_id"] == pin["service_id"]
                && k["pin"]["group_id"] == pin["group_id"]
                && k["pin"]["owner_root_fingerprint"] == pin["owner_root_fingerprint"]
                && k["pin"]["genesis_digest"] == pin["genesis_digest"],
            "ROLLBACK_QUARANTINE",
        )?;
        let old = array(&k["journal"], "events")?;
        let current = array(j, "events")?;
        check(
            current.len() >= old.len() && old.iter().zip(current).all(|(a, b)| a == b),
            "ROLLBACK_QUARANTINE",
        )?;
    }
    let i = &genesis["commit"]["body"]["intent"];
    let mut v = Verified {
        policy: policy_head(g)?,
        members: g["body"]["members"].clone(),
        epochs: vec![
            json!({"key_epoch":"0","epoch_digest":digest("p02-group-c2","epoch-intent",i)?,"key_commitment":i["body"]["key_commitment"]}),
        ],
        history: Value::Null,
        records: BTreeMap::new(),
        rosters: i["body"]["rosters"].clone(),
        write_state: "UNANCHORED_HISTORY",
        grants: genesis["pages"][0]["records"].as_array().unwrap().clone(),
        issuer: i["body"]["signer"].clone(),
        epoch_head: json!({"version":"0","digest":digest("p02-group-c2","epoch-commit",&genesis["commit"])?}),
        kind,
    };
    let mut archived = false;
    let mut removal = false;
    let mut history_required = false;
    let mut history_known = local_genesis;
    let mut previous_history = Value::Null;
    let mut independent_seen = pin["history"].is_null();
    let mut operations = BTreeSet::new();
    operations.insert(text(&g["body"]["operation_id"])?);
    let mut observed = BTreeMap::<String, u64>::new();
    for r in array(&i["body"], "rosters")? {
        observed.insert(
            text(&r["account_id"])?.into(),
            number(&r["roster"]["version"])?,
        );
    }
    for (index, e) in array(j, "events")?.iter().enumerate() {
        if let Some(k) = known
            && index == array(&k["journal"], "events")?.len()
        {
            for a in array(k, "accounts")? {
                observed.insert(
                    text(&a["pins"]["account_id"])?.into(),
                    number(&a["snapshot"]["head"]["version"])?,
                );
            }
        }
        let mut refs = Vec::new();
        match text(&e["kind"])? {
            "policy" => {
                refs.push(&e["policy"]["body"]["signer"]);
                if e["policy"]["body"]["action"] == "transfer" {
                    refs.push(&e["policy"]["body"]["payload"]["incoming_signer"]);
                }
            }
            "epoch" => {
                refs.extend(array(&e["commit"]["body"]["intent"]["body"], "rosters")?.iter());
                refs.push(&e["commit"]["body"]["intent"]["body"]["signer"]);
                if e["commit"]["body"]["policy"]["body"]["action"] == "admit" {
                    refs.push(&e["commit"]["body"]["policy"]["body"]["payload"]["acceptance"]["body"]["signer"]);
                }
            }
            "history" => {
                refs.extend(array(&e["history"]["body"]["descriptor"], "closed_rosters")?.iter());
                refs.push(&e["history"]["body"]["signer"]);
            }
            _ => return Err(Error("INVALID_GROUP_EVENT")),
        };
        for r in refs {
            let id = text(&r["account_id"])?;
            let head = if r["roster"].is_object() {
                &r["roster"]
            } else {
                &r["roster_head"]
            };
            let version = number(&head["version"])?;
            check(
                observed.get(id).is_none_or(|old| version >= *old),
                "ROLLBACK_QUARANTINE",
            )?;
            let a = anchor(proof, &r["account_id"])?;
            historical(codec, &a["snapshot"], &a["pins"], head)?;
            observed.insert(id.into(), version);
        }

        match text(&e["kind"])? {
            "policy" => {
                let p = &e["policy"];
                check(
                    operations.insert(text(&p["body"]["operation_id"])?),
                    "OPERATION_REPLAY",
                )?;
                let (next, loss, arch) = apply_policy(
                    codec, proof, p, &v.policy, &v.members, &v.kind, archived, false,
                )?;
                v.members = next;
                v.policy = policy_head(p)?;
                archived = arch;
                history_required |= loss;
                removal |= p["body"]["action"] == "remove";
            }
            "epoch" => {
                let c = &e["commit"];
                let b = &c["body"];
                let i = &b["intent"];
                let ib = &i["body"];
                check(
                    operations.insert(text(&b["operation_id"])?),
                    "OPERATION_REPLAY",
                )?;
                let cert = actor(codec, proof, i, "epoch-intent", "distribute-group-key")?;
                let writer = role(&v.members, &ib["signer"])?;
                let reason = text(&ib["reason"])?;
                let mut next = v.members.clone();
                let mut membership = v.policy.clone();
                if !b["policy"].is_null() {
                    check(
                        reason == "admission"
                            && writer == "owner"
                            && !archived
                            && b["policy"]["body"]["action"] == "admit"
                            && b["policy"]["body"]["operation_id"] == b["operation_id"],
                        "OWNER_REQUIRED",
                    )?;
                    (next, _, _) = apply_policy(
                        codec,
                        proof,
                        &b["policy"],
                        &v.policy,
                        &v.members,
                        &v.kind,
                        archived,
                        true,
                    )?;
                    membership = policy_head(&b["policy"])?;
                }
                check(
                    ib["expected_policy"] == v.policy
                        && ib["membership"] == membership
                        && ib["previous_epoch"] == v.epoch_head
                        && number(&ib["next_epoch"])? == v.epochs.len() as u64
                        && ib["retained_epochs"] == json!(v.epochs)
                        && ib["history_checkpoint_digest"] == v.history,
                    "POLICY_OR_EPOCH_CHANGED",
                )?;
                match reason {
                    "admission" => check(!b["policy"].is_null(), "ACCEPTED_INVITATION_REQUIRED")?,
                    "member-removal" => check(
                        removal && writer != "reader" && b["policy"].is_null(),
                        "WRITER_MAINTENANCE_REQUIRED",
                    )?,
                    "roster-maintenance" => check(
                        !removal && b["policy"].is_null() && ib["rosters"] != v.rosters,
                        "MANDATORY_ROSTER_MAINTENANCE_REQUIRED",
                    )?,
                    "optional" => check(
                        !removal
                            && writer != "reader"
                            && ib["rosters"] == v.rosters
                            && b["policy"].is_null(),
                        "OPTIONAL_REKEY_NOT_AUTHORIZED",
                    )?,
                    _ => return Err(Error("INVALID_EPOCH_REASON")),
                };
                let rs = array(ib, "rosters")?;
                check(rs.len() == next.as_array().unwrap().len(), "ROSTER_CHANGED")?;
                let mut recipients = Vec::new();
                for (m, r) in next.as_array().unwrap().iter().zip(rs) {
                    check(
                        m["account_id"] == r["account_id"]
                            && m["root_fingerprint"] == r["root_fingerprint"],
                        "ROSTER_CHANGED",
                    )?;
                    let a = anchor(proof, &m["account_id"])?;
                    let roster = historical(codec, &a["snapshot"], &a["pins"], &r["roster"])?;
                    check(
                        roster.generation == r["recovery_generation"],
                        "ROSTER_CHANGED",
                    )?;
                    for (id, d) in &roster.devices {
                        if d.active {
                            recipients.push(recipient(&roster, Some(id))?);
                        }
                    }
                    recipients.push(recipient(&roster, None)?);
                }
                let epoch = json!({"key_epoch":ib["next_epoch"],"epoch_digest":digest("p02-group-c2","epoch-intent",i)?,"key_commitment":ib["key_commitment"]});
                check(
                    !v.epochs
                        .iter()
                        .any(|e| e["key_commitment"] == epoch["key_commitment"]),
                    "FRESH_KEY_REQUIRED",
                )?;
                let mut epochs = v.epochs.clone();
                epochs.push(epoch.clone());
                let pages = array(e, "pages")?;
                let pc = grant_commitment(codec, pages)?;
                let d = &b["descriptor"];
                for (kind, r) in [("descriptor", d), ("epoch-commit", c)] {
                    scope_check(proof, r)?;
                    signed(
                        codec,
                        "p02-group-c2",
                        kind,
                        r,
                        text(&cert["body"]["device_signing_key"])?,
                    )?;
                    check(
                        r["body"]["operation_id"] == ib["operation_id"],
                        "GRANT_CONTEXT_MISMATCH",
                    )?;
                }
                let db = &d["body"];
                check(
                    db["intent_digest"] == epoch["epoch_digest"]
                        && db["membership"] == membership
                        && db["signer"] == ib["signer"]
                        && db["inventory_digest"] == pc["digest"]
                        && db["record_count"] == pc["record_count"]
                        && db["page_count"] == pc["page_count"]
                        && db["epoch_inventory_digest"]
                            == digest("p02-group-c2", "epochs", &json!(epochs))?,
                    "GRANT_DESCRIPTOR_MISMATCH",
                )?;
                let mut expected = BTreeSet::new();
                for epoch in &epochs {
                    for recipient in &recipients {
                        expected.insert(canonical(&json!({"purpose":"group-key-distribution","contract":"p02-identity-c1","protocol":"anynote","protocol_version":1,"service_id":pin["service_id"],"group_id":pin["group_id"],"key_epoch":epoch["key_epoch"],"epoch_digest":epoch["epoch_digest"],"membership_head":membership,"operation_id":ib["operation_id"],"issuer":ib["signer"],"recipient":recipient}))?);
                    }
                }
                let mut grants = Vec::new();
                for page in pages {
                    check(
                        page["service_id"] == pin["service_id"]
                            && page["group_id"] == pin["group_id"]
                            && page["operation_id"] == ib["operation_id"],
                        "GRANT_CONTEXT_MISMATCH",
                    )?;
                    for r in array(page, "records")? {
                        check(
                            expected.remove(&canonical(&r["body"]["context"])?),
                            "RECIPIENT_COVERAGE_MISMATCH",
                        )?;
                        signed(
                            codec,
                            "p02-identity-c1",
                            "grant",
                            r,
                            text(&cert["body"]["device_signing_key"])?,
                        )?;
                        grants.push(r.clone());
                    }
                }
                check(expected.is_empty(), "RECIPIENT_COVERAGE_MISMATCH")?;
                if reason == "roster-maintenance" {
                    history_required = true;
                }
                v.members = next;
                v.policy = membership;
                v.epochs = epochs;
                v.rosters = ib["rosters"].clone();
                v.grants = grants;
                v.issuer = ib["signer"].clone();
                v.epoch_head = json!({"version":ib["next_epoch"],"digest":digest("p02-group-c2","epoch-commit",c)?});
                removal = false;
            }
            "history" => {
                let h = &e["history"];
                let b = &h["body"];
                check(
                    operations.insert(text(&b["operation_id"])?),
                    "OPERATION_REPLAY",
                )?;
                let cert = actor(codec, proof, h, "history", "sign-content")?;
                check(
                    role(&v.members, &b["signer"])? != "reader",
                    "WRITER_REQUIRED",
                )?;
                let d = &b["descriptor"];
                check(
                    b["predecessor"] == previous_history
                        && number(&b["sequence"])?
                            == if previous_history.is_null() {
                                0
                            } else {
                                number(&previous_history["version"])? + 1
                            }
                        && d["closed_policy"] == v.reference()
                        && d["predecessor_checkpoint_digest"] == v.history,
                    "HISTORY_CONTEXT_MISMATCH",
                )?;
                let s = &b["signer"];
                check(
                    d["signer"]
                        == json!({"account_id":s["account_id"],"device_id":s["device_id"],"root_fingerprint":s["root_fingerprint"],"recovery_generation":s["recovery_generation"],"roster":s["roster_head"]}),
                    "HISTORY_CONTEXT_MISMATCH",
                )?;
                let closed = array(d, "closed_rosters")?;
                check(
                    closed.len() == v.members.as_array().unwrap().len(),
                    "ROSTER_CHANGED",
                )?;
                for (m, r) in v.members.as_array().unwrap().iter().zip(closed) {
                    let a = anchor(proof, &m["account_id"])?;
                    let roster = historical(codec, &a["snapshot"], &a["pins"], &r["roster"])?;
                    check(
                        r["account_id"] == m["account_id"]
                            && r["root_fingerprint"] == m["root_fingerprint"]
                            && r["recovery_generation"] == roster.generation,
                        "ROSTER_CHANGED",
                    )?;
                }
                let pages = array(e, "pages")?;
                HistoryAnchor::verify(
                    codec,
                    &canonical(h)?,
                    &pages.iter().map(canonical).collect::<Result<Vec<_>>>()?,
                    &digest("p02-group-c2", "history", h)?,
                    &un64(text(&cert["body"]["device_signing_key"])?)?,
                )?;
                let mut records = BTreeMap::new();
                for p in pages {
                    for record in array(p, "records")? {
                        records.insert(text(&record["revision_id"])?.into(), record.clone());
                    }
                }
                for (id, r) in &v.records {
                    check(records.get(id) == Some(r), "HISTORY_COMPLETENESS_MISMATCH")?;
                }
                v.records = records;
                previous_history = history_head(h)?;
                let protected = known.is_some_and(|k| {
                    k["journal"]["events"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|e| e["kind"] == "history" && e["history"] == *h)
                });
                history_known |= protected || previous_history == pin["history"];
                independent_seen |= previous_history == pin["history"];
                v.history = json!(digest("p02-file-c1", "history-checkpoint", d)?);
                history_required = false;
            }
            _ => return Err(Error("INVALID_GROUP_EVENT")),
        }
    }
    check(independent_seen, "HISTORY_PIN_MISMATCH")?;
    if history_known {
        for r in witnesses {
            let id = text(&r["revision_id"])?;
            if let Some(old) = v.records.get(id) {
                check(old == r, "REVISION_ID_CONFLICT")?;
            }
            v.records.insert(id.into(), r.clone());
        }
    }
    let mut current = Vec::new();
    for m in v.members.as_array().unwrap() {
        let a = anchor(proof, &m["account_id"])?;
        let r = Roster::replay(codec, &a["snapshot"], &a["pins"], None)?;
        check(
            m["root_fingerprint"] == r.pins["root_fingerprint"],
            "ROOT_PIN_MISMATCH",
        )?;
        current.push(json!({"account_id":m["account_id"],"root_fingerprint":m["root_fingerprint"],"recovery_generation":r.generation,"roster":r.head}));
    }
    v.write_state = if archived {
        "ARCHIVED"
    } else if removal || json!(current) != v.rosters {
        "REKEY_REQUIRED"
    } else if !history_known {
        "UNANCHORED_HISTORY"
    } else if history_required {
        "HISTORY_CLOSURE_REQUIRED"
    } else {
        "WRITABLE"
    };
    Ok(v)
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Adopt {
        proof: Value,
    },
    Details {
        group_id: String,
    },
    Card {
        group_id: String,
    },
    Invite {
        group_id: String,
        account: Value,
        expected_root: String,
        role: String,
        confirmed: bool,
    },
    Accept {
        group_id: String,
        invitation: Value,
        confirmed: bool,
    },
    Policy {
        group_id: String,
        policy_action: String,
        target_account_id: Option<String>,
        role: Option<String>,
        confirmed: bool,
    },
    TransferProposal {
        group_id: String,
        account_id: String,
        device_id: String,
        confirmed: bool,
    },
    Cosign {
        group_id: String,
        policy: Value,
        confirmed: bool,
    },
    Transfer {
        group_id: String,
        policy: Value,
        confirmed: bool,
    },
    History {
        group_id: String,
    },
    Epoch {
        group_id: String,
        reason: String,
        confirmed: bool,
    },
    OwnGrants {
        group_id: String,
        device_id: String,
    },
    OwnKeys {
        group_id: String,
        records: Vec<Value>,
    },
    Keys {
        group_id: String,
    },
    CancelAttempt {
        group_id: String,
        confirmed: bool,
    },
    FinishCancel {
        group_id: String,
        result: Value,
    },
    Retry {
        group_id: String,
    },
    Complete {
        group_id: String,
        result: Value,
    },
}
impl Request {
    pub(crate) fn group(&self) -> Result<String> {
        Ok(match self {
            Self::Adopt { proof } => text(&proof["pin"]["group_id"])?.into(),
            Self::Details { group_id }
            | Self::Card { group_id }
            | Self::Invite { group_id, .. }
            | Self::Accept { group_id, .. }
            | Self::Policy { group_id, .. }
            | Self::TransferProposal { group_id, .. }
            | Self::Cosign { group_id, .. }
            | Self::Transfer { group_id, .. }
            | Self::History { group_id }
            | Self::Epoch { group_id, .. }
            | Self::OwnGrants { group_id, .. }
            | Self::OwnKeys { group_id, .. }
            | Self::Keys { group_id }
            | Self::CancelAttempt { group_id, .. }
            | Self::FinishCancel { group_id, .. }
            | Self::Retry { group_id }
            | Self::Complete { group_id, .. } => group_id.clone(),
        })
    }
}
pub(crate) struct Outcome {
    pub data: Value,
    pub result: Value,
    pub keys: Value,
}
impl Drop for Outcome {
    fn drop(&mut self) {
        wipe_value(&mut self.keys);
        wipe_value(&mut self.data);
    }
}
fn attempt(family: &str, body: Value, pages: Value, commit: Value) -> Value {
    json!({"family":family,"body":body,"pages":pages,"commit":commit,"state":"PREPARED"})
}
pub(crate) fn pin(genesis: &Value) -> Result<Value> {
    let p = &genesis["commit"]["body"]["policy"];
    Ok(
        json!({"version":1,"service_id":p["body"]["service_id"],"group_id":p["body"]["group_id"],"owner_account_id":p["body"]["members"][0]["account_id"],"owner_root_fingerprint":p["body"]["members"][0]["root_fingerprint"],"genesis_digest":digest("p02-group-c2","policy",p)?,"history":null}),
    )
}
fn own_roster(codec: &Codec, proof: &Value, scope: &Scope) -> Result<Roster> {
    let a = anchor(proof, &json!(scope.account_id))?;
    Roster::replay(codec, &a["snapshot"], &a["pins"], None)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn command(
    codec: &Codec,
    request: &Request,
    scope: &Scope,
    pins: &Value,
    snapshot: &Value,
    old: Option<&Value>,
    witnesses: &[Value],
    signing: &[u8],
    encryption: &[u8],
    secrets: &Value,
) -> Result<Outcome> {
    let mut data = old.cloned().unwrap_or(Value::Null);
    let mut proof = if let Request::Adopt { proof } = request {
        proof.clone()
    } else {
        data["proof"].clone()
    };
    let own = proof["accounts"]
        .as_array_mut()
        .ok_or(Error("GROUP_PROOF_REQUIRED"))?
        .iter_mut()
        .find(|a| a["pins"]["account_id"] == scope.account_id)
        .ok_or(Error("ROOT_PIN_MISMATCH"))?;
    check(own["pins"] == *pins, "ROOT_PIN_MISMATCH")?;
    own["snapshot"] = snapshot.clone();
    let known = old.map(|d| &d["proof"]);
    let local = known.is_some_and(|k| {
        k["pin"]["owner_account_id"] == scope.account_id
            && k["journal"]["events"].as_array().is_some_and(Vec::is_empty)
    });
    let v = verify(codec, &proof, pins, known, witnesses, local)?;
    let roster = own_roster(codec, &proof, scope)?;
    let own = roster.active(&scope.device_id, Some("sign-content"))?;
    check(
        own.certificate["body"]["device_signing_key"] == b64(&signing[32..]),
        "DEVICE_KEY_MISMATCH",
    )?;
    let sender = signer(&roster, &scope.device_id)?;
    let group = &proof["pin"]["group_id"];
    let ctx = json!({"service_id":scope.service_id,"group_id":group});
    let mut result = Value::Null;
    let mut keys = json!([]);
    let mut next_attempt = None;
    match request {
        Request::Adopt { .. } => {
            codec.validate("p10-shared", "adopt-request", &proof)?;
            data = json!({"purpose":"p10-group-proof","version":1,"proof":proof,"attempt":old.map_or(Value::Null,|d|d["attempt"].clone()),"pending_key":old.map_or(Value::Null,|d|d["pending_key"].clone())});
            result = json!({"group_id":group,"members":v.members,"write_state":v.write_state});
        }
        Request::Details { .. } => {
            result = json!({"scope":ctx,"kind":v.kind,"members":v.members,"policy":v.reference(),"epochs":v.epochs,"write_state":v.write_state})
        }
        Request::Card { .. } => {
            let h = array(&proof["journal"], "events")?
                .iter()
                .rev()
                .find(|e| e["kind"] == "history")
                .ok_or(Error("INDEPENDENT_HISTORY_REQUIRED"))?;
            let head = history_head(&h["history"])?;
            result = proof.clone();
            result["pin"]["history"] = head;
        }
        Request::CancelAttempt { confirmed, .. } => {
            check(
                *confirmed
                    && data["attempt"].is_object()
                    && data["attempt"]["state"] != "COMMITTED"
                    && data["attempt"]["state"] != "CANCELLED",
                "CONFIRMATION_REQUIRED",
            )?;
            let op = attempt_operation(&data["attempt"])?;
            result = json!({"version":1,"operation_id":op});
        }
        Request::FinishCancel { result: r, .. } => {
            codec.validate("p10-shared", "result", r)?;
            let op = attempt_operation(&data["attempt"])?;
            let body = json!({"version":1,"operation_id":op});
            check(
                r["group_id"] == *group
                    && r["operation_id"] == op
                    && r["state"] == "CANCELLED"
                    && r["digest"] == hash(&canonical(&body)?),
                "RECEIPT_CONTEXT_MISMATCH",
            )?;
            data["attempt"]["state"] = json!("CANCELLED");
            wipe_value(&mut data["pending_key"]);
            data["pending_key"] = Value::Null;
            result = json!({"state":"CANCELLED"});
        }
        Request::Retry { .. } => {
            check(
                data["attempt"].is_object() && data["attempt"]["state"] != "COMMITTED",
                "RECORD_NOT_FOUND",
            )?;
            data["attempt"]["state"] = json!("SENT_UNKNOWN");
            result = data["attempt"].clone();
        }
        Request::Complete { result: r, .. } => {
            codec.validate("p10-shared", "result", r)?;
            let a = &data["attempt"];
            check(a.is_object(), "RECORD_NOT_FOUND")?;
            let body = &a["body"];
            let rec = [
                "invitation",
                "acceptance",
                "policy",
                "intent",
                "commit",
                "history",
            ]
            .iter()
            .find_map(|k| body.get(*k).filter(|v| !v.is_null()));
            let op = rec.map_or(&body["operation_id"], |r| &r["body"]["operation_id"]);
            let final_body = if a["family"] == "epoch" {
                json!({"version":1,"commit":a["commit"]})
            } else {
                body.clone()
            };
            check(
                r["group_id"] == *group
                    && r["operation_id"] == *op
                    && r["digest"] == hash(&canonical(&final_body)?)
                    && r["state"]
                        == match text(&a["family"])? {
                            "invite" => "INVITED",
                            "accept" => "ACCEPTED_PENDING_GRANTS",
                            "policy" => "POLICY_COMMITTED",
                            "consent" => "OWNER_CONSENT",
                            "epoch" => "ACTIVATED",
                            "history" => "HISTORY_CLOSED",
                            "cancel" => "CANCELLED",
                            _ => return Err(Error("INVALID_SHARED_COMMAND")),
                        },
                "RECEIPT_CONTEXT_MISMATCH",
            )?;
            if a["family"] == "epoch" && a["state"] != "COMMITTED" {
                let pending = &data["pending_key"];
                check(
                    pending.is_object()
                        && pending["group_id"] == *group
                        && pending["key_epoch"]
                            == a["commit"]["body"]["intent"]["body"]["next_epoch"]
                        && pending["epoch_digest"]
                            == digest(
                                "p02-group-c2",
                                "epoch-intent",
                                &a["commit"]["body"]["intent"],
                            )?
                        && key_commitment(
                            &ctx,
                            &Zeroizing::new(un64(text(&pending["group_secret"])?)?),
                        )? == a["commit"]["body"]["intent"]["body"]["key_commitment"],
                    "KEY_REPAIR_REQUIRED",
                )?;
                keys = json!([pending]);
            }
            data["attempt"]["state"] = json!("COMMITTED");
            wipe_value(&mut data["pending_key"]);
            data["pending_key"] = Value::Null;
            result = json!({"state":"COMMITTED"});
        }
        Request::Invite {
            account,
            expected_root,
            role: target_role,
            confirmed,
            ..
        } => {
            check(
                *confirmed
                    && ["reader", "editor"].contains(&target_role.as_str())
                    && account["pins"]["root_fingerprint"] == *expected_root,
                "IDENTITY_CONFIRMATION_REQUIRED",
            )?;
            codec.validate("p10-shared", "account-proof", account)?;
            Roster::replay(codec, &account["snapshot"], &account["pins"], None)?;
            let accounts = proof["accounts"].as_array_mut().unwrap();
            if let Some(old) = accounts
                .iter()
                .find(|a| a["pins"]["account_id"] == account["pins"]["account_id"])
            {
                check(old["pins"] == account["pins"], "ROOT_PIN_MISMATCH")?;
            } else {
                accounts.push(account.clone());
            }
            let mut b = common("group-invitation", &ctx, &random_id());
            b["policy"] = v.policy.clone();
            b["signer"] = sender.clone();
            b["target_account_id"] = account["pins"]["account_id"].clone();
            b["target_root_fingerprint"] = account["pins"]["root_fingerprint"].clone();
            b["role"] = json!(target_role);
            b["full_retained_history"] = json!(true);
            b["nonce"] = json!(b64(&libsodium_rs::random::bytes(32)));
            b["expires_at"] = json!((now()? + 172799000).to_string());
            let invite = public_sign(codec, "invitation", b, signing)?;
            verify_invite(codec, &proof, &invite, &v.policy, &v.members)?;
            next_attempt = Some(attempt(
                "invite",
                json!({"version":1,"invitation":invite}),
                json!([]),
                Value::Null,
            ));
        }
        Request::Accept {
            invitation,
            confirmed,
            ..
        } => {
            check(
                *confirmed
                    && invitation["body"]["target_account_id"] == scope.account_id
                    && invitation["body"]["target_root_fingerprint"] == pins["root_fingerprint"],
                "IDENTITY_CONFIRMATION_REQUIRED",
            )?;
            verify_invite(codec, &proof, invitation, &v.policy, &v.members)?;
            check(
                number(&invitation["body"]["expires_at"])? > now()?,
                "TRANSITION_EXPIRED",
            )?;
            let mut b = common(
                "group-invitation-acceptance",
                &ctx,
                text(&invitation["body"]["operation_id"])?,
            );
            b["invitation_digest"] = json!(digest("p02-group-c2", "invitation", invitation)?);
            b["policy"] = v.policy.clone();
            b["signer"] = sender.clone();
            b["full_retained_history"] = json!(true);
            let a = public_sign(codec, "acceptance", b, signing)?;
            verify_accept(codec, &proof, invitation, &a, &v.policy)?;
            next_attempt = Some(attempt(
                "accept",
                json!({"version":1,"acceptance":a}),
                json!([]),
                Value::Null,
            ));
        }
        Request::Policy {
            policy_action,
            target_account_id,
            role: target_role,
            confirmed,
            ..
        } => {
            check(
                *confirmed
                    && ["role", "remove", "archive", "unarchive"].contains(&policy_action.as_str()),
                "CONFIRMATION_REQUIRED",
            )?;
            let payload = if policy_action == "role" {
                json!({"target_account_id":target_account_id,"role":target_role})
            } else if policy_action == "remove" {
                json!({"target_account_id":target_account_id})
            } else {
                json!({})
            };
            let mut members = v.members.clone();
            if policy_action == "remove" {
                members.as_array_mut().unwrap().retain(|m| {
                    Some(text(&m["account_id"]).unwrap()) != target_account_id.as_deref()
                });
            }
            if policy_action == "role" {
                let m = members
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|m| {
                        Some(m["account_id"].as_str().unwrap()) == target_account_id.as_deref()
                    })
                    .ok_or(Error("TARGET_MEMBER_REQUIRED"))?;
                m["role"] = json!(target_role);
            }
            let p = make_policy(
                codec,
                &ctx,
                &v,
                &sender,
                policy_action,
                &payload,
                members,
                signing,
            )?;
            apply_policy(
                codec,
                &proof,
                &p,
                &v.policy,
                &v.members,
                &v.kind,
                v.write_state == "ARCHIVED",
                false,
            )?;
            next_attempt = Some(attempt(
                "policy",
                json!({"version":1,"policy":p}),
                json!([]),
                Value::Null,
            ));
        }
        Request::TransferProposal {
            account_id,
            device_id,
            confirmed,
            ..
        } => {
            check(
                *confirmed && v.kind == "shared" && role(&v.members, &sender)? == "owner",
                "OWNER_REQUIRED",
            )?;
            let a = anchor(&proof, &json!(account_id))?;
            let r = Roster::replay(codec, &a["snapshot"], &a["pins"], None)?;
            let incoming = signer(&r, device_id)?;
            check(
                role(&v.members, &incoming)? != "owner",
                "INCOMING_OWNER_REQUIRED",
            )?;
            let mut members = v.members.clone();
            for m in members.as_array_mut().unwrap() {
                if m["role"] == "owner" {
                    m["role"] = json!("editor");
                }
                if m["account_id"] == *account_id {
                    m["role"] = json!("owner");
                }
            }
            result = make_policy(
                codec,
                &ctx,
                &v,
                &sender,
                "transfer",
                &json!({"incoming_signer":incoming}),
                members,
                signing,
            )?;
        }
        Request::Cosign {
            policy: p,
            confirmed,
            ..
        }
        | Request::Transfer {
            policy: p,
            confirmed,
            ..
        } => {
            check(
                *confirmed && p["body"]["action"] == "transfer",
                "CONFIRMATION_REQUIRED",
            )?;
            let mut p = p.clone();
            let cosign = matches!(request, Request::Cosign { .. });
            if cosign {
                check(
                    p["body"]["payload"]["incoming_signer"] == sender,
                    "INCOMING_OWNER_REQUIRED",
                )?;
                p["cosignature"] = json!(crypto::sign(
                    &codec.signing("p02-group-c2", "policy-body", &p["body"])?,
                    signing
                )?);
            } else {
                check(p["body"]["signer"] == sender, "OWNER_REQUIRED")?;
            }
            apply_policy(
                codec,
                &proof,
                &p,
                &v.policy,
                &v.members,
                &v.kind,
                v.write_state == "ARCHIVED",
                false,
            )?;
            next_attempt = Some(attempt(
                if cosign { "consent" } else { "policy" },
                json!({"version":1,"policy":p}),
                json!([]),
                Value::Null,
            ));
        }
        Request::History { .. } => {
            check(
                v.write_state != "UNANCHORED_HISTORY" && role(&v.members, &sender)? != "reader",
                "INDEPENDENT_HISTORY_REQUIRED",
            )?;
            let pages = history_pages(&ctx, v.records.values().cloned().collect())?;
            let pc = history_commitment(&pages)?;
            let previous = array(&proof["journal"], "events")?
                .iter()
                .rev()
                .find(|e| e["kind"] == "history")
                .map(|e| history_head(&e["history"]))
                .transpose()?
                .unwrap_or(Value::Null);
            let rosters = current_rosters(codec, &proof, &v.members)?;
            let descriptor = json!({"purpose":"history-checkpoint","contract":"p02-file-c1","version":1,"service_id":scope.service_id,"group_id":group,"predecessor_checkpoint_digest":v.history,"closed_policy":v.reference(),"closed_rosters":rosters,"record_count":pc["record_count"],"page_count":pc["page_count"],"inventory_digest":pc["digest"],"signer":{"account_id":scope.account_id,"device_id":scope.device_id,"root_fingerprint":pins["root_fingerprint"],"recovery_generation":roster.generation,"roster":roster.head}});
            let mut b = common("group-history-checkpoint", &ctx, &random_id());
            b["sequence"] = json!(if previous.is_null() {
                "0".into()
            } else {
                (number(&previous["version"])? + 1).to_string()
            });
            b["predecessor"] = previous;
            b["descriptor_signature"] = json!(crypto::sign(
                &codec.signing("p02-file-c1", "checkpoint", &descriptor)?,
                signing
            )?);
            b["descriptor"] = descriptor;
            b["signer"] = sender.clone();
            let h = public_sign(codec, "history", b, signing)?;
            next_attempt = Some(attempt(
                "history",
                json!({"version":1,"history":h,"pages":pages}),
                json!([]),
                Value::Null,
            ));
        }
        Request::Epoch {
            reason, confirmed, ..
        } => {
            check(*confirmed, "CONFIRMATION_REQUIRED")?;
            let p = if reason == "admission" {
                let pending = &proof["journal"]["pending"];
                check(
                    pending["state"] == "ACCEPTED_PENDING_GRANTS",
                    "ACCEPTED_INVITATION_REQUIRED",
                )?;
                let i = &pending["invitation"];
                let a = &pending["acceptance"];
                verify_invite(codec, &proof, i, &v.policy, &v.members)?;
                verify_accept(codec, &proof, i, a, &v.policy)?;
                check(
                    v.write_state == "WRITABLE" && !v.history.is_null(),
                    "INDEPENDENT_HISTORY_REQUIRED",
                )?;
                let mut members = v.members.as_array().unwrap().clone();
                members.push(json!({"account_id":i["body"]["target_account_id"],"root_fingerprint":i["body"]["target_root_fingerprint"],"role":i["body"]["role"]}));
                members.sort_by(|a, b| a["account_id"].as_str().cmp(&b["account_id"].as_str()));
                let mut p = make_policy(
                    codec,
                    &ctx,
                    &v,
                    &sender,
                    "admit",
                    &json!({"invitation":i,"acceptance":a}),
                    json!(members),
                    signing,
                )?;
                p["body"]["operation_id"] = i["body"]["operation_id"].clone();
                public_sign(codec, "policy", p["body"].clone(), signing)?
            } else {
                Value::Null
            };
            let members = if p.is_null() {
                &v.members
            } else {
                &p["body"]["members"]
            };
            let membership = if p.is_null() {
                v.policy.clone()
            } else {
                policy_head(&p)?
            };
            let rosters = current_rosters(codec, &proof, members)?;
            let op = if p.is_null() {
                random_id()
            } else {
                text(&p["body"]["operation_id"])?.into()
            };
            let fresh = Zeroizing::new(libsodium_rs::random::bytes(32));
            let epoch = v.epochs.len().to_string();
            let mut b = common("group-epoch-intent", &ctx, &op);
            b["reason"] = json!(reason);
            b["expected_policy"] = v.policy.clone();
            b["membership"] = membership.clone();
            b["previous_epoch"] = v.epoch_head.clone();
            b["next_epoch"] = json!(epoch);
            b["retained_epochs"] = json!(v.epochs);
            b["key_commitment"] = json!(key_commitment(&ctx, &fresh)?);
            b["rosters"] = rosters;
            b["history_checkpoint_digest"] = v.history.clone();
            b["signer"] = sender.clone();
            b["expires_at"] = json!((now()? + 540000).to_string());
            let intent = public_sign(codec, "epoch-intent", b, signing)?;
            let ed = digest("p02-group-c2", "epoch-intent", &intent)?;
            let mut epochs = v.epochs.clone();
            epochs.push(json!({"key_epoch":epoch,"epoch_digest":ed,"key_commitment":intent["body"]["key_commitment"]}));
            let mut records = Vec::new();
            for m in members.as_array().unwrap() {
                let a = anchor(&proof, &m["account_id"])?;
                let r = Roster::replay(codec, &a["snapshot"], &a["pins"], None)?;
                let mut targets = r
                    .devices
                    .iter()
                    .filter(|(_, d)| d.active)
                    .map(|(id, _)| Some(id.as_str()))
                    .collect::<Vec<_>>();
                targets.push(None);
                for target in targets {
                    let recipient = recipient(&r, target)?;
                    let public = if let Some(id) = target {
                        &r.active(id, Some("receive-group-key"))?.certificate["body"]["device_encryption_key"]
                    } else {
                        &r.identity["body"]["recovery_encryption_key"]
                    };
                    for e in &epochs {
                        let k = if e["key_epoch"] == epoch {
                            Zeroizing::new(fresh.to_vec())
                        } else {
                            let old = array(secrets, "group_keys")?
                                .iter()
                                .find(|k| {
                                    k["group_id"] == *group
                                        && k["key_epoch"] == e["key_epoch"]
                                        && k["epoch_digest"] == e["epoch_digest"]
                                })
                                .ok_or(Error("EPOCH_KEY_REQUIRED"))?;
                            Zeroizing::new(un64(text(&old["group_secret"])?)?)
                        };
                        check(
                            key_commitment(&ctx, &k)? == e["key_commitment"],
                            "KEY_REPAIR_REQUIRED",
                        )?;
                        let c = json!({"purpose":"group-key-distribution","contract":"p02-identity-c1","protocol":"anynote","protocol_version":1,"service_id":scope.service_id,"group_id":group,"key_epoch":e["key_epoch"],"epoch_digest":e["epoch_digest"],"membership_head":membership,"operation_id":op,"issuer":sender,"recipient":recipient});
                        records.push(objects::seal_grant(
                            codec,
                            &canonical(&c)?,
                            &k,
                            &un64(text(public)?)?,
                            signing,
                        )?);
                    }
                }
            }
            records.sort_by_key(grant_order);
            let pages = grant_pages(&ctx, &op, records)?;
            let pc = grant_commitment(codec, &pages)?;
            let mut d = common("group-grant-descriptor", &ctx, &op);
            d["intent_digest"] = json!(ed);
            d["membership"] = membership;
            d["inventory_digest"] = pc["digest"].clone();
            d["record_count"] = pc["record_count"].clone();
            d["page_count"] = pc["page_count"].clone();
            d["epoch_inventory_digest"] = json!(digest("p02-group-c2", "epochs", &json!(epochs))?);
            d["signer"] = sender.clone();
            let descriptor = public_sign(codec, "descriptor", d, signing)?;
            let mut cb = common("group-epoch-commit", &ctx, &op);
            cb["policy"] = p.clone();
            cb["intent"] = intent.clone();
            cb["descriptor"] = descriptor;
            let commit = public_sign(codec, "epoch-commit", cb, signing)?;
            let mut test = proof.clone();
            test["journal"]["events"]
                .as_array_mut()
                .unwrap()
                .push(json!({"kind":"epoch","commit":commit,"pages":pages}));
            verify(codec, &test, pins, Some(&proof), witnesses, local)?;
            data["pending_key"] = json!({"service_id":scope.service_id,"group_id":group,"key_epoch":epoch,"epoch_digest":ed,"group_secret":b64(&fresh)});
            next_attempt = Some(attempt(
                "epoch",
                json!({"version":1,"intent":intent,"policy":p}),
                json!(pages),
                commit,
            ));
        }
        Request::OwnGrants { device_id, .. } => {
            role(&v.members, &sender)?;
            let target = roster.active(device_id, Some("receive-group-key"))?;
            let recipient = recipient(&roster, Some(device_id))?;
            let mut records = Vec::new();
            for e in &v.epochs {
                let k = array(secrets, "group_keys")?
                    .iter()
                    .find(|k| {
                        k["group_id"] == *group
                            && k["key_epoch"] == e["key_epoch"]
                            && k["epoch_digest"] == e["epoch_digest"]
                    })
                    .ok_or(Error("EPOCH_KEY_REQUIRED"))?;
                let k = Zeroizing::new(un64(text(&k["group_secret"])?)?);
                check(
                    key_commitment(&ctx, &k)? == e["key_commitment"],
                    "KEY_REPAIR_REQUIRED",
                )?;
                let context = json!({"purpose":"group-key-distribution","contract":"p02-identity-c1","protocol":"anynote","protocol_version":1,"service_id":scope.service_id,"group_id":group,"key_epoch":e["key_epoch"],"epoch_digest":e["epoch_digest"],"membership_head":v.policy,"operation_id":random_id(),"issuer":sender,"recipient":recipient});
                records.push(objects::seal_grant(
                    codec,
                    &canonical(&context)?,
                    &k,
                    &un64(text(&target.certificate["body"]["device_encryption_key"])?)?,
                    signing,
                )?);
            }
            result = json!({"version":1,"records":records});
        }
        Request::OwnKeys { records, .. } => {
            role(&v.members, &sender)?;
            check(records.len() <= 60, "RESOURCE_LIMIT")?;
            let expected = recipient(&roster, Some(&scope.device_id))?;
            let mut accepted = Vec::new();
            let mut epochs = BTreeSet::new();
            for r in records {
                let c = &r["body"]["context"];
                check(
                    c["service_id"] == scope.service_id
                        && c["group_id"] == *group
                        && c["membership_head"] == v.policy
                        && c["recipient"] == expected
                        && c["issuer"]["account_id"] == scope.account_id,
                    "RECIPIENT_ACCESS_MISMATCH",
                )?;
                let issuer = roster.active(
                    text(&c["issuer"]["device_id"])?,
                    Some("distribute-group-key"),
                )?;
                check(
                    signer(&roster, text(&c["issuer"]["device_id"])?)? == c["issuer"],
                    "ROSTER_CHANGED",
                )?;
                check(epochs.insert(text(&c["key_epoch"])?), "DUPLICATE_RECORD")?;
                let e = v
                    .epochs
                    .iter()
                    .find(|e| {
                        e["key_epoch"] == c["key_epoch"] && e["epoch_digest"] == c["epoch_digest"]
                    })
                    .ok_or(Error("EPOCH_INVENTORY_MISMATCH"))?;
                let k = objects::open_grant(
                    codec,
                    &canonical(r)?,
                    &canonical(c)?,
                    &un64(text(&issuer.certificate["body"]["device_signing_key"])?)?,
                    &un64(text(&own.certificate["body"]["device_encryption_key"])?)?,
                    encryption,
                )?;
                check(
                    key_commitment(&ctx, &k)? == e["key_commitment"],
                    "KEY_REPAIR_REQUIRED",
                )?;
                accepted.push(json!({"service_id":scope.service_id,"group_id":group,"key_epoch":e["key_epoch"],"epoch_digest":e["epoch_digest"],"group_secret":b64(&k)}));
            }
            result = json!({"state":"keys-local-saved","epochs":accepted.len()});
            keys = json!(accepted);
        }
        Request::Keys { .. } => {
            check(
                role(&v.members, &sender).is_ok() && v.write_state != "REKEY_REQUIRED",
                "ROSTER_CHANGED",
            )?;
            let cert = at(codec, &proof, &v.issuer)?
                .active(text(&v.issuer["device_id"])?, Some("distribute-group-key"))?
                .certificate
                .clone();
            let mut accepted = Vec::new();
            for grant in &v.grants {
                let c = &grant["body"]["context"];
                if c["recipient"]["kind"] != "device"
                    || c["recipient"]["account_id"] != scope.account_id
                    || c["recipient"]["device_id"] != scope.device_id
                {
                    continue;
                }
                let k = objects::open_grant(
                    codec,
                    &canonical(grant)?,
                    &canonical(c)?,
                    &un64(text(&cert["body"]["device_signing_key"])?)?,
                    &un64(text(&own.certificate["body"]["device_encryption_key"])?)?,
                    encryption,
                )?;
                let epoch = v
                    .epochs
                    .iter()
                    .find(|e| e["key_epoch"] == c["key_epoch"])
                    .ok_or(Error("KEYS_PENDING"))?;
                check(
                    key_commitment(&ctx, &k)? == epoch["key_commitment"],
                    "KEY_REPAIR_REQUIRED",
                )?;
                accepted.push(json!({"service_id":scope.service_id,"group_id":group,"key_epoch":c["key_epoch"],"epoch_digest":c["epoch_digest"],"group_secret":b64(&k)}));
            }
            check(accepted.len() == v.epochs.len(), "KEY_REPAIR_REQUIRED")?;
            result = json!({"state":"keys-local-saved","epochs":accepted.len()});
            keys = json!(accepted);
        }
    }
    if let Some(a) = next_attempt {
        check(
            data["attempt"].is_null()
                || ["COMMITTED", "CANCELLED"]
                    .contains(&data["attempt"]["state"].as_str().unwrap_or("")),
            "PUBLICATION_PENDING",
        )?;
        codec.validate("p10-shared", "attempt", &a)?;
        data["attempt"] = a.clone();
        data["proof"] = proof;
        result = a;
    }
    check(!result.is_null(), "INVALID_SHARED_COMMAND")?;
    codec.validate("p10-shared", "local-evidence", &data)?;
    Ok(Outcome { data, result, keys })
}
#[allow(clippy::too_many_arguments)]
fn make_policy(
    codec: &Codec,
    ctx: &Value,
    v: &Verified,
    sender: &Value,
    action: &str,
    payload: &Value,
    members: Value,
    key: &[u8],
) -> Result<Value> {
    let mut b = common("group-policy-event", ctx, &random_id());
    b["action"] = json!(action);
    b["version"] = json!((number(&v.policy["version"])? + 1).to_string());
    b["predecessor"] = v.policy.clone();
    b["signer"] = sender.clone();
    b["members"] = members;
    b["payload"] = payload.clone();
    public_sign(codec, "policy", b, key)
}
fn current_rosters(codec: &Codec, proof: &Value, members: &Value) -> Result<Value> {
    let mut out = Vec::new();
    for m in members.as_array().unwrap() {
        let a = anchor(proof, &m["account_id"])?;
        let r = Roster::replay(codec, &a["snapshot"], &a["pins"], None)?;
        out.push(json!({"account_id":m["account_id"],"root_fingerprint":m["root_fingerprint"],"recovery_generation":r.generation,"roster":r.head}));
    }
    Ok(json!(out))
}
fn grant_pages(ctx: &Value, op: &str, records: Vec<Value>) -> Result<Vec<Value>> {
    let mut pages = Vec::new();
    let mut batch = Vec::new();
    for r in records {
        let mut page = common("group-grant-page", ctx, op);
        page["page_index"] = json!(pages.len().to_string());
        let mut test = batch.clone();
        test.push(r.clone());
        page["records"] = json!(test);
        if !batch.is_empty() && (batch.len() == 500 || canonical(&page)?.len() > 1048576) {
            page["records"] = json!(batch);
            pages.push(page);
            batch = Vec::new();
        }
        batch.push(r);
    }
    if !batch.is_empty() {
        let mut p = common("group-grant-page", ctx, op);
        p["page_index"] = json!(pages.len().to_string());
        p["records"] = json!(batch);
        pages.push(p);
    }
    Ok(pages)
}
fn history_pages(ctx: &Value, records: Vec<Value>) -> Result<Vec<Value>> {
    let mut pages = Vec::new();
    let mut batch = Vec::new();
    for r in records {
        let mut test = batch.clone();
        test.push(r.clone());
        let p = json!({"purpose":"history-inventory-page","contract":"p02-file-c1","version":1,"service_id":ctx["service_id"],"group_id":ctx["group_id"],"page_index":pages.len().to_string(),"records":test});
        if !batch.is_empty() && (batch.len() == 500 || canonical(&p)?.len() > 1048576) {
            let mut p = p;
            p["records"] = json!(batch);
            pages.push(p);
            batch = Vec::new();
        }
        batch.push(r);
    }
    if !batch.is_empty() {
        pages.push(json!({"purpose":"history-inventory-page","contract":"p02-file-c1","version":1,"service_id":ctx["service_id"],"group_id":ctx["group_id"],"page_index":pages.len().to_string(),"records":batch}));
    }
    Ok(pages)
}
fn history_commitment(pages: &[Value]) -> Result<Value> {
    let count = pages
        .iter()
        .map(|p| p["records"].as_array().unwrap().len())
        .sum::<usize>();
    let mut bytes = b"AnyNote/p02-file-c1/hash/history-inventory\0".to_vec();
    bytes.extend((pages.len() as u32).to_be_bytes());
    bytes.extend((count as u64).to_be_bytes());
    for (n, p) in pages.iter().enumerate() {
        bytes.extend((n as u32).to_be_bytes());
        bytes.extend((p["records"].as_array().unwrap().len() as u32).to_be_bytes());
        bytes.extend((canonical(p)?.len() as u32).to_be_bytes());
        bytes.extend(un64(&digest("p02-file-c1", "history-page", p)?)?);
    }
    Ok(
        json!({"digest":hash(&bytes),"record_count":count.to_string(),"page_count":pages.len().to_string()}),
    )
}

pub(crate) fn object_author(
    codec: &Codec,
    proof: &Value,
    v: &Verified,
    bundle: &Value,
    scope: &Scope,
) -> Result<Value> {
    let own = own_roster(codec, proof, scope)?;
    let own_sender = signer(&own, &scope.device_id)?;
    role(&v.members, &own_sender)?;
    own.active(&scope.device_id, Some("receive-group-key"))?;
    let env = &bundle["envelope"];
    let c = &env["header"]["context"];
    check(
        c["service_id"] == proof["pin"]["service_id"] && c["group_id"] == proof["pin"]["group_id"],
        "CONTEXT_MISMATCH",
    )?;
    let a = anchor(proof, &c["author"]["account_id"])?;
    let past = historical(codec, &a["snapshot"], &a["pins"], &c["author"]["roster"])?;
    let d = past.active(text(&c["author"]["device_id"])?, Some("sign-content"))?;
    check(
        d.certificate["body"]["root_fingerprint"] == c["author"]["root_fingerprint"]
            && d.certificate["body"]["recovery_generation"] == c["author"]["recovery_generation"],
        "HISTORICAL_ROSTER_REQUIRED",
    )?;
    let policies = std::iter::once(&proof["journal"]["genesis"]["commit"]["body"]["policy"]).chain(
        array(&proof["journal"], "events")?.iter().filter_map(|e| {
            if e["kind"] == "policy" {
                Some(&e["policy"])
            } else if e["kind"] == "epoch" && !e["commit"]["body"]["policy"].is_null() {
                Some(&e["commit"]["body"]["policy"])
            } else {
                None
            }
        }),
    );
    let policy = policies
        .filter_map(|p| policy_head(p).ok().map(|h| (p, h)))
        .find(|(_, h)| *h == c["policy"]["membership"])
        .ok_or(Error("HISTORICAL_WRITER_REQUIRED"))?
        .0;
    let author = json!({"account_id":c["author"]["account_id"],"root_fingerprint":c["author"]["root_fingerprint"]});
    let author_role = role(&policy["body"]["members"], &author)?;
    check(
        author_role != "reader" && (c["object_kind"] != "group-metadata" || author_role == "owner"),
        "HISTORICAL_WRITER_REQUIRED",
    )?;
    let ed = digest("p02-v1", "envelope", env)?;
    let anchored = v.records.get(text(&c["revision_id"])?).is_some_and(|r| {
        r["envelope_digest"] == ed
            && r["object_id"] == c["object_id"]
            && r["object_kind"] == c["object_kind"]
            && r["parents"] == c["parents"]
    });
    if !anchored {
        check(
            v.write_state == "WRITABLE" && c["policy"] == v.reference(),
            "UNANCHORED_HISTORY",
        )?;
        let current = Roster::replay(codec, &a["snapshot"], &a["pins"], None)?;
        current.active(text(&c["author"]["device_id"])?, Some("sign-content"))?;
        check(current.head == c["author"]["roster"], "ROSTER_CHANGED")?;
    }
    check(
        v.epochs.iter().any(|e| {
            e["key_epoch"] == c["policy"]["key_epoch"]
                && e["epoch_digest"] == c["policy"]["epoch_digest"]
        }),
        "KEY_REPAIR_REQUIRED",
    )?;
    crypto::verify(
        &codec.signing("p02-v1", "header", &env["header"])?,
        text(&env["signature"])?,
        &un64(text(&d.certificate["body"]["device_signing_key"])?)?,
    )?;
    Ok(d.certificate.clone())
}

fn attempt_operation(a: &Value) -> Result<Value> {
    check(a.is_object(), "RECORD_NOT_FOUND")?;
    let b = &a["body"];
    let r = [
        "invitation",
        "acceptance",
        "policy",
        "intent",
        "commit",
        "history",
    ]
    .iter()
    .find_map(|k| b.get(*k).filter(|v| !v.is_null()));
    Ok(r.map_or(b["operation_id"].clone(), |r| {
        r["body"]["operation_id"].clone()
    }))
}
