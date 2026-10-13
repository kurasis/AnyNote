//! Current account-private content authority, encrypted SQLite journal and closed native commands.
pub mod sync;
use super::*;
use crate::device_groups::{create_private_genesis, historical, verify_genesis};
use crate::device_roster::{Roster, digest};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NotesRequest {
    Sync {
        request: sync::Request,
    },
    Summary {},
    PrepareGroup {},
    PrepareShared {},
    UpgradePrivate {
        group_id: String,
    },
    CopyPreview {
        source_group: String,
        destination_group: String,
        revision_id: String,
    },
    Copy {
        source_group: String,
        destination_group: String,
        destination_thread: String,
        revision_id: String,
        preview_digest: String,
        confirmed: bool,
    },
    Shared {
        request: crate::shared::Request,
    },
    RetryGroup {
        group_id: String,
    },
    GroupEvidence {
        group_id: String,
    },
    Group {
        status: Value,
    },
    Save {
        edit: Value,
    },
    Draft {
        draft_id: String,
    },
    Queue {
        draft_id: String,
    },
    Send {
        attempt_id: String,
    },
    Reject {
        attempt_id: String,
        code: String,
    },
    Ack {
        attempt_id: String,
        result: Value,
    },
    Open {
        request: Value,
    },
    Cached {
        revision_id: String,
    },
}
impl NotesRequest {
    fn wipe(&mut self) {
        match self {
            Self::Save { edit } => wipe_value(edit),
            Self::Group { status } => wipe_value(status),
            Self::Ack { result, .. } => wipe_value(result),
            Self::Open { request } => wipe_value(request),
            Self::Sync { request } => request.wipe(),
            _ => (),
        }
    }
}
struct Write {
    id: String,
    kind: String,
    data: Value,
}
impl Drop for Write {
    fn drop(&mut self) {
        wipe_value(&mut self.data);
    }
}
fn values<'a>(v: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    v[field].as_array().ok_or(Error("INTEGRITY_FAILURE"))
}
fn list<'a>(v: &'a mut Value, field: &str) -> Result<&'a mut Vec<Value>> {
    v[field].as_array_mut().ok_or(Error("INTEGRITY_FAILURE"))
}
fn find(v: &Value, field: &str, key: &str, id: &str) -> Result<Value> {
    values(v, field)?
        .iter()
        .find(|x| x[key] == id)
        .cloned()
        .ok_or(Error("RECORD_NOT_FOUND"))
}
fn index(v: &Value, field: &str, key: &str, id: &str) -> Result<usize> {
    values(v, field)?
        .iter()
        .position(|x| x[key] == id)
        .ok_or(Error("RECORD_NOT_FOUND"))
}
fn value_hash(v: &Value) -> Result<String> {
    Ok(hash(&canonical(v)?))
}
pub(crate) fn protected_ids(c: &Value) -> Result<BTreeMap<String, String>> {
    let mut ids = BTreeMap::new();
    for (field, key, kind) in [
        ("groups", "record_id", "group-evidence"),
        ("drafts", "record_id", "draft"),
        ("attempts", "record_id", "outbox"),
        ("witnesses", "cache_id", "cache"),
    ] {
        for item in values(c, field)? {
            check(
                ids.insert(text(&item[key])?.into(), kind.into()).is_none(),
                "DUPLICATE_RECORD",
            )?;
        }
    }
    for slot in ["stage", "pending"] {
        if let Some(items) = c["sync"][slot]["items"].as_array() {
            for item in items {
                let id = text(&item["cache_id"])?;
                check(ids.get(id).is_none_or(|k| k == "cache"), "DUPLICATE_RECORD")?;
                ids.insert(id.into(), "cache".into());
            }
        }
    }
    Ok(ids)
}
fn policy(info: &Value) -> Value {
    if info["policy"].is_object() {
        return info["policy"].clone();
    }
    json!({"membership":info["membership"],"key_epoch":"0","epoch_digest":info["epoch_digest"],"history_checkpoint_digest":null})
}
fn own<'a>(
    roster: &'a Roster,
    scope: &Scope,
    signing: &[u8],
) -> Result<&'a crate::device_roster::Device> {
    let known = roster.devices.get(&scope.device_id);
    check(
        known.is_some_and(|d| d.active),
        if known.is_some() {
            "DEVICE_REVOKED"
        } else {
            "DEVICE_NOT_TRUSTED"
        },
    )?;
    let d = roster.active(&scope.device_id, Some("sign-content"))?;
    check(
        d.certificate["body"]["device_signing_key"] == b64(&signing[32..]),
        "DEVICE_KEY_MISMATCH",
    )?;
    Ok(d)
}
fn author(roster: &Roster, scope: &Scope, signing: &[u8]) -> Result<Value> {
    let d = own(roster, scope, signing)?;
    Ok(
        json!({"account_id":scope.account_id,"device_id":scope.device_id,"root_fingerprint":roster.pins["root_fingerprint"],"recovery_generation":d.certificate["body"]["recovery_generation"],"roster":roster.head}),
    )
}
fn writable(
    group: &Value,
    info: &Value,
    roster: &Roster,
    scope: &Scope,
    signing: &[u8],
) -> Result<()> {
    own(roster, scope, signing)?;
    if info["policy"].is_object() {
        check(
            info["write_state"] == "WRITABLE",
            match info["write_state"].as_str() {
                Some("REKEY_REQUIRED") => "REKEY_REQUIRED",
                Some("HISTORY_CLOSURE_REQUIRED") => "HISTORY_CLOSURE_REQUIRED",
                Some("UNANCHORED_HISTORY") => "UNANCHORED_HISTORY",
                _ => "ROLE_FORBIDDEN",
            },
        )?;
        check(
            info["members"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["account_id"] == scope.account_id && m["role"] != "reader"),
            "ROLE_FORBIDDEN",
        )?;
    }
    check(info["rekey_required"] == false, "REKEY_REQUIRED")?;
    check(
        group["state"] == "COMMITTED" && group["status"].is_object(),
        "GROUP_NOT_COMMITTED",
    )?;
    let s = &group["status"];
    check(s["state"] == "active", "ROLE_FORBIDDEN")?;
    check(s["restore_quarantined"] == false, "RESTORE_QUARANTINE")?;
    check(s["rekey_required"] == false, "REKEY_REQUIRED")?;
    check(
        s["history_closure_required"] == false,
        "HISTORY_CLOSURE_REQUIRED",
    )?;
    check(
        s["membership"] == info["membership"]
            && s["key_epoch"] == policy(info)["key_epoch"]
            && s["epoch_digest"] == info["epoch_digest"]
            && s["history_checkpoint_digest"] == policy(info)["history_checkpoint_digest"],
        "POLICY_CHANGED",
    )
}
fn request_for(bundle: &Value) -> Value {
    let c = &bundle["envelope"]["header"]["context"];
    json!({"group_id":c["group_id"],"object_id":c["object_id"],"object_kind":c["object_kind"],"action":c["action"],"thread_id":c["thread_id"],"bundle":bundle})
}

impl Vault {
    pub(crate) fn note_control(&self, conn: &Connection, s: &State, key: &[u8]) -> Result<Value> {
        let id = note_local::control_id(&self.scope)?;
        let old: Option<Vec<u8>> = db(conn
            .query_row("SELECT frame FROM records WHERE id=?1", [&id], |r| r.get(0))
            .optional())?;
        match old {
            Some(bytes) => {
                let f = strict(&bytes, 8_388_608)?;
                let v = if f["contract"] == "p11-local-v1" {
                    paged_local::open(
                        &self.codec,
                        conn,
                        &self.scope,
                        &s.pins,
                        (&id, "note-control"),
                        &f,
                        key,
                    )?
                } else {
                    note_local::open(&self.scope, &s.pins, &id, "note-control", &f, key)?
                };
                self.codec.validate("p11-sync", "note-control", &v)?;
                Ok(v)
            }
            None => Ok(
                json!({"purpose":"p09-private-control","version":1,"groups":[],"drafts":[],"attempts":[],"witnesses":[]}),
            ),
        }
    }
    pub(crate) fn note_part_owned(
        &self,
        conn: &Connection,
        s: &State,
        key: &[u8],
        id: &str,
    ) -> Result<bool> {
        let ctl = note_local::control_id(&self.scope)?;
        let roots = self.note_control(conn, s, key)?;
        let mut checks = vec![(ctl, "note-control"), (s.vault_id.clone(), "vault-secrets")];
        for g in values(&roots, "groups")? {
            checks.push((text(&g["record_id"])?.to_owned(), "group-evidence"));
        }
        for (id, kind) in protected_ids(&roots)? {
            if kind == "cache" {
                checks.push((id, "cache"));
            }
        }
        for (root, kind) in checks {
            let exists: i64 = db(conn.query_row(
                "SELECT count(*) FROM records WHERE id=?1",
                [&root],
                |r| r.get(0),
            ))?;
            if exists == 0 {
                continue;
            }
            let f = frame(conn, &root)?;
            if f["contract"] != "p11-local-v1" {
                continue;
            }
            let mut m =
                paged_local::manifest(&self.codec, &self.scope, &s.pins, &root, kind, &f, key)?;
            let found = m["parts"]
                .as_array()
                .ok_or(Error("INTEGRITY_FAILURE"))?
                .iter()
                .any(|p| p["record_id"] == id);
            wipe_value(&mut m);
            if found {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn note_read(
        &self,
        i: &mut Inner,
        s: &State,
        control: &Value,
        id: &str,
        kind: &str,
    ) -> Result<Value> {
        check(
            protected_ids(control)?.get(id).is_some_and(|k| k == kind),
            "RESERVED_RECORD",
        )?;
        let f = frame(&i.conn, id)?;
        let bytes = canonical(&f)?;
        if let Some(old) = i.anchors.get(id) {
            check(old == &hash(&bytes), "ROLLBACK_QUARANTINE")?;
        }
        let key = &i.secrets.as_ref().ok_or(Error("VAULT_LOCKED"))?.key;
        let out = if kind == "cache" && f["contract"] == "p11-local-v1" {
            let v = paged_local::open(
                &self.codec,
                &i.conn,
                &self.scope,
                &s.pins,
                (id, kind),
                &f,
                key,
            )?;
            self.codec.validate("p11-sync", "header-evidence", &v)?;
            v
        } else if kind == "group-evidence" {
            if f["contract"] == "p11-local-v1" {
                paged_local::open(
                    &self.codec,
                    &i.conn,
                    &self.scope,
                    &s.pins,
                    (id, kind),
                    &f,
                    key,
                )?
            } else {
                note_local::open(&self.scope, &s.pins, id, kind, &f, key)?
            }
        } else {
            objects::open_local(
                &self.codec,
                &bytes,
                key,
                &canonical(&self.context(kind, id)?)?,
            )?["data"]
                .clone()
        };
        i.anchors.insert(id.into(), hash(&bytes));
        Ok(out)
    }
    fn note_info(
        &self,
        i: &mut Inner,
        s: &State,
        control: &Value,
        snapshot: &Value,
        group: &str,
    ) -> Result<(Value, Value, Value)> {
        let reference = find(control, "groups", "group_id", group)?;
        let data = self.note_read(
            i,
            s,
            control,
            text(&reference["record_id"])?,
            "group-evidence",
        )?;
        if data["purpose"] == "p10-group-proof" {
            let (proof, verified) = self.note_shared_proof(i, s, control, snapshot, &data)?;
            let info = json!({"group_id":group,"membership":verified.policy,"epoch_digest":verified.reference()["epoch_digest"],"policy":verified.reference(),"epochs":verified.epochs,"members":verified.members,"write_state":verified.write_state,"rekey_required":verified.write_state=="REKEY_REQUIRED"});
            return Ok((reference, proof["journal"]["genesis"].clone(), info));
        }
        let evidence = data["evidence"].clone();
        let mut info = verify_genesis(&self.codec, &evidence, snapshot, &s.pins)?;
        let epoch_version =
            text(&evidence["commit"]["body"]["intent"]["body"]["rosters"][0]["roster"]["version"])?
                .parse::<u64>()
                .map_err(|_| Error("INTEGRITY_FAILURE"))?;
        info["rekey_required"] = json!(values(snapshot, "events")?.iter().any(|e| {
            e["body"]["version"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|v| v > epoch_version)
                && matches!(e["body"]["kind"].as_str(), Some("revoke" | "reset"))
        }));
        check(
            info["group_id"] == group
                && evidence["commit"]["body"]["policy"]["body"]["members"][0]["account_id"]
                    == self.scope.account_id,
            "POLICY_CHANGED",
        )?;
        Ok((reference, evidence, info))
    }
    fn note_key(
        &self,
        i: &Inner,
        s: &State,
        group: &str,
        info: &Value,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut p = self.secret_plain(
            &i.conn,
            s,
            &i.secrets.as_ref().ok_or(Error("VAULT_LOCKED"))?.key,
        )?;
        let result = (|| {
            let k = values(&p["data"], "group_keys")?
                .iter()
                .find(|k| {
                    k["service_id"] == self.scope.service_id
                        && k["group_id"] == group
                        && k["key_epoch"] == policy(info)["key_epoch"]
                        && k["epoch_digest"] == info["epoch_digest"]
                })
                .ok_or(Error("KEYS_PENDING"))?;
            Ok(Zeroizing::new(un64(text(&k["group_secret"])?)?))
        })();
        wipe_value(&mut p);
        result
    }
    fn note_draft(&self, i: &mut Inner, s: &State, c: &Value, id: &str) -> Result<(Value, Value)> {
        let r = find(c, "drafts", "draft_id", id)?;
        let data = self.note_read(i, s, c, text(&r["record_id"])?, "draft")?;
        self.codec.validate("p02-v1", "draft", &data)?;
        check(
            data["draft_id"] == r["draft_id"] && value_hash(&data)? == r["saved_digest"],
            "INTEGRITY_FAILURE",
        )?;
        Ok((r, data))
    }
    fn note_attempt(
        &self,
        i: &mut Inner,
        s: &State,
        c: &Value,
        id: &str,
    ) -> Result<(Value, Value)> {
        let r = find(c, "attempts", "attempt_id", id)?;
        let data = self.note_read(i, s, c, text(&r["record_id"])?, "outbox")?;
        self.codec.validate("p02-v1", "outbox", &data)?;
        check(
            data["attempt_id"] == r["attempt_id"]
                && data["draft_id"] == r["draft_id"]
                && data["state"] == r["state"],
            "INTEGRITY_FAILURE",
        )?;
        Ok((r, data))
    }
    fn note_cache(&self, c: &mut Value, bundle: &Value) -> Result<Write> {
        let x = &bundle["envelope"]["header"]["context"];
        let ed = digest("p02-v1", "envelope", &bundle["envelope"])?;
        let revision = text(&x["revision_id"])?;
        let old = values(c, "witnesses")?
            .iter()
            .find(|w| w["revision_id"] == revision)
            .cloned();
        let w = if let Some(w) = old {
            check(
                w["group_id"] == x["group_id"]
                    && w["object_id"] == x["object_id"]
                    && w["envelope_digest"] == ed,
                "ROLLBACK_QUARANTINE",
            )?;
            w
        } else {
            check(values(c, "witnesses")?.len() < 10000, "RESOURCE_LIMIT")?;
            let w = json!({"group_id":x["group_id"],"object_id":x["object_id"],"revision_id":x["revision_id"],"envelope_digest":ed,"object_kind":x["object_kind"],"thread_id":x["thread_id"],"archived":x["archived"],"action":x["action"],"cache_id":random_id()});
            list(c, "witnesses")?.push(w.clone());
            w
        };
        Ok(Write {
            id: text(&w["cache_id"])?.into(),
            kind: "cache".into(),
            data: json!({"cached_kind":"object-bundle","record_bytes":b64(&canonical(bundle)?)}),
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn note_commit(
        &self,
        i: &mut Inner,
        cap: &Capability,
        before: &State,
        fence: u64,
        control: &Value,
        writes: &[Write],
        add_key: Option<&Value>,
    ) -> Result<()> {
        self.codec.validate("p11-sync", "note-control", control)?;
        check(
            canonical(control)?.len() <= 33_554_432 && writes.len() <= 16,
            "RESOURCE_LIMIT",
        )?;
        let ids = protected_ids(control)?;
        let old_control = self.note_control(&i.conn, before, &i.secrets.as_ref().unwrap().key)?;
        let old_ids = protected_ids(&old_control)?;
        let key = Zeroizing::new(i.secrets.as_ref().unwrap().key.to_vec());
        let mut frames = Vec::new();
        let mut remove_parts = Vec::new();
        let mut new_parts = std::collections::BTreeSet::new();
        let mut seen = std::collections::BTreeSet::new();
        let device = self.device_saved(i, before)?.0;
        let mut blocked = std::collections::BTreeSet::from([
            before.vault_id.clone(),
            device_local::control_id(&self.scope)?,
            note_local::control_id(&self.scope)?,
        ]);
        for field in ["pages", "staging"] {
            let pages = if field == "staging" {
                device[field]["pages"].as_array()
            } else {
                device[field].as_array()
            };
            if let Some(pages) = pages {
                for p in pages {
                    blocked.insert(text(p)?.into());
                }
            }
        }
        for id in ids.keys() {
            check(!blocked.contains(id), "RESERVED_RECORD")?;
        }
        for w in writes {
            check(
                seen.insert(w.id.clone()) && ids.get(&w.id).is_some_and(|k| k == &w.kind),
                "RESERVED_RECORD",
            )?;
            let old: Option<Vec<u8>> = db(i
                .conn
                .query_row("SELECT frame FROM records WHERE id=?1", [&w.id], |r| {
                    r.get(0)
                })
                .optional())?;
            if let Some(old) = old {
                check(
                    old_ids.get(&w.id).is_some_and(|k| k == &w.kind),
                    "RESERVED_RECORD",
                )?;
                if w.kind == "outbox" {
                    let mut p = objects::open_local(
                        &self.codec,
                        &old,
                        &key,
                        &canonical(&self.context("outbox", &w.id)?)?,
                    )?;
                    let result = (|| {
                        for k in [
                            "draft_id",
                            "attempt_id",
                            "revision_id",
                            "attempt_digest",
                            "bundle",
                        ] {
                            check(p["data"][k] == w.data[k], "IMMUTABLE_ATTEMPT")?;
                        }
                        outbox_transition(text(&p["data"]["state"])?, text(&w.data["state"])?)
                    })();
                    wipe_value(&mut p);
                    result?;
                }
            }
            let prior: Option<Vec<u8>> = db(i
                .conn
                .query_row("SELECT frame FROM records WHERE id=?1", [&w.id], |r| {
                    r.get(0)
                })
                .optional())?;
            if let Some(bytes) = prior {
                let f = strict(&bytes, 8_388_608)?;
                if f["contract"] == "p11-local-v1" {
                    let mut m = paged_local::manifest(
                        &self.codec,
                        &self.scope,
                        &before.pins,
                        &w.id,
                        &w.kind,
                        &f,
                        &key,
                    )?;
                    for p in m["parts"].as_array().ok_or(Error("INTEGRITY_FAILURE"))? {
                        remove_parts.push(text(&p["record_id"])?.to_owned());
                    }
                    wipe_value(&mut m);
                }
            }
            let f = if w.kind == "group-evidence"
                || (w.kind == "cache" && w.data["purpose"] == "p11-header-evidence")
            {
                if w.kind == "cache" {
                    self.codec
                        .validate("p11-sync", "header-evidence", &w.data)?;
                } else {
                    self.codec
                        .validate("p09-notes", "local-evidence", &w.data)?;
                }
                let (f, parts) = paged_local::prepare(
                    &self.codec,
                    &self.scope,
                    &before.pins,
                    &w.id,
                    &w.kind,
                    &w.data,
                    &key,
                )?;
                for (id, bytes) in parts {
                    check(new_parts.insert(id.clone()), "DUPLICATE_RECORD")?;
                    frames.push((id, bytes));
                }
                f
            } else {
                self.codec.validate("p02-v1", &w.kind, &w.data)?;
                objects::seal_local(
                    &self.codec,
                    &Zeroizing::new(canonical(
                        &json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"local-record-plaintext","context":self.context(&w.kind,&w.id)?,"data":w.data}),
                    )?),
                    &key,
                )?
            };
            frames.push((w.id.clone(), canonical(&f)?));
        }
        if let Some(k) = add_key {
            let mut p = self.secret_plain(&i.conn, before, &key)?;
            let result = (|| {
                let keys = list(&mut p["data"], "group_keys")?;
                let additions = if k.is_array() {
                    k.as_array().unwrap().clone()
                } else {
                    vec![k.clone()]
                };
                for k in additions {
                    if let Some(old) = keys.iter().find(|v| {
                        v["group_id"] == k["group_id"] && v["key_epoch"] == k["key_epoch"]
                    }) {
                        check(*old == k, "INTEGRITY_FAILURE")?;
                    } else {
                        keys.push(k.clone());
                    }
                }
                keys.sort_by_key(|v| {
                    format!(
                        "{}/{:0>19}",
                        v["group_id"].as_str().unwrap(),
                        v["key_epoch"].as_str().unwrap()
                    )
                });
                self.prepare_secret_pages(&i.conn, before, &key, &p["data"])
            })();
            wipe_value(&mut p);
            let (root, parts, prior) = result?;
            remove_parts.extend(prior);
            for (id, bytes) in parts {
                check(new_parts.insert(id.clone()), "DUPLICATE_RECORD")?;
                frames.push((id, bytes));
            }
            frames.push((before.vault_id.clone(), canonical(&root)?));
        }
        let id = note_local::control_id(&self.scope)?;
        let prior: Option<Vec<u8>> = db(i
            .conn
            .query_row("SELECT frame FROM records WHERE id=?1", [&id], |r| r.get(0))
            .optional())?;
        if let Some(bytes) = prior {
            let f = strict(&bytes, 8_388_608)?;
            if f["contract"] == "p11-local-v1" {
                let mut m = paged_local::manifest(
                    &self.codec,
                    &self.scope,
                    &before.pins,
                    &id,
                    "note-control",
                    &f,
                    &key,
                )?;
                for p in m["parts"].as_array().ok_or(Error("INTEGRITY_FAILURE"))? {
                    remove_parts.push(text(&p["record_id"])?.to_owned());
                }
                wipe_value(&mut m);
            }
        }
        let (ctl, parts) = paged_local::prepare(
            &self.codec,
            &self.scope,
            &before.pins,
            &id,
            "note-control",
            control,
            &key,
        )?;
        for (id, bytes) in parts {
            check(new_parts.insert(id.clone()), "DUPLICATE_RECORD")?;
            frames.push((id, bytes));
        }
        frames.push((id, canonical(&ctl)?));
        let tx = db(i
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut s = state(&tx, &self.codec, &self.scope)?;
        check(
            s.epoch == before.epoch && s.revision == before.revision,
            "STALE_WRITER",
        )?;
        self.fence(&s, fence)?;
        for id in &new_parts {
            check(
                db(
                    tx.query_row("SELECT count(*) FROM records WHERE id=?1", [id], |r| {
                        r.get::<_, i64>(0)
                    }),
                )? == 0,
                "RESERVED_RECORD",
            )?;
        }
        for id in &remove_parts {
            db(tx.execute("DELETE FROM records WHERE id=?1", [id]))?;
        }
        for (id, bytes) in &frames {
            db(tx.execute("INSERT INTO records(id,frame) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET frame=excluded.frame",params![id,bytes]))?;
        }
        for d in values(&old_control, "drafts")? {
            let id = text(&d["record_id"])?;
            if !ids.contains_key(id) {
                let a = values(control, "attempts")?
                    .iter()
                    .find(|a| {
                        a["draft_id"] == d["draft_id"]
                            && a["state"] == "COMMITTED"
                            && a["source_digest"] == d["saved_digest"]
                    })
                    .ok_or(Error("UNSYNCED_WORK_PROTECTED"))?;
                check(
                    writes.iter().any(|w| {
                        w.kind == "outbox"
                            && w.data["attempt_id"] == a["attempt_id"]
                            && w.data["state"] == "COMMITTED"
                    }),
                    "UNSYNCED_WORK_PROTECTED",
                )?;
                db(tx.execute("DELETE FROM records WHERE id=?1", [id]))?;
            }
        }
        let count: i64 = db(tx.query_row("SELECT count(*) FROM records", [], |r| r.get(0)))?;
        check(count <= 100000, "RESOURCE_LIMIT")?;
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        self.fence(&s, fence)?;
        s.revision += 1;
        put_state(&tx, &s)?;
        db(tx.commit())?;
        i.observed_revision = s.revision;
        for (id, b) in frames {
            i.anchors.insert(id, hash(&b));
        }
        Ok(())
    }
    fn note_history_records(
        &self,
        i: &mut Inner,
        s: &State,
        c: &Value,
        group: &str,
    ) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        for w in values(c, "witnesses")?
            .iter()
            .filter(|w| w["group_id"] == group)
        {
            let cache = self.note_read(i, s, c, text(&w["cache_id"])?, "cache")?;
            let envelope = if cache["purpose"] == "p11-header-evidence" {
                self.codec.validate("p11-sync", "header-evidence", &cache)?;
                cache["envelope"].clone()
            } else {
                self.codec
                    .decode("p02-v1", "bundle", &un64(text(&cache["record_bytes"])?)?)?["envelope"]
                    .clone()
            };
            let ctx = &envelope["header"]["context"];
            check(
                digest("p02-v1", "envelope", &envelope)? == w["envelope_digest"],
                "INTEGRITY_FAILURE",
            )?;
            out.push(json!({"object_kind":ctx["object_kind"],"object_id":ctx["object_id"],"revision_id":ctx["revision_id"],"envelope_digest":w["envelope_digest"],"parents":ctx["parents"],"payload_status":"retained"}));
        }
        out.sort_by(|a, b| a["revision_id"].as_str().cmp(&b["revision_id"].as_str()));
        Ok(out)
    }
    fn note_shared_proof(
        &self,
        i: &mut Inner,
        s: &State,
        c: &Value,
        snapshot: &Value,
        data: &Value,
    ) -> Result<(Value, crate::shared::Verified)> {
        let mut proof = data["proof"].clone();
        let own = proof["accounts"]
            .as_array_mut()
            .ok_or(Error("GROUP_PROOF_REQUIRED"))?
            .iter_mut()
            .find(|a| a["pins"]["account_id"] == self.scope.account_id)
            .ok_or(Error("ROOT_PIN_MISMATCH"))?;
        own["snapshot"] = snapshot.clone();
        let records = self.note_history_records(i, s, c, text(&proof["pin"]["group_id"])?)?;
        let local = proof["pin"]["owner_account_id"] == self.scope.account_id
            && values(&proof["journal"], "events")?.is_empty();
        let v = crate::shared::verify(
            &self.codec,
            &proof,
            &s.pins,
            Some(&data["proof"]),
            &records,
            local,
        )?;
        Ok((proof, v))
    }
    #[allow(clippy::too_many_arguments)]
    fn note_shared_command(
        &self,
        i: &mut Inner,
        cap: &Capability,
        s: &State,
        fence: u64,
        c: &mut Value,
        snapshot: &Value,
        request: &crate::shared::Request,
    ) -> Result<Value> {
        let group = request.group()?;
        check(valid_id(&group), "INVALID_REQUEST")?;
        let old = values(c, "groups")?
            .iter()
            .find(|g| g["group_id"] == group)
            .cloned();
        let data = if let Some(r) = &old {
            Some(self.note_read(i, s, c, text(&r["record_id"])?, "group-evidence")?)
        } else {
            None
        };
        check(
            data.as_ref()
                .is_none_or(|d| d["purpose"] == "p10-group-proof"),
            "GROUP_PROOF_REQUIRED",
        )?;
        let records = self.note_history_records(i, s, c, &group)?;
        let mut secrets = self.secret_plain(&i.conn, s, &i.secrets.as_ref().unwrap().key)?;
        let result = crate::shared::command(
            &self.codec,
            request,
            &self.scope,
            &s.pins,
            snapshot,
            data.as_ref(),
            &records,
            &i.secrets.as_ref().unwrap().signing,
            &i.secrets.as_ref().unwrap().encryption,
            &secrets["data"],
        );
        wipe_value(&mut secrets);
        let mut outcome = result?;
        let record = if let Some(r) = old {
            text(&r["record_id"])?.into()
        } else {
            check(values(c, "groups")?.len() < 1000, "RESOURCE_LIMIT")?;
            let r = random_id();
            list(c, "groups")?
                .push(json!({"group_id":group,"record_id":r,"state":"COMMITTED","status":null}));
            r
        };
        self.note_commit(
            i,
            cap,
            s,
            fence,
            c,
            &[Write {
                id: record,
                kind: "group-evidence".into(),
                data: outcome.data.clone(),
            }],
            Some(&outcome.keys),
        )?;
        Ok(std::mem::take(&mut outcome.result))
    }
    pub fn notes_command(&self, cap: &Capability, request: NotesRequest) -> Result<Value> {
        if let NotesRequest::CopyPreview {
            source_group,
            destination_group,
            revision_id,
        } = &request
        {
            return self
                .note_copy_preview(cap, source_group, destination_group, revision_id)
                .map(|(v, _)| v);
        }
        if let NotesRequest::Copy {
            source_group,
            destination_group,
            destination_thread,
            revision_id,
            preview_digest,
            confirmed,
        } = &request
        {
            let (preview, payload) =
                self.note_copy_preview(cap, source_group, destination_group, revision_id)?;
            check(
                *confirmed && preview["digest"] == *preview_digest && valid_id(destination_thread),
                "COPY_CONFIRMATION_REQUIRED",
            )?;
            let edit = json!({"draft_id":null,"group_id":destination_group,"object_id":null,"object_kind":"entry","thread_id":destination_thread,"action":"create","parents":[],"archived":false,"content":{"title":payload["title"],"markdown":payload["markdown"],"metadata_kind":"content","tags":payload["tags"],"checklist":payload["checklist"],"summary_entry_id":null,"preferences":[]}});
            return self.notes_command_inner(
                cap,
                NotesRequest::Save { edit },
                Some(hash(&canonical(
                    &preview["preview"]["destination_audience"],
                )?)),
            );
        }
        self.notes_command_inner(cap, request, None)
    }
    fn note_copy_preview(
        &self,
        cap: &Capability,
        source: &str,
        destination: &str,
        revision: &str,
    ) -> Result<(Value, Value)> {
        check(
            valid_id(source) && valid_id(destination) && valid_id(revision),
            "INVALID_REQUEST",
        )?;
        let summary = self.notes_command(cap, NotesRequest::Summary {})?;
        let src = summary["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["group_id"] == source)
            .ok_or(Error("GROUP_REQUIRED"))?;
        let dst = summary["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["group_id"] == destination)
            .ok_or(Error("GROUP_REQUIRED"))?;
        check(
            src["status"]["kind"] == "private"
                && src["status"]["settings"] == false
                && dst["status"]["kind"] == "shared",
            "COPY_AUDIENCE_REQUIRED",
        )?;
        let detail = self.notes_command(
            cap,
            NotesRequest::Shared {
                request: crate::shared::Request::Details {
                    group_id: destination.into(),
                },
            },
        )?;
        check(
            detail["write_state"] == "WRITABLE"
                && detail["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|m| m["account_id"] == self.scope.account_id && m["role"] != "reader"),
            "ROLE_FORBIDDEN",
        )?;
        let mut opened = self.notes_command(
            cap,
            NotesRequest::Cached {
                revision_id: revision.into(),
            },
        )?;
        let payload = std::mem::take(&mut opened["payload"]);
        check(
            payload["context"]["group_id"] == source
                && payload["context"]["object_kind"] == "entry"
                && payload["metadata_kind"] == "content"
                && payload["context"]["action"] != "soft-delete"
                && payload["context"]["attachments"]
                    .as_array()
                    .is_some_and(Vec::is_empty),
            "COPY_SCOPE_MISMATCH",
        )?;
        let preview = json!({"source_group":source,"destination_group":destination,"revision_id":revision,"source_audience":[self.scope.account_id],"destination_audience":detail["members"],"policy":detail["policy"],"scope":"selected-current-entry-only","title":payload["title"]});
        let digest = hash(&canonical(&preview)?);
        Ok((json!({"preview":preview,"digest":digest}), payload))
    }
    fn notes_command_inner(
        &self,
        cap: &Capability,
        mut request: NotesRequest,
        copy_audience: Option<String>,
    ) -> Result<Value> {
        let fence = self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let mut c = self.note_control(&i.conn, &s, &i.secrets.as_ref().unwrap().key)?;
        let ctl = note_local::control_id(&self.scope)?;
        let existing: Option<Vec<u8>> = db(i
            .conn
            .query_row("SELECT frame FROM records WHERE id=?1", [&ctl], |r| {
                r.get(0)
            })
            .optional())?;
        if let Some(bytes) = existing {
            if let Some(known) = i.anchors.get(&ctl) {
                check(known == &hash(&bytes), "ROLLBACK_QUARANTINE")?;
            }
            i.anchors.insert(ctl, hash(&bytes));
        }
        let snapshot = self.snapshot_for_groups(&mut i, &s)?;
        let roster = Roster::replay(&self.codec, &snapshot, &s.pins, i.device_anchor.as_ref())?;
        let result = (|| match &request {
            NotesRequest::Sync { request } => self.note_sync(
                &mut i,
                cap,
                &s,
                fence,
                &mut c,
                (&snapshot, &roster),
                request,
            ),
            NotesRequest::Summary {} => {
                let mut drafts = Vec::new();
                for d in values(&c, "drafts")? {
                    let a = values(&c, "attempts")?
                        .iter()
                        .rev()
                        .find(|a| a["draft_id"] == d["draft_id"]);
                    let mut out = d.clone();
                    out["attempt_id"] = a.map_or(Value::Null, |a| a["attempt_id"].clone());
                    out["state"] = json!(a.map_or("LOCAL_SAVED", |a| {
                        if a["state"] == "COMMITTED" && a["source_digest"] != d["saved_digest"] {
                            "LOCAL_SAVED"
                        } else {
                            a["state"].as_str().unwrap_or("INTEGRITY_FAILURE")
                        }
                    }));
                    drafts.push(out);
                }
                Ok(
                    json!({"groups":c["groups"],"drafts":drafts,"witnessed":values(&c,"witnesses")?.len(),"witnesses":c["witnesses"]}),
                )
            }
            NotesRequest::CopyPreview { .. } | NotesRequest::Copy { .. } => {
                Err(Error("INVALID_REQUEST"))
            }
            NotesRequest::UpgradePrivate { group_id } => {
                let (r, evidence, _) = self.note_info(&mut i, &s, &c, &snapshot, group_id)?;
                let old =
                    self.note_read(&mut i, &s, &c, text(&r["record_id"])?, "group-evidence")?;
                check(
                    old["purpose"] == "p09-private-genesis",
                    "GROUP_PROOF_REQUIRED",
                )?;
                let proof = json!({"pin":crate::shared::pin(&evidence)?,"journal":{"version":1,"group_id":group_id,"genesis":evidence,"events":[],"pending":null},"accounts":[{"pins":s.pins,"snapshot":snapshot}]});
                let records = self.note_history_records(&mut i, &s, &c, group_id)?;
                crate::shared::verify(&self.codec, &proof, &s.pins, None, &records, true)?;
                self.note_commit(&mut i,cap,&s,fence,&c,&[Write{id:text(&r["record_id"])?.into(),kind:"group-evidence".into(),data:json!({"purpose":"p10-group-proof","version":1,"proof":proof,"attempt":null})}],None)?;
                Ok(proof)
            }
            NotesRequest::PrepareShared {} => {
                own(&roster, &self.scope, &i.secrets.as_ref().unwrap().signing)?;
                check(values(&c, "groups")?.len() < 1000, "RESOURCE_LIMIT")?;
                let (request, mut key) = crate::device_groups::create_genesis_kind(
                    &self.codec,
                    &roster,
                    &self.scope,
                    &s.pins,
                    &i.secrets.as_ref().unwrap().signing,
                    "shared",
                )?;
                let group = text(&request["commit"]["body"]["group_id"])?.to_string();
                let mut evidence = request.clone();
                evidence["group_id"] = json!(group);
                let proof = json!({"pin":crate::shared::pin(&evidence)?,"journal":{"version":1,"group_id":group,"genesis":evidence,"events":[],"pending":null},"accounts":[{"pins":s.pins,"snapshot":snapshot}]});
                crate::shared::verify(&self.codec, &proof, &s.pins, None, &[], true)?;
                let record = random_id();
                list(&mut c,"groups")?.push(json!({"group_id":group,"record_id":record,"state":"GENESIS_PENDING","status":null}));
                let data =
                    json!({"purpose":"p10-group-proof","version":1,"proof":proof,"attempt":null});
                let outcome = self.note_commit(
                    &mut i,
                    cap,
                    &s,
                    fence,
                    &c,
                    &[Write {
                        id: record,
                        kind: "group-evidence".into(),
                        data,
                    }],
                    Some(&key),
                );
                wipe_value(&mut key);
                outcome?;
                Ok(json!({"group_id":group,"request":request}))
            }
            NotesRequest::Shared { request } => {
                self.note_shared_command(&mut i, cap, &s, fence, &mut c, &snapshot, request)
            }
            NotesRequest::PrepareGroup {} => {
                own(&roster, &self.scope, &i.secrets.as_ref().unwrap().signing)?;
                check(values(&c, "groups")?.len() < 1000, "RESOURCE_LIMIT")?;
                let (request, mut key) = create_private_genesis(
                    &self.codec,
                    &roster,
                    &self.scope,
                    &s.pins,
                    &i.secrets.as_ref().unwrap().signing,
                )?;
                let outcome = (|| {
                    verify_genesis(&self.codec, &request, &snapshot, &s.pins)?;
                    let group = request["commit"]["body"]["group_id"].clone();
                    let record_id = random_id();
                    list(&mut c,"groups")?.push(json!({"group_id":group,"record_id":record_id,"state":"GENESIS_PENDING","status":null}));
                    let mut evidence = request.clone();
                    evidence["group_id"] = group.clone();
                    let writes = [Write {
                        id: record_id,
                        kind: "group-evidence".into(),
                        data: json!({"purpose":"p09-private-genesis","version":1,"evidence":evidence}),
                    }];
                    self.note_commit(&mut i, cap, &s, fence, &c, &writes, Some(&key))?;
                    Ok(json!({"group_id":group,"request":request}))
                })();
                wipe_value(&mut key);
                outcome
            }
            NotesRequest::RetryGroup { group_id } | NotesRequest::GroupEvidence { group_id } => {
                check(valid_id(group_id), "INVALID_REQUEST")?;
                let (r, mut evidence, _) = self.note_info(&mut i, &s, &c, &snapshot, group_id)?;
                if matches!(&request, NotesRequest::RetryGroup { .. }) {
                    check(r["state"] == "GENESIS_PENDING", "GROUP_NOT_PENDING")?;
                    evidence.as_object_mut().unwrap().remove("group_id");
                    Ok(json!({"group_id":group_id,"request":evidence}))
                } else {
                    Ok(evidence)
                }
            }
            NotesRequest::Group { status } => {
                self.codec.validate("p09-notes", "group-status", status)?;
                if status["kind"] == "shared"
                    || status["key_epoch"] != "0"
                    || {
                        let old = values(&c, "groups")?
                            .iter()
                            .find(|g| g["group_id"] == status["group_id"]);
                        if let Some(r) = old {
                            self.note_read(
                                &mut i,
                                &s,
                                &c,
                                text(&r["record_id"])?,
                                "group-evidence",
                            )?["purpose"]
                                == "p10-group-proof"
                        } else {
                            false
                        }
                    }
                {
                    let group = text(&status["group_id"])?;
                    let (_, _, info) = self.note_info(&mut i, &s, &c, &snapshot, group)?;
                    check(
                        status["membership"] == info["membership"]
                            && status["key_epoch"] == policy(&info)["key_epoch"]
                            && status["epoch_digest"] == info["epoch_digest"]
                            && status["history_checkpoint_digest"]
                                == policy(&info)["history_checkpoint_digest"],
                        "POLICY_CHANGED",
                    )?;
                    let n = index(&c, "groups", "group_id", group)?;
                    let mut summary = status.clone();
                    summary.as_object_mut().unwrap().remove("genesis");
                    c["groups"][n]["status"] = summary;
                    c["groups"][n]["state"] = json!("COMMITTED");
                    self.note_commit(&mut i, cap, &s, fence, &c, &[], None)?;
                    return Ok(json!({"group_id":group,"state":"group-local-saved"}));
                }
                check(
                    status["owner_account_id"] == self.scope.account_id
                        && status["group_id"] == status["genesis"]["group_id"],
                    "POLICY_CHANGED",
                )?;
                let group = text(&status["group_id"])?;
                let info = verify_genesis(&self.codec, &status["genesis"], &snapshot, &s.pins)?;
                let old = values(&c, "groups")?
                    .iter()
                    .position(|g| g["group_id"] == group);
                let record_id;
                if let Some(n) = old {
                    let (_, evidence, _) = self.note_info(&mut i, &s, &c, &snapshot, group)?;
                    check(evidence == status["genesis"], "ROLLBACK_QUARANTINE")?;
                    record_id = text(&c["groups"][n]["record_id"])?.into();
                } else {
                    let signer = &status["genesis"]["commit"]["body"]["policy"]["body"]["signer"];
                    let d = roster
                        .active(text(&signer["device_id"])?, Some("sign-content"))
                        .map_err(|_| Error("UNANCHORED_HISTORY"))?;
                    check(
                        d.digest == signer["certificate_digest"],
                        "UNANCHORED_HISTORY",
                    )?;
                    check(values(&c, "groups")?.len() < 1000, "RESOURCE_LIMIT")?;
                    record_id = random_id();
                    list(&mut c,"groups")?.push(json!({"group_id":group,"record_id":record_id,"state":"COMMITTED","status":null}));
                }
                check(
                    status["membership"] == info["membership"]
                        && status["key_epoch"] == "0"
                        && status["epoch_digest"] == info["epoch_digest"],
                    "POLICY_CHANGED",
                )?;
                let n = index(&c, "groups", "group_id", group)?;
                let mut summary = status.clone();
                summary.as_object_mut().unwrap().remove("genesis");
                c["groups"][n]["state"] = json!("COMMITTED");
                c["groups"][n]["status"] = summary;
                let writes = [Write {
                    id: record_id,
                    kind: "group-evidence".into(),
                    data: json!({"purpose":"p09-private-genesis","version":1,"evidence":status["genesis"]}),
                }];
                self.note_commit(&mut i, cap, &s, fence, &c, &writes, None)?;
                Ok(json!({"group_id":group,"state":"group-local-saved"}))
            }
            NotesRequest::Save { edit } => {
                self.codec.validate("p09-notes", "edit-request", edit)?;
                let group = text(&edit["group_id"])?;
                let (g, _, info) = self.note_info(&mut i, &s, &c, &snapshot, group)?;
                let old = if edit["draft_id"].is_null() {
                    None
                } else {
                    Some(find(&c, "drafts", "draft_id", text(&edit["draft_id"])?)?)
                };
                if let Some(old) = &old {
                    check(
                        old["group_id"] == edit["group_id"]
                            && old["object_kind"] == edit["object_kind"]
                            && old["thread_id"] == edit["thread_id"]
                            && (edit["object_id"].is_null()
                                || edit["object_id"] == old["object_id"]),
                        "LOCAL_CONTEXT_MISMATCH",
                    )?;
                }
                let object_id = old
                    .as_ref()
                    .map(|d| d["object_id"].clone())
                    .unwrap_or_else(|| {
                        if edit["object_kind"] == "group-metadata" {
                            edit["group_id"].clone()
                        } else if edit["object_id"].is_null() {
                            json!(random_id())
                        } else {
                            edit["object_id"].clone()
                        }
                    });
                check(
                    edit["object_kind"] != "group-metadata" || object_id == edit["group_id"],
                    "CONTEXT_MISMATCH",
                )?;
                check(
                    edit["content"]["metadata_kind"] != "account-preferences"
                        || (g["status"]["settings"] == true
                            && edit["object_kind"] == "group-metadata"),
                    "PRIVATE_NAMESPACE_REQUIRED",
                )?;
                check(
                    g["status"]["settings"] != true
                        || edit["content"]["metadata_kind"] == "account-preferences",
                    "PRIVATE_NAMESPACE_REQUIRED",
                )?;
                if !edit["content"]["summary_entry_id"].is_null() {
                    check(
                        edit["object_kind"] == "thread"
                            && values(&c, "witnesses")?.iter().any(|w| {
                                w["group_id"] == edit["group_id"]
                                    && w["object_kind"] == "entry"
                                    && w["thread_id"] == object_id
                                    && w["object_id"] == edit["content"]["summary_entry_id"]
                                    && w["action"] != "soft-delete"
                            }),
                        "CONTEXT_MISMATCH",
                    )?;
                }
                for p in values(edit, "parents")? {
                    check(
                        values(&c, "witnesses")?.iter().any(|w| {
                            w["group_id"] == edit["group_id"]
                                && w["object_id"] == object_id
                                && w["revision_id"] == p["revision_id"]
                                && w["envelope_digest"] == p["envelope_digest"]
                        }),
                        "UNANCHORED_HISTORY",
                    )?;
                }
                let a = match author(&roster, &self.scope, &i.secrets.as_ref().unwrap().signing) {
                    Ok(a) => a,
                    Err(_) => {
                        let e = values(&snapshot, "events")?
                            .iter()
                            .rev()
                            .find(|e| {
                                e["body"]["payload"]["certificate"]["body"]["device_id"]
                                    == self.scope.device_id
                            })
                            .ok_or(Error("DEVICE_REVOKED"))?;
                        let h = json!({"version":e["body"]["version"],"digest":digest("p02-state-c1","event",e)?});
                        let old = historical(&self.codec, &snapshot, &s.pins, &h)?;
                        author(&old, &self.scope, &i.secrets.as_ref().unwrap().signing)?
                    }
                };
                let context = json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"object-context","service_id":self.scope.service_id,"group_id":group,"object_kind":edit["object_kind"],"object_id":object_id,"revision_id":random_id(),"operation_id":random_id(),"thread_id":edit["thread_id"],"action":edit["action"],"author":a,"policy":policy(&info),"parents":edit["parents"],"attachments":[],"payload_schema":1,"archived":edit["archived"]});
                let mut payload = edit["content"].clone();
                payload["contract"] = json!("p02-v1");
                payload["protocol"] = json!("anynote");
                payload["protocol_version"] = json!(1);
                payload["purpose"] = json!("object-plaintext");
                payload["context"] = context.clone();
                self.codec.validate("p02-v1", "payload", &payload)?;
                let draft_id = old
                    .as_ref()
                    .map_or_else(random_id, |d| d["draft_id"].as_str().unwrap().into());
                let data = json!({"draft_id":draft_id,"context":context,"payload":payload});
                self.codec.validate("p02-v1", "draft", &data)?;
                let mut r=old.unwrap_or_else(||json!({"draft_id":draft_id,"record_id":random_id(),"group_id":group,"object_id":object_id,"object_kind":edit["object_kind"],"thread_id":edit["thread_id"],"saved_digest":null}));
                r["saved_digest"] = json!(value_hash(&data)?);
                if let Some(audience) = &copy_audience {
                    writable(
                        &g,
                        &info,
                        &roster,
                        &self.scope,
                        &i.secrets.as_ref().unwrap().signing,
                    )?;
                    check(
                        *audience == hash(&canonical(&info["members"])?),
                        "COPY_CONFIRMATION_REQUIRED",
                    )?;
                    r["copy_audience_digest"] = json!(audience);
                }
                if let Ok(n) = index(&c, "drafts", "draft_id", &draft_id) {
                    c["drafts"][n] = r.clone();
                } else {
                    check(values(&c, "drafts")?.len() < 10000, "RESOURCE_LIMIT")?;
                    list(&mut c, "drafts")?.push(r.clone());
                }
                let writes = [Write {
                    id: text(&r["record_id"])?.into(),
                    kind: "draft".into(),
                    data,
                }];
                self.note_commit(&mut i, cap, &s, fence, &c, &writes, None)?;
                Ok(json!({"draft_id":draft_id,"object_id":object_id,"state":"LOCAL_SAVED"}))
            }
            NotesRequest::Draft { draft_id } => {
                check(valid_id(draft_id), "INVALID_REQUEST")?;
                let (_, mut data) = self.note_draft(&mut i, &s, &c, draft_id)?;
                let result = json!({"draft_id":draft_id,"payload":data["payload"]});
                wipe_value(&mut data);
                Ok(result)
            }
            NotesRequest::Queue { draft_id } => {
                check(valid_id(draft_id), "INVALID_REQUEST")?;
                let (mut d, mut data) = self.note_draft(&mut i, &s, &c, draft_id)?;
                let (g, _, info) =
                    self.note_info(&mut i, &s, &c, &snapshot, text(&d["group_id"])?)?;
                writable(
                    &g,
                    &info,
                    &roster,
                    &self.scope,
                    &i.secrets.as_ref().unwrap().signing,
                )?;
                if !d["copy_audience_digest"].is_null() {
                    check(
                        d["copy_audience_digest"] == hash(&canonical(&info["members"])?),
                        "COPY_CONFIRMATION_REQUIRED",
                    )?;
                }
                if data["context"]["object_kind"] == "group-metadata" && info["members"].is_array()
                {
                    check(
                        info["members"].as_array().unwrap().iter().any(|m| {
                            m["account_id"] == self.scope.account_id && m["role"] == "owner"
                        }),
                        "OWNER_REQUIRED",
                    )?;
                }
                if let Some(a) = values(&c, "attempts")?.iter().rev().find(|a| {
                    a["draft_id"] == draft_id.as_str()
                        && ["QUEUED", "SENT_UNKNOWN"].contains(&a["state"].as_str().unwrap_or(""))
                }) {
                    check(
                        a["source_digest"] == d["saved_digest"],
                        "PUBLICATION_PENDING",
                    )?;
                    let out = json!({"attempt_id":a["attempt_id"],"state":a["state"]});
                    wipe_value(&mut data);
                    return Ok(out);
                }
                check(values(&c, "attempts")?.len() < 10000, "RESOURCE_LIMIT")?;
                data["context"]["author"] =
                    author(&roster, &self.scope, &i.secrets.as_ref().unwrap().signing)?;
                data["context"]["policy"] = policy(&info);
                data["context"]["operation_id"] = json!(random_id());
                data["context"]["revision_id"] = json!(random_id());
                data["payload"]["context"] = data["context"].clone();
                self.codec.validate("p02-v1", "draft", &data)?;
                d["saved_digest"] = json!(value_hash(&data)?);
                let key = self.note_key(&i, &s, text(&d["group_id"])?, &info)?;
                let bundle = objects::seal_object(
                    &self.codec,
                    &Zeroizing::new(canonical(&data["payload"])?),
                    &key,
                    &i.secrets.as_ref().unwrap().signing,
                )?;
                let x = &bundle["envelope"]["header"]["context"];
                let out = json!({"draft_id":draft_id,"attempt_id":x["operation_id"],"revision_id":x["revision_id"],"state":"QUEUED","attempt_digest":digest("p02-v1","bundle",&bundle)?,"bundle":bundle,"receipt":null});
                self.codec.validate("p02-v1", "outbox", &out)?;
                let a = json!({"attempt_id":out["attempt_id"],"record_id":random_id(),"draft_id":draft_id,"source_digest":d["saved_digest"],"state":"QUEUED"});
                let n = index(&c, "drafts", "draft_id", draft_id)?;
                c["drafts"][n] = d.clone();
                list(&mut c, "attempts")?.push(a.clone());
                let result = json!({"attempt_id":a["attempt_id"],"state":"QUEUED"});
                let writes = [
                    Write {
                        id: text(&d["record_id"])?.into(),
                        kind: "draft".into(),
                        data,
                    },
                    Write {
                        id: text(&a["record_id"])?.into(),
                        kind: "outbox".into(),
                        data: out,
                    },
                ];
                self.note_commit(&mut i, cap, &s, fence, &c, &writes, None)?;
                Ok(result)
            }
            NotesRequest::Send { attempt_id } => {
                check(valid_id(attempt_id), "INVALID_REQUEST")?;
                let (r, mut data) = self.note_attempt(&mut i, &s, &c, attempt_id)?;
                check(
                    ["QUEUED", "SENT_UNKNOWN"].contains(&text(&data["state"])?),
                    "INVALID_OUTBOX_TRANSITION",
                )?;
                let (g, _, info) = self.note_info(
                    &mut i,
                    &s,
                    &c,
                    &snapshot,
                    text(&data["bundle"]["envelope"]["header"]["context"]["group_id"])?,
                )?;
                writable(
                    &g,
                    &info,
                    &roster,
                    &self.scope,
                    &i.secrets.as_ref().unwrap().signing,
                )?;
                let draft = values(&c, "drafts")?
                    .iter()
                    .find(|d| d["draft_id"] == data["draft_id"]);
                if let Some(d) = draft
                    && !d["copy_audience_digest"].is_null()
                {
                    check(
                        d["copy_audience_digest"] == hash(&canonical(&info["members"])?),
                        "COPY_CONFIRMATION_REQUIRED",
                    )?;
                }
                data["state"] = json!("SENT_UNKNOWN");
                let n = index(&c, "attempts", "attempt_id", attempt_id)?;
                c["attempts"][n]["state"] = json!("SENT_UNKNOWN");
                let result = json!({"attempt_id":attempt_id,"request":request_for(&data["bundle"]),"state":"SENT_UNKNOWN"});
                let writes = [Write {
                    id: text(&r["record_id"])?.into(),
                    kind: "outbox".into(),
                    data,
                }];
                self.note_commit(&mut i, cap, &s, fence, &c, &writes, None)?;
                Ok(result)
            }
            NotesRequest::Reject { attempt_id, code } => {
                check(
                    valid_id(attempt_id)
                        && [
                            "STALE_REVISION",
                            "REKEY_REQUIRED",
                            "HISTORY_CLOSURE_REQUIRED",
                            "POLICY_CHANGED",
                            "ROSTER_CHANGED",
                            "DEVICE_REVOKED",
                            "DEVICE_NOT_TRUSTED",
                            "ROLE_FORBIDDEN",
                            "NOT_FOUND",
                            "ACCESS_REVOKED",
                        ]
                        .contains(&code.as_str()),
                    "INVALID_REQUEST",
                )?;
                let (r, mut data) = self.note_attempt(&mut i, &s, &c, attempt_id)?;
                check(
                    ["QUEUED", "SENT_UNKNOWN"].contains(&text(&data["state"])?),
                    "INVALID_OUTBOX_TRANSITION",
                )?;
                let state = if code == "STALE_REVISION" {
                    "CONFLICT"
                } else if [
                    "REKEY_REQUIRED",
                    "HISTORY_CLOSURE_REQUIRED",
                    "POLICY_CHANGED",
                    "ROSTER_CHANGED",
                ]
                .contains(&code.as_str())
                {
                    "REKEY_REQUIRED"
                } else {
                    "ACCESS_LOST"
                };
                data["state"] = json!(state);
                let n = index(&c, "attempts", "attempt_id", attempt_id)?;
                c["attempts"][n]["state"] = json!(state);
                let result = json!({"state":state,"draft_id":data["draft_id"]});
                let writes = [Write {
                    id: text(&r["record_id"])?.into(),
                    kind: "outbox".into(),
                    data,
                }];
                self.note_commit(&mut i, cap, &s, fence, &c, &writes, None)?;
                Ok(result)
            }
            NotesRequest::Ack { attempt_id, result } => {
                check(valid_id(attempt_id), "INVALID_REQUEST")?;
                self.codec.validate("p09-notes", "receipt-result", result)?;
                let (r, mut data) = self.note_attempt(&mut i, &s, &c, attempt_id)?;
                check(
                    ["SENT_UNKNOWN", "COMMITTED"].contains(&text(&data["state"])?),
                    "INVALID_OUTBOX_TRANSITION",
                )?;
                let previously_committed = data["state"] == "COMMITTED";
                if previously_committed {
                    check(data["receipt"] == result["receipt"], "IDEMPOTENCY_MISMATCH")?;
                }
                let x = data["bundle"]["envelope"]["header"]["context"].clone();
                let ed = digest("p02-v1", "envelope", &data["bundle"]["envelope"])?;
                check(
                    result["receipt"]["operation_id"] == x["operation_id"]
                        && result["receipt"]["revision_id"] == x["revision_id"]
                        && result["receipt"]["envelope_digest"] == ed
                        && result["heads"]
                            == json!([{"revision_id":x["revision_id"],"envelope_digest":ed}]),
                    "RECEIPT_CONTEXT_MISMATCH",
                )?;
                data["state"] = json!("COMMITTED");
                data["receipt"] = result["receipt"].clone();
                self.codec.validate("p02-v1", "outbox", &data)?;
                let n = index(&c, "attempts", "attempt_id", attempt_id)?;
                c["attempts"][n]["state"] = json!("COMMITTED");
                let cached = self.note_cache(&mut c, &data["bundle"])?;
                let draft_id = text(&data["draft_id"])?.to_owned();
                let local = if values(&c, "drafts")?
                    .iter()
                    .any(|d| d["draft_id"] == draft_id)
                {
                    Some(self.note_draft(&mut i, &s, &c, &draft_id)?)
                } else {
                    check(previously_committed, "INTEGRITY_FAILURE")?;
                    None
                };
                let mut retired = local.is_none();
                let mut writes = vec![
                    Write {
                        id: text(&r["record_id"])?.into(),
                        kind: "outbox".into(),
                        data,
                    },
                    cached,
                ];
                if let Some((mut d, mut draft)) = local {
                    if d["saved_digest"] == r["source_digest"] {
                        list(&mut c, "drafts")?.retain(|d| d["draft_id"] != draft_id);
                        wipe_value(&mut draft);
                        retired = true;
                    } else if ["create", "update"].contains(&text(&x["action"])?)
                        && draft["context"]["action"] == x["action"]
                        && draft["context"]["parents"] == x["parents"]
                    {
                        draft["context"]["action"] = json!("update");
                        draft["context"]["parents"] = result["heads"].clone();
                        draft["context"]["operation_id"] = json!(random_id());
                        draft["context"]["revision_id"] = json!(random_id());
                        draft["payload"]["context"] = draft["context"].clone();
                        self.codec.validate("p02-v1", "draft", &draft)?;
                        d["saved_digest"] = json!(value_hash(&draft)?);
                        let n = index(&c, "drafts", "draft_id", &draft_id)?;
                        c["drafts"][n] = d.clone();
                        writes.push(Write {
                            id: text(&d["record_id"])?.into(),
                            kind: "draft".into(),
                            data: draft,
                        });
                    } else {
                        wipe_value(&mut draft);
                    }
                }
                let response = json!({"state":"COMMITTED","draft_id":draft_id,"revision_id":x["revision_id"],"draft_retired":retired});
                self.note_commit(&mut i, cap, &s, fence, &c, &writes, None)?;
                Ok(response)
            }
            NotesRequest::Open { request } => {
                self.note_open(&mut i, cap, &s, fence, &mut c, &snapshot, &roster, request)
            }
            NotesRequest::Cached { revision_id } => {
                check(valid_id(revision_id), "INVALID_REQUEST")?;
                let w = find(&c, "witnesses", "revision_id", revision_id)?;
                let cache = self.note_read(&mut i, &s, &c, text(&w["cache_id"])?, "cache")?;
                check(
                    cache["purpose"] != "p11-header-evidence",
                    "PAYLOAD_UNAVAILABLE",
                )?;
                let b =
                    self.codec
                        .decode("p02-v1", "bundle", &un64(text(&cache["record_bytes"])?)?)?;
                check(
                    digest("p02-v1", "envelope", &b["envelope"])? == w["envelope_digest"],
                    "INTEGRITY_FAILURE",
                )?;
                let x = &b["envelope"]["header"]["context"];
                let request = json!({"group_id":w["group_id"],"object_id":w["object_id"],"revision_id":revision_id,"object_kind":x["object_kind"],"thread_id":x["thread_id"],"bundle":b});
                self.note_open(&mut i, cap, &s, fence, &mut c, &snapshot, &roster, &request)
            }
        })();
        request.wipe();
        if result.is_ok() {
            check(
                self.signal.generation() == cap.generation,
                "STALE_CAPABILITY",
            )?;
            self.authorize(&mut i, cap)?;
        }
        result
    }
    #[allow(clippy::too_many_arguments)]
    fn note_open(
        &self,
        i: &mut Inner,
        cap: &Capability,
        s: &State,
        fence: u64,
        c: &mut Value,
        snapshot: &Value,
        roster: &Roster,
        request: &Value,
    ) -> Result<Value> {
        let result = self.note_verify(i, s, c, (snapshot, roster), request)?;
        let write = self.note_cache(c, &request["bundle"])?;
        self.note_commit(i, cap, s, fence, c, &[write], None)?;
        Ok(result)
    }
    fn note_verify(
        &self,
        i: &mut Inner,
        s: &State,
        c: &Value,
        evidence: (&Value, &Roster),
        request: &Value,
    ) -> Result<Value> {
        let (snapshot, roster) = evidence;
        self.codec.validate("p09-notes", "open-request", request)?;
        let b = &request["bundle"];
        self.codec.validate("p02-v1", "bundle", b)?;
        let x = &b["envelope"]["header"]["context"];
        let (_, _, info) = self.note_info(i, s, c, snapshot, text(&request["group_id"])?)?;
        if info["policy"].is_object() {
            for k in [
                "group_id",
                "object_id",
                "revision_id",
                "object_kind",
                "thread_id",
            ] {
                check(x[k] == request[k], "CONTEXT_MISMATCH")?;
            }
            let r = find(c, "groups", "group_id", text(&request["group_id"])?)?;
            let data = self.note_read(i, s, c, text(&r["record_id"])?, "group-evidence")?;
            let (proof, verified) = self.note_shared_proof(i, s, c, snapshot, &data)?;
            let cert =
                crate::shared::object_author(&self.codec, &proof, &verified, b, &self.scope)?;
            let mut key_info = info.clone();
            key_info["policy"] = x["policy"].clone();
            key_info["epoch_digest"] = x["policy"]["epoch_digest"].clone();
            let key = self.note_key(i, s, text(&request["group_id"])?, &key_info)?;
            check(
                crate::device_groups::key_commitment(
                    &json!({"service_id":self.scope.service_id,"group_id":request["group_id"]}),
                    &key,
                )? == verified
                    .epochs
                    .iter()
                    .find(|e| e["key_epoch"] == x["policy"]["key_epoch"])
                    .ok_or(Error("KEYS_PENDING"))?["key_commitment"],
                "KEY_REPAIR_REQUIRED",
            )?;
            let payload = objects::open_object(
                &self.codec,
                &canonical(b)?,
                &key,
                &un64(text(&cert["body"]["device_signing_key"])?)?,
                &canonical(x)?,
            )?;
            check(
                payload["metadata_kind"] != "account-preferences",
                "PRIVATE_NAMESPACE_REQUIRED",
            )?;

            return Ok(
                json!({"payload":payload,"envelope_digest":digest("p02-v1","envelope",&b["envelope"])?}),
            );
        }
        check(
            x["service_id"] == self.scope.service_id
                && x["group_id"] == request["group_id"]
                && x["object_id"] == request["object_id"]
                && x["revision_id"] == request["revision_id"]
                && x["object_kind"] == request["object_kind"]
                && x["thread_id"] == request["thread_id"]
                && x["author"]["account_id"] == self.scope.account_id
                && x["author"]["root_fingerprint"] == s.pins["root_fingerprint"]
                && x["policy"] == policy(&info),
            "CONTEXT_MISMATCH",
        )?;
        let past = historical(&self.codec, snapshot, &s.pins, &x["author"]["roster"])?;
        let actor = past.active(text(&x["author"]["device_id"])?, Some("sign-content"))?;
        check(
            actor.certificate["body"]["recovery_generation"] == x["author"]["recovery_generation"],
            "CONTEXT_MISMATCH",
        )?;
        let ed = digest("p02-v1", "envelope", &b["envelope"])?;
        let current = roster
            .devices
            .get(text(&x["author"]["device_id"])?)
            .is_some_and(|d| {
                d.active
                    && d.certificate["body"]["recovery_generation"]
                        == x["author"]["recovery_generation"]
            });
        let known = values(c, "witnesses")?.iter().any(|w| {
            w["group_id"] == x["group_id"]
                && w["object_id"] == x["object_id"]
                && w["revision_id"] == x["revision_id"]
                && w["envelope_digest"] == ed
        });
        check(current || known, "UNANCHORED_HISTORY")?;
        let key = self.note_key(i, s, text(&request["group_id"])?, &info)?;
        let payload = objects::open_object(
            &self.codec,
            &canonical(b)?,
            &key,
            &un64(text(&actor.certificate["body"]["device_signing_key"])?)?,
            &canonical(x)?,
        )?;

        Ok(json!({"payload":payload,"envelope_digest":ed}))
    }
}
