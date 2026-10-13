//! Private-settings genesis and same-account key custody. General group transitions remain P10.
use super::*;
use crate::device_roster::{Roster, digest, signed};

pub(crate) fn signer(roster: &Roster, id: &str) -> Result<Value> {
    let d = roster.active(id, Some("distribute-group-key"))?;
    Ok(
        json!({"account_id":roster.pins["account_id"],"device_id":id,"root_fingerprint":roster.pins["root_fingerprint"],"recovery_generation":roster.generation,"roster_head":roster.head,"certificate_digest":d.digest}),
    )
}
pub(crate) fn recipient(roster: &Roster, id: Option<&str>) -> Result<Value> {
    let mut out = json!({"kind":if id.is_some(){"device"}else{"account-recovery"},"account_id":roster.pins["account_id"],"root_fingerprint":roster.pins["root_fingerprint"],"recovery_generation":roster.generation,"roster_head":roster.head});
    let key = if let Some(id) = id {
        let d = roster.active(id, Some("receive-group-key"))?;
        out["device_id"] = json!(id);
        out["certificate_digest"] = json!(d.digest);
        &d.certificate["body"]["device_encryption_key"]
    } else {
        &roster.identity["body"]["recovery_encryption_key"]
    };
    let mut bytes = b"AnyNote/p02-identity-c1/hash/x25519-public-key\0".to_vec();
    bytes.extend(un64(text(key)?)?);
    out["encryption_key_fingerprint"] = json!(hash(&bytes));
    Ok(out)
}
pub(crate) fn key_commitment(scope: &Value, key: &[u8]) -> Result<String> {
    check(key.len() == 32, "INVALID_KEY_LENGTH")?;
    let mut b = b"AnyNote/p02-group-c2/hash/group-epoch-key\0".to_vec();
    b.extend(canonical(scope)?);
    b.extend(key);
    Ok(hash(&b))
}
pub(crate) fn public_sign(codec: &Codec, kind: &str, body: Value, key: &[u8]) -> Result<Value> {
    codec.validate("p02-group-c2", &format!("{kind}-body"), &body)?;
    let mut value = json!({"signature":anynote_crypto_core::crypto::sign(&codec.signing("p02-group-c2",&format!("{kind}-body"),&body)?,key)?,"body":body});
    if kind == "policy" {
        value["cosignature"] = Value::Null;
    }
    codec.validate("p02-group-c2", kind, &value)?;
    Ok(value)
}
pub(crate) fn common(purpose: &str, scope: &Value, operation: &str) -> Value {
    json!({"purpose":purpose,"contract":"p02-group-c2","protocol":"anynote","protocol_version":1,"service_id":scope["service_id"],"group_id":scope["group_id"],"operation_id":operation})
}
fn page_commitment(page: &Value) -> Result<String> {
    let records = page["records"].as_array().ok_or(Error("SCHEMA_MISMATCH"))?;
    let mut bytes = b"AnyNote/p02-group-c2/hash/grant-inventory\0".to_vec();
    bytes.extend(1_u32.to_be_bytes());
    bytes.extend((records.len() as u64).to_be_bytes());
    bytes.extend(0_u32.to_be_bytes());
    bytes.extend((records.len() as u32).to_be_bytes());
    bytes.extend((canonical(page)?.len() as u32).to_be_bytes());
    bytes.extend(un64(&digest("p02-group-c2", "grant-page", page)?)?);
    Ok(hash(&bytes))
}
fn grant_context(
    roster: &Roster,
    issuer: &str,
    target: Option<&str>,
    group: &Value,
    operation: &str,
) -> Result<Value> {
    Ok(
        json!({"purpose":"group-key-distribution","contract":"p02-identity-c1","protocol":"anynote","protocol_version":1,"service_id":roster.pins["service_id"],"group_id":group["group_id"],"key_epoch":"0","epoch_digest":group["epoch_digest"],"membership_head":group["membership"],"operation_id":operation,"issuer":signer(roster,issuer)?,"recipient":recipient(roster,target)?}),
    )
}
pub(crate) fn historical(
    codec: &Codec,
    snapshot: &Value,
    pins: &Value,
    head: &Value,
) -> Result<Roster> {
    let events = snapshot["events"]
        .as_array()
        .ok_or(Error("SCHEMA_MISMATCH"))?;
    let index = events
        .iter()
        .position(|e| {
            e["body"]["version"] == head["version"]
                && digest("p02-state-c1", "event", e).is_ok_and(|d| json!(d) == head["digest"])
        })
        .ok_or(Error("UNANCHORED_HISTORY"))?;
    Roster::replay(
        codec,
        &json!({"identity":snapshot["identity"],"events":&events[..=index],"head":head,"generation":events[index]["body"]["generation"]}),
        pins,
        None,
    )
}
pub(crate) fn verify_genesis(
    codec: &Codec,
    evidence: &Value,
    snapshot: &Value,
    pins: &Value,
) -> Result<Value> {
    verify_genesis_kind(codec, evidence, snapshot, pins, "private")
}
pub(crate) fn verify_genesis_kind(
    codec: &Codec,
    evidence: &Value,
    snapshot: &Value,
    pins: &Value,
    kind: &str,
) -> Result<Value> {
    check(["private", "shared"].contains(&kind), "INVALID_REQUEST")?;
    let b = &evidence["commit"]["body"];
    let policy = &b["policy"];
    let p = &policy["body"];
    let intent = &b["intent"];
    let v = &intent["body"];
    let descriptor = &b["descriptor"];
    let d = &descriptor["body"];
    codec.validate("p02-group-c2", "epoch-commit", &evidence["commit"])?;
    let pages = evidence["pages"]
        .as_array()
        .ok_or(Error("SCHEMA_MISMATCH"))?;
    check(pages.len() == 1, "RESOURCE_LIMIT")?;
    codec.validate("p02-group-c2", "grant-page", &pages[0])?;
    let roster = historical(codec, snapshot, pins, &p["signer"]["roster_head"])?;
    let actor = roster.active(text(&p["signer"]["device_id"])?, Some("sign-content"))?;
    let sender = signer(&roster, text(&p["signer"]["device_id"])?)?;
    for (kind, record) in [
        ("policy", policy),
        ("epoch-intent", intent),
        ("descriptor", descriptor),
        ("epoch-commit", &evidence["commit"]),
    ] {
        signed(
            codec,
            "p02-group-c2",
            kind,
            record,
            text(&actor.certificate["body"]["device_signing_key"])?,
        )?;
        check(
            record["body"]["service_id"] == pins["service_id"]
                && record["body"]["group_id"] == b["group_id"]
                && record["body"]["operation_id"] == b["operation_id"],
            "GRANT_CONTEXT_MISMATCH",
        )?;
    }
    check(
        policy["cosignature"].is_null()
            && p["action"] == "genesis"
            && p["payload"]["group_kind"] == kind
            && p["version"] == "0"
            && p["predecessor"].is_null()
            && p["members"]
                == json!([{"account_id":pins["account_id"],"root_fingerprint":pins["root_fingerprint"],"role":"owner"}])
            && p["signer"] == sender
            && v["signer"] == sender
            && d["signer"] == sender,
        "POLICY_REQUIRED",
    )?;
    let membership = json!({"version":"0","digest":digest("p02-group-c2","policy",policy)?});
    let epoch = digest("p02-group-c2", "epoch-intent", intent)?;
    check(
        v["reason"] == "genesis"
            && v["previous_epoch"].is_null()
            && v["next_epoch"] == "0"
            && v["retained_epochs"] == json!([])
            && v["history_checkpoint_digest"].is_null()
            && v["expected_policy"] == membership
            && v["membership"] == membership
            && d["membership"] == membership
            && d["intent_digest"] == epoch,
        "INTEGRITY_FAILURE",
    )?;
    check(
        v["rosters"]
            == json!([{"account_id":pins["account_id"],"root_fingerprint":pins["root_fingerprint"],"recovery_generation":roster.generation,"roster":roster.head}]),
        "ROSTER_CHANGED",
    )?;
    let page = &pages[0];
    let records = page["records"].as_array().ok_or(Error("SCHEMA_MISMATCH"))?;
    check(
        page["service_id"] == pins["service_id"]
            && page["group_id"] == b["group_id"]
            && page["operation_id"] == b["operation_id"]
            && page["page_index"] == "0",
        "INTEGRITY_FAILURE",
    )?;
    let mut expected = std::collections::BTreeMap::new();
    for (id, device) in &roster.devices {
        if device.active {
            expected.insert(format!("device/{id}"), recipient(&roster, Some(id))?);
        }
    }
    expected.insert("account-recovery/".into(), recipient(&roster, None)?);
    let count = expected.len();
    check(
        records.len() == count
            && text(&d["record_count"])?
                .parse::<usize>()
                .map_err(|_| Error("SCHEMA_MISMATCH"))?
                == count
            && d["page_count"] == "1"
            && d["inventory_digest"] == page_commitment(page)?
            && d["epoch_inventory_digest"]
                == digest(
                    "p02-group-c2",
                    "epochs",
                    &json!([{"key_epoch":"0","epoch_digest":epoch,"key_commitment":v["key_commitment"]}]),
                )?,
        "RECIPIENT_COVERAGE_MISMATCH",
    )?;
    let group = json!({"group_id":b["group_id"],"epoch_digest":epoch,"membership":membership,"key_commitment":v["key_commitment"]});
    let mut previous = None;
    for record in records {
        let ctx = &record["body"]["context"];
        let r = &ctx["recipient"];
        let rid = format!(
            "{}/{}",
            text(&r["kind"])?,
            r["device_id"].as_str().unwrap_or("")
        );
        let recipient = expected
            .remove(&rid)
            .ok_or(Error("RECIPIENT_COVERAGE_MISMATCH"))?;
        let mut wanted = grant_context(
            &roster,
            text(&sender["device_id"])?,
            r["device_id"].as_str(),
            &group,
            text(&b["operation_id"])?,
        )?;
        wanted["recipient"] = recipient;
        check(*ctx == wanted, "GRANT_CONTEXT_MISMATCH")?;
        signed(
            codec,
            "p02-identity-c1",
            "grant",
            record,
            text(&actor.certificate["body"]["device_signing_key"])?,
        )?;
        let order = format!(
            "0000000000000000000/{}/{}/{}",
            text(&r["account_id"])?,
            text(&r["kind"])?,
            r["device_id"].as_str().unwrap_or("")
        );
        check(
            previous.as_ref().is_none_or(|old: &String| old < &order),
            "UNORDERED_OR_DUPLICATE",
        )?;
        previous = Some(order);
    }
    check(expected.is_empty(), "RECIPIENT_COVERAGE_MISMATCH")?;
    Ok(group)
}
impl Vault {
    pub(crate) fn snapshot_for_groups(&self, i: &mut Inner, s: &State) -> Result<Value> {
        let (control, _) = self.device_saved(i, s)?;
        let mut events = Vec::new();
        for id in control["pages"]
            .as_array()
            .ok_or(Error("ROSTER_PROOF_REQUIRED"))?
        {
            let id = text(id)?;
            let p = crate::device_local::open(
                &self.scope,
                &s.pins,
                id,
                "roster-page",
                &frame(&i.conn, id)?,
                &i.secrets.as_ref().unwrap().key,
            )?;
            events.extend(
                p["events"]
                    .as_array()
                    .ok_or(Error("INTEGRITY_FAILURE"))?
                    .iter()
                    .cloned(),
            );
        }
        Ok(
            json!({"identity":control["identity"],"head":control["head"],"generation":control["generation"],"events":events}),
        )
    }
    fn save_group_key(
        &self,
        i: &mut Inner,
        cap: &Capability,
        before: &State,
        fence: u64,
        control: &Value,
        key: &Value,
    ) -> Result<()> {
        let local_key = Zeroizing::new(i.secrets.as_ref().unwrap().key.to_vec());
        let f = frame(&i.conn, &before.vault_id)?;
        let mut plain = objects::open_local(
            &self.codec,
            &canonical(&f)?,
            &local_key,
            &canonical(&self.context("vault-secrets", &before.vault_id)?)?,
        )?;
        let result = (|| {
            let values = plain["data"]["group_keys"]
                .as_array_mut()
                .ok_or(Error("INTEGRITY_FAILURE"))?;
            if let Some(old) = values
                .iter()
                .find(|v| v["group_id"] == key["group_id"] && v["key_epoch"] == key["key_epoch"])
            {
                check(old == key, "INTEGRITY_FAILURE")?;
            } else {
                values.push(key.clone());
            }
            values.sort_by_key(|v| {
                format!(
                    "{}/{:0>19}",
                    v["group_id"].as_str().unwrap(),
                    v["key_epoch"].as_str().unwrap()
                )
            });
            self.codec
                .validate("p02-v1", "vault-secrets", &plain["data"])?;
            let encrypted =
                objects::seal_local(&self.codec, &Zeroizing::new(canonical(&plain)?), &local_key)?;
            let id = crate::device_local::control_id(&self.scope)?;
            let ctl = crate::device_local::seal(
                &self.scope,
                &before.pins,
                &id,
                "device-control",
                control,
                &local_key,
            )?;
            let tx = db(i
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate))?;
            let mut s = state(&tx, &self.codec, &self.scope)?;
            check(
                s.epoch == before.epoch && s.revision == before.revision,
                "STALE_WRITER",
            )?;
            self.fence(&s, fence)?;
            db(tx.execute(
                "UPDATE records SET frame=?1 WHERE id=?2",
                params![canonical(&encrypted)?, s.vault_id],
            ))?;
            db(tx.execute("INSERT INTO records(id,frame) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET frame=excluded.frame",params![id,canonical(&ctl)?]))?;
            s.revision += 1;
            put_state(&tx, &s)?;
            check(
                self.signal.generation() == cap.generation,
                "STALE_CAPABILITY",
            )?;
            db(tx.commit())?;
            i.observed_revision = s.revision;
            Ok(())
        })();
        wipe_value(&mut plain);
        result
    }
    pub fn device_settings_genesis(&self, cap: &Capability) -> Result<Value> {
        let fence = self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (mut control, roster) = self.device_saved(&mut i, &s)?;
        let roster = roster.ok_or(Error("ROSTER_PROOF_REQUIRED"))?;
        roster.active(&self.scope.device_id, Some("sign-content"))?;
        if let Some(request) = control.get("genesis_request") {
            return Ok(request.clone());
        }
        let (request, mut key_record) = create_private_genesis(
            &self.codec,
            &roster,
            &self.scope,
            &s.pins,
            &i.secrets.as_ref().unwrap().signing,
        )?;
        verify_genesis(
            &self.codec,
            &request,
            &self.snapshot_for_groups(&mut i, &s)?,
            &s.pins,
        )?;
        control["genesis_request"] = request.clone();
        let result = self.save_group_key(&mut i, cap, &s, fence, &control, &key_record);
        wipe_value(&mut key_record);
        result?;
        Ok(request)
    }
    pub fn device_group_keys(
        &self,
        cap: &Capability,
        evidence: &Value,
        records: &[Value],
        kit: Option<&Value>,
        target: Option<&str>,
    ) -> Result<Value> {
        let fence = self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (mut control, roster) = self.device_saved(&mut i, &s)?;
        let roster = roster.ok_or(Error("ROSTER_PROOF_REQUIRED"))?;
        roster.active(&self.scope.device_id, Some("receive-group-key"))?;
        let snapshot = self.snapshot_for_groups(&mut i, &s)?;
        let group = verify_genesis(&self.codec, evidence, &snapshot, &s.pins)?;
        check(records.len() <= 60, "RESOURCE_LIMIT")?;
        let secret = i.secrets.as_ref().unwrap();
        let key = if let Some(kit) = kit {
            let root = objects::recover_root(
                &self.codec,
                &Zeroizing::new(canonical(kit)?),
                &canonical(&s.pins)?,
            )?;
            let matches = records
                .iter()
                .filter(|r| {
                    r["body"]["context"]["group_id"] == group["group_id"]
                        && r["body"]["context"]["recipient"]["kind"] == "account-recovery"
                })
                .collect::<Vec<_>>();
            check(matches.len() == 1, "KEYS_PENDING")?;
            let r = matches[0];
            let ctx = &r["body"]["context"];
            let issuer = historical(
                &self.codec,
                &snapshot,
                &s.pins,
                &ctx["issuer"]["roster_head"],
            )?;
            let device = issuer.active(
                text(&ctx["issuer"]["device_id"])?,
                Some("distribute-group-key"),
            )?;
            check(
                ctx["recipient"] == recipient(&issuer, None)?
                    && ctx["issuer"] == signer(&issuer, text(&ctx["issuer"]["device_id"])?)?
                    && ctx["service_id"] == s.pins["service_id"]
                    && ctx["key_epoch"] == "0"
                    && ctx["epoch_digest"] == group["epoch_digest"]
                    && ctx["membership_head"] == group["membership"],
                "GRANT_CONTEXT_MISMATCH",
            )?;
            objects::open_grant(
                &self.codec,
                &canonical(r)?,
                &canonical(ctx)?,
                &un64(text(&device.certificate["body"]["device_signing_key"])?)?,
                root.1.public_key.as_ref(),
                root.1.secret_key.as_ref(),
            )?
        } else if target.is_some() {
            let mut p = objects::open_local(
                &self.codec,
                &canonical(&frame(&i.conn, &s.vault_id)?)?,
                &secret.key,
                &canonical(&self.context("vault-secrets", &s.vault_id)?)?,
            )?;
            let result = (|| {
                let key = p["data"]["group_keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|k| {
                        k["group_id"] == group["group_id"]
                            && k["key_epoch"] == "0"
                            && k["epoch_digest"] == group["epoch_digest"]
                    })
                    .ok_or(Error("KEYS_PENDING"))?;
                Ok(Zeroizing::new(un64(text(&key["group_secret"])?)?))
            })();
            wipe_value(&mut p);
            result?
        } else {
            let matches = records
                .iter()
                .filter(|r| {
                    r["body"]["context"]["group_id"] == group["group_id"]
                        && r["body"]["context"]["recipient"]["device_id"] == self.scope.device_id
                })
                .collect::<Vec<_>>();
            check(matches.len() == 1, "KEYS_PENDING")?;
            let r = matches[0];
            let ctx = &r["body"]["context"];
            let issuer = historical(
                &self.codec,
                &snapshot,
                &s.pins,
                &ctx["issuer"]["roster_head"],
            )?;
            let actor = issuer.active(
                text(&ctx["issuer"]["device_id"])?,
                Some("distribute-group-key"),
            )?;
            check(
                ctx["recipient"] == recipient(&issuer, Some(&self.scope.device_id))?
                    && ctx["issuer"] == signer(&issuer, text(&ctx["issuer"]["device_id"])?)?
                    && ctx["key_epoch"] == "0"
                    && ctx["epoch_digest"] == group["epoch_digest"]
                    && ctx["membership_head"] == group["membership"],
                "GRANT_CONTEXT_MISMATCH",
            )?;
            let pk =
                libsodium_rs::crypto_scalarmult::curve25519::scalarmult_base(&secret.encryption)
                    .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
            objects::open_grant(
                &self.codec,
                &canonical(r)?,
                &canonical(ctx)?,
                &un64(text(&actor.certificate["body"]["device_signing_key"])?)?,
                &pk,
                &secret.encryption,
            )?
        };
        check(
            key_commitment(
                &json!({"service_id":self.scope.service_id,"group_id":group["group_id"]}),
                &key,
            )? == group["key_commitment"],
            "INTEGRITY_FAILURE",
        )?;
        let mut key_record = json!({"service_id":self.scope.service_id,"group_id":group["group_id"],"key_epoch":"0","epoch_digest":group["epoch_digest"],"group_secret":b64(&key)});
        let result =
            if let Some(target) = target.or_else(|| kit.map(|_| self.scope.device_id.as_str())) {
                roster.active(&self.scope.device_id, Some("distribute-group-key"))?;
                let context = grant_context(
                    &roster,
                    &self.scope.device_id,
                    Some(target),
                    &group,
                    &random_id(),
                )?;
                let recipient = roster.active(target, Some("receive-group-key"))?;
                let grant = objects::seal_grant(
                    &self.codec,
                    &canonical(&context)?,
                    &key,
                    &un64(text(
                        &recipient.certificate["body"]["device_encryption_key"],
                    )?)?,
                    &secret.signing,
                )?;
                let request = json!({"version":1,"records":[grant]});
                control["grant_request"] = request.clone();
                self.save_group_key(&mut i, cap, &s, fence, &control, &key_record)?;
                Ok(request)
            } else {
                self.save_group_key(&mut i, cap, &s, fence, &control, &key_record)?;
                Ok(json!({"state":"keys-local-saved","group_id":group["group_id"]}))
            };
        wipe_value(&mut key_record);
        result
    }
}

pub(crate) fn create_private_genesis(
    codec: &Codec,
    roster: &Roster,
    installation: &Scope,
    pins: &Value,
    signing: &[u8],
) -> Result<(Value, Value)> {
    create_genesis_kind(codec, roster, installation, pins, signing, "private")
}
pub(crate) fn create_genesis_kind(
    codec: &Codec,
    roster: &Roster,
    installation: &Scope,
    pins: &Value,
    signing: &[u8],
    kind: &str,
) -> Result<(Value, Value)> {
    check(["private", "shared"].contains(&kind), "INVALID_REQUEST")?;
    roster.active(&installation.device_id, Some("sign-content"))?;
    let scope = json!({"service_id":installation.service_id,"group_id":random_id()});
    let op = random_id();
    let sender = signer(roster, &installation.device_id)?;
    let key = Zeroizing::new(libsodium_rs::random::bytes(32));
    let mut policy = common("group-policy-event", &scope, &op);
    policy["action"] = json!("genesis");
    policy["version"] = json!("0");
    policy["predecessor"] = Value::Null;
    policy["signer"] = sender.clone();
    policy["members"] = json!([{"account_id":installation.account_id,"root_fingerprint":pins["root_fingerprint"],"role":"owner"}]);
    policy["payload"] = json!({"group_kind":kind});
    let policy = public_sign(codec, "policy", policy, signing)?;
    let membership = json!({"version":"0","digest":digest("p02-group-c2","policy",&policy)?});
    let mut intent = common("group-epoch-intent", &scope, &op);
    intent["reason"] = json!("genesis");
    intent["expected_policy"] = membership.clone();
    intent["membership"] = membership.clone();
    intent["previous_epoch"] = Value::Null;
    intent["next_epoch"] = json!("0");
    intent["retained_epochs"] = json!([]);
    intent["key_commitment"] = json!(key_commitment(&scope, &key)?);
    intent["rosters"] = json!([{"account_id":installation.account_id,"root_fingerprint":pins["root_fingerprint"],"recovery_generation":roster.generation,"roster":roster.head}]);
    intent["history_checkpoint_digest"] = Value::Null;
    intent["signer"] = sender.clone();
    intent["expires_at"] = json!((now()? + 540000).to_string());
    let intent = public_sign(codec, "epoch-intent", intent, signing)?;
    let epoch = digest("p02-group-c2", "epoch-intent", &intent)?;
    let group = json!({"group_id":scope["group_id"],"epoch_digest":epoch,"membership":membership});
    let mut targets = roster
        .devices
        .iter()
        .filter(|(_, d)| d.active)
        .map(|(id, _)| Some(id.as_str()))
        .collect::<Vec<_>>();
    targets.push(None);
    let mut records = Vec::new();
    for target in targets {
        let context = grant_context(roster, &installation.device_id, target, &group, &op)?;
        let public = if let Some(id) = target {
            &roster.active(id, Some("receive-group-key"))?.certificate["body"]["device_encryption_key"]
        } else {
            &roster.identity["body"]["recovery_encryption_key"]
        };
        records.push(objects::seal_grant(
            codec,
            &canonical(&context)?,
            &key,
            &un64(text(public)?)?,
            signing,
        )?);
    }
    records.sort_by_key(|r| {
        format!(
            "{}/{}/{}",
            r["body"]["context"]["recipient"]["account_id"]
                .as_str()
                .unwrap(),
            r["body"]["context"]["recipient"]["kind"].as_str().unwrap(),
            r["body"]["context"]["recipient"]["device_id"]
                .as_str()
                .unwrap_or("")
        )
    });
    let mut page = common("group-grant-page", &scope, &op);
    page["page_index"] = json!("0");
    page["records"] = json!(records);
    codec.validate("p02-group-c2", "grant-page", &page)?;
    let mut descriptor = common("group-grant-descriptor", &scope, &op);
    descriptor["intent_digest"] = json!(epoch);
    descriptor["membership"] = membership;
    descriptor["inventory_digest"] = json!(page_commitment(&page)?);
    descriptor["record_count"] = json!(page["records"].as_array().unwrap().len().to_string());
    descriptor["page_count"] = json!("1");
    descriptor["epoch_inventory_digest"] = json!(digest(
        "p02-group-c2",
        "epochs",
        &json!([{"key_epoch":"0","epoch_digest":epoch,"key_commitment":intent["body"]["key_commitment"]}])
    )?);
    descriptor["signer"] = sender;
    let descriptor = public_sign(codec, "descriptor", descriptor, signing)?;
    let mut commit = common("group-epoch-commit", &scope, &op);
    commit["policy"] = policy;
    commit["intent"] = intent;
    commit["descriptor"] = descriptor;
    let commit = public_sign(codec, "epoch-commit", commit, signing)?;
    let request = json!({"version":1,"commit":commit,"pages":[page]});
    let key_record = json!({"service_id":installation.service_id,"group_id":scope["group_id"],"key_epoch":"0","epoch_digest":epoch,"group_secret":b64(&key)});
    Ok((request, key_record))
}
