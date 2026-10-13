//! Independently pinned P02 roster replay. No authentication, hardware or group-role claim.
use super::*;
use anynote_crypto_core::crypto;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
pub(crate) struct Device {
    pub certificate: Value,
    pub digest: String,
    pub active: bool,
    pub parent: Option<String>,
}
pub(crate) struct Roster {
    pub identity: Value,
    pub pins: Value,
    pub head: Value,
    pub generation: String,
    pub limit: String,
    pub devices: BTreeMap<String, Device>,
}
pub(crate) fn digest(profile: &str, purpose: &str, value: &Value) -> Result<String> {
    let mut bytes = format!("AnyNote/{profile}/hash/{purpose}\0").into_bytes();
    bytes.extend(canonical(value)?);
    Ok(hash(&bytes))
}
pub(crate) fn signed(
    codec: &Codec,
    profile: &str,
    kind: &str,
    record: &Value,
    key: &str,
) -> Result<()> {
    codec.validate(profile, kind, record)?;
    crypto::verify(
        &codec.signing(profile, &format!("{kind}-body"), &record["body"])?,
        text(&record["signature"])?,
        &un64(key)?,
    )
}
impl Roster {
    fn scope(&self, body: &Value) -> Result<()> {
        for key in ["service_id", "account_id", "root_fingerprint"] {
            check(body[key] == self.pins[key], "ROOT_PIN_MISMATCH")?;
        }
        Ok(())
    }
    pub fn active(&self, id: &str, capability: Option<&str>) -> Result<&Device> {
        let device = self.devices.get(id).ok_or(Error("DEVICE_NOT_ACTIVE"))?;
        check(
            device.active && device.certificate["body"]["recovery_generation"] == self.generation,
            "DEVICE_NOT_ACTIVE",
        )?;
        if let Some(cap) = capability {
            check(
                device.certificate["body"]["capabilities"]
                    .as_array()
                    .is_some_and(|v| v.iter().any(|x| x == cap)),
                "CAPABILITY_MISMATCH",
            )?;
        }
        Ok(device)
    }
    fn current(&self, body: &Value) -> Result<()> {
        self.scope(body)?;
        check(
            body["generation"] == self.generation && body["roster"] == self.head,
            "ROSTER_CHANGED",
        )
    }
    fn fresh(&self, codec: &Codec, device: &Value) -> Result<()> {
        codec.validate("p02-state-c1", "device", device)?;
        check(
            !self.devices.contains_key(text(&device["device_id"])?),
            "DEVICE_ID_REUSE",
        )?;
        let sk = text(&device["signing_key"])?;
        let ek = text(&device["encryption_key"])?;
        check(
            sk != ek
                && ![
                    text(&self.identity["body"]["root_signing_key"])?,
                    text(&self.identity["body"]["recovery_encryption_key"])?,
                ]
                .contains(&sk)
                && ![
                    text(&self.identity["body"]["root_signing_key"])?,
                    text(&self.identity["body"]["recovery_encryption_key"])?,
                ]
                .contains(&ek),
            "KEY_PURPOSE_COLLISION",
        )?;
        for old in self.devices.values() {
            let keys = [
                &old.certificate["body"]["device_signing_key"],
                &old.certificate["body"]["device_encryption_key"],
            ];
            check(
                !keys.contains(&&device["signing_key"])
                    && !keys.contains(&&device["encryption_key"]),
                "DEVICE_KEY_REUSE",
            )?;
        }
        let caps = device["capabilities"]
            .as_array()
            .ok_or(Error("SCHEMA_MISMATCH"))?;
        check(
            caps.windows(2).all(|p| p[0].as_str() < p[1].as_str()),
            "CAPABILITY_MISMATCH",
        )
    }
    #[allow(clippy::too_many_arguments)] // Explicit closed certificate bindings; no verifier exception.
    fn certificate(
        &self,
        codec: &Codec,
        record: &Value,
        device: &Value,
        generation: &str,
        issuer: Value,
        transcript: String,
        key: &str,
    ) -> Result<()> {
        let expected = json!({"purpose":"provisional-device-certificate","contract":"p02-identity-c1","protocol":"anynote","protocol_version":1,"service_id":self.pins["service_id"],"account_id":self.pins["account_id"],"root_fingerprint":self.pins["root_fingerprint"],"recovery_generation":generation,"predecessor_roster":self.head,"issuer":issuer,"device_id":device["device_id"],"device_signing_key":device["signing_key"],"device_encryption_key":device["encryption_key"],"capabilities":device["capabilities"],"pairing_transcript_digest":transcript});
        check(record["body"] == expected, "CERTIFICATE_CONTEXT_MISMATCH")?;
        signed(codec, "p02-identity-c1", "certificate", record, key)
    }
    pub fn descendants(&self, targets: &[String]) -> Result<Vec<String>> {
        for id in targets {
            self.active(id, None)?;
        }
        let mut all: BTreeSet<String> = targets.iter().cloned().collect();
        loop {
            let before = all.len();
            for (id, d) in &self.devices {
                if d.active && d.parent.as_ref().is_some_and(|p| all.contains(p)) {
                    all.insert(id.clone());
                }
            }
            if before == all.len() {
                break;
            }
        }
        Ok(all.into_iter().collect())
    }
    pub fn approval(
        &self,
        codec: &Codec,
        transcript: &Value,
        approval: &Value,
        clock: Option<u64>,
    ) -> Result<()> {
        codec.validate("p02-state-c1", "transcript", transcript)?;
        codec.validate("p02-state-c1", "approval", approval)?;
        let o = &transcript["offer"]["body"];
        let r = &transcript["response"]["body"];
        let a = &approval["body"];
        self.current(o)?;
        self.current(r)?;
        self.current(a)?;
        self.fresh(codec, &o["device"])?;
        if let Some(t) = clock {
            let expires: u64 = text(&o["expires_at"])?
                .parse()
                .map_err(|_| Error("SCHEMA_MISMATCH"))?;
            check(expires > t && expires - t <= 600000, "ENROLLMENT_EXPIRED")?;
        }
        signed(
            codec,
            "p02-state-c1",
            "offer",
            &transcript["offer"],
            text(&o["device"]["signing_key"])?,
        )?;
        let actor = self.active(text(&r["approver"]["device_id"])?, Some("delegate-device"))?;
        check(
            r["approver"]["certificate_digest"] == actor.digest
                && r["operation_id"] == o["operation_id"]
                && r["expires_at"] == o["expires_at"]
                && r["offer_digest"] == digest("p02-state-c1", "offer", &transcript["offer"])?
                && r["invitation_digest"] == o["invitation_digest"],
            "PAIRING_TRANSCRIPT_MISMATCH",
        )?;
        signed(
            codec,
            "p02-state-c1",
            "response",
            &transcript["response"],
            text(&actor.certificate["body"]["device_signing_key"])?,
        )?;
        let invite = &transcript["invitation"];
        if invite.is_null() {
            check(
                o["invitation_digest"].is_null(),
                "PAIRING_TRANSCRIPT_MISMATCH",
            )?;
        } else {
            self.current(&invite["body"])?;
            check(
                invite["body"]["operation_id"] == o["operation_id"]
                    && invite["body"]["expires_at"] == o["expires_at"]
                    && invite["body"]["approver"] == r["approver"]
                    && o["invitation_digest"] == digest("p02-state-c1", "invitation", invite)?,
                "PAIRING_TRANSCRIPT_MISMATCH",
            )?;
            signed(
                codec,
                "p02-state-c1",
                "invitation",
                invite,
                text(&actor.certificate["body"]["device_signing_key"])?,
            )?;
        }
        let transcript_digest = digest("p02-state-c1", "transcript", transcript)?;
        check(
            a["operation_id"] == o["operation_id"]
                && a["expires_at"] == o["expires_at"]
                && a["session_binding"] == o["session_binding"]
                && a["transcript_digest"] == transcript_digest,
            "APPROVAL_CONTEXT_MISMATCH",
        )?;
        let caps = o["device"]["capabilities"]
            .as_array()
            .ok_or(Error("SCHEMA_MISMATCH"))?;
        check(
            caps.iter().all(|x| {
                actor.certificate["body"]["capabilities"]
                    .as_array()
                    .unwrap()
                    .contains(x)
            }),
            "CAPABILITY_ESCALATION",
        )?;
        self.certificate(codec, &a["certificate"], &o["device"], &self.generation, json!({"kind":"device","device_id":r["approver"]["device_id"],"certificate_digest":actor.digest}), transcript_digest, text(&actor.certificate["body"]["device_signing_key"])?)?;
        signed(
            codec,
            "p02-state-c1",
            "approval",
            approval,
            text(&actor.certificate["body"]["device_signing_key"])?,
        )
    }
    fn apply(&mut self, codec: &Codec, event: &Value, index: usize) -> Result<()> {
        codec.validate("p02-state-c1", "event", event)?;
        let b = &event["body"];
        self.scope(b)?;
        check(
            b["predecessor"] == self.head
                && text(&b["version"])?
                    .parse::<usize>()
                    .map_err(|_| Error("SCHEMA_MISMATCH"))?
                    == index,
            "ROSTER_CHANGED",
        )?;
        let kind = text(&b["kind"])?;
        let p = &b["payload"];
        let mut certificate = None;
        let mut parent = None;
        if kind == "register" || kind == "reset" {
            check(
                (kind == "register") == self.head.is_null() && b["signer"] == "root",
                "INVALID_ROOT_TRANSITION",
            )?;
            let generation = if kind == "reset" {
                (self
                    .generation
                    .parse::<u64>()
                    .map_err(|_| Error("SCHEMA_MISMATCH"))?
                    + 1)
                .to_string()
            } else {
                "0".into()
            };
            check(b["generation"] == generation, "GENERATION_MISMATCH")?;
            let c = &p["challenge"]["context"];
            self.current(c)?;
            self.fresh(codec, &c["device"])?;
            check(
                c["intent"] == kind
                    && p["active_device_limit"]
                        .as_str()
                        .is_some_and(|s| s.parse::<u8>().is_ok_and(|v| (1..=32).contains(&v)))
                    && (self.head.is_null() || p["active_device_limit"] == self.limit),
                "CHALLENGE_CONTEXT_MISMATCH",
            )?;
            let confirmation = &p["confirmation"];
            let proof = &confirmation["body"];
            self.scope(proof)?;
            check(
                proof["challenge_digest"] == digest("p02-state-c1", "challenge", &p["challenge"])?
                    && proof["device_id"] == c["device"]["device_id"]
                    && proof["session_binding"] == c["session_binding"],
                "POSSESSION_CONTEXT_MISMATCH",
            )?;
            signed(
                codec,
                "p02-state-c1",
                "possession",
                confirmation,
                text(&c["device"]["signing_key"])?,
            )?;
            check(
                p["challenge"]["challenge_digest"]
                    == digest(
                        "p02-state-c1",
                        "challenge-plaintext",
                        &json!({"purpose":"device-encryption-proof","context":c,"secret":proof["challenge_response"]}),
                    )?,
                "ENCRYPTION_POSSESSION_MISMATCH",
            )?;
            self.certificate(
                codec,
                &p["certificate"],
                &c["device"],
                &generation,
                json!({"kind":"root","root_fingerprint":self.pins["root_fingerprint"]}),
                digest("p02-state-c1", "challenge", &p["challenge"])?,
                text(&self.identity["body"]["root_signing_key"])?,
            )?;
            signed(
                codec,
                "p02-state-c1",
                "event",
                event,
                text(&self.identity["body"]["root_signing_key"])?,
            )?;
            if kind == "reset" {
                for d in self.devices.values_mut() {
                    d.active = false;
                }
            }
            self.generation = generation;
            self.limit = text(&p["active_device_limit"])?.to_owned();
            certificate = Some(p["certificate"].clone());
        } else {
            check(
                !self.head.is_null() && b["generation"] == self.generation,
                "GENERATION_MISMATCH",
            )?;
            if kind == "enroll" {
                self.approval(codec, &p["transcript"], &p["approval"], None)?;
                let offer = &p["transcript"]["offer"]["body"];
                let approval = &p["approval"]["body"];
                let proof = &p["confirmation"]["body"];
                self.current(proof)?;
                check(
                    proof["operation_id"] == b["operation_id"]
                        && offer["operation_id"] == b["operation_id"]
                        && proof["session_binding"] == offer["session_binding"]
                        && proof["transcript_digest"] == approval["transcript_digest"]
                        && proof["certificate_digest"]
                            == digest(
                                "p02-identity-c1",
                                "device-certificate",
                                &approval["certificate"],
                            )?
                        && proof["approval_digest"]
                            == digest("p02-state-c1", "approval", &p["approval"])?
                        && b["signer"] == offer["device"]["device_id"],
                    "CONFIRMATION_CONTEXT_MISMATCH",
                )?;
                check(
                    approval["challenge_digest"]
                        == digest(
                            "p02-state-c1",
                            "pairing-proof-plaintext",
                            &json!({"purpose":"pairing-encryption-proof","transcript_digest":approval["transcript_digest"],"device_id":offer["device"]["device_id"],"secret":proof["challenge_response"]}),
                        )?,
                    "ENCRYPTION_POSSESSION_MISMATCH",
                )?;
                signed(
                    codec,
                    "p02-state-c1",
                    "confirmation",
                    &p["confirmation"],
                    text(&offer["device"]["signing_key"])?,
                )?;
                signed(
                    codec,
                    "p02-state-c1",
                    "event",
                    event,
                    text(&offer["device"]["signing_key"])?,
                )?;
                check(
                    self.devices.values().filter(|d| d.active).count()
                        < self
                            .limit
                            .parse::<usize>()
                            .map_err(|_| Error("SCHEMA_MISMATCH"))?,
                    "DEVICE_LIMIT",
                )?;
                parent = Some(
                    text(&p["transcript"]["response"]["body"]["approver"]["device_id"])?.into(),
                );
                certificate = Some(approval["certificate"].clone());
            } else {
                check(kind == "revoke", "UNSUPPORTED_PURPOSE")?;
                let actor = self.active(text(&b["signer"])?, Some("delegate-device"))?;
                signed(
                    codec,
                    "p02-state-c1",
                    "event",
                    event,
                    text(&actor.certificate["body"]["device_signing_key"])?,
                )?;
                let targets = p["targets"]
                    .as_array()
                    .ok_or(Error("SCHEMA_MISMATCH"))?
                    .iter()
                    .map(|v| text(v).map(str::to_owned))
                    .collect::<Result<Vec<_>>>()?;
                check(
                    targets.windows(2).all(|v| v[0] < v[1]),
                    "UNORDERED_OR_DUPLICATE",
                )?;
                let affected = self.descendants(&targets)?;
                check(
                    json!(affected) == p["affected_devices"]
                        && !affected.iter().any(|id| b["signer"] == *id),
                    "DESCENDANT_CLOSURE_MISMATCH",
                )?;
                for id in affected {
                    self.devices.get_mut(&id).unwrap().active = false;
                }
            }
        }
        if let Some(certificate) = certificate {
            let id = text(&certificate["body"]["device_id"])?.to_owned();
            let digest = digest("p02-identity-c1", "device-certificate", &certificate)?;
            self.devices.insert(
                id,
                Device {
                    certificate,
                    digest,
                    active: true,
                    parent,
                },
            );
        }
        self.head = json!({"version":b["version"],"digest":digest("p02-state-c1","event",event)?});
        Ok(())
    }
    pub fn replay(
        codec: &Codec,
        snapshot: &Value,
        pins: &Value,
        anchor: Option<&Value>,
    ) -> Result<Self> {
        check(
            canonical(snapshot)?.len() <= 33554432
                && snapshot.as_object().is_some_and(|o| o.len() == 4),
            "RESOURCE_LIMIT",
        )?;
        let identity =
            objects::verify_identity(codec, &canonical(&snapshot["identity"])?, &canonical(pins)?)?;
        let events = snapshot["events"]
            .as_array()
            .ok_or(Error("SCHEMA_MISMATCH"))?;
        check(
            !events.is_empty() && events.len() <= 10000,
            "RESOURCE_LIMIT",
        )?;
        let mut s = Self {
            identity,
            pins: pins.clone(),
            head: Value::Null,
            generation: "0".into(),
            limit: "0".into(),
            devices: BTreeMap::new(),
        };
        let mut seen = anchor.is_none();
        let mut operations = BTreeSet::new();
        for (index, event) in events.iter().enumerate() {
            check(
                operations.insert(text(&event["body"]["operation_id"])?.to_owned()),
                "OPERATION_REPLAY",
            )?;
            s.apply(codec, event, index)?;
            if anchor == Some(&s.head) {
                seen = true;
            }
        }
        check(seen, "ROLLBACK_QUARANTINE")?;
        check(
            s.head == snapshot["head"] && s.generation == snapshot["generation"],
            "INTEGRITY_FAILURE",
        )?;
        Ok(s)
    }
    pub fn summary(&self) -> Value {
        json!({"head":self.head,"generation":self.generation,"active_device_limit":self.limit,"devices":self.devices.iter().map(|(id,d)|json!({"device_id":id,"status":if d.active {"ACTIVE"} else {"REVOKED"},"parent_device_id":d.parent,"certificate_digest":d.digest,"generation":d.certificate["body"]["recovery_generation"]})).collect::<Vec<_>>()})
    }
}
