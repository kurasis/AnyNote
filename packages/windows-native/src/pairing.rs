//! Closed native pairing coordinator. Device keys, channel state and signed retries stay native.
use crate::{host::Host, *};
use anynote_auth_native::control::Route;
use anynote_crypto_core::{
    codec::{canonical, domain},
    crypto::{b64, hash, un64},
};
use anynote_local_vault::{Capability, Record};
use serde::Deserialize;
use serde_json::json;
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Status {},
    StartOffer {},
    StartInvitation {},
    Scan { qr: Value },
    Poll {},
    Approve { confirmed: bool },
    Confirm { confirmed: bool },
    Retry {},
    Cancel { confirmed: bool },
}
impl Drop for Command {
    fn drop(&mut self) {
        if let Self::Scan { qr } = self {
            wipe(qr);
        }
    }
}
fn digest(kind: &str, value: &Value) -> Result<String> {
    Ok(hash(&domain(
        "p02-state-c1",
        "hash",
        kind,
        &canonical(value)?,
    )))
}
fn transcript(p: &Value) -> Result<Value> {
    check(
        p["offer"].is_object() && p["response"].is_object(),
        "PAIRING_ORDER",
    )?;
    Ok(
        json!({"purpose":"pairing-transcript","contract":"p02-state-c1","protocol":"anynote","protocol_version":1,"invitation":p["invitation"],"offer":p["offer"],"response":p["response"]}),
    )
}
impl Host {
    fn pairing_id(&self) -> Result<String> {
        let mut bytes = b"AnyNote/P14/native-pairing\0".to_vec();
        bytes.extend(canonical(&json!(self.profile.scope))?);
        Ok(b64(&un64(&hash(&bytes))?[..16]))
    }
    fn save_pairing(&self, cap: &Capability, p: &Value) -> Result<()> {
        check(canonical(p)?.len() <= 4194304, "RESOURCE_LIMIT")?;
        let id = self.pairing_id()?;
        let mut context = b"AnyNote/P14/pairing-operation\0".to_vec();
        context.extend(canonical(&json!([
            self.profile.scope,
            crate::id(string(p, "operation_id")?)?
        ]))?);
        let operation = b64(&un64(&hash(&context))?[..16]);
        for _ in 0..16 {
            let previous = self.vault.content_read(cap, &id, "import-state")?;
            match self.vault.content_commit(
                cap,
                previous.revision,
                &[
                    Record {
                        id: id.clone(),
                        kind: "import-state".into(),
                        data: p.clone(),
                    },
                    Record {
                        id: operation.clone(),
                        kind: "import-state".into(),
                        data: p.clone(),
                    },
                ],
                &[],
            ) {
                Ok(()) => return Ok(()),
                Err(Error("STALE_WRITER")) => (),
                Err(e) => return Err(e),
            }
        }
        Err(Error("STALE_WRITER"))
    }
    fn pairing_summary(&self, p: &Value) -> Result<Value> {
        let device = &p["offer"]["body"]["device"];
        Ok(
            json!({"state":p["state"],"operation_id":p["operation_id"],"side":p["side"],"retry_pending":p["outbox"].is_object(),"ceremony":{"service_id":self.profile.scope.service_id,"account_id":self.profile.scope.account_id,"root_fingerprint":self.profile.service.pins["root_fingerprint"],"device":device,"device_fingerprint":if device.is_object(){let mut bytes=b"AnyNote/P08/device-preview\0".to_vec();bytes.extend(canonical(device)?);json!(hash(&bytes))}else{Value::Null},"expires_at":p["expires_at"]}}),
        )
    }
    fn send_pairing_outbox(&self, cap: &Capability, p: &mut Value) -> Result<()> {
        if !p["outbox"].is_object() {
            return Ok(());
        }
        let route = match string(&p["outbox"], "kind")? {
            "create" => Route::Enrollment,
            "relay" => Route::Relay,
            "approve" => Route::EnrollmentApprove,
            "confirm" => Route::EnrollmentConfirm,
            "cancel" => Route::CancelEnrollment,
            _ => return Err(Error("INTEGRITY_FAILURE")),
        };
        let operation = string(p, "operation_id")?;
        self.api(
            cap,
            route,
            if matches!(route, Route::Enrollment) {
                None
            } else {
                Some(operation)
            },
            None,
            &[],
            Some(&p["outbox"]["body"]),
        )?;
        p["last_request"] = p["outbox"].clone();
        p["outbox"] = Value::Null;
        self.save_pairing(cap, p)
    }
    fn pairing_outbox(
        &self,
        cap: &Capability,
        p: &mut Value,
        kind: &str,
        body: Value,
    ) -> Result<()> {
        check(p["outbox"].is_null(), "PUBLICATION_PENDING")?;
        p["outbox"] = json!({"kind":kind,"body":body});
        self.save_pairing(cap, p)?;
        self.send_pairing_outbox(cap, p)
    }
    fn pairing_frame(
        &self,
        cap: &Capability,
        p: &Value,
        message: &str,
        value: &Value,
        anchor: &str,
        seal: bool,
    ) -> Result<Value> {
        self.vault
            .native_pairing_frame(cap, string(p, "handle")?, message, value, anchor, seal)
    }
    pub fn pairing_command(&self, cap: &Capability, command: &Command) -> Result<Value> {
        let mut guard = self.pairing.lock().map_err(|_| Error("HOST_BUSY"))?;
        if guard
            .as_ref()
            .is_some_and(|p| p["generation"] != self.current())
        {
            *guard = None;
        }
        if guard.is_none()
            && let Some(mut stored) = self
                .vault
                .content_read(cap, &self.pairing_id()?, "import-state")?
                .data
        {
            stored["handle"] = Value::Null;
            if !matches!(stored["state"].as_str(), Some("ACTIVE" | "CANCELLED")) {
                stored["state"] = json!("RESTART_REQUIRED");
            }
            stored["generation"] = json!(self.current());
            *guard = Some(stored);
        }
        if matches!(command, Command::Status {}) {
            return self.pairing_summary(guard.as_ref().unwrap_or(&json!({"state":"IDLE"})));
        }
        let roster = self.sync_devices(cap)?;
        let active = roster["devices"]
            .as_array()
            .ok_or(Error("INTEGRITY_FAILURE"))?
            .iter()
            .any(|d| d["device_id"] == self.profile.scope.device_id && d["status"] == "ACTIVE");
        if matches!(
            command,
            Command::StartOffer {} | Command::StartInvitation {} | Command::Scan { .. }
        ) {
            check(
                guard.as_ref().is_none_or(|p| {
                    matches!(
                        p["state"].as_str(),
                        Some("CANCELLED" | "EXPIRED" | "ACTIVE")
                    )
                }),
                "PAIRING_BUSY",
            )?;
            if !active {
                check(
                    self.vault.device_pairing_state(cap)?.is_null(),
                    "PAIRING_RESTART_REQUIRED",
                )?;
            }
            let new_device = !active;
            let mut p = json!({"purpose":"p14-native-pairing","version":1,"generation":self.current(),"side":if new_device{"new-device"}else{"approver"},"handle":null,"invitation":null,"offer":null,"response":null,"approval":null,"seen":[],"outbox":null,"state":"WAITING"});
            let me = self.api(cap, Route::Me, None, None, &[], None)?;
            let session = string(&me["session"], "id")?;
            let mut qr_result = Value::Null;
            match command {
                Command::StartOffer {} | Command::StartInvitation {} => {
                    let offer = matches!(command, Command::StartOffer {});
                    check(offer == new_device, "PAIRING_ORDER")?;
                    let record = if offer {
                        self.vault.device_offer(cap, session, None)?
                    } else {
                        self.vault.device_invitation(cap)?
                    };
                    let mode = if offer {
                        "new-device-offer"
                    } else {
                        "existing-device-invitation"
                    };
                    let qr = self.vault.native_pairing_qr(cap, &record, mode)?;
                    p["handle"] = qr["handle"].clone();
                    p[if offer { "offer" } else { "invitation" }] = record.clone();
                    p["operation_id"] = record["body"]["operation_id"].clone();
                    p["expires_at"] = record["body"]["expires_at"].clone();
                    qr_result = qr["qr"].clone();
                    p["outbox"] =
                        json!({"kind":"create","body":{"version":1,"mode":mode,"record":record}});
                }
                Command::Scan { qr } => {
                    let channel = self.vault.native_pairing_scan(cap, qr, new_device)?;
                    p["handle"] = channel["handle"].clone();
                    p["operation_id"] = qr["record"]["body"]["operation_id"].clone();
                    p["expires_at"] = qr["record"]["body"]["expires_at"].clone();
                    let (message, value, anchor, offer) = if new_device {
                        p["invitation"] = qr["record"].clone();
                        p["offer"] =
                            self.vault
                                .device_offer(cap, session, Some(&p["invitation"]))?;
                        (
                            "new-device-offer",
                            p["offer"].clone(),
                            digest("invitation", &p["invitation"])?,
                            p["offer"].clone(),
                        )
                    } else {
                        p["offer"] = qr["record"].clone();
                        p["response"] =
                            self.vault.device_response(cap, &p["offer"], None)?["response"].clone();
                        self.vault
                            .verify_device_pairing(cap, &transcript(&p)?, None)?;
                        p["state"] = json!("APPROVAL_REQUIRED");
                        (
                            "approver-response",
                            p["response"].clone(),
                            digest("offer", &p["offer"])?,
                            Value::Null,
                        )
                    };
                    let frame = self.pairing_frame(cap, &p, message, &value, &anchor, true)?;
                    p["outbox"] =
                        json!({"kind":"relay","body":{"version":1,"frame":frame,"offer":offer}});
                }
                _ => unreachable!(),
            }
            self.save_pairing(cap, &p)?;
            *guard = Some(p);
            let p = guard.as_mut().unwrap();
            self.send_pairing_outbox(cap, p)?;
            let mut summary = self.pairing_summary(p)?;
            if !qr_result.is_null() {
                summary["qr"] = qr_result.take();
            }
            return Ok(summary);
        }
        let p = guard.as_mut().ok_or(Error("PAIRING_REQUIRED"))?;
        match command {
            Command::Poll {} => {
                self.send_pairing_outbox(cap, p)?;
                let operation = string(p, "operation_id")?.to_owned();
                let relay = self.api(cap, Route::PollRelay, Some(&operation), None, &[], None)?;
                check(relay["operation_id"] == operation, "CONTEXT_MISMATCH")?;
                if relay["state"] == "confirmed" {
                    self.sync_devices(cap)?;
                    self.vault.finish_device_pairing(cap, &operation)?;
                    p["state"] = json!("ACTIVE");
                    p["handle"] = Value::Null;
                    self.save_pairing(cap, p)?;
                    return self.pairing_summary(p);
                }
                if relay["state"] == "expired" || relay["state"] == "cancelled" {
                    p["state"] = json!(if relay["state"] == "expired" {
                        "EXPIRED"
                    } else {
                        "CANCELLED"
                    });
                    p["handle"] = Value::Null;
                    self.save_pairing(cap, p)?;
                    return self.pairing_summary(p);
                }
                check(p["handle"].is_string(), "PAIRING_RESTART_REQUIRED")?;
                for frame in relay["frames"].as_array().ok_or(Error("INVALID_PAGE"))? {
                    let message = string(&frame["context"], "message")?;
                    let own = p["side"] == "new-device";
                    if own == message.starts_with("new-device-") {
                        continue;
                    }
                    let frame_digest = hash(&canonical(frame)?);
                    if p["seen"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|v| v == &frame_digest)
                    {
                        continue;
                    }
                    let anchor = match message {
                        "new-device-offer" => digest("invitation", &p["invitation"])?,
                        "approver-response" => digest("offer", &p["offer"])?,
                        "approver-approval" => digest("transcript", &transcript(p)?)?,
                        _ => return Err(Error("PAIRING_ORDER")),
                    };
                    let value = self.pairing_frame(cap, p, message, frame, &anchor, false)?;
                    p["seen"].as_array_mut().unwrap().push(json!(frame_digest));
                    match message {
                        "new-device-offer" => {
                            check(p["offer"].is_null(), "PAIRING_ORDER")?;
                            p["offer"] = value;
                            p["response"] = self.vault.device_response(
                                cap,
                                &p["offer"],
                                Some(&p["invitation"]),
                            )?["response"]
                                .clone();
                            self.vault
                                .verify_device_pairing(cap, &transcript(p)?, None)?;
                            let response = self.pairing_frame(
                                cap,
                                p,
                                "approver-response",
                                &p["response"],
                                &digest("offer", &p["offer"])?,
                                true,
                            )?;
                            p["state"] = json!("APPROVAL_REQUIRED");
                            self.pairing_outbox(
                                cap,
                                p,
                                "relay",
                                json!({"version":1,"frame":response,"offer":null}),
                            )?;
                        }
                        "approver-response" => {
                            check(p["response"].is_null(), "PAIRING_ORDER")?;
                            p["response"] = value;
                            self.vault
                                .verify_device_pairing(cap, &transcript(p)?, None)?;
                        }
                        "approver-approval" => {
                            check(p["approval"].is_null(), "PAIRING_ORDER")?;
                            self.vault
                                .verify_device_pairing(cap, &transcript(p)?, Some(&value))?;
                            p["approval"] = value;
                            p["state"] = json!("CONFIRMATION_REQUIRED");
                        }
                        _ => return Err(Error("PAIRING_ORDER")),
                    }
                    self.save_pairing(cap, p)?;
                }
            }
            Command::Approve { confirmed } => {
                check(
                    *confirmed && p["state"] == "APPROVAL_REQUIRED",
                    "USER_CONFIRMATION_REQUIRED",
                )?;
                let t = transcript(p)?;
                let approval = self.vault.device_approval(cap, &t, true)?;
                let frame = self.pairing_frame(
                    cap,
                    p,
                    "approver-approval",
                    &approval,
                    &digest("transcript", &t)?,
                    true,
                )?;
                p["approval"] = approval.clone();
                p["state"] = json!("APPROVED");
                self.pairing_outbox(
                    cap,
                    p,
                    "approve",
                    json!({"version":1,"transcript":t,"approval":approval,"frame":frame}),
                )?;
            }
            Command::Confirm { confirmed } => {
                check(
                    *confirmed && p["state"] == "CONFIRMATION_REQUIRED",
                    "USER_CONFIRMATION_REQUIRED",
                )?;
                let me = self.api(cap, Route::Me, None, None, &[], None)?;
                let event = self.vault.device_confirmation(
                    cap,
                    &transcript(p)?,
                    &p["approval"],
                    string(&me["session"], "id")?,
                    true,
                )?;
                p["state"] = json!("CONFIRMING");
                self.pairing_outbox(cap, p, "confirm", json!({"version":1,"event":event}))?;
                self.sync_devices(cap)?;
                self.vault
                    .finish_device_pairing(cap, string(p, "operation_id")?)?;
                p["state"] = json!("ACTIVE");
                p["handle"] = Value::Null;
                self.save_pairing(cap, p)?;
            }
            Command::Retry {} => {
                let pending = self.vault.device_pairing_state(cap)?;
                if pending["event"].is_object() && p["outbox"].is_null() {
                    p["outbox"] =
                        json!({"kind":"confirm","body":{"version":1,"event":pending["event"]}});
                    self.save_pairing(cap, p)?;
                }
                self.send_pairing_outbox(cap, p)?;
            }
            Command::Cancel { confirmed } => {
                check(*confirmed, "USER_CONFIRMATION_REQUIRED")?;
                check(p["outbox"]["kind"] != "confirm", "IMMUTABLE_ATTEMPT")?;
                self.api(
                    cap,
                    Route::CancelEnrollment,
                    Some(string(p, "operation_id")?),
                    None,
                    &[],
                    Some(&json!({"version":1})),
                )?;
                p["state"] = json!("CANCELLED");
                p["handle"] = Value::Null;
                p["outbox"] = Value::Null;
                self.save_pairing(cap, p)?;
            }
            _ => return Err(Error("PAIRING_ORDER")),
        }
        self.pairing_summary(p)
    }
}
