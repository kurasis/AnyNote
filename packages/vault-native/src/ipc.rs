//! Typed deny-by-default boundary for a trusted native main-window registration.
//! Native host obtains origin/window identity from its window runtime, not JSON.
use super::*;
pub enum WindowRole {
    Main,
    Preview,
}
pub struct HostBinding {
    role: WindowRole,
    origin: String,
    hwnd: Option<usize>,
}
impl HostBinding {
    pub fn from_native_window(role: WindowRole, actual_origin: &str) -> Self {
        Self {
            role,
            origin: actual_origin.into(),
            hwnd: None,
        }
    }
    pub fn from_native_main_window(actual_origin: &str, hwnd: usize) -> Self {
        Self {
            role: WindowRole::Main,
            origin: actual_origin.into(),
            hwnd: Some(hwnd),
        }
    }
    fn allowed(&self) -> Result<()> {
        check(
            matches!(self.role, WindowRole::Main)
                && ["tauri://localhost", "http://tauri.localhost"].contains(&self.origin.as_str()),
            "IPC_SCOPE_DENIED",
        )
    }
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Status {},
    UnlockPhrase {
        phrase: String,
    },
    UnlockHello {},
    RotateToPhrase {
        capability: String,
        phrase: String,
    },
    Lock {},
    Read {
        capability: String,
        id: String,
        kind: String,
    },
    Save {
        capability: String,
        records: Vec<InputRecord>,
    },
    Notes {
        capability: String,
        request: crate::notes::NotesRequest,
    },
    DeviceSettings {
        capability: String,
    },
    DeviceGroupKeys {
        capability: String,
        evidence: Value,
        records: Vec<Value>,
        kit: Option<Value>,
        target: Option<String>,
        confirmed: bool,
    },
    DeviceSnapshot {
        capability: String,
        snapshot: Value,
    },
    DevicePublic {
        capability: String,
    },
    DeviceInvitation {
        capability: String,
    },
    DeviceOffer {
        capability: String,
        session_id: String,
        invitation: Option<Value>,
    },
    DeviceResponse {
        capability: String,
        offer: Value,
        invitation: Option<Value>,
    },
    DeviceApproval {
        capability: String,
        transcript: Value,
        confirmed: bool,
    },
    DeviceConfirmation {
        capability: String,
        transcript: Value,
        approval: Value,
        session_id: String,
        confirmed: bool,
    },
    DeviceRecovery {
        capability: String,
        kit: Value,
        challenge: Value,
        session_id: String,
        confirmed: bool,
    },
    DeviceRevoke {
        capability: String,
        targets: Vec<String>,
        confirmed: bool,
    },
    DeviceRetry {
        capability: String,
        activation: bool,
    },
    PairingQr {
        capability: String,
        record: Value,
        mode: String,
    },
    PairingScan {
        capability: String,
        qr: Value,
        new_device: bool,
    },
    PairingFrame {
        capability: String,
        handle: String,
        message: String,
        value: Value,
        anchor: String,
        seal: bool,
    },
    DeviceProof {
        capability: String,
        challenge: Value,
        session_id: String,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputRecord {
    id: String,
    kind: String,
    data: Value,
}
pub struct Endpoint {
    vault: Arc<Vault>,
    handles: Mutex<std::collections::BTreeMap<String, Capability>>,
}
impl Endpoint {
    pub fn new(vault: Arc<Vault>) -> Self {
        Self {
            vault,
            handles: Mutex::new(Default::default()),
        }
    }
    pub fn lock(&self) {
        self.vault.lock_signal().invalidate();
        self.vault.lock();
        if let Ok(mut h) = self.handles.lock() {
            h.clear();
        }
    }
    pub fn invoke(&self, binding: &HostBinding, bytes: &[u8]) -> Result<Value> {
        binding.allowed()?;
        // The public roster has its own 16 MiB bound; other requests retain P07 limits.
        let parsed = strict(bytes, 16_781_312)?;
        if parsed["operation"] != "device-snapshot" {
            check(bytes.len() <= 8_388_608, "RESOURCE_LIMIT")?;
        }
        let mut request: Request =
            serde_json::from_value(parsed).map_err(|_| Error("INVALID_IPC"))?;
        match &mut request {
            Request::Status {} => Ok(json!({"state":self.vault.status()?})),
            Request::Lock {} => {
                self.lock();
                self.vault.lock_all()?;
                Ok(json!({"state":"locked"}))
            }
            Request::UnlockPhrase { phrase } => {
                check(phrase.len() <= 1024, "RESOURCE_LIMIT")?;
                let result = self.vault.unlock_phrase(phrase);
                phrase.zeroize();
                let c = result?;
                let token = c.value.clone();
                let mut h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                h.clear();
                h.insert(token.clone(), c);
                Ok(json!({"capability":token,"state":"unlocked"}))
            }
            Request::UnlockHello {} => {
                let hwnd = binding.hwnd.ok_or(Error("INVALID_NATIVE_WINDOW"))?;
                let cap = self.vault.unlock_hello(hwnd)?;
                let token = cap.value.clone();
                let mut h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                h.clear();
                h.insert(token.clone(), cap);
                Ok(json!({"state":"unlocked","capability":token}))
            }
            Request::RotateToPhrase { capability, phrase } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let cap = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                let result = self.vault.rotate_to_phrase(cap, phrase, true);
                phrase.zeroize();
                result?;
                Ok(json!({"state":"locked","protection":"phrase"}))
            }
            Request::Read {
                capability,
                id,
                kind,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault.read(c, id, kind)
            }
            Request::Save {
                capability,
                records,
            } => {
                check(
                    records.len() <= 16
                        && records.iter().all(|r| {
                            ["cache", "search", "draft", "outbox", "transfer"]
                                .contains(&r.kind.as_str())
                        }),
                    "IPC_SCOPE_DENIED",
                )?;
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                let values: Vec<_> = records
                    .iter_mut()
                    .map(|r| Record {
                        id: r.id.clone(),
                        kind: r.kind.clone(),
                        data: std::mem::take(&mut r.data),
                    })
                    .collect();
                let fence = self.vault.lease(c)?;
                self.vault.save_batch(c, fence, &values)?;
                Ok(json!({"state":"local-saved"}))
            }
            Request::Notes {
                capability,
                request,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                let value = std::mem::replace(request, crate::notes::NotesRequest::Summary {});
                self.vault.notes_command(c, value)
            }
            Request::DeviceSettings { capability } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault.device_settings_genesis(c)
            }
            Request::DeviceGroupKeys {
                capability,
                evidence,
                records,
                kit,
                target,
                confirmed,
            } => {
                check(*confirmed, "USER_CONFIRMATION_REQUIRED")?;
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                let result = self.vault.device_group_keys(
                    c,
                    evidence,
                    records,
                    kit.as_ref(),
                    target.as_deref(),
                );
                if let Some(kit) = kit {
                    wipe_value(kit);
                }
                result
            }
            Request::DeviceSnapshot {
                capability,
                snapshot,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault.record_device_snapshot(c, snapshot)
            }
            Request::DevicePublic { capability } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault.device_public(c)
            }
            Request::DeviceInvitation { capability } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault.device_invitation(c)
            }
            Request::DeviceOffer {
                capability,
                session_id,
                invitation,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault.device_offer(c, session_id, invitation.as_ref())
            }
            Request::DeviceResponse {
                capability,
                offer,
                invitation,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault.device_response(c, offer, invitation.as_ref())
            }
            Request::DeviceApproval {
                capability,
                transcript,
                confirmed,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault.device_approval(c, transcript, *confirmed)
            }
            Request::DeviceConfirmation {
                capability,
                transcript,
                approval,
                session_id,
                confirmed,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault
                    .device_confirmation(c, transcript, approval, session_id, *confirmed)
            }
            Request::DeviceRecovery {
                capability,
                kit,
                challenge,
                session_id,
                confirmed,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                let result = self
                    .vault
                    .device_recovery_reset(c, kit, challenge, session_id, *confirmed);
                wipe_value(kit);
                result
            }
            Request::DeviceRevoke {
                capability,
                targets,
                confirmed,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault.device_revoke(c, targets, *confirmed)
            }
            Request::DeviceRetry {
                capability,
                activation,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault.device_retry(c, *activation)
            }
            Request::PairingQr {
                capability,
                record,
                mode,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault.native_pairing_qr(c, record, mode)
            }
            Request::PairingScan {
                capability,
                qr,
                new_device,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                let result = self.vault.native_pairing_scan(c, qr, *new_device);
                wipe_value(qr);
                result
            }
            Request::PairingFrame {
                capability,
                handle,
                message,
                value,
                anchor,
                seal,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault
                    .native_pairing_frame(c, handle, message, value, anchor, *seal)
            }
            Request::DeviceProof {
                capability,
                challenge,
                session_id,
            } => {
                let h = self.handles.lock().map_err(|_| Error("VAULT_BUSY"))?;
                let c = h.get(capability).ok_or(Error("VAULT_LOCKED"))?;
                self.vault
                    .device_proof(c, &canonical(challenge)?, session_id)
            }
        }
    }
}
