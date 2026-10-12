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
        let parsed = strict(bytes, 8_388_608)?;
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
