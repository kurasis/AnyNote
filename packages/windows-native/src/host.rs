//! High-level main-window commands. Network replies/proofs never come from renderer JSON.
use crate::*;
use anynote_auth_native::{Adapter, Credentials, control::Route};
use anynote_crypto_core::codec::{canonical, strict};
use anynote_local_vault::{Capability, Scope, Vault, notes::NotesRequest};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroize;
/// Frozen P06 commitment. This binds the OAuth grant to both native public keys.
pub fn native_commitment(device: &Value) -> Result<String> {
    let mut bytes = b"AnyNote/P06/device-key-commitment\0".to_vec();
    for k in ["signing_key", "encryption_key"] {
        let key = anynote_crypto_core::crypto::un64(string(device, k)?)?;
        check(key.len() == 32, "INVALID_DEVICE_KEY")?;
        bytes.extend(key);
    }
    Ok(anynote_crypto_core::crypto::hash(&bytes))
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub issuer: String,
    pub app: String,
    pub pins: Value,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u8,
    pub scope: Scope,
    pub service: Service,
    pub credential_id: String,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Status {},
    Unlock {
        phrase: String,
    },
    UnlockHello {},
    Lock {},
    Login {},
    FinishLogin {},
    Logout {},
    Summary {},
    Refresh {},
    CreateGroup {
        title: String,
        shared: bool,
        resume: Option<String>,
    },
    Threads {
        group_id: String,
        after: Option<String>,
    },
    Entries {
        group_id: String,
        thread_id: String,
        after: Option<String>,
    },
    Open {
        group_id: String,
        object_id: String,
        revision_id: String,
    },
    Save {
        edit: Value,
        publish: bool,
    },
    Publish {
        draft_id: String,
    },
    ResolveDraft {
        draft_id: String,
        confirmed: bool,
    },
    Draft {
        draft_id: String,
    },
    ObjectAction {
        group_id: String,
        object_id: String,
        revision_id: String,
        action: String,
        confirmed: bool,
    },
    Preferences {
        key: Option<String>,
        target_id: Option<String>,
        value: Option<String>,
    },
    CopyPreview {
        source_group: String,
        destination_group: String,
        revision_id: String,
    },
    CopyNote {
        source_group: String,
        destination_group: String,
        destination_thread: String,
        revision_id: String,
        preview_digest: String,
        confirmed: bool,
    },
    RecoverDraft {
        draft_id: String,
        destination_group: String,
        destination_thread: String,
        confirmed: bool,
    },
    Versions {
        group_id: String,
        object_id: String,
    },
    Restore {
        group_id: String,
        object_id: String,
        revision_id: String,
    },
    Search {
        query: String,
        group_id: Option<String>,
    },
    RebuildSearch {},
    Storage {},
    Cache {},
    RemoveCache {
        group_id: String,
        file_version_id: String,
        confirmed: bool,
    },
    PinCache {
        group_id: String,
        file_version_id: String,
        additional_bytes: u64,
        confirmed: bool,
    },
    Transfers {},
    RecoveryJobs {},
    CancelJob {
        job_id: String,
    },
    Files {
        group_id: String,
        after: Option<String>,
    },
    Retention {
        group_id: String,
        apply: bool,
        confirmed: bool,
    },
    PinRevision {
        revision_id: String,
        pinned: bool,
    },
    Devices {},
    DeliverKeys {
        group_id: String,
        device_id: String,
        confirmed: bool,
    },
    Sessions {},
    RevokeSession {
        session_id: String,
        confirmed: bool,
    },
    AccessPoll {
        group_id: Option<String>,
    },
    Members {
        group_id: String,
    },
    Shared {
        group_id: String,
        action: String,
        target_account_id: Option<String>,
        role: Option<String>,
        confirmed: bool,
    },
    Device {
        action: String,
        value: Option<Value>,
        confirmed: bool,
    },
    Offline {},
    LocalObjects {
        group_id: String,
        thread_id: Option<String>,
        after: Option<String>,
    },
    Diagnostics {},
    Pairing {
        request: crate::pairing::Command,
    },
}
impl Drop for Request {
    fn drop(&mut self) {
        match self {
            Self::Unlock { phrase } => phrase.zeroize(),
            Self::Save { edit, .. } => wipe(edit),
            Self::Device { value: Some(v), .. } => wipe(v),
            _ => {}
        }
    }
}
pub struct Binding {
    pub label: String,
    pub origin: String,
    pub hwnd: usize,
}
impl Binding {
    pub fn validate(&self) -> Result<()> {
        check(
            self.label == "main"
                && ["http://tauri.localhost", "tauri://localhost"].contains(&self.origin.as_str()),
            "IPC_SCOPE_DENIED",
        )
    }
}
pub struct Host {
    pub vault: Arc<Vault>,
    pub profile: Profile,
    pub adapter: Adapter,
    pub generation: Arc<AtomicU64>,
    cap: Mutex<Option<Arc<Capability>>>,
    pub jobs: crate::jobs::Jobs,
    pub selections: crate::selection::Selections,
    pub imports: Mutex<std::collections::BTreeMap<String, crate::imports::ValidatedImport>>,
    pub pairing: Mutex<Option<Value>>,
    pub group_creation: Mutex<()>,
    pending_login: Mutex<Option<(Instant, Credentials)>>,
    pub root: PathBuf,
}
impl Host {
    fn service_binding_id(&self) -> String {
        let mut bytes = b"AnyNote/P14/native-service-binding\0".to_vec();
        bytes.extend(canonical(&json!(self.profile.scope)).unwrap());
        anynote_crypto_core::crypto::b64(
            &anynote_crypto_core::crypto::un64(&anynote_crypto_core::crypto::hash(&bytes)).unwrap()
                [..16],
        )
    }
    /// Called only by trusted native first-time creation after independent configuration selection.
    pub fn bind_new_service(&self, cap: &Capability) -> Result<()> {
        check(
            self.vault.native_profile_pins(cap)? == self.profile.service.pins,
            "ROOT_PIN_MISMATCH",
        )?;
        let id = self.service_binding_id();
        let existing = self.vault.content_read(cap, &id, "content-control")?;
        check(existing.data.is_none(), "SERVICE_ALREADY_BOUND")?;
        self.vault.content_commit(cap,existing.revision,&[anynote_local_vault::Record{id,kind:"content-control".into(),data:json!({"purpose":"p14-service-binding","version":1,"scope":self.profile.scope,"service":self.profile.service,"credential_id":self.profile.credential_id})}],&[])
    }
    fn verify_service(&self, cap: &Capability) -> Result<()> {
        let record = self
            .vault
            .content_read(cap, &self.service_binding_id(), "content-control")?
            .data
            .ok_or(Error("SERVICE_BINDING_REQUIRED"))?;
        check(
            record
                == json!({"purpose":"p14-service-binding","version":1,"scope":self.profile.scope,"service":self.profile.service,"credential_id":self.profile.credential_id}),
            "SERVICE_CONFIGURATION_CHANGED",
        )
    }
    pub fn open(root: &Path) -> Result<Self> {
        let b = std::fs::read(root.join("profile.json")).map_err(|_| Error("PROFILE_REQUIRED"))?;
        let profile: Profile = serde_json::from_value(strict(&b, 65536)?)
            .map_err(|_| Error("INVALID_SERVICE_CONFIGURATION"))?;
        check(profile.version == 1, "UNSUPPORTED_PROFILE")?;
        let adapter = Adapter::new(&profile.service.issuer, &profile.service.app)
            .map_err(|_| Error("INVALID_SERVICE_CONFIGURATION"))?;
        let vault = Arc::new(Vault::open(
            &root.join("vault.sqlite"),
            profile.scope.clone(),
        )?);
        Ok(Self::from_parts(root, profile, vault, adapter))
    }
    pub fn from_parts(root: &Path, profile: Profile, vault: Arc<Vault>, adapter: Adapter) -> Self {
        Self {
            vault,
            profile,
            adapter,
            generation: Arc::new(AtomicU64::new(0)),
            cap: Mutex::new(None),
            jobs: Default::default(),
            selections: Default::default(),
            imports: Default::default(),
            pairing: Default::default(),
            group_creation: Default::default(),
            pending_login: Mutex::new(None),
            root: root.into(),
        }
    }
    pub fn create(
        root: &Path,
        service: Service,
        phrase: &str,
        hello: bool,
        hwnd: usize,
    ) -> Result<Self> {
        check(!root.join("profile.json").exists(), "PROFILE_EXISTS")?;
        check(
            !root.join("profile-pending.json").exists() && !root.join("vault.sqlite").exists(),
            "SETUP_RECOVERY_REQUIRED",
        )?;
        id(string(&service.pins, "service_id")?)?;
        id(string(&service.pins, "account_id")?)?;
        check(
            string(&service.pins, "root_fingerprint")?.len() == 43,
            "INVALID_IDENTITY_PIN",
        )?;
        let adapter = Adapter::new(&service.issuer, &service.app)
            .map_err(|_| Error("INVALID_SERVICE_CONFIGURATION"))?;
        let scope = Scope {
            service_id: string(&service.pins, "service_id")?.into(),
            account_id: string(&service.pins, "account_id")?.into(),
            device_id: random_id(),
            profile_id: random_id(),
        };
        std::fs::create_dir_all(root).map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        let profile = Profile {
            version: 1,
            scope,
            service,
            credential_id: random_id(),
        };
        let mut pending =
            crate::selection::Destination::create(&root.join("profile-pending.json"))?;
        std::io::Write::write_all(
            &mut pending,
            &canonical(
                &serde_json::to_value(&profile)
                    .map_err(|_| Error("INVALID_SERVICE_CONFIGURATION"))?,
            )?,
        )
        .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        pending.finish()?;
        let vault = Arc::new(Vault::open(
            &root.join("vault.sqlite"),
            profile.scope.clone(),
        )?);
        let mut host = Self::from_parts(root, profile, vault, adapter);
        let service = host.profile.service.clone();
        host.finish_setup(service, phrase, hello, hwnd)?;
        Ok(host)
    }
    /// Resume only the exact native pending profile, with independently reselected public trust.
    pub fn resume_setup(
        root: &Path,
        service: Service,
        phrase: &str,
        hello: bool,
        hwnd: usize,
    ) -> Result<Self> {
        check(!root.join("profile.json").exists(), "PROFILE_EXISTS")?;
        let bytes = std::fs::read(root.join("profile-pending.json"))
            .map_err(|_| Error("SETUP_RECOVERY_REQUIRED"))?;
        let mut profile: Profile = serde_json::from_value(strict(&bytes, 65536)?)
            .map_err(|_| Error("INVALID_SERVICE_CONFIGURATION"))?;
        check(
            profile.version == 1
                && service.pins["service_id"] == profile.scope.service_id
                && service.pins["account_id"] == profile.scope.account_id,
            "LOCAL_CONTEXT_MISMATCH",
        )?;
        let adapter = Adapter::new(&service.issuer, &service.app)
            .map_err(|_| Error("INVALID_SERVICE_CONFIGURATION"))?;
        profile.service = service.clone();
        let vault = Arc::new(Vault::open(
            &root.join("vault.sqlite"),
            profile.scope.clone(),
        )?);
        let mut host = Self::from_parts(root, profile, vault, adapter);
        host.finish_setup(service, phrase, hello, hwnd)?;
        Ok(host)
    }
    fn finish_setup(
        &mut self,
        service: Service,
        phrase: &str,
        hello: bool,
        hwnd: usize,
    ) -> Result<()> {
        check(
            service.issuer == self.profile.service.issuer
                && service.app == self.profile.service.app
                && service.pins == self.profile.service.pins,
            "SERVICE_CONFIGURATION_CHANGED",
        )?;
        if self.vault.status()? == "enrollment-required" {
            if hello {
                self.vault
                    .initialize_device_hello(hwnd, service.pins.clone())?;
            } else {
                self.vault
                    .initialize_device_phrase(phrase, service.pins.clone(), true)?;
            }
        }
        let cap = if hello {
            self.vault.unlock_hello(hwnd)?
        } else {
            self.vault.unlock_phrase(phrase)?
        };
        let result = match self
            .vault
            .content_read(&cap, &self.service_binding_id(), "content-control")?
            .data
        {
            Some(binding) => {
                self.profile.credential_id = string(&binding, "credential_id")?.to_owned();
                self.verify_service(&cap)
            }
            None => self.bind_new_service(&cap),
        };
        self.vault.lock_all()?;
        result?;
        let mut out = crate::selection::Destination::create(&self.root.join("profile.json"))?;
        std::io::Write::write_all(
            &mut out,
            &canonical(
                &serde_json::to_value(&self.profile)
                    .map_err(|_| Error("INVALID_SERVICE_CONFIGURATION"))?,
            )?,
        )
        .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        out.finish()?;
        std::fs::remove_file(self.root.join("profile-pending.json"))
            .map_err(|_| Error("SETUP_CLEANUP_PENDING"))?;
        Ok(())
    }
    pub fn current(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
    pub fn lock(&self) {
        self.invalidate();
        self.finish_lock();
    }
    pub fn invalidate(&self) {
        self.vault.lock_signal().invalidate();
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.jobs.pause_all();
        self.selections.clear();
    }
    pub fn finish_lock(&self) {
        if let Ok(mut imports) = self.imports.try_lock() {
            imports.clear();
        }
        if let Ok(mut pairing) = self.pairing.try_lock() {
            if let Some(value) = pairing.as_mut() {
                wipe(value);
            }
            *pairing = None;
        }
        if let Ok(mut c) = self.cap.try_lock() {
            *c = None;
        }
        let _ = self.vault.lock_all();
    }
    pub fn capability(&self, g: u64) -> Result<Arc<Capability>> {
        check(g == self.current(), "STALE_CAPABILITY")?;
        let cap = self
            .cap
            .lock()
            .map_err(|_| Error("HOST_BUSY"))?
            .clone()
            .ok_or(Error("VAULT_LOCKED"))?;
        self.vault.lease(&cap)?;
        self.verify_service(&cap)?;
        Ok(cap)
    }
    pub fn api(
        &self,
        cap: &Capability,
        route: Route,
        a: Option<&str>,
        b: Option<&str>,
        query: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<Value> {
        self.verify_service(cap)?;
        let response = self.vault.control_http(
            cap,
            &self.profile.credential_id,
            &self.adapter,
            route,
            a,
            b,
            query,
            body,
        )?;
        let v = strict(&response.bytes, 33558528)?;
        if !(200..300).contains(&response.status) {
            if matches!(
                v["error"]["code"].as_str(),
                Some("DEVICE_REVOKED" | "DEVICE_NOT_TRUSTED" | "SESSION_EXPIRED" | "AUTH_REQUIRED")
            ) {
                self.lock();
                return Err(Error("STALE_CAPABILITY"));
            }
            return Err(Error(match v["error"]["code"].as_str() {
                Some("NOT_FOUND") => "NOT_FOUND",
                Some("DEVICE_REVOKED") => "DEVICE_REVOKED",
                Some("DEVICE_NOT_TRUSTED") => "DEVICE_NOT_TRUSTED",
                Some("STALE_REVISION") => "STALE_REVISION",
                Some("QUOTA_EXCEEDED") => "QUOTA_EXCEEDED",
                Some("RATE_LIMITED") => "RATE_LIMITED",
                Some("SYNC_CURSOR_EXPIRED") => "SYNC_CURSOR_EXPIRED",
                Some("REKEY_REQUIRED") => "REKEY_REQUIRED",
                Some("HISTORY_CLOSURE_REQUIRED") => "HISTORY_CLOSURE_REQUIRED",
                Some("POLICY_CHANGED") => "POLICY_CHANGED",
                Some("ROSTER_CHANGED") => "ROSTER_CHANGED",
                Some("ACCESS_REVOKED") => "ACCESS_REVOKED",
                Some("SESSION_EXPIRED" | "AUTH_REQUIRED") => "REAUTH_REQUIRED",
                Some("ROLE_FORBIDDEN") => "ROLE_FORBIDDEN",
                Some("IDEMPOTENCY_MISMATCH") => "IDEMPOTENCY_MISMATCH",
                _ => "API_DENIED",
            }));
        }
        Ok(v)
    }
    pub(crate) fn notes(&self, cap: &Capability, v: Value) -> Result<Value> {
        let r: NotesRequest = serde_json::from_value(v).map_err(|_| Error("INVALID_REQUEST"))?;
        self.vault.notes_command(cap, r)
    }
    pub fn roster(&self, cap: &Capability, account: &str, expected_root: &str) -> Result<Value> {
        id(account)?;
        let mut identity = Value::Null;
        let mut events = Vec::new();
        let mut cursor = None::<String>;
        let mut head = Value::Null;
        let mut generation = Value::Null;
        loop {
            let mut query = vec![("root", expected_root)];
            if let Some(c) = &cursor {
                query.push(("after", c.as_str()));
                query.push(("head", string(&head, "digest")?));
            }
            let page = self.api(cap, Route::Roster, Some(account), None, &query, None)?;
            let rows = page["events"].as_array().ok_or(Error("INVALID_ROSTER"))?;
            check(events.len() + rows.len() <= 10000, "RESOURCE_LIMIT")?;
            events.extend(rows.iter().cloned());
            if head.is_null() {
                head = page["head"].clone();
                generation = page["generation"].clone();
                identity = page["identity"].clone();
            } else {
                check(
                    head == page["head"]
                        && generation == page["generation"]
                        && identity == page["identity"],
                    "ROSTER_CHANGED",
                )?;
            }
            if page["next"].is_null() {
                break;
            }
            let next = string(&page, "next")?.to_owned();
            check(cursor.as_ref() != Some(&next), "INVALID_PAGE_ORDER")?;
            cursor = Some(next);
        }
        Ok(json!({"identity":identity,"events":events,"head":head,"generation":generation}))
    }
    pub fn prove(&self, cap: &Capability) -> Result<()> {
        let me = self.api(cap, Route::Me, None, None, &[], None)?;
        check(
            me["session"]["account_id"] == self.profile.scope.account_id,
            "ACCOUNT_MISMATCH",
        )?;
        let result = self.api(
            cap,
            Route::Challenge,
            None,
            None,
            &[],
            Some(&json!({"version":1,"device_id":self.profile.scope.device_id})),
        )?;
        let proof = self.vault.device_proof(
            cap,
            &canonical(&result["challenge"])?,
            string(&me["session"], "id")?,
        )?;
        self.api(cap,Route::Proof,None,None,&[],Some(&json!({"version":1,"challenge_id":result["challenge"]["context"]["challenge_id"],"proof":proof})))?;
        let snap = self.roster(
            cap,
            &self.profile.scope.account_id,
            string(&self.profile.service.pins, "root_fingerprint")?,
        )?;
        self.vault.record_device_snapshot(cap, &snap)?;
        Ok(())
    }
    pub fn group(&self, cap: &Capability, group: &str) -> Result<Value> {
        id(group)?;
        let status = self.api(cap, Route::Group, Some(group), None, &[], None)?;
        if status["kind"] == "shared" || status["key_epoch"] != "0" {
            self.shared_proof(cap, group)?;
        }
        self.notes(cap, json!({"action":"group","status":status}))?;
        if status["kind"] == "private" && status["key_epoch"] == "0" {
            {
                let envelopes = self.api(cap, Route::DeviceEnvelopes, None, None, &[], None)?;
                let records = envelopes["records"]
                    .as_array()
                    .unwrap_or(&Vec::new())
                    .iter()
                    .filter(|r| r["body"]["context"]["group_id"] == group)
                    .cloned()
                    .collect::<Vec<_>>();
                if !records.is_empty() {
                    self.vault
                        .device_group_keys(cap, &status["genesis"], &records, None, None)?;
                }
            }
        } else {
            // The captured signed epoch journal is authoritative. The mailbox may also
            // retain older equivalent resealings, which must not become duplicate epochs.
            match self.notes(
                cap,
                json!({"action":"shared","request":{"action":"keys","group_id":group}}),
            ) {
                Ok(_) => (),
                Err(Error("KEYS_PENDING" | "KEY_REPAIR_REQUIRED")) => {
                    let envelopes = self.api(cap, Route::DeviceEnvelopes, None, None, &[], None)?;
                    let records = envelopes["records"]
                        .as_array()
                        .ok_or(Error("INVALID_PAGE"))?
                        .iter()
                        .filter(|r| {
                            r["body"]["context"]["group_id"] == group
                                && r["body"]["context"]["recipient"]["device_id"]
                                    == self.profile.scope.device_id
                                && r["body"]["context"]["issuer"]["account_id"]
                                    == self.profile.scope.account_id
                                && r["body"]["context"]["membership_head"] == status["membership"]
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    check(!records.is_empty(), "KEYS_PENDING")?;
                    for record in records {
                        self.notes(cap,json!({"action":"shared","request":{"action":"own-keys","group_id":group,"records":[record]}}))?;
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(status)
    }
    pub fn shared_proof(&self, cap: &Capability, group: &str) -> Result<Value> {
        let mut proof = match self.notes(cap, json!({"action":"shared-proof","group_id":group})) {
            Ok(proof) => proof,
            Err(Error("GROUP_PROOF_REQUIRED")) => {
                self.notes(cap, json!({"action":"upgrade-private","group_id":group}))?
            }
            Err(e) => return Err(e),
        };
        let journal = self.api(cap, Route::Journal, Some(group), None, &[], None)?;
        let accounts = proof["accounts"]
            .as_array_mut()
            .ok_or(Error("GROUP_PROOF_REQUIRED"))?;
        for account in accounts {
            account["snapshot"] = self.roster(
                cap,
                string(&account["pins"], "account_id")?,
                string(&account["pins"], "root_fingerprint")?,
            )?;
        }
        proof["journal"] = journal;
        self.notes(
            cap,
            json!({"action":"shared","request":{"action":"adopt","proof":proof}}),
        )?;
        Ok(proof)
    }
    pub fn open_revision(
        &self,
        cap: &Capability,
        group: &str,
        object: &str,
        revision: &str,
    ) -> Result<Value> {
        self.group(cap, group)?;
        let state = self.api(cap, Route::Object, Some(object), None, &[], None)?;
        let bundle = self.api(
            cap,
            Route::Revision,
            Some(object),
            Some(revision),
            &[],
            None,
        )?;
        let opened=self.notes(cap,json!({"action":"open","request":{"group_id":group,"object_id":object,"revision_id":revision,"object_kind":state["object"]["object_kind"],"thread_id":state["object"]["thread_id"],"bundle":bundle["bundle"]}}))?;
        Ok(
            json!({"object":state["object"],"payload":opened["payload"],"envelope_digest":opened["envelope_digest"]}),
        )
    }
    pub fn publish(&self, cap: &Capability, draft: &str) -> Result<Value> {
        self.publish_bound(cap, draft, false)
    }
    fn publication_error(&self, cap: &Capability, attempt: &str, error: Error) -> Error {
        if matches!(
            error.0,
            "STALE_REVISION"
                | "REKEY_REQUIRED"
                | "HISTORY_CLOSURE_REQUIRED"
                | "POLICY_CHANGED"
                | "ROSTER_CHANGED"
                | "ROLE_FORBIDDEN"
                | "NOT_FOUND"
                | "ACCESS_REVOKED"
        ) {
            // Preserve the immutable attempt and source, but classify a definitive
            // refusal so a later reviewed publication uses a fresh operation.
            let _ = self.notes(
                cap,
                json!({"action":"reject","attempt_id":attempt,"code":error.0}),
            );
        }
        error
    }
    fn publish_bound(&self, cap: &Capability, draft: &str, merge: bool) -> Result<Value> {
        id(draft)?;
        let d = match self.notes(cap, json!({"action":"draft","draft_id":draft})) {
            Ok(v) => v,
            Err(Error("RECORD_NOT_FOUND")) => {
                let attempt = self
                    .vault
                    .committed_note_attempt(cap, draft)?
                    .ok_or(Error("RECORD_NOT_FOUND"))?;
                let result = self.api(cap, Route::Receipt, Some(&attempt), None, &[], None)?;
                return self.notes(
                    cap,
                    json!({"action":"ack","attempt_id":attempt,"result":result}),
                );
            }
            Err(e) => return Err(e),
        };
        let group = string(&d["payload"]["context"], "group_id")?;
        self.group(cap, group)?;
        let summary = self.notes(cap, json!({"action":"summary"}))?;
        let pending = summary["drafts"]
            .as_array()
            .ok_or(Error("INTEGRITY_FAILURE"))?
            .iter()
            .find(|d| {
                d["draft_id"] == draft
                    && matches!(d["state"].as_str(), Some("QUEUED" | "SENT_UNKNOWN"))
            })
            .and_then(|d| d["attempt_id"].as_str())
            .map(str::to_owned);
        let attempt = if let Some(attempt) = pending {
            attempt
        } else {
            check(
                merge
                    || d["payload"]["context"]["parents"]
                        .as_array()
                        .ok_or(Error("INTEGRITY_FAILURE"))?
                        .len()
                        <= 1,
                "CONFLICT_CONFIRMATION_REQUIRED",
            )?;
            let queued = self.notes(cap, json!({"action":"queue","draft_id":draft}))?;
            string(&queued, "attempt_id")?.to_owned()
        };
        // An existing receipt is read/acked before any fresh writer check or send.
        // This also permits reconciling an already committed attempt after role loss.
        match self.api(cap, Route::Receipt, Some(&attempt), None, &[], None) {
            Ok(result) => {
                return self.notes(
                    cap,
                    json!({"action":"ack","attempt_id":attempt,"result":result}),
                );
            }
            Err(Error("NOT_FOUND")) => (),
            Err(e) => return Err(e),
        }
        let sent = self
            .notes(cap, json!({"action":"send","attempt_id":attempt}))
            .map_err(|e| self.publication_error(cap, &attempt, e))?;
        let request = &sent["request"];
        let c = &request["bundle"]["envelope"]["header"]["context"];
        let route = if c["action"] == "soft-delete" {
            Route::Tombstone
        } else if c["action"] == "restore" {
            Route::Restore
        } else if c["action"] == "create" && c["object_kind"] == "thread" {
            Route::CreateThread
        } else if c["action"] == "create" && c["object_kind"] == "entry" {
            Route::CreateEntry
        } else {
            Route::Commit
        };
        let resource = if matches!(route, Route::CreateThread) {
            group
        } else if matches!(route, Route::CreateEntry) {
            string(c, "thread_id")?
        } else {
            string(c, "object_id")?
        };
        let result = self
            .api(cap, route, Some(resource), None, &[], Some(request))
            .map_err(|e| self.publication_error(cap, &attempt, e))?;
        self.notes(
            cap,
            json!({"action":"ack","attempt_id":attempt,"result":result}),
        )
    }
    pub fn execute(&self, binding: &Binding, g: u64, mut request: Request) -> Result<Value> {
        binding.validate()?;
        match &mut request {
            Request::Status {} => {
                return Ok(
                    json!({"state":self.vault.status()?,"generation":self.current(),"login_pending":self.pending_login.lock().unwrap().is_some(),"device_id":self.profile.scope.device_id,"version":"0.14.0"}),
                );
            }
            Request::Lock {} => {
                self.lock();
                return Ok(json!({"state":"locked","generation":self.current()}));
            }
            Request::Unlock { phrase } => {
                check(g == self.current(), "STALE_CAPABILITY")?;
                let result = self.vault.unlock_phrase(phrase);
                phrase.zeroize();
                if g != self.current() {
                    self.vault.lock();
                    return Err(Error("STALE_CAPABILITY"));
                }
                *self.cap.lock().map_err(|_| Error("HOST_BUSY"))? = Some(Arc::new(result?));
                return Ok(json!({"state":"unlocked","generation":self.current()}));
            }
            Request::UnlockHello {} => {
                check(g == self.current(), "STALE_CAPABILITY")?;
                let c = self.vault.unlock_hello(binding.hwnd)?;
                if g != self.current() {
                    self.vault.lock();
                    return Err(Error("STALE_CAPABILITY"));
                }
                *self.cap.lock().map_err(|_| Error("HOST_BUSY"))? = Some(Arc::new(c));
                return Ok(json!({"state":"unlocked","generation":self.current()}));
            }
            _ => {}
        }
        let cap = self.capability(g)?;
        self.verify_service(&cap)?;
        let mut result = match &mut request {
            Request::Summary {} => self.notes(&cap, json!({"action":"summary"})),
            Request::FinishLogin {} => {
                let (created, credentials) = self
                    .pending_login
                    .lock()
                    .map_err(|_| Error("HOST_BUSY"))?
                    .take()
                    .ok_or(Error("LOGIN_REQUIRED"))?;
                check(
                    created.elapsed() < Duration::from_secs(120),
                    "REAUTH_REQUIRED",
                )?;
                let me = self
                    .adapter
                    .control(Some(&credentials), Route::Me, None, None, &[], None)
                    .map_err(|_| Error("REAUTH_REQUIRED"))?;
                let v = strict(&me.bytes, 65536)?;
                check(
                    v["session"]["account_id"] == self.profile.scope.account_id,
                    "ACCOUNT_MISMATCH",
                )?;
                self.vault
                    .store_credentials(&cap, &self.profile.credential_id, &credentials)?;
                self.sync_devices(&cap)?;
                Ok(json!({"state":credentials.state}))
            }
            Request::Login {} => {
                let public = self.vault.device_public(&cap)?;
                let commitment = native_commitment(&public)?;
                let credentials = self
                    .adapter
                    .login(&commitment, false)
                    .map_err(|_| Error("AUTHENTICATION_UNAVAILABLE"))?;
                *self.pending_login.lock().map_err(|_| Error("HOST_BUSY"))? =
                    Some((Instant::now(), credentials));
                Ok(json!({"state":"LOGIN_READY","unlock_required":true}))
            }
            Request::Logout {} => {
                self.api(
                    &cap,
                    Route::Logout,
                    None,
                    None,
                    &[],
                    Some(&json!({"version":1})),
                )?;
                self.vault
                    .clear_session(&cap, &self.profile.credential_id)?;
                self.lock();
                return Ok(json!({"state":"locked","generation":self.current()}));
            }
            Request::Refresh {} => {
                self.prove(&cap)?;
                self.refresh(&cap)
            }
            Request::Offline {} => self.local_groups(&cap),
            Request::LocalObjects {
                group_id,
                thread_id,
                after,
            } => self.local_objects(&cap, group_id, thread_id.as_deref(), after.as_deref()),
            Request::Threads { group_id, after } => {
                self.group(&cap, group_id)?;
                self.list_open(&cap, Route::Threads, group_id, group_id, after.as_deref())
            }
            Request::Entries {
                group_id,
                thread_id,
                after,
            } => {
                self.group(&cap, group_id)?;
                self.list_open(&cap, Route::Entries, thread_id, group_id, after.as_deref())
            }
            Request::Open {
                group_id,
                object_id,
                revision_id,
            } => self.open_revision(&cap, group_id, object_id, revision_id),
            Request::Save { edit, publish } => {
                let saved = self.notes(&cap, json!({"action":"save","edit":edit}))?;
                if *publish {
                    self.publish(&cap, string(&saved, "draft_id")?)
                } else {
                    Ok(saved)
                }
            }
            Request::Publish { draft_id } => self.publish(&cap, draft_id),
            Request::ResolveDraft {
                draft_id,
                confirmed,
            } => {
                check(*confirmed, "CONFIRMATION_REQUIRED")?;
                self.publish_bound(&cap, draft_id, true)
            }
            Request::Draft { draft_id } => {
                self.notes(&cap, json!({"action":"draft","draft_id":draft_id}))
            }
            Request::ObjectAction {
                group_id,
                object_id,
                revision_id,
                action,
                confirmed,
            } => {
                check(*confirmed, "CONFIRMATION_REQUIRED")?;
                check(
                    ["archive", "unarchive", "soft-delete"].contains(&action.as_str()),
                    "INVALID_REQUEST",
                )?;
                let opened = self.open_revision(&cap, group_id, object_id, revision_id)?;
                let object = &opened["object"];
                check(
                    object["heads"]
                        .as_array()
                        .is_some_and(|h| h.len() == 1 && h[0]["revision_id"] == *revision_id),
                    "CONFLICT_CONFIRMATION_REQUIRED",
                )?;
                let mut content = opened["payload"].clone();
                let deleting = action == "soft-delete";
                if deleting {
                    content = json!({"title":"","markdown":"","metadata_kind":"content","tags":[],"checklist":[],"summary_entry_id":null,"preferences":[]});
                }
                let mut edit = Self::edit(
                    group_id,
                    string(object, "object_kind")?,
                    Some(object_id),
                    object["thread_id"].as_str(),
                    &content,
                    object["heads"].clone(),
                    if deleting { "soft-delete" } else { "update" },
                );
                edit["archived"] = json!(action == "archive");
                let result = self.notes(&cap, json!({"action":"save","edit":edit}));
                wipe(&mut content);
                let saved = result?;
                self.publish(&cap, string(&saved, "draft_id")?)
            }
            Request::Preferences {
                key,
                target_id,
                value,
            } => self.preferences(&cap, key.as_deref(), target_id.as_deref(), value.as_deref()),
            Request::CopyPreview {
                source_group,
                destination_group,
                revision_id,
            } => {
                self.group(&cap, source_group)?;
                self.group(&cap, destination_group)?;
                self.notes(&cap,json!({"action":"copy-preview","source_group":source_group,"destination_group":destination_group,"revision_id":revision_id}))
            }
            Request::CopyNote {
                source_group,
                destination_group,
                destination_thread,
                revision_id,
                preview_digest,
                confirmed,
            } => {
                self.group(&cap, source_group)?;
                self.group(&cap, destination_group)?;
                self.notes(&cap,json!({"action":"copy","source_group":source_group,"destination_group":destination_group,"destination_thread":destination_thread,"revision_id":revision_id,"preview_digest":preview_digest,"confirmed":confirmed}))
            }
            Request::RecoverDraft {
                draft_id,
                destination_group,
                destination_thread,
                confirmed,
            } => {
                self.group(&cap, destination_group)?;
                self.notes(&cap,json!({"action":"recover-draft","draft_id":draft_id,"destination_group":destination_group,"destination_thread":destination_thread,"confirmed":confirmed}))
            }
            Request::CreateGroup {
                title,
                shared,
                resume,
            } => self.create_group(&cap, title, *shared, resume.as_deref()),
            Request::Search { query, group_id } => {
                anynote_content_native::Search::new(&self.vault, &cap, &self.profile.scope)?
                    .search(query, group_id.as_deref())
            }
            Request::RebuildSearch {} => {
                let search =
                    anynote_content_native::Search::new(&self.vault, &cap, &self.profile.scope)?;
                search.clear(true)?;
                let summary = self.notes(&cap, json!({"action":"summary"}))?;
                let revisions = summary["witnesses"]
                    .as_array()
                    .ok_or(Error("INTEGRITY_FAILURE"))?
                    .iter()
                    .filter_map(|r| r["revision_id"].as_str().map(str::to_owned))
                    .collect::<Vec<_>>();
                search.index(&revisions)
            }
            Request::Storage {} => self.api(&cap, Route::Storage, None, None, &[], None),
            Request::Cache {} => {
                anynote_local_vault::notes::file_cache::CipherCache::for_vault(&self.vault)?
                    .summary()
            }
            Request::RemoveCache {
                group_id,
                file_version_id,
                confirmed,
            } => {
                anynote_local_vault::notes::file_cache::CipherCache::for_vault(&self.vault)?
                    .remove(group_id, file_version_id, *confirmed)?;
                Ok(json!({"state":"REMOVED"}))
            }
            Request::PinCache {
                group_id,
                file_version_id,
                additional_bytes,
                confirmed,
            } => {
                anynote_local_vault::notes::file_cache::CipherCache::for_vault(&self.vault)?
                    .pin_existing(group_id, file_version_id, *additional_bytes, *confirmed)?;
                Ok(json!({"state":"PINNED"}))
            }
            Request::Transfers {} => Ok(
                json!({"jobs":self.jobs.summary(g)?,"transfers":self.vault.file_transfers(&cap)?}),
            ),
            Request::RecoveryJobs {} => self.native_job_summaries(g),
            Request::CancelJob { job_id } => {
                self.jobs.cancel(job_id)?;
                Ok(json!({"state":"PAUSED"}))
            }
            Request::Files { group_id, after } => {
                self.group(&cap, group_id)?;
                self.list_files(&cap, group_id, after.as_deref())
            }
            Request::Devices {} => self.sync_devices(&cap),
            Request::DeliverKeys {
                group_id,
                device_id,
                confirmed,
            } => {
                check(*confirmed, "USER_CONFIRMATION_REQUIRED")?;
                id(device_id)?;
                self.prove(&cap)?;
                let status = self.group(&cap, group_id)?;
                let body = if status["kind"] == "private" && status["key_epoch"] == "0" {
                    self.vault.device_group_keys(
                        &cap,
                        &status["genesis"],
                        &[],
                        None,
                        Some(device_id),
                    )?
                } else {
                    self.notes(&cap,json!({"action":"shared","request":{"action":"own-grants","group_id":group_id,"device_id":device_id}}))?
                };
                self.api(
                    &cap,
                    Route::DeliverDeviceEnvelopes,
                    None,
                    None,
                    &[],
                    Some(&body),
                )
            }
            Request::Sessions {} => self.api(&cap, Route::Sessions, None, None, &[], None),
            Request::RevokeSession {
                session_id,
                confirmed,
            } => {
                check(*confirmed, "CONFIRMATION_REQUIRED")?;
                self.api(
                    &cap,
                    Route::RevokeSession,
                    Some(id(session_id)?),
                    None,
                    &[],
                    Some(&json!({"version":1})),
                )
            }
            Request::AccessPoll { group_id } => {
                let roster = self.sync_devices(&cap)?;
                let own = roster["devices"]
                    .as_array()
                    .ok_or(Error("INTEGRITY_FAILURE"))?
                    .iter()
                    .find(|d| d["device_id"] == self.profile.scope.device_id);
                if own.is_none() {
                    return Ok(json!({"state":"ENROLLMENT_REQUIRED"}));
                }
                if own.is_some_and(|d| d["status"] == "REVOKED") {
                    self.lock();
                    return Err(Error("STALE_CAPABILITY"));
                }
                let checked = self.prove(&cap).and_then(|_| {
                    if let Some(group) = group_id {
                        self.group(&cap, group)
                    } else {
                        Ok(json!({"state":"ACTIVE"}))
                    }
                });
                match checked {
                    Err(Error(
                        "DEVICE_REVOKED" | "DEVICE_NOT_TRUSTED" | "REAUTH_REQUIRED" | "NOT_FOUND",
                    )) => {
                        self.lock();
                        return Err(Error("STALE_CAPABILITY"));
                    }
                    result => result,
                }
            }
            Request::Members { group_id } => {
                self.shared_proof(&cap, group_id)?;
                self.notes(
                    &cap,
                    json!({"action":"shared","request":{"action":"details","group_id":group_id}}),
                )
            }
            Request::Retention {
                group_id,
                apply,
                confirmed,
            } => {
                self.group(&cap, group_id)?;
                if *apply {
                    check(*confirmed, "CONFIRMATION_REQUIRED")?;
                }
                let body = json!({"version":1,"confirm":true,"after":null});
                self.api(
                    &cap,
                    if *apply {
                        Route::RetentionApply
                    } else {
                        Route::Retention
                    },
                    Some(group_id),
                    None,
                    &[],
                    if *apply { Some(&body) } else { None },
                )
            }
            Request::PinRevision {
                revision_id,
                pinned,
            } => self.api(
                &cap,
                Route::RetentionPin,
                Some(revision_id),
                None,
                &[],
                Some(&json!({"version":1,"pinned":pinned})),
            ),
            Request::Versions {
                group_id,
                object_id,
            } => {
                self.group(&cap, group_id)?;
                self.api(&cap, Route::Revisions, Some(object_id), None, &[], None)
            }
            Request::Restore {
                group_id,
                object_id,
                revision_id,
            } => {
                let opened = self.open_revision(&cap, group_id, object_id, revision_id)?;
                let state = self.api(&cap, Route::Object, Some(object_id), None, &[], None)?;
                let p = &opened["payload"];
                let saved=self.notes(&cap,json!({"action":"save","edit":Self::edit(group_id,string(&state["object"],"object_kind")?,Some(object_id),state["object"]["thread_id"].as_str(),p,state["object"]["heads"].clone(),"restore")}))?;
                self.publish(&cap, string(&saved, "draft_id")?)
            }
            Request::Shared {
                group_id,
                action,
                target_account_id,
                role,
                confirmed,
            } => self.shared_change(
                &cap,
                group_id,
                action,
                target_account_id.as_deref(),
                role.as_deref(),
                *confirmed,
            ),
            Request::Device {
                action,
                value,
                confirmed,
            } => self.device(&cap, action, value.as_ref(), *confirmed),
            Request::Diagnostics {} => Ok(
                json!({"version":"0.14.0","platform":std::env::consts::OS,"state":self.vault.status()?,"physical_acceptance":false,"logging":"content-free","memory":crate::memory::report(),"custody":"native SQLite and current-user DPAPI","production_signing":"NOT_CONFIGURED"}),
            ),
            Request::Pairing { request } => self.pairing_command(&cap, request),
            _ => Err(Error("INVALID_REQUEST")),
        };
        if g != self.current() {
            if let Ok(v) = &mut result {
                wipe(v);
            }
            return Err(Error("STALE_CAPABILITY"));
        }
        result
    }
    pub fn edit(
        group: &str,
        kind: &str,
        object: Option<&str>,
        thread: Option<&str>,
        content: &Value,
        parents: Value,
        action: &str,
    ) -> Value {
        json!({"draft_id":null,"group_id":group,"object_id":object,"object_kind":kind,"thread_id":thread,"action":action,"parents":parents,"archived":false,"attachments":content["context"]["attachments"].as_array().cloned().unwrap_or_default(),"content":{"title":content["title"],"markdown":content["markdown"],"metadata_kind":content["metadata_kind"],"tags":content["tags"],"checklist":content["checklist"],"summary_entry_id":content["summary_entry_id"],"preferences":content["preferences"]}})
    }
    fn list_open(
        &self,
        cap: &Capability,
        route: Route,
        resource: &str,
        group: &str,
        after: Option<&str>,
    ) -> Result<Value> {
        if let Some(after) = after {
            id(after)?;
        }
        let query = after.map(|v| vec![("after", v)]).unwrap_or_default();
        let page = self.api(cap, route, Some(resource), None, &query, None)?;
        let mut items = Vec::new();
        for object in page["objects"].as_array().ok_or(Error("INVALID_PAGE"))? {
            let revision = object["heads"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|h| h["revision_id"].as_str())
                .ok_or(Error("PAYLOAD_UNAVAILABLE"))?;
            let p = self.open_revision(cap, group, string(object, "object_id")?, revision)?;
            items.push(json!({"object":object,"payload":p["payload"]}));
        }
        Ok(json!({"items":items,"next":page["next"]}))
    }
    fn refresh(&self, cap: &Capability) -> Result<Value> {
        let synchronization = match self.catch_up(cap) {
            Ok(state) => json!({"state":state["state"],"complete":true}),
            Err(Error(
                code @ ("KEYS_PENDING"
                | "EPOCH_KEY_REQUIRED"
                | "GROUP_PROOF_REQUIRED"
                | "RECORD_NOT_FOUND"
                | "UNANCHORED_HISTORY"
                | "INDEPENDENT_HISTORY_REQUIRED"
                | "KEY_REPAIR_REQUIRED"),
            )) => json!({"state":"INCOMPLETE","complete":false,"reason":code}),
            Err(e) => return Err(e),
        };
        let mut items = Vec::new();
        let mut after = None::<String>;
        loop {
            let query = after
                .as_ref()
                .map(|v| vec![("after", v.as_str())])
                .unwrap_or_default();
            let page = self.api(cap, Route::GroupList, None, None, &query, None)?;
            for g in page["groups"].as_array().ok_or(Error("INVALID_PAGE"))? {
                let group = string(g, "group_id")?;
                if let Err(error) = self.group(cap, group) {
                    match error {
                        Error(
                            code @ ("KEYS_PENDING"
                            | "EPOCH_KEY_REQUIRED"
                            | "GROUP_PROOF_REQUIRED"
                            | "RECORD_NOT_FOUND"
                            | "UNANCHORED_HISTORY"
                            | "INDEPENDENT_HISTORY_REQUIRED"
                            | "KEY_REPAIR_REQUIRED"),
                        ) => {
                            items.push(json!({"group":g,"title":"Encrypted group","attention":code,"decrypted":false}));
                            continue;
                        }
                        e => return Err(e),
                    }
                }
                let metadata = match self.api(cap, Route::Object, Some(group), None, &[], None) {
                    Ok(v) => v,
                    Err(Error("NOT_FOUND")) => Value::Null,
                    Err(e) => return Err(e),
                };
                let title = if metadata["object"]["heads"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty())
                {
                    match self.open_revision(
                        cap,
                        group,
                        group,
                        string(&metadata["object"]["heads"][0], "revision_id")?,
                    ) {
                        Ok(opened) => opened["payload"]["title"].clone(),
                        Err(Error(
                            code @ ("KEYS_PENDING"
                            | "EPOCH_KEY_REQUIRED"
                            | "UNANCHORED_HISTORY"
                            | "KEY_REPAIR_REQUIRED"),
                        )) => {
                            items.push(json!({"group":g,"title":"Encrypted group","attention":code,"decrypted":false}));
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    json!("Untitled")
                };
                items.push(json!({"group":g,"title":title}));
            }
            check(items.len() <= 1000, "RESOURCE_LIMIT")?;
            if page["next"].is_null() {
                break;
            }
            let next = string(&page, "next")?.to_owned();
            check(after.as_ref() != Some(&next), "INVALID_PAGE_ORDER")?;
            after = Some(next);
        }
        Ok(
            json!({"items":items,"next":null,"synchronization":synchronization,"local":self.notes(cap,json!({"action":"summary"}))?}),
        )
    }
    fn preferences(
        &self,
        cap: &Capability,
        key: Option<&str>,
        target: Option<&str>,
        value: Option<&str>,
    ) -> Result<Value> {
        self.prove(cap)?;
        let summary = self.notes(cap, json!({"action":"summary"}))?;
        let settings = summary["groups"]
            .as_array()
            .ok_or(Error("INTEGRITY_FAILURE"))?
            .iter()
            .find(|g| g["status"]["settings"] == true)
            .ok_or(Error("SETTINGS_REQUIRED"))?;
        let group = string(settings, "group_id")?;
        self.group(cap, group)?;
        let object = match self.api(cap, Route::Object, Some(group), None, &[], None) {
            Ok(v) => v["object"].clone(),
            Err(Error("NOT_FOUND")) => Value::Null,
            Err(e) => return Err(e),
        };
        let heads = object["heads"].as_array().cloned().unwrap_or_default();
        check(heads.len() <= 1, "CONFLICT_CONFIRMATION_REQUIRED")?;
        let mut preferences = if let Some(head) = heads.first() {
            self.open_revision(cap,group,group,string(head,"revision_id")?)?["payload"]["preferences"].clone()
        } else {
            json!([])
        };
        if let Some(key) = key {
            check(
                ["favorite", "group-order", "thread-order", "read-marker"].contains(&key),
                "INVALID_REQUEST",
            )?;
            let target = id(target.ok_or(Error("INVALID_REQUEST"))?)?;
            let value = value.ok_or(Error("INVALID_REQUEST"))?;
            check(
                value.len() <= 20
                    && value.parse::<u64>().is_ok()
                    && (key != "favorite" || ["0", "1"].contains(&value)),
                "INVALID_REQUEST",
            )?;
            let rows = preferences
                .as_array_mut()
                .ok_or(Error("INTEGRITY_FAILURE"))?;
            rows.retain(|p| !(p["key"] == key && p["target_id"] == target));
            rows.push(json!({"key":key,"target_id":target,"value":value}));
            rows.sort_by_key(|p| {
                format!(
                    "{}/{}",
                    p["key"].as_str().unwrap_or(""),
                    p["target_id"].as_str().unwrap_or("")
                )
            });
            let content = json!({"title":"","markdown":"","metadata_kind":"account-preferences","tags":[],"checklist":[],"summary_entry_id":null,"preferences":preferences});
            let edit = Self::edit(
                group,
                "group-metadata",
                Some(group),
                None,
                &content,
                json!(heads),
                if object.is_null() { "create" } else { "update" },
            );
            let saved = self.notes(cap, json!({"action":"save","edit":edit}))?;
            self.publish(cap, string(&saved, "draft_id")?)?;
        } else {
            check(target.is_none() && value.is_none(), "INVALID_REQUEST")?;
        }
        Ok(json!({"preferences":preferences}))
    }
    fn shared_change(
        &self,
        cap: &Capability,
        group: &str,
        action: &str,
        target: Option<&str>,
        role: Option<&str>,
        confirmed: bool,
    ) -> Result<Value> {
        check(confirmed, "CONFIRMATION_REQUIRED")?;
        if !matches!(action, "retry" | "cancel") {
            // Capture peer publications before changing their authority or endorsing
            // a history inventory; a stale local catalog is not a complete closure.
            self.resync(cap)?;
        }
        self.shared_proof(cap, group)?;
        if action == "cancel" {
            let request=self.notes(cap,json!({"action":"shared","request":{"action":"cancel-attempt","group_id":group,"confirmed":true}}))?;
            let result = self.api(
                cap,
                Route::CancelShared,
                Some(group),
                None,
                &[],
                Some(&request),
            )?;
            return self.notes(cap,json!({"action":"shared","request":{"action":"finish-cancel","group_id":group,"result":result}}));
        }
        let request = match action {
            "retry" => json!({"action":"retry","group_id":group}),
            "history" => json!({"action":"history","group_id":group}),
            "optional" | "roster-maintenance" | "member-removal" | "admission" => {
                json!({"action":"epoch","group_id":group,"reason":action,"confirmed":true})
            }
            "remove" | "role" | "archive" | "unarchive" => {
                json!({"action":"policy","group_id":group,"policy_action":action,"target_account_id":target,"role":role,"confirmed":true})
            }
            _ => return Err(Error("INVALID_REQUEST")),
        };
        let prepared = self.notes(cap, json!({"action":"shared","request":request}))?;
        self.send_shared(cap, group, &prepared)
    }
    pub fn send_shared(&self, cap: &Capability, group: &str, prepared: &Value) -> Result<Value> {
        let family = string(prepared, "family")?;
        let body = &prepared["body"];
        let record = [
            "invitation",
            "acceptance",
            "policy",
            "intent",
            "commit",
            "history",
        ]
        .iter()
        .find_map(|key| body.get(*key).filter(|v| !v.is_null()));
        let operation = record
            .map(|r| &r["body"]["operation_id"])
            .unwrap_or(&body["operation_id"]);
        let operation = operation.as_str().ok_or(Error("INVALID_REQUEST"))?;
        let receipt_family = if family == "epoch" { "commit" } else { family };
        let receipt = self.api(
            cap,
            Route::SecurityReceipt,
            Some(operation),
            None,
            &[("family", receipt_family)],
            None,
        );
        let result = match receipt {
            Ok(result) => result,
            Err(Error("NOT_FOUND")) => {
                let route = match family {
                    "history" => Route::History,
                    "policy" => Route::Policy,
                    "invite" => Route::Invite,
                    "accept" => Route::Accept,
                    "consent" => Route::OwnerConsent,
                    "cancel" => Route::CancelShared,
                    "epoch" => Route::EpochBegin,
                    _ => return Err(Error("INVALID_REQUEST")),
                };
                let mut result = self.api(cap, route, Some(group), None, &[], Some(body))?;
                if family == "epoch" {
                    for page in prepared["pages"]
                        .as_array()
                        .ok_or(Error("INVALID_REQUEST"))?
                    {
                        self.api(
                            cap,
                            Route::EpochPage,
                            Some(group),
                            None,
                            &[],
                            Some(&json!({"version":1,"page":page})),
                        )?;
                    }
                    result = self.api(
                        cap,
                        Route::EpochCommit,
                        Some(group),
                        None,
                        &[],
                        Some(&json!({"version":1,"commit":prepared["commit"]})),
                    )?;
                }
                result
            }
            Err(e) => return Err(e),
        };
        self.notes(cap,json!({"action":"shared","request":{"action":"complete","group_id":group,"result":result}}))?;
        Ok(result)
    }
    pub fn sync_devices(&self, cap: &Capability) -> Result<Value> {
        let snapshot = self.roster(
            cap,
            &self.profile.scope.account_id,
            string(&self.profile.service.pins, "root_fingerprint")?,
        )?;
        self.vault.record_device_snapshot(cap, &snapshot)
    }
    pub fn revoke_preview(&self, g: u64, targets: &Value) -> Result<Value> {
        let cap = self.capability(g)?;
        let summary = self.sync_devices(&cap)?;
        let mut affected = targets
            .as_array()
            .ok_or(Error("INVALID_REQUEST"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or(Error("INVALID_REQUEST"))
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        check(!affected.is_empty(), "INVALID_REQUEST")?;
        let devices = summary["devices"]
            .as_array()
            .ok_or(Error("INTEGRITY_FAILURE"))?;
        check(
            affected.iter().all(|target| {
                devices
                    .iter()
                    .any(|d| d["device_id"] == *target && d["status"] == "ACTIVE")
            }),
            "INVALID_REQUEST",
        )?;
        loop {
            let before = affected.len();
            for device in devices {
                if device["status"] == "ACTIVE"
                    && device["parent_device_id"]
                        .as_str()
                        .is_some_and(|p| affected.contains(p))
                {
                    affected.insert(string(device, "device_id")?.into());
                }
            }
            if affected.len() == before {
                break;
            }
        }
        check(
            !affected.contains(&self.profile.scope.device_id),
            "REVOKER_IN_CLOSURE",
        )?;
        Ok(json!({"head":summary["head"],"affected":affected,"targets":targets}))
    }

    fn device(
        &self,
        cap: &Capability,
        action: &str,
        value: Option<&Value>,
        confirmed: bool,
    ) -> Result<Value> {
        let v = value.unwrap_or(&Value::Null);
        if action != "public" {
            self.sync_devices(cap)?;
        }
        match action {
            "public" => self.vault.device_public(cap),
            "revoke" => {
                check(confirmed, "CONFIRMATION_REQUIRED")?;
                let targets = v["targets"]
                    .as_array()
                    .ok_or(Error("INVALID_REQUEST"))?
                    .iter()
                    .map(|s| {
                        s.as_str()
                            .map(str::to_owned)
                            .ok_or(Error("INVALID_REQUEST"))
                    })
                    .collect::<Result<Vec<_>>>()?;
                check(v["head"].is_object(), "CONFIRMATION_REQUIRED")?;
                let prepared =
                    self.vault
                        .device_revoke_bound(cap, &targets, true, Some(&v["head"]))?;
                let result = self.api(
                    cap,
                    Route::RevokeDevice,
                    targets.first().map(String::as_str),
                    None,
                    &[],
                    Some(&json!({"version":1,"event":prepared})),
                )?;
                Ok(result)
            }
            _ => Err(Error("INVALID_REQUEST")),
        }
    }
}
