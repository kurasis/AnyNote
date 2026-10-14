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
    },
    Threads {
        group_id: String,
    },
    Entries {
        group_id: String,
        thread_id: String,
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
    Draft {
        draft_id: String,
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
    Transfers {},
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
    Sessions {},
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
    Diagnostics {},
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
        let vault = Arc::new(Vault::open(&root.join("vault.sqlite"), scope.clone())?);
        if hello {
            vault.initialize_device_hello(hwnd, service.pins.clone())?;
        } else {
            vault.initialize_device_phrase(phrase, service.pins.clone(), true)?;
        }
        let profile = Profile {
            version: 1,
            scope,
            service,
            credential_id: random_id(),
        };
        let host = Self::from_parts(root, profile, vault, adapter);
        let cap = if hello {
            host.vault.unlock_hello(hwnd)?
        } else {
            host.vault.unlock_phrase(phrase)?
        };
        host.bind_new_service(&cap)?;
        host.vault.lock();
        let mut out = crate::selection::Destination::create(&root.join("profile.json"))?;
        std::io::Write::write_all(
            &mut out,
            &canonical(
                &serde_json::to_value(&host.profile)
                    .map_err(|_| Error("INVALID_SERVICE_CONFIGURATION"))?,
            )?,
        )
        .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        out.finish()?;
        Ok(host)
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
        if let Ok(mut c) = self.cap.try_lock() {
            *c = None;
        }
        self.vault.lock();
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
            return Err(Error(match v["error"]["code"].as_str() {
                Some("NOT_FOUND") => "NOT_FOUND",
                Some("DEVICE_REVOKED") => "DEVICE_REVOKED",
                Some("DEVICE_NOT_TRUSTED") => "DEVICE_NOT_TRUSTED",
                Some("STALE_REVISION") => "STALE_REVISION",
                Some("QUOTA_EXCEEDED") => "QUOTA_EXCEEDED",
                Some("RATE_LIMITED") => "RATE_LIMITED",
                Some("SYNC_CURSOR_EXPIRED") => "SYNC_CURSOR_EXPIRED",
                Some("REKEY_REQUIRED") => "REKEY_REQUIRED",
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
            if let Ok(envelopes) = self.api(cap, Route::DeviceEnvelopes, None, None, &[], None) {
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
            self.notes(
                cap,
                json!({"action":"shared","request":{"action":"keys","group_id":group}}),
            )?;
        }
        Ok(status)
    }
    pub fn shared_proof(&self, cap: &Capability, group: &str) -> Result<Value> {
        let mut proof = self.notes(cap, json!({"action":"group-evidence","group_id":group}))?;
        if proof["proof"].is_object() {
            proof = proof["proof"].clone();
        }
        if proof["pin"].is_null() {
            proof = self.notes(cap, json!({"action":"upgrade-private","group_id":group}))?;
        }
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
        self.notes(cap,json!({"action":"open","request":{"group_id":group,"object_id":object,"revision_id":revision,"object_kind":state["object"]["object_kind"],"thread_id":state["object"]["thread_id"],"bundle":bundle["bundle"]}}))
    }
    pub fn publish(&self, cap: &Capability, draft: &str) -> Result<Value> {
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
        let queued = self.notes(cap, json!({"action":"queue","draft_id":draft}))?;
        let attempt = string(&queued, "attempt_id")?;
        let sent = self.notes(cap, json!({"action":"send","attempt_id":attempt}))?;
        let request = &sent["request"];
        let c = &request["bundle"]["envelope"]["header"]["context"];
        let route = if c["action"] == "create" && c["object_kind"] == "thread" {
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
        let receipt = self.api(
            cap,
            Route::Receipt,
            Some(string(c, "operation_id")?),
            None,
            &[],
            None,
        );
        let result = match receipt {
            Ok(v) => v,
            Err(Error("NOT_FOUND")) => {
                self.api(cap, route, Some(resource), None, &[], Some(request))?
            }
            Err(e) => return Err(e),
        };
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
                    json!({"state":self.vault.status()?,"generation":self.current(),"login_pending":self.pending_login.lock().unwrap().is_some(),"version":"0.14.0"}),
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
            Request::Offline {} => self.notes(
                &cap,
                json!({"action":"sync","request":{"action":"offline"}}),
            ),
            Request::Threads { group_id } => {
                self.group(&cap, group_id)?;
                self.list_open(&cap, Route::Threads, group_id, group_id)
            }
            Request::Entries {
                group_id,
                thread_id,
            } => {
                self.group(&cap, group_id)?;
                self.list_open(&cap, Route::Entries, thread_id, group_id)
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
            Request::Draft { draft_id } => {
                self.notes(&cap, json!({"action":"draft","draft_id":draft_id}))
            }
            Request::CreateGroup { title, shared } => {
                check(title.len() <= 4096, "RESOURCE_LIMIT")?;
                self.prove(&cap)?;
                let made = self.notes(
                    &cap,
                    json!({"action":if *shared{"prepare-shared"}else{"prepare-group"}}),
                )?;
                let status = self.api(
                    &cap,
                    Route::CreateGroup,
                    None,
                    None,
                    &[],
                    Some(&made["request"]),
                )?;
                self.notes(&cap, json!({"action":"group","status":status}))?;
                let saved=self.notes(&cap,json!({"action":"save","edit":Self::edit(string(&status,"group_id")?,"group-metadata",Some(string(&status,"group_id")?),None,&json!({"title":title,"markdown":"","metadata_kind":"content","tags":[],"checklist":[],"summary_entry_id":null,"preferences":[]}),json!([]),"create")}))?;
                self.publish(&cap, string(&saved, "draft_id")?)?;
                Ok(status)
            }
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
            Request::Transfers {} => Ok(
                json!({"jobs":self.jobs.summary(g)?,"transfers":self.vault.file_transfers(&cap)?}),
            ),
            Request::CancelJob { job_id } => {
                self.jobs.cancel(job_id)?;
                Ok(json!({"state":"PAUSED"}))
            }
            Request::Files { group_id, after } => {
                self.group(&cap, group_id)?;
                self.list_files(&cap, group_id, after.as_deref())
            }
            Request::Devices {} => self.api(&cap, Route::Devices, None, None, &[], None),
            Request::Sessions {} => self.api(&cap, Route::Sessions, None, None, &[], None),
            Request::Members { group_id } => {
                self.shared_proof(&cap, group_id)?;
                self.api(&cap, Route::Members, Some(group_id), None, &[], None)
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
                json!({"version":"0.14.0","platform":std::env::consts::OS,"state":self.vault.status()?,"physical_acceptance":false,"logging":"content-free","custody":"native SQLite and current-user DPAPI","production_signing":"NOT_CONFIGURED"}),
            ),
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
        json!({"draft_id":null,"group_id":group,"object_id":object,"object_kind":kind,"thread_id":thread,"action":action,"parents":parents,"archived":false,"content":{"title":content["title"],"markdown":content["markdown"],"metadata_kind":content["metadata_kind"],"tags":content["tags"],"checklist":content["checklist"],"summary_entry_id":content["summary_entry_id"],"preferences":content["preferences"]}})
    }
    fn list_open(
        &self,
        cap: &Capability,
        route: Route,
        resource: &str,
        group: &str,
    ) -> Result<Value> {
        let page = self.api(cap, route, Some(resource), None, &[], None)?;
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
        self.resync(cap)?;
        let page = self.api(cap, Route::GroupList, None, None, &[], None)?;
        let mut items = Vec::new();
        for g in page["groups"].as_array().ok_or(Error("INVALID_PAGE"))? {
            let group = string(g, "group_id")?;
            self.group(cap, group)?;
            let metadata = match self.api(cap, Route::Object, Some(group), None, &[], None) {
                Ok(v) => v,
                Err(Error("NOT_FOUND")) => Value::Null,
                Err(e) => return Err(e),
            };
            let title = if metadata["object"]["heads"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
            {
                self.open_revision(
                    cap,
                    group,
                    group,
                    string(&metadata["object"]["heads"][0], "revision_id")?,
                )?["payload"]["title"]
                    .clone()
            } else {
                json!("Untitled")
            };
            items.push(json!({"group":g,"title":title}));
        }
        Ok(
            json!({"items":items,"next":page["next"],"local":self.notes(cap,json!({"action":"summary"}))?}),
        )
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
        self.shared_proof(cap, group)?;
        let request = match action {
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
        let family = string(&prepared, "family")?;
        let route = match family {
            "history" => Route::History,
            "policy" => Route::Policy,
            "epoch" => Route::EpochBegin,
            _ => return Err(Error("INVALID_REQUEST")),
        };
        let mut result = self.api(cap, route, Some(group), None, &[], Some(&prepared["body"]))?;
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
                    &[("index", string(page, "page_index")?)],
                    Some(page),
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
        self.notes(cap,json!({"action":"shared","request":{"action":"complete","group_id":group,"result":result}}))?;
        Ok(result)
    }
    fn device(
        &self,
        cap: &Capability,
        action: &str,
        value: Option<&Value>,
        confirmed: bool,
    ) -> Result<Value> {
        let v = value.unwrap_or(&Value::Null);
        match action {
            "public" => self.vault.device_public(cap),
            "invitation" => self.vault.device_invitation(cap),
            "offer" => {
                let me = self.api(cap, Route::Me, None, None, &[], None)?;
                self.vault
                    .device_offer(cap, string(&me["session"], "id")?, value)
            }
            "response" => self.vault.device_response(cap, v, None),
            "approval" => self.vault.device_approval(cap, v, confirmed),
            "confirmation" => {
                check(confirmed, "CONFIRMATION_REQUIRED")?;
                let me = self.api(cap, Route::Me, None, None, &[], None)?;
                self.vault.device_confirmation(
                    cap,
                    &v["transcript"],
                    &v["approval"],
                    string(&me["session"], "id")?,
                    true,
                )
            }
            "revoke" => {
                check(confirmed, "CONFIRMATION_REQUIRED")?;
                let targets = v
                    .as_array()
                    .ok_or(Error("INVALID_REQUEST"))?
                    .iter()
                    .map(|s| {
                        s.as_str()
                            .map(str::to_owned)
                            .ok_or(Error("INVALID_REQUEST"))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let prepared = self.vault.device_revoke(cap, &targets, true)?;
                let result = self.api(
                    cap,
                    Route::RevokeDevice,
                    targets.first().map(String::as_str),
                    None,
                    &[],
                    Some(&prepared["request"]),
                )?;
                Ok(result)
            }
            _ => Err(Error("INVALID_REQUEST")),
        }
    }
}
