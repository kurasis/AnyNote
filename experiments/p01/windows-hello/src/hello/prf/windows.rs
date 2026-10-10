//! System32-only WebAuthn calls on a uniquely created app test credential.
use super::{
    auth_context_for, bindings::*, exercise, interrupted, invalid, Capability, Experiment,
    Provider, Report, RP,
};
use crate::{
    hello::proof::{Failure, Outcome},
    storage::{Error, Result},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::{
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{FreeLibrary, GetLastError},
    System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32},
    UI::WindowsAndMessaging::IsWindow,
};
use zeroize::{Zeroize, Zeroizing};

pub(crate) mod combined;
const MAX_ID: usize = 4096;
const MAX_DATA: usize = 65_536;
const TIMEOUT_MS: u32 = 60_000;
static PENDING_DELETE: Mutex<Option<Vec<u8>>> = Mutex::new(None);

struct Module(usize);
impl Module {
    fn load(name: &[u16]) -> std::result::Result<Self, Failure> {
        let handle =
            unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if handle.is_null() {
            return Err(native(unsafe { GetLastError() }, "load-system-dll"));
        }
        Ok(Self(handle as usize))
    }
    fn symbol<T: Copy>(&self, name: &[u8]) -> std::result::Result<T, Failure> {
        let proc = unsafe { GetProcAddress(self.0 as *mut _, name.as_ptr()) }
            .ok_or_else(|| native(unsafe { GetLastError() }, "resolve-webauthn-export"))?;
        // All callers supply a generated, exact API function-pointer type.
        if std::mem::size_of::<T>() != std::mem::size_of_val(&proc) {
            return Err(invalid("webauthn-pointer-layout"));
        }
        Ok(unsafe { std::mem::transmute_copy(&proc) })
    }
}
impl Drop for Module {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0 as *mut _);
        }
    }
}

struct Api {
    module: Module,
    version: WebAuthNGetApiVersionNumber,
    available: WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable,
    make: WebAuthNAuthenticatorMakeCredential,
    get: WebAuthNAuthenticatorGetAssertion,
    free_make: WebAuthNFreeCredentialAttestation,
    free_get: WebAuthNFreeAssertion,
    delete: WebAuthNDeletePlatformCredential,
    cancellation_id: WebAuthNGetCancellationId,
    cancel: WebAuthNCancelCurrentOperation,
}
impl Api {
    fn load() -> std::result::Result<Self, Failure> {
        let module = Module::load(&wide("webauthn.dll"))?;
        Ok(Self {
            version: module.symbol(b"WebAuthNGetApiVersionNumber\0")?,
            available: module.symbol(b"WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable\0")?,
            make: module.symbol(b"WebAuthNAuthenticatorMakeCredential\0")?,
            get: module.symbol(b"WebAuthNAuthenticatorGetAssertion\0")?,
            free_make: module.symbol(b"WebAuthNFreeCredentialAttestation\0")?,
            free_get: module.symbol(b"WebAuthNFreeAssertion\0")?,
            delete: module.symbol(b"WebAuthNDeletePlatformCredential\0")?,
            cancellation_id: module.symbol(b"WebAuthNGetCancellationId\0")?,
            cancel: module.symbol(b"WebAuthNCancelCurrentOperation\0")?,
            module,
        })
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn native(code: u32, operation: &'static str) -> Failure {
    // Only explicit native cancellation codes are cancellation, never parameter errors.
    Failure {
        status: if code == 0x800704C7 || code == 0x80090036 {
            Outcome::Cancelled
        } else {
            Outcome::Failed
        },
        code: Some(code),
        operation: Some(operation),
    }
}
fn status(hr: i32, operation: &'static str) -> std::result::Result<(), Failure> {
    if hr == 0 {
        Ok(())
    } else {
        Err(native(hr as u32, operation))
    }
}

#[repr(C)]
struct OsVersion {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    service_pack: [u16; 128],
}
fn os_build() -> Option<u32> {
    let module = Module::load(&wide("ntdll.dll")).ok()?;
    let get: unsafe extern "system" fn(*mut OsVersion) -> i32 =
        module.symbol(b"RtlGetVersion\0").ok()?;
    let mut v = OsVersion {
        size: std::mem::size_of::<OsVersion>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        service_pack: [0; 128],
    };
    (unsafe { get(&mut v) } == 0).then_some(v.build)
}

/// Bounded views into buffers owned by webauthn.dll, consumed before native free.
unsafe fn bytes<'a>(p: *const u8, len: u32, max: usize) -> std::result::Result<&'a [u8], Failure> {
    if len == 0 || len as usize > max || p.is_null() {
        return Err(invalid("webauthn-output-length"));
    }
    Ok(unsafe { std::slice::from_raw_parts(p, len as usize) })
}
unsafe fn name_matches(p: *const u16) -> bool {
    if p.is_null() {
        return false;
    }
    let mut name = Vec::new();
    for i in 0..128 {
        let c = unsafe { p.add(i).read_unaligned() };
        if c == 0 {
            return String::from_utf16(&name)
                .is_ok_and(|s| s.eq_ignore_ascii_case("Windows Hello"));
        }
        name.push(c);
    }
    false
}
unsafe fn select(
    list: *const WEBAUTHN_AUTHENTICATOR_DETAILS_LIST,
    cap: &mut Capability,
) -> std::result::Result<Vec<u8>, Failure> {
    if list.is_null() {
        cap.hello_candidates = Some(0);
        return Err(invalid("hello-route-absent"));
    }
    let list = unsafe { &*list };
    if list.cAuthenticatorDetails > 32
        || (list.cAuthenticatorDetails != 0 && list.ppAuthenticatorDetails.is_null())
    {
        return Err(invalid("webauthn-authenticator-list-length"));
    }
    let mut found = Vec::<Vec<u8>>::new();
    let mut locked = false;
    for i in 0..list.cAuthenticatorDetails as usize {
        let p = unsafe { list.ppAuthenticatorDetails.add(i).read() };
        if p.is_null() {
            return Err(invalid("webauthn-authenticator-entry"));
        }
        if unsafe { (*p).dwVersion } != 1 {
            return Err(invalid("webauthn-authenticator-version"));
        }
        let entry = unsafe { &*p };
        if !unsafe { name_matches(entry.pwszAuthenticatorName) } {
            continue;
        }
        let id =
            unsafe { bytes(entry.pbAuthenticatorId, entry.cbAuthenticatorId, MAX_ID) }?.to_vec();
        locked |= entry.bLocked != 0;
        if !found.contains(&id) {
            found.push(id);
        }
    }
    cap.hello_candidates = Some(found.len() as u32);
    cap.hello_locked = Some(locked);
    if found.len() != 1 {
        return Err(invalid("hello-route-absent-or-ambiguous"));
    }
    if locked {
        return Err(invalid("hello-route-locked"));
    }
    Ok(found.remove(0))
}

unsafe fn prf_secret(
    p: *mut WEBAUTHN_HMAC_SECRET_SALT,
) -> std::result::Result<Zeroizing<[u8; 32]>, Failure> {
    if p.is_null() {
        return Err(invalid("prf-output-missing"));
    }
    let s = unsafe { &*p };
    let b = unsafe { bytes(s.pbFirst, s.cbFirst, 32) }?;
    if b.len() != 32 || s.cbSecond != 0 {
        return Err(invalid("prf-output-size"));
    }
    let mut output = Zeroizing::new([0; 32]);
    output.copy_from_slice(b);
    Ok(output)
}
unsafe fn wipe_secret(p: *mut WEBAUTHN_HMAC_SECRET_SALT) {
    if p.is_null() {
        return;
    }
    let s = unsafe { &*p };
    for (p, n) in [(s.pbFirst, s.cbFirst), (s.pbSecond, s.cbSecond)] {
        if !p.is_null() && n as usize <= MAX_DATA {
            unsafe { std::slice::from_raw_parts_mut(p, n as usize) }.zeroize();
        }
    }
}
struct Created<'a> {
    p: *mut WEBAUTHN_CREDENTIAL_ATTESTATION,
    api: &'a Api,
}
impl Drop for Created<'_> {
    fn drop(&mut self) {
        if !self.p.is_null() {
            unsafe {
                if (*self.p).dwVersion >= 7 {
                    wipe_secret((*self.p).pHmacSecret);
                }
                (self.api.free_make)(self.p);
            }
        }
    }
}
struct Assertion<'a> {
    p: *mut WEBAUTHN_ASSERTION,
    api: &'a Api,
}
impl Drop for Assertion<'_> {
    fn drop(&mut self) {
        if !self.p.is_null() {
            unsafe {
                if (*self.p).dwVersion >= 3 {
                    wipe_secret((*self.p).pHmacSecret);
                }
                (self.api.free_get)(self.p);
            }
        }
    }
}

/// Cancellation watcher does not release the DLL/GUID until the synchronous API returns.
struct Dispatched {
    hr: i32,
    expired: bool,
}
fn watch_cancel(
    done: &AtomicBool,
    current: &(dyn Fn() -> bool + Sync),
    deadline: Instant,
    cancel: impl FnOnce(),
) {
    while !done.load(Ordering::Acquire) {
        if !current() || Instant::now() >= deadline {
            cancel();
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn dispatch(
    api: &Api,
    hwnd: usize,
    current: &(dyn Fn() -> bool + Sync),
    call: impl FnOnce(*mut GUID) -> i32,
) -> std::result::Result<Dispatched, Failure> {
    if !current() || unsafe { IsWindow(hwnd as *mut _) } == 0 {
        return Err(interrupted("prf-session-before-prompt"));
    }
    let mut guid = GUID::default();
    status(
        unsafe { (api.cancellation_id)(&mut guid) },
        "webauthn-cancellation-id",
    )?;
    let done = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_millis(TIMEOUT_MS as u64);
    let cancel_guid = guid;
    let result = std::thread::scope(|scope| {
        scope.spawn(|| {
            watch_cancel(&done, current, deadline, || unsafe {
                (api.cancel)(&cancel_guid);
            });
        });
        struct Complete<'a>(&'a AtomicBool);
        impl Drop for Complete<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let _complete = Complete(&done);
        call(&mut guid)
    });
    // Caller first retains any newly created credential for unconditional cleanup.
    Ok(Dispatched {
        hr: result,
        expired: Instant::now() >= deadline,
    })
}

struct Probe<'a> {
    rp: &'static str,
    user: Option<[u8; 32]>,
    api: Option<Api>,
    cap: Capability,
    route: Vec<u8>,
    credential: Option<Vec<u8>>,
    creation_without_id: bool,
    salt: Zeroizing<[u8; 32]>,
    changed: Zeroizing<[u8; 32]>,
    created: Option<Zeroizing<[u8; 32]>>,
    first: Option<Zeroizing<[u8; 32]>>,
    hwnd: usize,
    current: &'a (dyn Fn() -> bool + Sync),
    attestation: Option<super::AttestationObservation>,
}
impl Probe<'_> {
    fn client(&self, kind: &str) -> Vec<u8> {
        let mut challenge = Zeroizing::new([0u8; 32]);
        libsodium_rs::random::fill_bytes(challenge.as_mut_slice());
        serde_json::to_vec(&serde_json::json!({"type":kind,"challenge":URL_SAFE_NO_PAD.encode(challenge.as_slice()),"origin":format!("https://{}", self.rp),"crossOrigin":false})).unwrap()
    }
    fn create(&mut self, direct: bool) -> std::result::Result<(), Failure> {
        let api = self
            .api
            .as_ref()
            .ok_or_else(|| invalid("webauthn-not-loaded"))?;
        let rp_id = wide(self.rp);
        let rp_name = wide(if self.rp == "p01.anynote.desktop.invalid" {
            "PassKey Local vault unlock"
        } else if direct {
            "PassKey Local attestation test"
        } else {
            "PassKey Local PRF test"
        });
        let name = wide(&format!(
            "PassKey Local {} {}",
            if self.rp == "p01.anynote.desktop.invalid" {
                "vault"
            } else {
                "test"
            },
            uuid::Uuid::new_v4()
        ));
        let kind = wide("public-key");
        let hash = wide("SHA-256");
        let mut user_id = [0u8; 32];
        libsodium_rs::random::fill_bytes(&mut user_id);
        if let Some(id) = self.user {
            user_id = id;
        }
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: 1,
            pwszId: rp_id.as_ptr(),
            pwszName: rp_name.as_ptr(),
            ..Default::default()
        };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: 1,
            cbId: 32,
            pbId: user_id.as_mut_ptr(),
            pwszName: name.as_ptr(),
            pwszDisplayName: rp_name.as_ptr(),
            ..Default::default()
        };
        let mut param = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: 1,
            pwszCredentialType: kind.as_ptr(),
            lAlg: -7,
        };
        let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &mut param,
        };
        let mut json = self.client("webauthn.create");
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: 1,
            cbClientDataJSON: json.len() as u32,
            pbClientDataJSON: json.as_mut_ptr(),
            pwszHashAlgId: hash.as_ptr(),
        };
        let mut salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: 32,
            pbFirst: self.salt.as_mut_ptr(),
            ..Default::default()
        };
        let mut options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: 9,
            dwTimeoutMilliseconds: TIMEOUT_MS,
            dwAuthenticatorAttachment: 1,
            bRequireResidentKey: 1,
            dwUserVerificationRequirement: 1,
            dwAttestationConveyancePreference: if direct {
                WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT as u32
            } else {
                WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE as u32
            },
            bEnablePrf: 1,
            pPRFGlobalEval: &mut salt,
            cbAuthenticatorId: self.route.len() as u32,
            pbAuthenticatorId: self.route.as_mut_ptr(),
            ..Default::default()
        };
        let mut output = Created {
            p: ptr::null_mut(),
            api,
        };
        let dispatched = dispatch(api, self.hwnd, self.current, |guid| {
            options.pCancellationId = guid;
            unsafe {
                (api.make)(
                    self.hwnd as HWND,
                    &rp,
                    &user,
                    &params,
                    &client,
                    &options,
                    &mut output.p,
                )
            }
        })?;
        // Capture only the exact output of this creation call; never enumerate user credentials.
        if !output.p.is_null() {
            if let Ok(id) = unsafe {
                bytes(
                    (*output.p).pbCredentialId,
                    (*output.p).cbCredentialId,
                    MAX_ID,
                )
            } {
                self.credential = Some(id.to_vec());
            }
        }
        self.creation_without_id = dispatched.hr == 0 && self.credential.is_none();
        if !(self.current)() || dispatched.expired {
            return Err(interrupted("prf-session-after-create"));
        }
        status(dispatched.hr, "webauthn-prf-create")?;
        if output.p.is_null() {
            return Err(invalid("webauthn-create-null"));
        }
        if unsafe { (*output.p).dwVersion } < 8 {
            return Err(invalid("prf-create-version-support-or-transport"));
        }
        let o = unsafe { &*output.p };
        if o.bPrfEnabled == 0 || o.bResidentKey == 0 || o.dwUsedTransport != 16 {
            return Err(invalid("prf-create-version-support-or-transport"));
        }
        let id = self
            .credential
            .as_ref()
            .ok_or_else(|| invalid("prf-credential-id-missing"))?;
        auth_context_for(
            self.rp,
            unsafe { bytes(o.pbAuthenticatorData, o.cbAuthenticatorData, MAX_DATA) }?,
            Some(id),
        )?;
        if direct {
            // These are borrowed OS output buffers, valid only until Created frees
            // them. Record bounded sizes/known formats, never identity/cert bytes.
            unsafe { super::direct::observe_attestation(o, &mut self.attestation) }?;
        } else {
            self.created = Some(unsafe { prf_secret(o.pHmacSecret) }?);
        }
        Ok(())
    }
    fn assert(&mut self, changed: bool) -> std::result::Result<Zeroizing<[u8; 32]>, Failure> {
        let api = self
            .api
            .as_ref()
            .ok_or_else(|| invalid("webauthn-not-loaded"))?;
        let mut id = self
            .credential
            .as_ref()
            .ok_or_else(|| invalid("prf-credential-id-missing"))?
            .clone();
        let rp = wide(self.rp);
        let kind = wide("public-key");
        let hash = wide("SHA-256");
        let mut credential = WEBAUTHN_CREDENTIAL_EX {
            dwVersion: 1,
            cbId: id.len() as u32,
            pbId: id.as_mut_ptr(),
            pwszCredentialType: kind.as_ptr(),
            dwTransports: 16,
        };
        let mut entry = &mut credential as *mut _;
        let mut allow = WEBAUTHN_CREDENTIAL_LIST {
            cCredentials: 1,
            ppCredentials: &mut entry,
        };
        let mut salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: 32,
            pbFirst: if changed {
                self.changed.as_mut_ptr()
            } else {
                self.salt.as_mut_ptr()
            },
            ..Default::default()
        };
        let mut salts = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut salt,
            ..Default::default()
        };
        let mut json = self.client("webauthn.get");
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: 1,
            cbClientDataJSON: json.len() as u32,
            pbClientDataJSON: json.as_mut_ptr(),
            pwszHashAlgId: hash.as_ptr(),
        };
        let mut options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: 9,
            dwTimeoutMilliseconds: TIMEOUT_MS,
            dwAuthenticatorAttachment: 1,
            dwUserVerificationRequirement: 1,
            pAllowCredentialList: &mut allow,
            pHmacSecretSaltValues: &mut salts,
            cbAuthenticatorId: self.route.len() as u32,
            pbAuthenticatorId: self.route.as_mut_ptr(),
            ..Default::default()
        };
        let mut output = Assertion {
            p: ptr::null_mut(),
            api,
        };
        let dispatched = dispatch(api, self.hwnd, self.current, |guid| {
            options.pCancellationId = guid;
            unsafe {
                (api.get)(
                    self.hwnd as HWND,
                    rp.as_ptr(),
                    &client,
                    &options,
                    &mut output.p,
                )
            }
        })?;
        if !(self.current)() || dispatched.expired {
            return Err(interrupted("prf-session-after-assertion"));
        }
        status(
            dispatched.hr,
            if changed {
                "webauthn-prf-changed-input"
            } else {
                "webauthn-prf-assertion"
            },
        )?;
        if output.p.is_null() {
            return Err(invalid("webauthn-assertion-null"));
        }
        if unsafe { (*output.p).dwVersion } < 6 {
            return Err(invalid("prf-assertion-version-transport-or-credential"));
        }
        let o = unsafe { &*output.p };
        if o.dwUsedTransport != 16
            || unsafe { bytes(o.Credential.pbId, o.Credential.cbId, MAX_ID) }? != id
        {
            return Err(invalid("prf-assertion-version-transport-or-credential"));
        }
        auth_context_for(
            self.rp,
            unsafe { bytes(o.pbAuthenticatorData, o.cbAuthenticatorData, MAX_DATA) }?,
            None,
        )?;
        unsafe { prf_secret(o.pHmacSecret) }
    }
}

impl Provider for Probe<'_> {
    fn step(&mut self, step: &'static str) -> std::result::Result<(), Failure> {
        match step {
            "webauthn-load" => {
                self.cap.os_build = os_build();
                self.api = Some(Api::load()?);
                Ok(())
            }
            "webauthn-api" => {
                let version = unsafe { (self.api.as_ref().unwrap().version)() };
                self.cap.api_version = Some(version);
                if version < 9 {
                    Err(invalid("webauthn-api-9-required"))
                } else {
                    Ok(())
                }
            }
            "hello-platform" => {
                let mut available = 0;
                status(
                    unsafe { (self.api.as_ref().unwrap().available)(&mut available) },
                    "webauthn-platform-availability",
                )?;
                self.cap.platform_available = Some(available != 0);
                if available == 0 {
                    Err(invalid("webauthn-platform-unavailable"))
                } else {
                    Ok(())
                }
            }
            "hello-route" => {
                let api = self.api.as_ref().unwrap();
                let get: WebAuthNGetAuthenticatorList =
                    api.module.symbol(b"WebAuthNGetAuthenticatorList\0")?;
                let free: WebAuthNFreeAuthenticatorList =
                    api.module.symbol(b"WebAuthNFreeAuthenticatorList\0")?;
                let options = WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS { dwVersion: 1 };
                let mut list = ptr::null_mut();
                let hr = unsafe { get(&options, &mut list) };
                let selected = if hr == 0 {
                    unsafe { select(list, &mut self.cap) }
                } else {
                    Err(native(hr as u32, "webauthn-authenticator-list"))
                };
                if !list.is_null() {
                    unsafe {
                        free(list);
                    }
                }
                self.route = selected?;
                Ok(())
            }
            "prf-create" | "webauthn-direct-create" => {
                // Retry only an exact app-created pending credential before another creation.
                let mut pending = PENDING_DELETE
                    .lock()
                    .map_err(|_| invalid("prf-cleanup-lock"))?;
                if let Some(id) = pending.as_ref() {
                    status(
                        unsafe {
                            (self.api.as_ref().unwrap().delete)(id.len() as u32, id.as_ptr())
                        },
                        "delete-pending-prf-test",
                    )?;
                    *pending = None;
                }
                drop(pending);
                self.create(step == "webauthn-direct-create")
            }
            "prf-first" => {
                let key = self.assert(false)?;
                if !libsodium_rs::utils::memcmp(
                    key.as_slice(),
                    self.created
                        .as_ref()
                        .ok_or_else(|| invalid("prf-creation-secret-missing"))?
                        .as_slice(),
                ) {
                    return Err(invalid("prf-create-assertion-mismatch"));
                }
                self.created = None;
                self.first = Some(key);
                Ok(())
            }
            "prf-repeat" => {
                let key = self.assert(false)?;
                if !libsodium_rs::utils::memcmp(
                    key.as_slice(),
                    self.first.as_ref().unwrap().as_slice(),
                ) {
                    return Err(invalid("prf-repeat-mismatch"));
                }
                Ok(())
            }
            "prf-changed" => {
                let key = self.assert(true)?;
                if libsodium_rs::utils::memcmp(
                    key.as_slice(),
                    self.first.as_ref().unwrap().as_slice(),
                ) {
                    return Err(invalid("prf-changed-input-collision"));
                }
                Ok(())
            }
            "prf-roundtrip" => super::roundtrip(self.first.as_ref().unwrap()),
            _ => Err(invalid("prf-invalid-stage")),
        }
    }
    fn cleanup(&mut self) -> std::result::Result<(), Failure> {
        self.created = None;
        self.first = None;
        if self.creation_without_id {
            return Err(invalid("prf-cleanup-credential-id-unavailable"));
        }
        // A retry that stops at API/platform detection must still retry the
        // exact pending deletion; an early failure cannot hide a leftover key.
        let mut pending = PENDING_DELETE
            .lock()
            .map_err(|_| invalid("prf-cleanup-lock"))?;
        let Some(id) = self.credential.take().or_else(|| pending.take()) else {
            return Ok(());
        };
        let Some(api) = self.api.as_ref() else {
            *pending = Some(id);
            return Err(invalid("prf-cleanup-api-unavailable"));
        };
        let result = status(
            unsafe { (api.delete)(id.len() as u32, id.as_ptr()) },
            "delete-prf-test-passkey",
        );
        if result.is_err() {
            *pending = Some(id);
        }
        result
    }
    fn capability(&self) -> Capability {
        self.cap.clone()
    }
    fn attestation(&self) -> Option<super::AttestationObservation> {
        self.attestation.clone()
    }
}
impl Drop for Probe<'_> {
    fn drop(&mut self) {
        if self.credential.is_some() {
            let _ = self.cleanup();
        }
    }
}

pub fn run(
    hwnd: usize,
    current: impl Fn() -> bool + Sync,
    experiment: Experiment,
) -> Result<Report> {
    let _attempt = crate::hello::Attempt::begin()?;
    libsodium_rs::ensure_init().map_err(|_| Error::new("UNAVAILABLE"))?;
    let mut salt = Zeroizing::new([0u8; 32]);
    let mut changed = Zeroizing::new([0u8; 32]);
    libsodium_rs::random::fill_bytes(salt.as_mut_slice());
    libsodium_rs::random::fill_bytes(changed.as_mut_slice());
    let mut p = Probe {
        rp: RP,
        user: None,
        api: None,
        cap: Capability {
            routing: "display-name-candidate",
            tpm_binding: "not-verified",
            ..Default::default()
        },
        route: Vec::new(),
        credential: None,
        creation_without_id: false,
        salt,
        changed,
        created: None,
        first: None,
        hwnd,
        current: &current,
        attestation: None,
    };
    Ok(exercise(&mut p, &current, experiment))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_system_loader_reports_version_and_refuses_missing_exports() {
        let api = Api::load().unwrap();
        let version = unsafe { (api.version)() };
        assert!(version > 0);
        assert!(api
            .module
            .symbol::<WebAuthNGetApiVersionNumber>(b"PassKeyLocalMissingExport\0")
            .is_err());
        assert!(os_build().is_some());
    }
    #[test]
    fn native_dispatch_never_prompts_after_session_invalidation() {
        let api = Api::load().unwrap();
        assert!(dispatch(&api, 0, &|| false, |_| panic!("must not prompt")).is_err());
    }
    #[test]
    fn cancellation_watcher_refuses_invalidated_and_expired_requests_once() {
        use std::sync::atomic::AtomicUsize;
        for expired in [false, true] {
            let count = AtomicUsize::new(0);
            watch_cancel(
                &AtomicBool::new(false),
                &|| expired,
                if expired {
                    Instant::now()
                } else {
                    Instant::now() + Duration::from_secs(10)
                },
                || {
                    count.fetch_add(1, Ordering::AcqRel);
                },
            );
            assert_eq!(count.load(Ordering::Acquire), 1);
        }
        watch_cancel(&AtomicBool::new(true), &|| false, Instant::now(), || {
            panic!("completed request must not cancel")
        });
        let valid = AtomicBool::new(true);
        let done = AtomicBool::new(false);
        let count = AtomicUsize::new(0);
        std::thread::scope(|s| {
            s.spawn(|| {
                watch_cancel(
                    &done,
                    &|| valid.load(Ordering::Acquire),
                    Instant::now() + Duration::from_secs(10),
                    || {
                        count.fetch_add(1, Ordering::AcqRel);
                    },
                )
            });
            valid.store(false, Ordering::Release);
        });
        assert_eq!(count.load(Ordering::Acquire), 1);
    }
    #[test]
    fn prf_output_is_bounded_and_wiped_including_invalid_size() {
        let mut first = [7u8; 32];
        let mut second = [8u8; 32];
        let mut salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: 32,
            pbFirst: first.as_mut_ptr(),
            ..Default::default()
        };
        assert_eq!(
            unsafe { prf_secret(&mut salt) }.unwrap().as_slice(),
            &[7; 32]
        );
        for n in [0, 31, 33, u32::MAX] {
            salt.cbFirst = n;
            assert!(unsafe { prf_secret(&mut salt) }.is_err());
        }
        salt.cbFirst = 32;
        salt.cbSecond = 32;
        salt.pbSecond = second.as_mut_ptr();
        assert!(unsafe { prf_secret(&mut salt) }.is_err());
        unsafe {
            wipe_secret(&mut salt);
        }
        assert_eq!(first, [0; 32]);
        assert_eq!(second, [0; 32]);
        assert!(unsafe { prf_secret(ptr::null_mut()) }.is_err());
        salt.pbFirst = ptr::null_mut();
        assert!(unsafe { prf_secret(&mut salt) }.is_err());
    }
    #[test]
    fn routing_rejects_ambiguous_and_locked_candidates_without_a_trust_claim() {
        let name = wide("Windows Hello");
        let mut id = [1u8; 16];
        let mut other_id = [2u8; 16];
        let mut entry = WEBAUTHN_AUTHENTICATOR_DETAILS {
            dwVersion: 1,
            cbAuthenticatorId: 16,
            pbAuthenticatorId: id.as_mut_ptr(),
            pwszAuthenticatorName: name.as_ptr(),
            ..Default::default()
        };
        let mut other = WEBAUTHN_AUTHENTICATOR_DETAILS {
            pbAuthenticatorId: other_id.as_mut_ptr(),
            ..entry
        };
        let mut entries = [&mut entry as *mut _, &mut other as *mut _];
        let mut list = WEBAUTHN_AUTHENTICATOR_DETAILS_LIST {
            cAuthenticatorDetails: 1,
            ppAuthenticatorDetails: entries.as_mut_ptr(),
        };
        let mut cap = Capability {
            routing: "display-name-candidate",
            tpm_binding: "not-verified",
            ..Default::default()
        };
        assert_eq!(unsafe { select(&list, &mut cap) }.unwrap(), id);
        assert_eq!(cap.tpm_binding, "not-verified");
        list.cAuthenticatorDetails = 2;
        assert!(unsafe { select(&list, &mut cap) }.is_err());
        assert_eq!(cap.hello_candidates, Some(2));
        list.cAuthenticatorDetails = 1;
        entry.bLocked = 1;
        assert!(unsafe { select(&list, &mut cap) }.is_err());
        assert_eq!(cap.hello_locked, Some(true));
        list.cAuthenticatorDetails = 33;
        assert!(unsafe { select(&list, &mut cap) }.is_err());
    }
    #[test]
    fn original_native_errors_cannot_be_reclassified_as_cancellation_or_success() {
        for code in [0x80090027, 0x8009000a, 0x80090029, 0x8009000b] {
            let e = native(code, "webauthn-prf-assertion");
            assert_eq!(e.code, Some(code));
            assert_eq!(e.status, Outcome::Failed);
            assert_eq!(e.operation, Some("webauthn-prf-assertion"));
        }
        for code in [0x800704c7, 0x80090036] {
            assert_eq!(
                native(code, "webauthn-prf-assertion").status,
                Outcome::Cancelled
            );
        }
    }
}
