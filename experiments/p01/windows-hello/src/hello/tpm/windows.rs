//! App-owned Platform KSP key only. No Passport/AIK/EK/owner-auth access.
use super::{
    exercise, pcp_policy_matches, policy_matches, Experiment, Metadata, Provider, Report,
    PCP_ENCRYPTION_KIND, PCP_TPM12_PROVIDER_FLAG, PCP_USAGE_KIND_MASK,
};
use crate::{
    hello::{
        prf::{interrupted, invalid},
        proof::{self, ExportCheck, Failure, Outcome},
    },
    storage::{Error, Result},
};
use ::windows::Win32::{
    Foundation::{NTE_BAD_KEYSET, NTE_USER_CANCELLED},
    Security::{Cryptography::*, OBJECT_SECURITY_INFORMATION},
};
use std::sync::Mutex;
use windows_core::PCWSTR;
use windows_sys::Win32::{
    Foundation::{FreeLibrary, GetLastError},
    System::{
        LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32},
        TpmBaseServices::{TPM_DEVICE_INFO, TPM_VERSION_20},
    },
};
use zeroize::Zeroizing;

pub(crate) mod combined;
mod read_public;

// Keep the portable decoder tied to the maintained Microsoft SDK constants.
const _: () = assert!(PCP_ENCRYPTION_KIND == NCRYPT_PCP_ENCRYPTION_KEY);
const _: () = assert!(PCP_TPM12_PROVIDER_FLAG == NCRYPT_TPM12_PROVIDER);

fn device_info() -> std::result::Result<TPM_DEVICE_INFO, Failure> {
    struct Module(*mut std::ffi::c_void);
    impl Drop for Module {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.0);
            }
        }
    }
    let module = unsafe {
        LoadLibraryExW(
            windows_sys::core::w!("tbs.dll"),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    let native = |code, operation| Failure {
        status: Outcome::Failed,
        code: Some(code),
        operation: Some(operation),
    };
    if module.is_null() {
        return Err(native(unsafe { GetLastError() }, "tpm-load-system-tbs"));
    }
    let module = Module(module);
    let address = unsafe { GetProcAddress(module.0, c"Tbsi_GetDeviceInfo".as_ptr().cast()) }
        .ok_or_else(|| native(unsafe { GetLastError() }, "tpm-resolve-device-info"))?;
    // Exact SDK function signature, using the maintained SDK device structure.
    let get: unsafe extern "system" fn(u32, *mut std::ffi::c_void) -> u32 =
        unsafe { std::mem::transmute(address) };
    let mut info = TPM_DEVICE_INFO::default();
    let status = unsafe {
        get(
            std::mem::size_of::<TPM_DEVICE_INFO>() as u32,
            (&mut info as *mut TPM_DEVICE_INFO).cast(),
        )
    };
    if status != 0 {
        return Err(native(status, "tpm-get-device-info"));
    }
    if info.structVersion != 1 {
        return Err(invalid("tpm-device-info-version"));
    }
    Ok(info)
}

fn hardware_device(info: &TPM_DEVICE_INFO) -> bool {
    info.structVersion == 1
        && info.tpmVersion == TPM_VERSION_20
        && matches!(info.tpmInterfaceType, 1..=3 | 5)
}

static PENDING_DELETE: Mutex<Option<Vec<u16>>> = Mutex::new(None);

struct Handle(usize);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(self.0));
            }
        }
    }
}
fn failed(e: windows_core::Error, operation: &'static str) -> Failure {
    Failure {
        status: if e.code() == NTE_USER_CANCELLED {
            Outcome::Cancelled
        } else {
            Outcome::Failed
        },
        code: Some(e.code().0 as u32),
        operation: Some(operation),
    }
}
fn number(
    handle: usize,
    property: PCWSTR,
    operation: &'static str,
) -> std::result::Result<u32, Failure> {
    let mut data = [0u8; 4];
    let mut length = 0;
    unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(handle),
            property,
            Some(&mut data),
            &mut length,
            OBJECT_SECURITY_INFORMATION(NCRYPT_SILENT_FLAG.0),
        )
    }
    .map_err(|e| failed(e, operation))?;
    if length != 4 {
        return Err(invalid("tpm-property-dword-length"));
    }
    Ok(u32::from_le_bytes(data))
}
fn set(
    handle: usize,
    property: PCWSTR,
    value: u32,
    operation: &'static str,
) -> std::result::Result<(), Failure> {
    unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(handle),
            property,
            &value.to_le_bytes(),
            NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|e| failed(e, operation))
}
fn open(provider: usize, name: &[u16]) -> std::result::Result<Handle, Failure> {
    let mut key = NCRYPT_KEY_HANDLE(0);
    unsafe {
        NCryptOpenKey(
            NCRYPT_PROV_HANDLE(provider),
            &mut key,
            PCWSTR(name.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|e| failed(e, "tpm-reopen-exact-test-key"))?;
    Ok(Handle(key.0))
}
fn delete_pending(provider: usize) -> std::result::Result<(), Failure> {
    let mut pending = PENDING_DELETE
        .lock()
        .map_err(|_| invalid("tpm-cleanup-lock"))?;
    if let Some(name) = pending.as_ref() {
        match open(provider, name) {
            Ok(mut key) => {
                // Platform KSP rejects SILENT on deletion (NTE_BAD_FLAGS).
                // Documented flags zero, only the exact app-owned synthetic key.
                unsafe { NCryptDeleteKey(NCRYPT_KEY_HANDLE(key.0), 0) }
                    .map_err(|e| failed(e, "tpm-delete-pending-key"))?;
                key.0 = 0;
            }
            Err(e) if e.code == Some(NTE_BAD_KEYSET.0 as u32) => {}
            Err(e) => return Err(e),
        }
        *pending = None;
    }
    Ok(())
}
struct Probe<'a> {
    key: Handle,
    provider: Handle,
    name: Vec<u16>,
    metadata: Metadata,
    secret: Zeroizing<[u8; 32]>,
    ciphertext: Vec<u8>,
    exports: Vec<ExportCheck>,
    current: &'a dyn Fn() -> bool,
    synthetic: bool,
    local_public: Vec<u8>,
    local_name: Vec<u8>,
}
impl Probe<'_> {
    fn policy(&self, key: usize) -> std::result::Result<(), Failure> {
        let export = number(key, NCRYPT_EXPORT_POLICY_PROPERTY, "tpm-read-export-policy")?;
        let usage = number(key, NCRYPT_KEY_USAGE_PROPERTY, "tpm-read-key-usage")?;
        let length = number(key, NCRYPT_LENGTH_PROPERTY, "tpm-read-key-length")?;
        policy_matches(export, usage, length)
    }
    fn readback(&mut self) -> std::result::Result<(), Failure> {
        // Keep actual bounded observations even when a later comparison fails.
        self.metadata.export_policy = Some(number(
            self.key.0,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            "tpm-read-export-policy",
        )?);
        self.metadata.key_usage = Some(number(
            self.key.0,
            NCRYPT_KEY_USAGE_PROPERTY,
            "tpm-read-key-usage",
        )?);
        self.metadata.key_length_bits = Some(number(
            self.key.0,
            NCRYPT_LENGTH_PROPERTY,
            "tpm-read-key-length",
        )?);
        let pcp_usage = number(
            self.key.0,
            NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
            "tpm-read-pcp-key-usage",
        )?;
        self.metadata.pcp_key_usage = Some(pcp_usage);
        self.metadata.pcp_usage_kind = Some(pcp_usage & PCP_USAGE_KIND_MASK);
        self.metadata.pcp_usage_flags = Some(pcp_usage & !PCP_USAGE_KIND_MASK);
        policy_matches(
            self.metadata.export_policy.unwrap(),
            self.metadata.key_usage.unwrap(),
            self.metadata.key_length_bits.unwrap(),
        )?;
        pcp_policy_matches(pcp_usage)?;
        Ok(())
    }
    fn decrypt(
        &self,
        key: usize,
        input: &[u8],
        hash: PCWSTR,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, Failure> {
        if !(self.current)() {
            return Err(interrupted("tpm-session-changed-before-decrypt"));
        }
        let padding = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: hash,
            ..Default::default()
        };
        let mut output = Zeroizing::new(vec![0u8; 256]);
        let mut actual = 0;
        let result = unsafe {
            NCryptDecrypt(
                NCRYPT_KEY_HANDLE(key),
                Some(input),
                Some((&padding as *const BCRYPT_OAEP_PADDING_INFO).cast()),
                Some(output.as_mut_slice()),
                &mut actual,
                NCRYPT_FLAGS(NCRYPT_PAD_OAEP_FLAG.0 | NCRYPT_SILENT_FLAG.0),
            )
        };
        if !(self.current)() {
            return Err(interrupted("tpm-session-changed-after-decrypt"));
        }
        result.map_err(|e| failed(e, "tpm-silent-oaep-decrypt"))?;
        if actual as usize > output.len() {
            return Err(invalid("tpm-decrypt-output-length"));
        }
        output.truncate(actual as usize);
        Ok(output)
    }
    fn unwrap(&self, key: usize) -> std::result::Result<(), Failure> {
        self.policy(key)?;
        let secret = self.decrypt(key, &self.ciphertext, BCRYPT_SHA256_ALGORITHM)?;
        if secret.len() != 32 || !libsodium_rs::utils::memcmp(&secret, self.secret.as_slice()) {
            return Err(invalid("tpm-secret-mismatch"));
        }
        Ok(())
    }
    fn exports(&mut self) -> std::result::Result<(), Failure> {
        let (observations, result) = proof::measure_exports(self.current, |format| {
            let kind = match format {
                "rsa-private" => BCRYPT_RSAPRIVATE_BLOB,
                "rsa-full-private" => BCRYPT_RSAFULLPRIVATE_BLOB,
                "pkcs8-private" => NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                _ => unreachable!(),
            };
            let mut output = Zeroizing::new([0u8; 16_384]);
            let mut actual = 0;
            unsafe {
                NCryptExportKey(
                    NCRYPT_KEY_HANDLE(self.key.0),
                    None,
                    kind,
                    None,
                    Some(output.as_mut_slice()),
                    &mut actual,
                    NCRYPT_SILENT_FLAG,
                )
            }
            .map_err(|e| failed(e, "tpm-private-export"))
        });
        self.exports = observations;
        result
    }
}
impl Provider for Probe<'_> {
    fn step(&mut self, step: &'static str) -> std::result::Result<(), Failure> {
        match step {
            "tpm-provider-open" => {
                let mut provider = NCRYPT_PROV_HANDLE(0);
                unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) }
                    .map_err(|e| failed(e, "open-platform-crypto-provider"))?;
                self.provider = Handle(provider.0);
                if self.synthetic {
                    delete_pending(self.provider.0)?;
                }
            }
            "tpm-provider-properties" => {
                let flags = number(
                    self.provider.0,
                    NCRYPT_IMPL_TYPE_PROPERTY,
                    "tpm-provider-implementation",
                )?;
                self.metadata.implementation_flags = Some(flags);
                if flags & NCRYPT_IMPL_HARDWARE_FLAG == 0 || flags & NCRYPT_IMPL_SOFTWARE_FLAG != 0
                {
                    return Err(invalid("tpm-hardware-provider-required"));
                }
                let info = device_info()?;
                self.metadata.tpm_version = Some(info.tpmVersion);
                self.metadata.interface_type = Some(info.tpmInterfaceType);
                if !hardware_device(&info) {
                    return Err(invalid("tpm-version-two-required"));
                }
            }
            "tpm-key-create" => {
                if self.synthetic
                    && PENDING_DELETE
                        .lock()
                        .map_err(|_| invalid("tpm-cleanup-lock"))?
                        .is_some()
                {
                    return Err(invalid("tpm-pending-key-delete-required"));
                }
                let mut key = NCRYPT_KEY_HANDLE(0);
                unsafe {
                    NCryptCreatePersistedKey(
                        NCRYPT_PROV_HANDLE(self.provider.0),
                        &mut key,
                        NCRYPT_RSA_ALGORITHM,
                        PCWSTR(self.name.as_ptr()),
                        CERT_KEY_SPEC(0),
                        // Documented per-user initialization flags; no key is
                        // generated until the separate silent FinalizeKey call.
                        NCRYPT_FLAGS(0),
                    )
                }
                .map_err(|e| failed(e, "tpm-create-app-test-key"))?;
                self.key = Handle(key.0);
                if self.synthetic {
                    *PENDING_DELETE
                        .lock()
                        .map_err(|_| invalid("tpm-cleanup-lock"))? = Some(self.name.clone());
                }
            }
            "tpm-key-policy" => {
                set(
                    self.key.0,
                    NCRYPT_LENGTH_PROPERTY,
                    2048,
                    "tpm-set-key-length",
                )?;
                set(
                    self.key.0,
                    NCRYPT_KEY_USAGE_PROPERTY,
                    NCRYPT_ALLOW_DECRYPT_FLAG,
                    "tpm-set-decrypt-only",
                )?;
                // PCP_ENCRYPTION_KEY (2) is decrypt-only in the PCP namespace;
                // common CNG ALLOW_DECRYPT (1) has a different numbering scheme.
                set(
                    self.key.0,
                    NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                    NCRYPT_PCP_ENCRYPTION_KEY,
                    "tpm-set-pcp-decrypt-only",
                )?;
                set(
                    self.key.0,
                    NCRYPT_EXPORT_POLICY_PROPERTY,
                    0,
                    "tpm-disallow-export",
                )?;
                unsafe { NCryptFinalizeKey(NCRYPT_KEY_HANDLE(self.key.0), NCRYPT_SILENT_FLAG) }
                    .map_err(|e| failed(e, "tpm-finalize-test-key"))?;
            }
            "tpm-key-readback" => {
                self.readback()?;
                let mut name = [0u8; 1024];
                let mut actual = 0;
                unsafe {
                    NCryptGetProperty(
                        NCRYPT_HANDLE(self.key.0),
                        NCRYPT_PCP_TPM2BNAME_PROPERTY,
                        Some(&mut name),
                        &mut actual,
                        OBJECT_SECURITY_INFORMATION(NCRYPT_SILENT_FLAG.0),
                    )
                }
                .map_err(|e| failed(e, "tpm-read-key-object-name"))?;
                if actual == 0 || actual as usize > name.len() {
                    return Err(invalid("tpm-key-object-name-length"));
                }
                // Only a length observation, never a trusted attestation or parsed claim.
                self.metadata.key_name_bytes = Some(actual);
            }
            "tpm-read-public" => {
                let (public, name, attributes) = read_public::measure(self.provider.0, self.key.0)?;
                self.local_public = public;
                self.local_name = name;
                self.metadata.object_attributes = Some(attributes);
            }
            "tpm-reopen-read-public" => {
                self.readback()?;
                let (public, name, attributes) = read_public::measure(self.provider.0, self.key.0)?;
                if public != self.local_public
                    || name != self.local_name
                    || Some(attributes) != self.metadata.object_attributes
                {
                    return Err(invalid("tpm-reopened-key-binding-mismatch"));
                }
            }
            "tpm-public-wrap" => {
                self.ciphertext =
                    proof::windows::wrap_oaep_public(NCRYPT_KEY_HANDLE(self.key.0), &self.secret)?;
            }
            "tpm-unwrap-first" => self.unwrap(self.key.0)?,
            "tpm-reopen-unwrap" => {
                // Dispose the original key AND provider before reopening. Still the same process.
                self.key = Handle(0);
                self.provider = Handle(0);
                let mut provider = NCRYPT_PROV_HANDLE(0);
                unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) }
                    .map_err(|e| failed(e, "tpm-reopen-provider"))?;
                self.provider = Handle(provider.0);
                self.key = open(self.provider.0, &self.name)?;
                self.readback()?;
                self.unwrap(self.key.0)?;
            }
            "tpm-negative-controls" => {
                // Each negative is bracketed by a successful decrypt to exclude provider failure.
                for wrong_hash in [false, true] {
                    self.unwrap(self.key.0)?;
                    let mut changed = self.ciphertext.clone();
                    if !wrong_hash {
                        changed[0] ^= 1;
                    }
                    match self.decrypt(
                        self.key.0,
                        &changed,
                        if wrong_hash {
                            BCRYPT_SHA1_ALGORITHM
                        } else {
                            BCRYPT_SHA256_ALGORITHM
                        },
                    ) {
                        Ok(_) => return Err(invalid("tpm-invalid-ciphertext-accepted")),
                        Err(e)
                            if e.status == Outcome::Interrupted
                                || e.status == Outcome::Cancelled =>
                        {
                            return Err(e)
                        }
                        Err(_) => {}
                    }
                    self.unwrap(self.key.0)?;
                }
            }
            "private-export" => self.exports()?,
            _ => return Err(invalid("tpm-unknown-fixed-stage")),
        }
        Ok(())
    }
    fn cleanup(&mut self) -> std::result::Result<(), Failure> {
        // Cleanup is unconditional, independent of session invalidation.
        if self.key.0 != 0 {
            // Deletion is a separate lifecycle operation, not a decrypt fallback.
            unsafe { NCryptDeleteKey(NCRYPT_KEY_HANDLE(self.key.0), 0) }
                .map_err(|e| failed(e, "tpm-delete-test-key"))?;
            self.key.0 = 0;
            *PENDING_DELETE
                .lock()
                .map_err(|_| invalid("tpm-cleanup-lock"))? = None;
        } else if self.provider.0 != 0 {
            delete_pending(self.provider.0)?;
        } else if PENDING_DELETE
            .lock()
            .map_err(|_| invalid("tpm-cleanup-lock"))?
            .is_some()
        {
            let mut provider = NCRYPT_PROV_HANDLE(0);
            unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) }
                .map_err(|e| failed(e, "tpm-cleanup-provider-open"))?;
            self.provider = Handle(provider.0);
            delete_pending(self.provider.0)?;
        }
        Ok(())
    }
    fn metadata(&self) -> Metadata {
        self.metadata.clone()
    }
    fn exports(&self) -> Vec<ExportCheck> {
        self.exports.clone()
    }
}
pub fn run(current: impl Fn() -> bool, experiment: Experiment) -> Result<Report> {
    let _attempt = crate::hello::Attempt::begin()?;
    if !current() {
        return Err(Error::new("STALE"));
    }
    let name: Vec<u16> = format!("PassKeyLocal.TpmInnerTest.{}", uuid::Uuid::new_v4())
        .encode_utf16()
        .chain([0])
        .collect();
    let mut secret = Zeroizing::new([0u8; 32]);
    libsodium_rs::random::fill_bytes(secret.as_mut_slice());
    let mut probe = Probe {
        key: Handle(0),
        provider: Handle(0),
        name,
        metadata: Metadata::default(),
        secret,
        ciphertext: vec![],
        exports: vec![],
        current: &current,
        synthetic: experiment != Experiment::Capability,
        local_public: vec![],
        local_name: vec![],
    };
    Ok(exercise(&mut probe, &current, experiment))
}

#[cfg(test)]
mod tests {
    use super::*;
    static SOFTWARE_CONTROLS: Mutex<()> = Mutex::new(());
    #[test]
    fn emulator_unknown_version_and_unknown_interface_are_not_hardware_candidates() {
        let mut info = TPM_DEVICE_INFO {
            structVersion: 1,
            tpmVersion: TPM_VERSION_20,
            tpmInterfaceType: 3,
            tpmImpRevision: 0,
        };
        for interface in [1, 2, 3, 5] {
            info.tpmInterfaceType = interface;
            assert!(hardware_device(&info));
        }
        for interface in [0, 4, 6, u32::MAX] {
            info.tpmInterfaceType = interface;
            assert!(!hardware_device(&info));
        }
        info.tpmInterfaceType = 3;
        info.tpmVersion = 1;
        assert!(!hardware_device(&info));
        info.tpmVersion = TPM_VERSION_20;
        info.structVersion = 2;
        assert!(!hardware_device(&info));
    }
    fn software_probe() -> Probe<'static> {
        let mut provider = NCRYPT_PROV_HANDLE(0);
        unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) }.unwrap();
        let name: Vec<u16> = format!("PassKeyLocal.SoftwareTpmControl.{}", uuid::Uuid::new_v4())
            .encode_utf16()
            .chain([0])
            .collect();
        let mut secret = Zeroizing::new([0u8; 32]);
        libsodium_rs::random::fill_bytes(secret.as_mut_slice());
        Probe {
            key: Handle(0),
            provider: Handle(provider.0),
            name,
            metadata: Metadata::default(),
            secret,
            ciphertext: vec![],
            exports: vec![],
            current: &|| true,
            synthetic: true,
            local_public: vec![],
            local_name: vec![],
        }
    }
    fn prepare_software_control(p: &mut Probe<'_>) -> std::result::Result<(), Failure> {
        // Software KSP has no PCP usage property. Explicit test-only preparation;
        // production always requests and verifies PCP_ENCRYPTION_KEY.
        p.step("tpm-key-create")?;
        set(
            p.key.0,
            NCRYPT_LENGTH_PROPERTY,
            2048,
            "software-control-length",
        )?;
        set(
            p.key.0,
            NCRYPT_KEY_USAGE_PROPERTY,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            "software-control-decrypt-only",
        )?;
        set(
            p.key.0,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            0,
            "software-control-export-policy",
        )?;
        unsafe { NCryptFinalizeKey(NCRYPT_KEY_HANDLE(p.key.0), NCRYPT_SILENT_FLAG) }
            .map_err(|e| failed(e, "software-control-finalize"))
    }
    #[test]
    fn software_provider_cannot_satisfy_the_hardware_preflight() {
        let mut p = software_probe();
        let e = p.step("tpm-provider-properties").unwrap_err();
        assert_eq!(e.operation, Some("tpm-hardware-provider-required"));
        assert_eq!(p.key.0, 0);
    }
    #[test]
    fn readback_retains_observed_properties_when_pcp_usage_is_unsupported() {
        let _control = SOFTWARE_CONTROLS.lock().unwrap();
        let mut p = software_probe();
        let result = (|| {
            prepare_software_control(&mut p)?;
            let error = p.readback().unwrap_err();
            assert_eq!(error.operation, Some("tpm-read-pcp-key-usage"));
            assert_eq!(p.metadata.export_policy, Some(0));
            assert_eq!(p.metadata.key_usage, Some(NCRYPT_ALLOW_DECRYPT_FLAG));
            assert_eq!(p.metadata.key_length_bits, Some(2048));
            assert_eq!(p.metadata.pcp_key_usage, None);
            Ok::<_, Failure>(())
        })();
        p.cleanup().unwrap();
        assert_eq!(p.key.0, 0);
        assert!(PENDING_DELETE.lock().unwrap().is_none());
        result.unwrap();
    }
    #[test]
    fn software_control_exercises_actual_wrap_unwrap_negative_controls_and_export_policy() {
        let _control = SOFTWARE_CONTROLS.lock().unwrap();
        // This oracle checks native crypto plumbing. It cannot select a software
        // provider in the installed command or supply physical TPM evidence.
        let mut p = software_probe();
        let result = (|| {
            prepare_software_control(&mut p)?;
            p.policy(p.key.0)?;
            p.step("tpm-public-wrap")?;
            p.step("tpm-unwrap-first")?;
            p.step("tpm-negative-controls")?;
            let reopened = open(p.provider.0, &p.name)?;
            p.unwrap(reopened.0)?;
            let observation = p.step("private-export");
            assert_eq!(p.exports.len(), 3);
            // Software KSP may reject the operation with NTE_NOT_SUPPORTED;
            // that is not explicit permission denial and must fail the stage.
            assert!(p.exports.iter().all(|e| {
                e.result == "refused"
                    || (e.result == "failed" && e.native_code.as_deref() == Some("0x80090029"))
                    || (e.result == "unsupported-format"
                        && e.native_code.as_deref() == Some("0x8009000A"))
            }));
            assert_eq!(
                observation.is_ok(),
                p.exports.iter().all(|e| e.result == "refused")
            );
            p.current = &|| false;
            let e = p.unwrap(p.key.0).unwrap_err();
            assert_eq!(e.status, Outcome::Interrupted);
            Ok::<_, Failure>(())
        })();
        let cleanup = p.cleanup();
        cleanup.unwrap();
        result.unwrap();
    }

    #[test]
    fn software_exportable_impostor_fails_the_export_denial_stage() {
        let _control = SOFTWARE_CONTROLS.lock().unwrap();
        // Explicitly exportable synthetic software key, selected only by cfg(test).
        let mut p = software_probe();
        let result = (|| {
            p.step("tpm-key-create")?;
            set(
                p.key.0,
                NCRYPT_LENGTH_PROPERTY,
                2048,
                "software-control-length",
            )?;
            set(
                p.key.0,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG,
                "software-control-exportable",
            )?;
            unsafe { NCryptFinalizeKey(NCRYPT_KEY_HANDLE(p.key.0), NCRYPT_SILENT_FLAG) }
                .map_err(|e| failed(e, "software-control-finalize"))?;
            let e = p.step("private-export").unwrap_err();
            assert_eq!(e.status, Outcome::Failed);
            assert_eq!(e.code, None);
            assert!(p.exports.iter().any(|e| e.result == "unexpected-success"));
            Ok::<_, Failure>(())
        })();
        let cleanup = p.cleanup();
        cleanup.unwrap();
        result.unwrap();
    }
    #[test]
    fn software_key_cannot_supply_the_provider_owned_tbs_context() {
        let _guard = SOFTWARE_CONTROLS.lock().unwrap();
        let mut p = software_probe();
        prepare_software_control(&mut p).unwrap();
        let result = read_public::measure(p.provider.0, p.key.0);
        p.cleanup().unwrap();
        assert_eq!(
            result.unwrap_err().operation,
            Some("tpm-read-public-provider-context")
        );
    }
}
