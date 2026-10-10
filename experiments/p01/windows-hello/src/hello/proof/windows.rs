//! Microsoft Passport CNG capability experiment using maintained SDK bindings.
//! No OS/account Hello keys are opened, enumerated or changed.
use super::{
    exercise, exercise_selected, AttestationClaim, Experiment, ExportCheck, Failure, Outcome,
    Provider, Report, Stage,
};
use crate::storage::{Error, Result};
use ::windows::Win32::{
    Foundation::{NTE_BAD_KEYSET, NTE_SILENT_CONTEXT, NTE_USER_CANCELLED},
    Security::Cryptography::*,
};
use std::sync::Mutex;
use windows_core::{w, PCWSTR};
use zeroize::Zeroizing;

// Provider-specific property used by existing Passport CNG clients. It is not
// present in the current public ncrypt.h. It must set AND read back; no alias,
// guessed fallback or supported-policy claim when the provider rejects it.
const CACHE_TYPE: PCWSTR = w!("NgcCacheType");
static PENDING_DELETE: Mutex<Option<Vec<u16>>> = Mutex::new(None);

/// Selected only by the fixed native experiment, never by IPC arguments.
/// The primary proof and authorized OAEP action always retain OAEP/SHA-256.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RsaPadding {
    OaepSha256,
    Pkcs1Compatibility,
}
impl RsaPadding {
    fn for_experiment(experiment: Experiment) -> Self {
        match experiment {
            Experiment::Pkcs1Compatibility | Experiment::Pkcs1Behavior => Self::Pkcs1Compatibility,
            _ => Self::OaepSha256,
        }
    }
    fn info(self) -> Option<BCRYPT_OAEP_PADDING_INFO> {
        match self {
            Self::OaepSha256 => Some(BCRYPT_OAEP_PADDING_INFO {
                pszAlgId: BCRYPT_SHA256_ALGORITHM,
                ..Default::default()
            }),
            Self::Pkcs1Compatibility => None,
        }
    }
    fn encrypt_flags(self) -> BCRYPT_FLAGS {
        match self {
            Self::OaepSha256 => BCRYPT_PAD_OAEP,
            Self::Pkcs1Compatibility => BCRYPT_PAD_PKCS1,
        }
    }
    fn decrypt_flags(self) -> NCRYPT_FLAGS {
        match self {
            Self::OaepSha256 => NCRYPT_PAD_OAEP_FLAG,
            Self::Pkcs1Compatibility => NCRYPT_PAD_PKCS1_FLAG,
        }
    }
    fn encrypt_operation(self) -> &'static str {
        match self {
            Self::OaepSha256 => "public-oaep-sha256-encrypt",
            Self::Pkcs1Compatibility => "public-pkcs1-v1_5-encrypt",
        }
    }
    fn decrypt_operation(self) -> &'static str {
        match self {
            Self::OaepSha256 => "authorized-oaep-sha256-decrypt",
            Self::Pkcs1Compatibility => "authorized-pkcs1-v1_5-decrypt",
        }
    }
}

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
struct PublicAlgorithm(BCRYPT_ALG_HANDLE);
impl Drop for PublicAlgorithm {
    fn drop(&mut self) {
        unsafe {
            let _ = BCryptCloseAlgorithmProvider(self.0, 0);
        }
    }
}
struct PublicKey(BCRYPT_KEY_HANDLE);
impl Drop for PublicKey {
    fn drop(&mut self) {
        unsafe {
            let _ = BCryptDestroyKey(self.0);
        }
    }
}

fn open_test_key(
    provider: NCRYPT_PROV_HANDLE,
    name: PCWSTR,
) -> std::result::Result<Handle, Failure> {
    let mut key = NCRYPT_KEY_HANDLE(0);
    unsafe {
        NCryptOpenKey(
            provider,
            &mut key,
            name,
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|e| failed(e).at("decrypt-key-open-silent"))?;
    Ok(Handle(key.0))
}

enum PrivateKey<'a> {
    Authorized(&'a Handle),
    Silent(Handle),
}
impl PrivateKey<'_> {
    fn handle(&self) -> &Handle {
        match self {
            Self::Authorized(key) => key,
            Self::Silent(key) => key,
        }
    }
}
/// Authorized operations use the flags-zero creation handle, whose parent
/// HWND was set before finalization. Silent probes use independent reopened
/// handles to measure access without any gesture request. No UI-permitted
/// OpenKey or unsupported provider-level HWND is required.
fn private_key<'a>(
    provider: NCRYPT_PROV_HANDLE,
    name: PCWSTR,
    created: &'a Handle,
    silent: bool,
) -> std::result::Result<PrivateKey<'a>, Failure> {
    if silent {
        return open_test_key(provider, name).map(PrivateKey::Silent);
    }
    if created.0 == 0 {
        return Err(Failure::failed().at("decrypt-created-key-unavailable"));
    }
    Ok(PrivateKey::Authorized(created))
}

/// Keep generation rejection separate from the provider's cryptographic error.
fn decrypt_current(
    key: NCRYPT_KEY_HANDLE,
    ciphertext: &[u8],
    padding: Option<&BCRYPT_OAEP_PADDING_INFO>,
    plaintext: &mut [u8],
    actual: &mut u32,
    flags: NCRYPT_FLAGS,
    current: &dyn Fn() -> bool,
) -> std::result::Result<windows_core::Result<()>, Failure> {
    if !current() {
        return Err(Failure {
            status: Outcome::Interrupted,
            code: None,
            operation: Some("decrypt-session-changed-before-private-call"),
        });
    }
    Ok(unsafe {
        NCryptDecrypt(
            key,
            Some(ciphertext),
            padding.map(|info| (info as *const BCRYPT_OAEP_PADDING_INFO).cast()),
            Some(plaintext),
            actual,
            flags,
        )
    })
}

/// Encrypt using only the app key's public RSA component. Passport remains
/// the sole owner of the private key and the sole production decrypt provider.
/// Public encryption needs no Hello authorization or private-key operation.
fn wrap_public_key(
    key: NCRYPT_KEY_HANDLE,
    secret: &[u8; 32],
    scheme: RsaPadding,
) -> std::result::Result<Vec<u8>, Failure> {
    // Bounded RSA public blob: header, exponent and 2048-bit modulus. Never
    // request a private/full-private blob or persist/return the public blob.
    let mut blob = [0u8; 512];
    let mut actual = 0;
    unsafe {
        NCryptExportKey(
            key,
            None,
            BCRYPT_RSAPUBLIC_BLOB,
            None,
            Some(&mut blob),
            &mut actual,
            NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|e| failed(e).at("public-key-export"))?;
    if (actual as usize) < std::mem::size_of::<BCRYPT_RSAKEY_BLOB>() || actual as usize > blob.len()
    {
        return Err(Failure::failed().at("public-key-export-length"));
    }

    let mut algorithm = BCRYPT_ALG_HANDLE::default();
    unsafe {
        BCryptOpenAlgorithmProvider(
            &mut algorithm,
            BCRYPT_RSA_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        )
    }
    .ok()
    .map_err(|e| failed(e).at("public-rsa-provider-open"))?;
    let algorithm = PublicAlgorithm(algorithm);
    let mut public = BCRYPT_KEY_HANDLE::default();
    unsafe {
        BCryptImportKeyPair(
            algorithm.0,
            None,
            BCRYPT_RSAPUBLIC_BLOB,
            &mut public,
            &blob[..actual as usize],
            0,
        )
    }
    .ok()
    .map_err(|e| failed(e).at("public-key-import"))?;
    // Declared after the algorithm: release this key before its provider.
    let public = PublicKey(public);
    let padding = scheme.info();
    let mut ciphertext = vec![0; 256];
    unsafe {
        BCryptEncrypt(
            public.0,
            Some(secret),
            padding
                .as_ref()
                .map(|info| (info as *const BCRYPT_OAEP_PADDING_INFO).cast()),
            None,
            Some(&mut ciphertext),
            &mut actual,
            scheme.encrypt_flags(),
        )
    }
    .ok()
    .map_err(|e| failed(e).at(scheme.encrypt_operation()))?;
    if actual != 256 {
        return Err(Failure::failed().at("public-ciphertext-length"));
    }
    Ok(ciphertext)
}
pub(in crate::hello) fn wrap_oaep_public(
    key: NCRYPT_KEY_HANDLE,
    secret: &[u8; 32],
) -> std::result::Result<Vec<u8>, Failure> {
    wrap_public_key(key, secret, RsaPadding::OaepSha256)
}

struct Probe<'a> {
    // Rust drops fields in declaration order. Release any remaining key
    // handle before its provider, including a failed-deletion exit.
    key: Handle,
    provider: Handle,
    name: Vec<u16>,
    hwnd: usize,
    secret: Zeroizing<[u8; 32]>,
    ciphertext: Vec<u8>,
    scheme: RsaPadding,
    exports: Vec<ExportCheck>,
    attestation_claim: Option<AttestationClaim>,
    current: &'a dyn Fn() -> bool,
}
fn failed(error: windows_core::Error) -> Failure {
    Failure {
        status: if error.code() == NTE_USER_CANCELLED {
            Outcome::Cancelled
        } else {
            Outcome::Failed
        },
        code: Some(error.code().0 as u32),
        operation: None,
    }
}
fn require_silent_refusal(
    result: windows_core::Result<()>,
    scheme: RsaPadding,
) -> std::result::Result<(), Failure> {
    match result {
        Err(error) if error.code() == NTE_SILENT_CONTEXT => Ok(()),
        Err(error) => Err(failed(error).at(match scheme {
            RsaPadding::OaepSha256 => "silent-oaep-sha256-decrypt",
            RsaPadding::Pkcs1Compatibility => "silent-pkcs1-v1_5-decrypt",
        })),
        Ok(()) => Err(Failure::failed().at("silent-decrypt-unexpected-success")),
    }
}
pub(crate) fn current_sid() -> std::result::Result<String, Failure> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, HANDLE},
        Security::Authorization::ConvertSidToStringSidW,
        Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct Text(*mut u16);
    impl Drop for Text {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
    let os_error = || failed(windows_core::Error::from_thread()).at("current-user-sid");
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(os_error());
        }
        let token = Token(token);
        // Aligned, bounded TokenUser storage. No impersonation or caller SID.
        let mut data = [0usize; 128];
        let mut actual = 0;
        if GetTokenInformation(
            token.0,
            TokenUser,
            data.as_mut_ptr().cast(),
            std::mem::size_of_val(&data) as u32,
            &mut actual,
        ) == 0
        {
            return Err(os_error());
        }
        if actual < std::mem::size_of::<TOKEN_USER>() as u32
            || actual as usize > std::mem::size_of_val(&data)
        {
            return Err(Failure::failed());
        }
        let user = &*data.as_ptr().cast::<TOKEN_USER>();
        let mut text = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            return Err(os_error());
        }
        let text = Text(text);
        let length = (0..184)
            .find(|index| *text.0.add(*index) == 0)
            .ok_or_else(Failure::failed)?;
        String::from_utf16(std::slice::from_raw_parts(text.0, length))
            .map_err(|_| Failure::failed())
    }
}
fn measure_key_exports(
    key: NCRYPT_KEY_HANDLE,
    current: impl Fn() -> bool,
) -> (Vec<ExportCheck>, std::result::Result<(), Failure>) {
    super::measure_exports(current, |label| {
        let format = match label {
            "rsa-private" => BCRYPT_RSAPRIVATE_BLOB,
            "rsa-full-private" => BCRYPT_RSAFULLPRIVATE_BLOB,
            "pkcs8-private" => NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
            _ => unreachable!("Native export formats are fixed"),
        };
        let mut output = Zeroizing::new([0u8; 16_384]);
        let mut actual = 0;
        unsafe {
            NCryptExportKey(
                key,
                None,
                format,
                None,
                Some(output.as_mut_slice()),
                &mut actual,
                NCRYPT_SILENT_FLAG,
            )
        }
        .map_err(failed)
    })
}

/// One fixed documented API candidate. No authority/OS AIK key is opened;
/// support is measured, not assumed. The unknown returned format is not parsed
/// or blessed as a trusted TPM claim. Flags must be zero per Microsoft S21.
fn create_claim_current(
    key: NCRYPT_KEY_HANDLE,
    nonce: &mut [u8; 32],
    output: &mut [u8],
    actual: &mut u32,
    current: &dyn Fn() -> bool,
) -> std::result::Result<windows_core::Result<()>, Failure> {
    if !current() {
        return Err(Failure {
            status: Outcome::Interrupted,
            code: None,
            operation: Some("attestation-session-changed-before-call"),
        });
    }
    let mut nonce_buffer = BCryptBuffer {
        cbBuffer: 32,
        BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
        pvBuffer: nonce.as_mut_ptr().cast(),
    };
    let parameters = BCryptBufferDesc {
        ulVersion: BCRYPTBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut nonce_buffer,
    };
    Ok(unsafe {
        NCryptCreateClaim(
            Some(key),
            None,
            NCRYPT_CLAIM_SUBJECT_ONLY,
            Some(&parameters),
            Some(output),
            actual,
            0,
        )
    })
}
impl Probe<'_> {
    fn attestation(&mut self) -> std::result::Result<(), Failure> {
        self.context(&self.key)?;
        let mut output = Zeroizing::new([0u8; 16_384]);
        let mut actual = 0;
        let result = create_claim_current(
            NCRYPT_KEY_HANDLE(self.key.0),
            &mut self.secret,
            output.as_mut_slice(),
            &mut actual,
            self.current,
        )?;
        self.attestation_claim = Some(AttestationClaim {
            api: "NCryptCreateClaim",
            claim_type: "subject-only",
            result: if result.is_err() {
                "unavailable"
            } else if actual == 0 || actual as usize > output.len() {
                "invalid-length"
            } else {
                "returned-unverified"
            },
            verification: "not-performed",
            bytes: if result.is_ok() && actual > 0 && actual as usize <= output.len() {
                Some(actual)
            } else {
                None
            },
        });
        if !(self.current)() {
            return Err(Failure {
                status: Outcome::Interrupted,
                code: None,
                operation: Some("attestation-session-changed-after-call"),
            });
        }
        result.map_err(|error| failed(error).at("create-subject-only-attestation-claim"))?;
        if actual == 0 || actual as usize > output.len() {
            return Err(Failure::failed().at("attestation-claim-length"));
        }
        Ok(())
    }
    fn delete_pending(&self) -> std::result::Result<(), Failure> {
        let mut pending = PENDING_DELETE.lock().map_err(|_| Failure::failed())?;
        if let Some(name) = pending.as_ref() {
            let mut provider = NCRYPT_PROV_HANDLE(0);
            unsafe { NCryptOpenStorageProvider(&mut provider, MS_NGC_KEY_STORAGE_PROVIDER, 0) }
                .map_err(failed)?;
            let _provider = Handle(provider.0);
            let mut key = NCRYPT_KEY_HANDLE(0);
            unsafe {
                match NCryptOpenKey(
                    provider,
                    &mut key,
                    PCWSTR(name.as_ptr()),
                    CERT_KEY_SPEC(0),
                    NCRYPT_SILENT_FLAG,
                ) {
                    Ok(()) => {
                        let mut owned = Handle(key.0);
                        NCryptDeleteKey(key, NCRYPT_SILENT_FLAG.0).map_err(failed)?;
                        owned.0 = 0;
                    }
                    Err(error) if error.code() == NTE_BAD_KEYSET => {}
                    Err(error) => return Err(failed(error)),
                }
            }
            *pending = None;
        }
        Ok(())
    }
    fn set(&self, property: PCWSTR, bytes: &[u8]) -> std::result::Result<(), Failure> {
        unsafe { NCryptSetProperty(NCRYPT_HANDLE(self.key.0), property, bytes, NCRYPT_FLAGS(0)) }
            .map_err(failed)
    }
    fn number(&self, property: PCWSTR) -> std::result::Result<u32, Failure> {
        let mut bytes = [0; 4];
        let mut length = 0;
        unsafe {
            NCryptGetProperty(
                NCRYPT_HANDLE(self.key.0),
                property,
                Some(&mut bytes),
                &mut length,
                windows::Win32::Security::OBJECT_SECURITY_INFORMATION(0),
            )
        }
        .map_err(failed)?;
        if length != 4 {
            return Err(Failure::failed());
        }
        Ok(u32::from_le_bytes(bytes))
    }
    fn open(&self) -> std::result::Result<Handle, Failure> {
        open_test_key(
            NCRYPT_PROV_HANDLE(self.provider.0),
            PCWSTR(self.name.as_ptr()),
        )
    }
    fn context(&self, key: &Handle) -> std::result::Result<(), Failure> {
        let message: Vec<u8> =
            "PassKey Local: test an app key only; no vault unlock. / Проверка тестового ключа приложения; хранилище не разблокируется."
                .encode_utf16()
                .chain(Some(0))
                .flat_map(u16::to_le_bytes)
                .collect();
        unsafe {
            NCryptSetProperty(
                NCRYPT_HANDLE(key.0),
                NCRYPT_WINDOW_HANDLE_PROPERTY,
                &self.hwnd.to_le_bytes(),
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| failed(e).at("set-window-handle"))?;
            NCryptSetProperty(
                NCRYPT_HANDLE(key.0),
                NCRYPT_USE_CONTEXT_PROPERTY,
                &message,
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| failed(e).at("set-use-context"))?;
        }
        Ok(())
    }
    #[cfg(test)]
    fn padding() -> BCRYPT_OAEP_PADDING_INFO {
        RsaPadding::OaepSha256.info().unwrap()
    }
    fn decrypt(&self, silent: bool) -> std::result::Result<(), Failure> {
        let selected = private_key(
            NCRYPT_PROV_HANDLE(self.provider.0),
            PCWSTR(self.name.as_ptr()),
            &self.key,
            silent,
        )?;
        let key = selected.handle();
        // Check stored policy again on the selected key; a handle flag alone
        // is not a durable authorization policy. No secret key leaves CNG.
        let mut cache = [0; 4];
        let mut length = 0;
        unsafe {
            NCryptGetProperty(
                NCRYPT_HANDLE(key.0),
                CACHE_TYPE,
                Some(&mut cache),
                &mut length,
                windows::Win32::Security::OBJECT_SECURITY_INFORMATION(0),
            )
        }
        .map_err(|e| failed(e).at("decrypt-policy-readback"))?;
        if length != 4 {
            return Err(Failure::failed().at("decrypt-policy-length"));
        }
        if u32::from_le_bytes(cache) != 1 {
            return Err(Failure::failed().at("decrypt-policy-mismatch"));
        }
        if !silent {
            self.context(key)?;
            unsafe {
                NCryptSetProperty(
                    NCRYPT_HANDLE(key.0),
                    NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY,
                    &NCRYPT_PIN_CACHE_REQUIRE_GESTURE_FLAG.to_le_bytes(),
                    NCRYPT_FLAGS(0),
                )
            }
            .map_err(|e| failed(e).at("decrypt-require-fresh-gesture"))?;
        }
        // Use an actual output buffer. A size-only query can succeed without
        // authorizing a private-key operation and is not an unwrap proof.
        let padding = self.scheme.info();
        let mut plaintext = Zeroizing::new([0u8; 256]);
        let mut actual = 0;
        let flags = if silent {
            self.scheme.decrypt_flags() | NCRYPT_SILENT_FLAG
        } else {
            self.scheme.decrypt_flags()
        };
        // Context/gesture setup may have outlived a lock. Check again before
        // starting any private operation, even within this report stage.
        let result = decrypt_current(
            NCRYPT_KEY_HANDLE(key.0),
            &self.ciphertext,
            padding.as_ref(),
            plaintext.as_mut_slice(),
            &mut actual,
            flags,
            self.current,
        )?;
        if silent {
            return require_silent_refusal(result, self.scheme);
        }
        result.map_err(|e| failed(e).at(self.scheme.decrypt_operation()))?;
        if actual != 32 || !libsodium_rs::utils::memcmp(&plaintext[..32], self.secret.as_slice()) {
            return Err(Failure::failed().at("decrypt-secret-mismatch"));
        }
        Ok(())
    }
    fn export_denied(&mut self) -> std::result::Result<(), Failure> {
        let (checks, result) = measure_key_exports(NCRYPT_KEY_HANDLE(self.key.0), self.current);
        self.exports = checks;
        result
    }
}
impl Provider for Probe<'_> {
    fn attestation_claim(&self) -> Option<AttestationClaim> {
        self.attestation_claim.clone()
    }
    fn export_checks(&self) -> Vec<ExportCheck> {
        self.exports.clone()
    }
    fn step(&mut self, stage: Stage) -> std::result::Result<(), Failure> {
        match stage {
            Stage::AttestationClaim => self.attestation()?,
            Stage::HelloConfiguration => {
                if crate::hello::diagnostics::check()["helloConfiguration"] != "available" {
                    return Err(Failure::failed());
                }
            }
            Stage::ProviderOpen => {
                let mut provider = NCRYPT_PROV_HANDLE(0);
                unsafe { NCryptOpenStorageProvider(&mut provider, MS_NGC_KEY_STORAGE_PROVIDER, 0) }
                    .map_err(failed)?;
                self.provider = Handle(provider.0);
                // Retry only the exact app-created key whose deletion failed
                // in this process. Never enumerate or delete OS-owned keys.
                self.delete_pending()?;
            }
            Stage::KeyCreate => {
                // Passport containers are current SID // domain / subdomain /
                // identity. Keep the SID natively; never return it in reports.
                self.name = format!(
                    "{}//PassKeyLocal.Proof/v1/{}",
                    current_sid()?,
                    uuid::Uuid::new_v4()
                )
                .encode_utf16()
                .chain(Some(0))
                .collect();
                let mut key = NCRYPT_KEY_HANDLE(0);
                unsafe {
                    NCryptCreatePersistedKey(
                        NCRYPT_PROV_HANDLE(self.provider.0),
                        &mut key,
                        BCRYPT_RSA_ALGORITHM,
                        PCWSTR(self.name.as_ptr()),
                        CERT_KEY_SPEC(0),
                        NCRYPT_FLAGS(0),
                    )
                }
                .map_err(failed)?;
                self.key = Handle(key.0);
            }
            Stage::KeyPolicy => {
                self.set(NCRYPT_LENGTH_PROPERTY, &2048u32.to_le_bytes())
                    .map_err(|e| e.at("set-rsa-length"))?;
                self.set(
                    NCRYPT_KEY_USAGE_PROPERTY,
                    &NCRYPT_ALLOW_DECRYPT_FLAG.to_le_bytes(),
                )
                .map_err(|e| e.at("set-decrypt-only-usage"))?;
                // An intrinsically non-exportable provider can expose a zero
                // policy without permitting a redundant property write.
                // The finalized policy and actual export denial are still
                // mandatory; this does not accept an unsupported readback.
                if self.number(NCRYPT_EXPORT_POLICY_PROPERTY).ok() != Some(0) {
                    self.set(NCRYPT_EXPORT_POLICY_PROPERTY, &0u32.to_le_bytes())
                        .map_err(|e| e.at("set-no-export-policy"))?;
                }
                self.set(CACHE_TYPE, &1u32.to_le_bytes())
                    .map_err(|e| e.at("set-mandatory-authorization-policy"))?;
                self.context(&self.key)
                    .map_err(|e| e.at("set-owned-window-context"))?;
                unsafe { NCryptFinalizeKey(NCRYPT_KEY_HANDLE(self.key.0), NCRYPT_FLAGS(0)) }
                    .map_err(|e| failed(e).at("finalize-test-key"))?;
            }
            Stage::PolicyReadback => {
                if self.number(NCRYPT_LENGTH_PROPERTY)? != 2048
                    || self.number(NCRYPT_KEY_USAGE_PROPERTY)? != NCRYPT_ALLOW_DECRYPT_FLAG
                    || self.number(NCRYPT_EXPORT_POLICY_PROPERTY)? != 0
                    || self.number(CACHE_TYPE)? != 1
                {
                    return Err(Failure::failed());
                }
            }
            Stage::PublicWrap => {
                self.ciphertext =
                    wrap_public_key(NCRYPT_KEY_HANDLE(self.key.0), &self.secret, self.scheme)?;
            }
            Stage::PrivateExport => self.export_denied()?,
            Stage::SilentBefore | Stage::SilentAfterFirst | Stage::SilentAfterSecond => {
                self.decrypt(true)?
            }
            Stage::UnwrapFirst | Stage::UnwrapSecond => self.decrypt(false)?,
            Stage::TestKeyDelete => return Err(Failure::failed()),
        }
        Ok(())
    }
    fn cleanup(&mut self) -> std::result::Result<(), Failure> {
        if self.key.0 == 0 {
            // Cleanup is allowed even if Hello became unavailable. Do not
            // report deletion success while a previous app key remains.
            return self.delete_pending();
        }
        let result =
            unsafe { NCryptDeleteKey(NCRYPT_KEY_HANDLE(self.key.0), NCRYPT_SILENT_FLAG.0) };
        match result {
            Ok(()) => {
                self.key.0 = 0;
                Ok(())
            }
            Err(error) => {
                if self
                    .open()
                    .is_err_and(|error| error.code == Some(NTE_BAD_KEYSET.0 as u32))
                {
                    // Failure before finalization may leave only a live
                    // handle. Confirm the named persisted key is absent.
                    self.key = Handle(0);
                    return Ok(());
                }
                if let Ok(mut pending) = PENDING_DELETE.lock() {
                    *pending = Some(self.name.clone());
                }
                Err(failed(error).at("delete-test-key"))
            }
        }
    }
}

pub fn run(hwnd: usize, current: impl Fn() -> bool, experiment: Experiment) -> Result<Report> {
    let _attempt = crate::hello::Attempt::begin()?;
    libsodium_rs::ensure_init().map_err(|_| Error::new("UNAVAILABLE"))?;
    let mut secret = Zeroizing::new([0u8; 32]);
    libsodium_rs::random::fill_bytes(secret.as_mut_slice());
    let mut probe = Probe {
        provider: Handle(0),
        key: Handle(0),
        name: Vec::new(),
        hwnd,
        secret,
        ciphertext: Vec::new(),
        scheme: RsaPadding::for_experiment(experiment),
        exports: Vec::new(),
        attestation_claim: None,
        current: &current,
    };
    Ok(match experiment {
        Experiment::SecurityProof => exercise(&mut probe, &current),
        Experiment::AuthorizedOaepCapability
        | Experiment::Pkcs1Compatibility
        | Experiment::Pkcs1Behavior
        | Experiment::AttestationCapability => exercise_selected(&mut probe, &current, experiment),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_claim_api_is_guarded_and_preserves_its_native_failure() {
        let mut nonce = [0x55; 32];
        let mut output = [0xAA; 1024];
        let mut actual = 123;
        let stopped = create_claim_current(
            NCRYPT_KEY_HANDLE(0),
            &mut nonce,
            &mut output,
            &mut actual,
            &|| false,
        )
        .unwrap_err();
        assert_eq!(stopped.status, Outcome::Interrupted);
        assert_eq!(output, [0xAA; 1024]);
        assert_eq!(actual, 123);
        // Intentionally invalid app handle: exercise actual API failure mapping,
        // not a fabricated provider/TPM success. Never opens an OS key or UI.
        let native = create_claim_current(
            NCRYPT_KEY_HANDLE(0),
            &mut nonce,
            &mut output,
            &mut actual,
            &|| true,
        )
        .unwrap()
        .unwrap_err();
        let original = native.code().0 as u32;
        assert_ne!(original, 0);
        assert_eq!(
            failed(native)
                .at("create-subject-only-attestation-claim")
                .code,
            Some(original)
        );
    }

    #[test]
    fn owned_creation_and_silent_reopened_keys_interoperate_without_relaxing_refusal() {
        // A named, app-owned software key and a hidden native window exercise
        // real Windows object lifetime, key HWND context, reopen/decrypt
        // and cleanup. They supply no Passport, prompt or TPM evidence.
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, HWND_MESSAGE,
        };
        struct TestWindow(windows_sys::Win32::Foundation::HWND);
        impl Drop for TestWindow {
            fn drop(&mut self) {
                unsafe {
                    DestroyWindow(self.0);
                }
            }
        }
        struct TestKey {
            handle: Handle,
        }
        impl TestKey {
            fn delete(&mut self) -> windows_core::Result<()> {
                unsafe { NCryptDeleteKey(NCRYPT_KEY_HANDLE(self.handle.0), NCRYPT_SILENT_FLAG.0) }?;
                self.handle.0 = 0;
                Ok(())
            }
        }
        impl Drop for TestKey {
            fn drop(&mut self) {
                if self.handle.0 != 0 {
                    let _ = self.delete();
                }
            }
        }
        unsafe {
            let window = TestWindow(CreateWindowExW(
                0,
                w!("STATIC").as_ptr(),
                w!("PassKey Local synthetic test").as_ptr(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            ));
            assert!(!window.0.is_null());
            let mut provider = NCRYPT_PROV_HANDLE(0);
            NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0).unwrap();
            let _provider = Handle(provider.0);
            let name: Vec<u16> = format!("PassKeyLocal.UnitTest.{}", uuid::Uuid::new_v4())
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut key = NCRYPT_KEY_HANDLE(0);
            NCryptCreatePersistedKey(
                provider,
                &mut key,
                BCRYPT_RSA_ALGORITHM,
                PCWSTR(name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
            .unwrap();
            let mut owned_key = TestKey {
                handle: Handle(key.0),
            };
            NCryptSetProperty(
                NCRYPT_HANDLE(key.0),
                NCRYPT_LENGTH_PROPERTY,
                &2048u32.to_le_bytes(),
                NCRYPT_FLAGS(0),
            )
            .unwrap();
            NCryptSetProperty(
                NCRYPT_HANDLE(key.0),
                NCRYPT_EXPORT_POLICY_PROPERTY,
                &0u32.to_le_bytes(),
                NCRYPT_FLAGS(0),
            )
            .unwrap();
            NCryptSetProperty(
                NCRYPT_HANDLE(key.0),
                NCRYPT_WINDOW_HANDLE_PROPERTY,
                &(window.0 as usize).to_le_bytes(),
                NCRYPT_FLAGS(0),
            )
            .unwrap();
            NCryptFinalizeKey(key, NCRYPT_FLAGS(0)).unwrap();
            let secret = Zeroizing::new([0x6bu8; 32]);
            let ciphertext = wrap_public_key(key, &secret, RsaPadding::OaepSha256).unwrap();
            let padding = Probe::padding();
            for silent in [false, true] {
                let selected =
                    private_key(provider, PCWSTR(name.as_ptr()), &owned_key.handle, silent)
                        .unwrap();
                let mut plaintext = Zeroizing::new([0u8; 256]);
                let mut actual = 0;
                let flags = if silent {
                    NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG
                } else {
                    NCRYPT_PAD_OAEP_FLAG
                };
                let result = NCryptDecrypt(
                    NCRYPT_KEY_HANDLE(selected.handle().0),
                    Some(&ciphertext),
                    Some((&padding as *const BCRYPT_OAEP_PADDING_INFO).cast()),
                    Some(plaintext.as_mut_slice()),
                    &mut actual,
                    flags,
                );
                assert!(result.is_ok());
                assert_eq!(actual, 32);
                assert!(libsodium_rs::utils::memcmp(
                    &plaintext[..32],
                    secret.as_slice()
                ));
                if silent {
                    assert_eq!(
                        require_silent_refusal(result, RsaPadding::OaepSha256)
                            .unwrap_err()
                            .operation,
                        Some("silent-decrypt-unexpected-success")
                    );
                }
            }
            // With a stale generation, reject before calling CNG even with
            // invalid crypto parameters; leave output and length untouched.
            let mut untouched = Zeroizing::new([0x7au8; 256]);
            let mut length = 123;
            let error = decrypt_current(
                NCRYPT_KEY_HANDLE(0),
                &[0],
                Some(&padding),
                untouched.as_mut_slice(),
                &mut length,
                NCRYPT_PAD_OAEP_FLAG,
                &|| false,
            )
            .unwrap_err();
            assert_eq!(error.status, Outcome::Interrupted);
            assert_eq!(
                error.operation,
                Some("decrypt-session-changed-before-private-call")
            );
            assert_eq!(length, 123);
            assert!(untouched.iter().all(|byte| *byte == 0x7a));
            // The same parameters in a current generation reach real CNG and
            // preserve its native failure, rather than inventing interruption.
            assert!(decrypt_current(
                NCRYPT_KEY_HANDLE(0),
                &[0],
                Some(&padding),
                untouched.as_mut_slice(),
                &mut length,
                NCRYPT_PAD_OAEP_FLAG,
                &|| true
            )
            .unwrap()
            .is_err());
            owned_key.delete().unwrap();
            let error = match open_test_key(provider, PCWSTR(name.as_ptr())) {
                Ok(_) => panic!("Deleted synthetic key unexpectedly reopened"),
                Err(error) => error,
            };
            assert_eq!(error.operation, Some("decrypt-key-open-silent"));
            assert_eq!(error.code, Some(NTE_BAD_KEYSET.0 as u32));
            let error = match private_key(provider, PCWSTR(name.as_ptr()), &owned_key.handle, false)
            {
                Ok(_) => panic!("Deleted creation handle unexpectedly accepted"),
                Err(error) => error,
            };
            assert_eq!(error.operation, Some("decrypt-created-key-unavailable"));
        }
    }

    #[test]
    fn exported_public_wrap_uses_oaep_sha256_and_rejects_corruption() {
        // An unnamed, ephemeral software key is a Windows API interoperability
        // fixture only. This provider is never selected by production code and
        // this test supplies no Passport, consent or TPM evidence.
        unsafe {
            let mut provider = NCRYPT_PROV_HANDLE(0);
            NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0).unwrap();
            let _provider = Handle(provider.0);
            let mut key = NCRYPT_KEY_HANDLE(0);
            NCryptCreatePersistedKey(
                provider,
                &mut key,
                BCRYPT_RSA_ALGORITHM,
                PCWSTR::null(),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
            .unwrap();
            let _key = Handle(key.0);
            NCryptSetProperty(
                NCRYPT_HANDLE(key.0),
                NCRYPT_LENGTH_PROPERTY,
                &2048u32.to_le_bytes(),
                NCRYPT_FLAGS(0),
            )
            .unwrap();
            NCryptSetProperty(
                NCRYPT_HANDLE(key.0),
                NCRYPT_EXPORT_POLICY_PROPERTY,
                &0u32.to_le_bytes(),
                NCRYPT_FLAGS(0),
            )
            .unwrap();
            NCryptFinalizeKey(key, NCRYPT_FLAGS(0)).unwrap();
            let (export_checks, export_gate) = measure_key_exports(key, || true);
            // This actual software KSP reports unsupported export with policy
            // zero, not NTE_PERM. Preserve that unresolved result; the fixture
            // must not manufacture explicit denial or provider eligibility.
            let failure = export_gate.unwrap_err();
            assert_eq!(failure.code, Some(0x80090029));
            assert_eq!(failure.operation, Some("private-export-rsa"));
            assert_eq!(export_checks.len(), 3);
            assert_eq!(export_checks[0].result, "failed");
            assert_eq!(export_checks[0].native_code.as_deref(), Some("0x80090029"));
            assert!(export_checks
                .iter()
                .all(|check| check.result != "unexpected-success" && check.result != "not-run"));
            // Positive control: an explicitly exportable software fixture
            // actually exports. The production gate must stop after success.
            let mut exportable = NCRYPT_KEY_HANDLE(0);
            NCryptCreatePersistedKey(
                provider,
                &mut exportable,
                BCRYPT_RSA_ALGORITHM,
                PCWSTR::null(),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
            .unwrap();
            let _exportable = Handle(exportable.0);
            NCryptSetProperty(
                NCRYPT_HANDLE(exportable.0),
                NCRYPT_EXPORT_POLICY_PROPERTY,
                &(NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG).to_le_bytes(),
                NCRYPT_FLAGS(0),
            )
            .unwrap();
            NCryptFinalizeKey(exportable, NCRYPT_FLAGS(0)).unwrap();
            let (checks, result) = measure_key_exports(exportable, || true);
            assert_eq!(result.unwrap_err().operation, Some("private-export-rsa"));
            assert_eq!(checks[0].result, "unexpected-success");
            assert!(checks[1..].iter().all(|check| check.result == "not-run"));
            let secret = Zeroizing::new([0x5au8; 32]);
            let mut ciphertext = wrap_public_key(key, &secret, RsaPadding::OaepSha256).unwrap();
            let padding = Probe::padding();
            let mut plaintext = Zeroizing::new([0u8; 256]);
            let mut actual = 0;
            let decrypt = |ciphertext: &[u8],
                           padding: &BCRYPT_OAEP_PADDING_INFO,
                           plaintext: &mut [u8],
                           actual: &mut u32| {
                NCryptDecrypt(
                    key,
                    Some(ciphertext),
                    Some((padding as *const BCRYPT_OAEP_PADDING_INFO).cast()),
                    Some(plaintext),
                    actual,
                    NCRYPT_PAD_OAEP_FLAG,
                )
            };
            decrypt(&ciphertext, &padding, plaintext.as_mut_slice(), &mut actual).unwrap();
            assert_eq!(actual, 32);
            assert!(libsodium_rs::utils::memcmp(
                &plaintext[..32],
                secret.as_slice()
            ));
            // A logged-in software key can decrypt silently. That real API
            // success must be rejected by the production authorization gate.
            let silent = NCryptDecrypt(
                key,
                Some(&ciphertext),
                Some((&padding as *const BCRYPT_OAEP_PADDING_INFO).cast()),
                Some(plaintext.as_mut_slice()),
                &mut actual,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            );
            assert!(silent.is_ok());
            let refusal = require_silent_refusal(silent, RsaPadding::OaepSha256).unwrap_err();
            assert_eq!(refusal.status, Outcome::Failed);
            assert_eq!(refusal.operation, Some("silent-decrypt-unexpected-success"));
            let parameter_error = require_silent_refusal(
                Err(windows::Win32::Foundation::NTE_INVALID_PARAMETER.into()),
                RsaPadding::OaepSha256,
            )
            .unwrap_err();
            assert_eq!(parameter_error.status, Outcome::Failed);
            assert_eq!(parameter_error.code, Some(0x80090027));
            assert_eq!(
                parameter_error.operation,
                Some("silent-oaep-sha256-decrypt")
            );
            assert!(
                require_silent_refusal(Err(NTE_SILENT_CONTEXT.into()), RsaPadding::OaepSha256)
                    .is_ok()
            );
            // The separately selected legacy diagnostic uses SDK PKCS#1
            // encryption/decryption with null padding info. Compare both
            // schemes on the same real API key: wrong-scheme decrypts fail.
            assert!(
                RsaPadding::for_experiment(Experiment::SecurityProof) == RsaPadding::OaepSha256
            );
            assert!(
                RsaPadding::for_experiment(Experiment::AuthorizedOaepCapability)
                    == RsaPadding::OaepSha256
            );
            let legacy = RsaPadding::for_experiment(Experiment::Pkcs1Compatibility);
            assert!(legacy == RsaPadding::Pkcs1Compatibility);
            assert!(RsaPadding::for_experiment(Experiment::Pkcs1Behavior) == legacy);
            assert!(legacy.info().is_none());
            let legacy_ciphertext = wrap_public_key(key, &secret, legacy).unwrap();
            decrypt_current(
                key,
                &legacy_ciphertext,
                None,
                plaintext.as_mut_slice(),
                &mut actual,
                legacy.decrypt_flags(),
                &|| true,
            )
            .unwrap()
            .unwrap();
            assert_eq!(actual, 32);
            assert!(libsodium_rs::utils::memcmp(
                &plaintext[..32],
                secret.as_slice()
            ));
            // Actual silent legacy decrypt succeeds on this software fixture,
            // which must fail the same strict gate used by the Passport probe.
            let silent_legacy = decrypt_current(
                key,
                &legacy_ciphertext,
                None,
                plaintext.as_mut_slice(),
                &mut actual,
                legacy.decrypt_flags() | NCRYPT_SILENT_FLAG,
                &|| true,
            )
            .unwrap();
            assert!(silent_legacy.is_ok());
            assert_eq!(
                require_silent_refusal(silent_legacy, legacy)
                    .unwrap_err()
                    .operation,
                Some("silent-decrypt-unexpected-success")
            );
            let error = require_silent_refusal(
                Err(windows::Win32::Foundation::NTE_INVALID_PARAMETER.into()),
                legacy,
            )
            .unwrap_err();
            assert_eq!(error.code, Some(0x80090027));
            assert_eq!(error.operation, Some("silent-pkcs1-v1_5-decrypt"));
            assert!(require_silent_refusal(Err(NTE_SILENT_CONTEXT.into()), legacy).is_ok());
            assert!(decrypt_current(
                key,
                &ciphertext,
                None,
                plaintext.as_mut_slice(),
                &mut actual,
                legacy.decrypt_flags(),
                &|| true
            )
            .unwrap()
            .is_err());
            assert!(decrypt(
                &legacy_ciphertext,
                &padding,
                plaintext.as_mut_slice(),
                &mut actual
            )
            .is_err());
            // No scheme can bypass the actual private-call generation guard.
            let mut untouched = Zeroizing::new([0x7au8; 256]);
            let mut untouched_length = 123;
            let stale = decrypt_current(
                key,
                &legacy_ciphertext,
                None,
                untouched.as_mut_slice(),
                &mut untouched_length,
                legacy.decrypt_flags(),
                &|| false,
            )
            .unwrap_err();
            assert_eq!(stale.status, Outcome::Interrupted);
            assert_eq!(untouched_length, 123);
            assert!(untouched.iter().all(|byte| *byte == 0x7a));
            let wrong_hash = BCRYPT_OAEP_PADDING_INFO {
                pszAlgId: BCRYPT_SHA1_ALGORITHM,
                ..Default::default()
            };
            assert!(decrypt(
                &ciphertext,
                &wrong_hash,
                plaintext.as_mut_slice(),
                &mut actual
            )
            .is_err());
            ciphertext[0] ^= 1;
            assert!(decrypt(&ciphertext, &padding, plaintext.as_mut_slice(), &mut actual).is_err());
        }
    }

    #[test]
    fn native_container_identity_comes_from_the_current_process_token() {
        let sid = super::current_sid().unwrap();
        assert!(sid.starts_with("S-1-"));
        assert!(sid.len() < 184);
        assert!(sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'S' || b == b'-'));
    }
}
