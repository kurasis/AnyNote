//! GPL-3.0-only. Frozen product AES-GCM wrapper with the preserved real native
//! PRF/TPM provider. No P01 synthetic wrapper, consent-only gate or software PRF.
use super::*;
#[cfg(windows)]
use crate::hello::{
    prf::windows::combined::Credential,
    proof::{Failure, Outcome},
    tpm::windows::combined::Key,
};
#[cfg(windows)]
fn mapped(f: Failure) -> Error {
    Error(match f.status {
        Outcome::Cancelled => "HELLO_CANCELLED",
        Outcome::Interrupted => "STALE_CAPABILITY",
        _ => "HELLO_UNAVAILABLE",
    })
}
#[cfg(windows)]
const RP: &str = "p07.anynote.desktop.invalid";
#[cfg(windows)]
fn journal(v: &Vault) -> PathBuf {
    v.path.parent().unwrap().join(format!(
        "hello-{}-{}.json",
        v.scope.device_id, v.scope.profile_id
    ))
}
#[cfg(windows)]
fn save(v: &Vault, j: &Value) -> Result<()> {
    filesystem::atomic_json(&journal(v), &canonical(j)?).map_err(|_| Error("HELLO_JOURNAL_FAILURE"))
}
impl Vault {
    /// Host-only operation. P14 passes the real native main HWND; never an HWND
    /// supplied by renderer data. Provider callbacks also check the OS window.
    #[cfg(windows)]
    pub fn initialize_hello(&self, hwnd: usize, secrets: &[u8], pins: Value) -> Result<()> {
        let _attempt = hello::Attempt::begin().map_err(|_| Error("VAULT_BUSY"))?;
        let generation = self.signal.generation();
        let current = || self.signal.generation() == generation;
        check(!journal(self).exists(), "HELLO_CLEANUP_REQUIRED")?;
        let name = format!("AnyNote.P07.{}.{}", self.scope.profile_id, random_id());
        let salt: [u8; 32] = libsodium_rs::random::bytes(32).try_into().unwrap();
        let user: [u8; 32] = un64(&hash(&canonical(&self.scope)?))?.try_into().unwrap();
        let mut j = json!({"schema":1,"scope":self.scope,"key_name":name,"user":b64(&user),"salt":b64(&salt),"ready":false,"public":null,"wrapper":null});
        save(self, &j)?;
        let mut credential = Credential::for_rp(hwnd, &current, salt, user, RP);
        let mut tpm = Key::new(&name, &current);
        let result = (|| {
            credential.initialize().map_err(mapped)?;
            let (public, name) = tpm.prepare().map_err(mapped)?;
            j["public"] = json!(b64(&public));
            save(self, &j)?;
            let (id, _created) = credential.create().map_err(mapped)?;
            // Enrollment proves a new, uncached authorization and exact TPM reopen before
            // committing any product wrapper. A crash leaves only the exact owned journal.
            j["credential"] = json!(b64(&id));
            save(self, &j)?;
            tpm.reopen(&public, &name).map_err(mapped)?;
            let prf = credential.authorize().map_err(mapped)?;
            let d = json!({"context":self.unlock_context("windows-webauthn-prf"),"provider":"windows-hello-webauthn-prf-tpm","provider_format":1,"credential_id":b64(&id),"prf_salt":b64(&salt),"tpm_name":b64(&name),"tpm_public_sha256":hash(&public),"machine_binding_id":random_id()});
            let key = Zeroizing::new(libsodium_rs::random::bytes(32));
            let inner = local::wrap_native(&self.codec, &canonical(&d)?, &key, prf.as_slice())?;
            let check_key = local::unwrap_native(
                &self.codec,
                &canonical(&inner)?,
                &canonical(&d)?,
                prf.as_slice(),
            )?;
            check(*check_key == *key, "INTEGRITY_FAILURE")?;
            let outer_key =
                Zeroizing::new(<[u8; 32]>::try_from(libsodium_rs::random::bytes(32)).unwrap());
            let tpm_ciphertext = tpm.wrap(&outer_key).map_err(mapped)?;
            let recovered = tpm.unwrap(&tpm_ciphertext).map_err(mapped)?;
            check(
                recovered.len() == 32
                    && libsodium_rs::utils::memcmp(&recovered, outer_key.as_slice()),
                "INTEGRITY_FAILURE",
            )?;
            let wrapper = custody::seal(
                &self.codec,
                &self.scope,
                &d,
                &inner,
                &tpm_ciphertext,
                outer_key.as_slice(),
            )?;
            let data = self.codec.decode("p02-v1", "vault-secrets", secrets)?;
            check(
                data["group_keys"].as_array().is_some_and(|a| a.is_empty()),
                "INITIAL_GROUP_KEYS_FORBIDDEN",
            )?;
            check(current(), "STALE_CAPABILITY")?;
            j["wrapper"] = wrapper.clone();
            save(self, &j)?;
            self.initialize(key, wrapper, data, pins)?;
            j["ready"] = json!(true);
            save(self, &j)
        })();
        // Never delete an unknown provider object. If creation was interrupted, the
        // journal identifies the exact objects for a later explicit cleanup operation.
        result
    }
    #[cfg(not(windows))]
    pub fn initialize_hello(&self, _hwnd: usize, _secrets: &[u8], _pins: Value) -> Result<()> {
        Err(Error("WINDOWS_PROVIDER_REQUIRED"))
    }
    #[cfg(windows)]
    pub fn unlock_hello(&self, hwnd: usize) -> Result<Capability> {
        let _attempt = hello::Attempt::begin().map_err(|_| Error("VAULT_BUSY"))?;
        let generation = self.signal.generation();
        let current = || self.signal.generation() == generation;
        let raw =
            filesystem::read(&journal(self), 16384).map_err(|_| Error("HELLO_JOURNAL_FAILURE"))?;
        let j = strict(&raw, 16384)?;
        check(
            j["schema"] == 1
                && j["ready"] == true
                && j["scope"] == serde_json::to_value(&self.scope).unwrap(),
            "HELLO_CLEANUP_REQUIRED",
        )?;
        let snapshot = {
            let i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
            state(&i.conn, &self.codec, &self.scope)?
        };
        let w = snapshot
            .wrappers
            .iter()
            .find(|w| w["purpose"] == "windows-native-custody")
            .ok_or(Error("HELLO_UNAVAILABLE"))?;
        check(j["wrapper"] == *w, "INTEGRITY_FAILURE")?;
        let d = w["descriptor"].clone();
        let public = un64(text(&j["public"])?)?;
        check(hash(&public) == d["tpm_public_sha256"], "INTEGRITY_FAILURE")?;
        let salt: [u8; 32] = un64(text(&d["prf_salt"])?)?
            .try_into()
            .map_err(|_| Error("INVALID_WRAPPER"))?;
        let user: [u8; 32] = un64(&hash(&canonical(&self.scope)?))?.try_into().unwrap();
        let name = text(&j["key_name"])?;
        check(
            name.starts_with(&format!("AnyNote.P07.{}.", self.scope.profile_id)),
            "INVALID_WRAPPER",
        )?;
        let mut tpm = Key::new(name, &current);
        tpm.reopen(&public, &un64(text(&d["tpm_name"])?)?)
            .map_err(mapped)?;
        let mut credential = Credential::for_rp(hwnd, &current, salt, user, RP);
        credential
            .reopen(&un64(text(&d["credential_id"])?)?)
            .map_err(mapped)?;
        let prf = credential.authorize().map_err(mapped)?;
        let outer_key = tpm
            .unwrap(&un64(text(&w["tpm_ciphertext"])?)?)
            .map_err(mapped)?;
        check(outer_key.len() == 32, "INTEGRITY_FAILURE")?;
        let inner = custody::open(&self.codec, &self.scope, w, &outer_key)?;
        let key = local::unwrap_native(
            &self.codec,
            &canonical(&inner)?,
            &canonical(&d)?,
            prf.as_slice(),
        )?;
        check(current(), "STALE_CAPABILITY")?;
        self.activate(key, snapshot.epoch, generation)
    }
    #[cfg(not(windows))]
    pub fn unlock_hello(&self, _hwnd: usize) -> Result<Capability> {
        Err(Error("WINDOWS_PROVIDER_REQUIRED"))
    }
}
