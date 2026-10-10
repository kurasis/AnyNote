//! Narrow persisted synthetic-key adapter; ownership lives in the durable journal.
use super::*;
pub(crate) struct Key<'a>(Probe<'a>);
impl<'a> Key<'a> {
    pub(crate) fn new(name: &str, current: &'a dyn Fn() -> bool) -> Self {
        Self(Probe {
            key: Handle(0),
            provider: Handle(0),
            name: name.encode_utf16().chain([0]).collect(),
            metadata: Metadata::default(),
            secret: Zeroizing::new([0; 32]),
            ciphertext: vec![],
            exports: vec![],
            current,
            synthetic: false,
            local_public: vec![],
            local_name: vec![],
        })
    }
    pub(crate) fn prepare(&mut self) -> std::result::Result<(Vec<u8>, Vec<u8>), Failure> {
        for s in [
            "tpm-provider-open",
            "tpm-provider-properties",
            "tpm-key-create",
            "tpm-key-policy",
            "tpm-key-readback",
            "tpm-read-public",
        ] {
            self.0.step(s)?;
        }
        Ok((self.0.local_public.clone(), self.0.local_name.clone()))
    }
    pub(crate) fn reopen(
        &mut self,
        public: &[u8],
        name: &[u8],
    ) -> std::result::Result<(), Failure> {
        // Never retain a previous key/provider handle across a reopen probe.
        self.0.key = Handle(0);
        self.0.provider = Handle(0);
        self.0.step("tpm-provider-open")?;
        self.0.step("tpm-provider-properties")?;
        self.0.key = open(self.0.provider.0, &self.0.name)?;
        self.0.step("tpm-key-readback")?;
        self.0.step("tpm-read-public")?;
        if self.0.local_public != public || self.0.local_name != name {
            return Err(invalid("combined-tpm-binding-mismatch"));
        }
        Ok(())
    }
    pub(crate) fn wrap(&self, secret: &[u8; 32]) -> std::result::Result<Vec<u8>, Failure> {
        proof::windows::wrap_oaep_public(NCRYPT_KEY_HANDLE(self.0.key.0), secret)
    }
    pub(crate) fn unwrap(&self, cipher: &[u8]) -> std::result::Result<Zeroizing<Vec<u8>>, Failure> {
        self.0.policy(self.0.key.0)?;
        self.0
            .decrypt(self.0.key.0, cipher, BCRYPT_SHA256_ALGORITHM)
    }
    pub(crate) fn cleanup(&mut self) -> std::result::Result<(), Failure> {
        if self.0.provider.0 == 0 {
            self.0.step("tpm-provider-open")?;
        }
        if self.0.key.0 == 0 {
            match open(self.0.provider.0, &self.0.name) {
                Ok(k) => self.0.key = k,
                Err(e) if e.code == Some(NTE_BAD_KEYSET.0 as u32) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        unsafe { NCryptDeleteKey(NCRYPT_KEY_HANDLE(self.0.key.0), 0) }
            .map_err(|e| failed(e, "combined-delete-tpm-key"))?;
        self.0.key.0 = 0;
        match open(self.0.provider.0, &self.0.name) {
            Err(e) if e.code == Some(NTE_BAD_KEYSET.0 as u32) => Ok(()),
            Err(e) => Err(e),
            Ok(_) => Err(invalid("combined-tpm-delete-readback")),
        }
    }
}
