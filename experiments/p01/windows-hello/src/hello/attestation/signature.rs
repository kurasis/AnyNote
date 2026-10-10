//! Public signature verification only. It supplies no TPM/AIK trust decision.
use super::{cng_modulus, Error, UnverifiedCertification};
use sha2::{Digest, Sha256};
use windows::Win32::Security::Cryptography::*;

struct Algorithm(BCRYPT_ALG_HANDLE);
impl Drop for Algorithm {
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

/// A correct signature from an UNTRUSTED AIK public key. It is not an eligible
/// protection key, verified TPM, authentication result or unlock capability.
pub struct SignatureCheckedCertification<'a> {
    certification: UnverifiedCertification<'a>,
}
impl SignatureCheckedCertification<'_> {
    pub fn untrusted_certification(&self) -> &UnverifiedCertification<'_> {
        &self.certification
    }
}

impl<'a> UnverifiedCertification<'a> {
    /// Check RSASSA/PKCS#1 SHA256 using the fixed Windows primitive provider.
    /// Signature padding here does not approve PKCS#1 credential ENCRYPTION.
    /// AIK certificate chain/EKU/revocation and same-key acquisition remain
    /// required; even an attacker-owned software key can pass this function.
    /// Native callers must bind `current` to their actual request/session.
    pub fn check_signature(
        self,
        aik_cng_public: &[u8],
        current: impl Fn() -> bool,
    ) -> Result<SignatureCheckedCertification<'a>, Error> {
        if !current() {
            return Err(Error::SessionChanged);
        }
        cng_modulus(aik_cng_public)?;
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
        .map_err(|_| Error::Signature)?;
        let algorithm = Algorithm(algorithm);
        let mut key = BCRYPT_KEY_HANDLE::default();
        unsafe {
            BCryptImportKeyPair(
                algorithm.0,
                None,
                BCRYPT_RSAPUBLIC_BLOB,
                &mut key,
                aik_cng_public,
                0,
            )
        }
        .ok()
        .map_err(|_| Error::Signature)?;
        // Drop the public key before its algorithm handle on every exit path.
        let key = PublicKey(key);
        if !current() {
            return Err(Error::SessionChanged);
        }
        let digest = Sha256::digest(self.certify_info);
        let padding = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
        };
        let result = unsafe {
            BCryptVerifySignature(
                key.0,
                Some((&padding as *const BCRYPT_PKCS1_PADDING_INFO).cast()),
                &digest,
                self.signature,
                BCRYPT_PAD_PKCS1,
            )
        }
        .ok();
        if !current() {
            return Err(Error::SessionChanged);
        }
        result.map_err(|_| Error::Signature)?;
        Ok(SignatureCheckedCertification {
            certification: self,
        })
    }
}
