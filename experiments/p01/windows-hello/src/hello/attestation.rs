//! Bounded TPM 2.0 certification inspection for an exact app RSA public key.
//! Parsed claims and even valid signatures are UNTRUSTED: AIK certificate/trust
//! verification and supported same-key authority acquisition are absent.
//! This module has no IPC, enrollment, credential, OS-key or provider access.
use sha2::{Digest, Sha256};

const MAX_CLAIM: usize = 4096;
const SHA256: u16 = 0x000B;
const RSA: u16 = 0x0001;
const NULL: u16 = 0x0010;
const REQUIRED_ATTRIBUTES: u32 = 0x0002_0032; // decrypt, fixedTPM/Parent, sensitiveDataOrigin
const ALLOWED_ATTRIBUTES: u32 = 0x0002_04F6;

/// Fixed error classifications; no key, claim, certificate or nonce is logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Format,
    UnsupportedProfile,
    SubjectMismatch,
    NonceMismatch,
    NameMismatch,
    Signature,
    SessionChanged,
}

struct Reader<'a> {
    remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let value = self.remaining.get(..length).ok_or(Error::Length)?;
        self.remaining = &self.remaining[length..];
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn le32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn sized(&mut self) -> Result<&'a [u8], Error> {
        let size = usize::from(self.u16()?);
        self.take(size)
    }
    fn finish(self) -> Result<(), Error> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(Error::Length)
        }
    }
}

/// Only the public RSA1 blob profile exported by the existing 2048-bit app key.
fn cng_modulus(blob: &[u8]) -> Result<&[u8], Error> {
    if blob.len() != 24 + 3 + 256 {
        return Err(Error::Length);
    }
    let mut r = Reader::new(blob);
    if r.le32()? != 0x3141_5352
        || r.le32()? != 2048
        || r.le32()? != 3
        || r.le32()? != 256
        || r.le32()? != 0
        || r.le32()? != 0
        || r.take(3)? != [1, 0, 1]
    {
        return Err(Error::UnsupportedProfile);
    }
    let modulus = r.take(256)?;
    if modulus[0] & 0x80 == 0 || modulus[255] & 1 == 0 {
        return Err(Error::UnsupportedProfile);
    }
    r.finish()?;
    Ok(modulus)
}

pub(crate) fn subject_name(area: &[u8], expected_public: &[u8]) -> Result<[u8; 34], Error> {
    // Name hashes exactly TPMT_PUBLIC, never a TPM2B or provider size prefix.
    let mut r = Reader::new(area);
    if r.u16()? != RSA || r.u16()? != SHA256 {
        return Err(Error::UnsupportedProfile);
    }
    let attributes = r.u32()?;
    if attributes & REQUIRED_ATTRIBUTES != REQUIRED_ATTRIBUTES
        || attributes & !ALLOWED_ATTRIBUTES != 0
    {
        return Err(Error::UnsupportedProfile);
    }
    let policy = r.sized()?;
    if !policy.is_empty() && policy.len() != 32 {
        return Err(Error::UnsupportedProfile);
    }
    // Unrestricted decrypt-only RSA, no symmetric cipher or fixed scheme.
    // Reject unsupported templates rather than guessing their wire layout.
    if r.u16()? != NULL || r.u16()? != NULL || r.u16()? != 2048 {
        return Err(Error::UnsupportedProfile);
    }
    if !matches!(r.u32()?, 0 | 65537) {
        return Err(Error::UnsupportedProfile);
    }
    let modulus = r.sized()?;
    if modulus != cng_modulus(expected_public)? {
        return Err(Error::SubjectMismatch);
    }
    r.finish()?;
    let mut name = [0; 34];
    name[..2].copy_from_slice(&SHA256.to_be_bytes());
    name[2..].copy_from_slice(&Sha256::digest(area));
    Ok(name)
}

fn sha256_name(name: &[u8]) -> Result<(), Error> {
    if name.len() != 34 || name[..2] != SHA256.to_be_bytes() {
        return Err(Error::UnsupportedProfile);
    }
    Ok(())
}

fn inspect_certify_info(bytes: &[u8], name: &[u8; 34], nonce: &[u8; 32]) -> Result<(), Error> {
    let mut r = Reader::new(bytes);
    if r.u32()? != 0xFF54_4347 || r.u16()? != 0x8017 {
        return Err(Error::Format);
    }
    sha256_name(r.sized()?)?; // qualifiedSigner; trust is NOT established by this name
    if r.sized()? != nonce {
        return Err(Error::NonceMismatch);
    }
    r.take(8 + 4 + 4)?; // clock, resetCount, restartCount; no app expiry inference
    if r.take(1)? != [1] {
        return Err(Error::UnsupportedProfile); // safe TPM clock profile only
    }
    r.take(8)?; // firmwareVersion is neither logged nor an eligibility flag
    if r.sized()? != name {
        return Err(Error::NameMismatch);
    }
    sha256_name(r.sized()?)?; // subject qualifiedName, no claimed parent trust
    r.finish()
}

/// Structurally matched, but unauthenticated. Not serializable or an eligibility
/// token. Its fields are private so callers cannot fabricate a checked claim.
pub struct UnverifiedCertification<'a> {
    certify_info: &'a [u8],
    signature: &'a [u8],
}

/// Inspect standard TPMS_ATTEST/TPMT_PUBLIC and a raw RSASSA/SHA256 signature.
/// Expected key/nonce must come from native state. For the documented Platform
/// KSP KAWA wrapper use inspect_pcp_web_authn; never guess another blob's layout.
/// This does NOT establish Passport support, signer trust or TPM binding.
pub fn inspect<'a>(
    certify_info: &'a [u8],
    signature: &'a [u8],
    subject_public_area: &[u8],
    expected_cng_public: &[u8],
    expected_nonce: &[u8; 32],
) -> Result<UnverifiedCertification<'a>, Error> {
    if certify_info.len() > 1024
        || subject_public_area.len() > 512
        || certify_info
            .len()
            .saturating_add(subject_public_area.len())
            .saturating_add(signature.len())
            > MAX_CLAIM
    {
        return Err(Error::Length);
    }
    if signature.len() != 256 {
        return Err(Error::UnsupportedProfile);
    }
    let name = subject_name(subject_public_area, expected_cng_public)?;
    inspect_certify_info(certify_info, &name, expected_nonce)?;
    Ok(UnverifiedCertification {
        certify_info,
        signature,
    })
}

impl UnverifiedCertification<'_> {
    /// Signature input only, not a secret or authenticated TPM evidence. The
    /// caller still needs a supported acquisition route and trusted AIK chain.
    pub fn signature_input(&self) -> (&[u8], &[u8]) {
        (self.certify_info, self.signature)
    }
}

#[cfg(windows)]
mod signature;

mod pcp;
#[cfg(test)]
pub use pcp::inspect_pcp_web_authn;

#[cfg(test)]
mod tests;
