//! Fixed read-only TPM2_ReadPublic wire format. No raw command IPC.
//! A local OS/TBS observation is not a signed attestation or Hello authorization.
use crate::hello::{
    attestation,
    prf::invalid,
    proof::{Failure, Outcome},
};

pub(super) const MAX_RESPONSE: usize = 1024;

pub(super) fn command(handle: u32) -> [u8; 14] {
    let mut command = [0x80, 1, 0, 0, 0, 14, 0, 0, 1, 0x73, 0, 0, 0, 0];
    command[10..].copy_from_slice(&handle.to_be_bytes());
    command
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Failure> {
        let bytes = self
            .0
            .get(..count)
            .ok_or_else(|| invalid("tpm-read-public-length"))?;
        self.0 = &self.0[count..];
        Ok(bytes)
    }
    fn sized(&mut self) -> Result<&'a [u8], Failure> {
        let size = u16::from_be_bytes(self.take(2)?.try_into().unwrap());
        self.take(size as usize)
    }
}

pub(super) fn inspect(response: &[u8], cng_public: &[u8], pcp_name: &[u8]) -> Result<u32, Failure> {
    if !(10..=MAX_RESPONSE).contains(&response.len()) {
        return Err(invalid("tpm-read-public-length"));
    }
    let mut r = Reader(response);
    if r.take(2)? != [0x80, 1] {
        return Err(invalid("tpm-read-public-response-tag"));
    }
    let size = u32::from_be_bytes(r.take(4)?.try_into().unwrap());
    if size as usize != response.len() {
        return Err(invalid("tpm-read-public-length"));
    }
    let code = u32::from_be_bytes(r.take(4)?.try_into().unwrap());
    if code != 0 {
        return Err(Failure {
            status: Outcome::Failed,
            code: Some(code),
            operation: Some("tpm-read-public-response"),
        });
    }
    let area = r.sized()?;
    let expected_name = attestation::subject_name(area, cng_public).map_err(|error| {
        invalid(match error {
            attestation::Error::SubjectMismatch => "tpm-read-public-key-mismatch",
            attestation::Error::UnsupportedProfile => "tpm-read-public-template-unsupported",
            _ => "tpm-read-public-area-invalid",
        })
    })?;
    let name = r.sized()?;
    if name != expected_name || pcp_name != expected_name {
        return Err(invalid("tpm-read-public-name-mismatch"));
    }
    let qualified = r.sized()?;
    if qualified.len() != 34 || qualified[..2] != [0, 0x0b] || !r.0.is_empty() {
        return Err(invalid("tpm-read-public-qualified-name-shape"));
    }
    // subject_name validated the complete area including decrypt-only, fixedTPM,
    // fixedParent, sensitiveDataOrigin, SHA-256 Name and exact CNG RSA modulus.
    Ok(u32::from_be_bytes(area[4..8].try_into().unwrap()))
}

#[cfg(test)]
mod tests;
