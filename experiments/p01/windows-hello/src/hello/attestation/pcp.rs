//! Documented Platform KSP WebAuthn certification wrapper, not Passport/VBS.
//! Contract: Microsoft win32metadata 1bfb76d ncrypt.h and Chromium 544a340
//! crypto/unexportable_key_win.cc. No provider/authority acquisition or trust.
use super::{inspect, Error, Reader, UnverifiedCertification, MAX_CLAIM};

const HEADER_SIZE: u32 = 24;

// Tie wire layout to maintained Windows SDK bindings on both GNU and MSVC.
#[cfg(windows)]
const _: () = {
    use std::mem::{offset_of, size_of};
    use windows::Win32::Security::Cryptography::NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT as Header;
    assert!(size_of::<Header>() == HEADER_SIZE as usize);
    assert!(offset_of!(Header, Magic) == 0);
    assert!(offset_of!(Header, Version) == 4);
    assert!(offset_of!(Header, HeaderSize) == 8);
    assert!(offset_of!(Header, cbCertifyInfo) == 12);
    assert!(offset_of!(Header, cbSignature) == 16);
    assert!(offset_of!(Header, cbTpmPublic) == 20);
};

/// Inspect the exact version-1 NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT.
/// All six header DWORDs are little endian; embedded TPM structures retain
/// their big-endian encoding. Signature is raw RSA, not TPMT_SIGNATURE.
/// No allocations, size-query retries, alternate framing or fallback parsing.
/// Expected subject and nonce must originate in native state, not the claim.
/// The result remains UNTRUSTED, even after a successful signature check.
pub fn inspect_pcp_web_authn<'a>(
    claim: &'a [u8],
    expected_cng_public: &[u8],
    expected_nonce: &[u8; 32],
) -> Result<UnverifiedCertification<'a>, Error> {
    if claim.len() > MAX_CLAIM {
        return Err(Error::Length);
    }
    let mut r = Reader::new(claim);
    if r.le32()? != 0x4B41_5741 || r.le32()? != 1 || r.le32()? != HEADER_SIZE {
        return Err(Error::Format);
    }
    let info_size: usize = r.le32()?.try_into().map_err(|_| Error::Length)?;
    let signature_size: usize = r.le32()?.try_into().map_err(|_| Error::Length)?;
    let public_size: usize = r.le32()?.try_into().map_err(|_| Error::Length)?;
    // Checked slices avoid attacker-controlled length sums/overflow/allocation.
    let info = r.take(info_size)?;
    let signature = r.take(signature_size)?;
    let public_area = r.take(public_size)?;
    r.finish()?;
    inspect(
        info,
        signature,
        public_area,
        expected_cng_public,
        expected_nonce,
    )
}
