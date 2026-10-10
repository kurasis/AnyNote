//! Shape-only direct attestation discovery. All claims remain unverified.
//! Input is owned by System32 webauthn.dll, never renderer-controlled pointers.
use super::{bindings::*, invalid, AttestationObservation};
use crate::hello::proof::Failure;

// Compare only documented literal formats. Unknown strings/identity are never
// copied or logged. The SDK guarantees a live null-terminated UTF-16 string.
unsafe fn literal(p: *const u16, expected: &str) -> bool {
    if p.is_null() {
        return false;
    }
    for (i, c) in expected.encode_utf16().chain(Some(0)).enumerate() {
        if unsafe { p.add(i).read_unaligned() } != c {
            return false;
        }
    }
    true
}

fn bounded(p: *const u8, len: u32, max: u32, empty: bool) -> Result<(), Failure> {
    if len > max || (!empty && len == 0) || (len != 0 && p.is_null()) {
        return Err(invalid("webauthn-attestation-buffer-shape"));
    }
    Ok(())
}

/// Safety: output and its pointed-to structures/strings must be live native
/// WebAuthn API output (or valid test allocations). Caller retains native RAII
/// ownership until this function returns. Certificate/payload bytes are unread.
pub(super) unsafe fn observe_attestation(
    output: &WEBAUTHN_CREDENTIAL_ATTESTATION,
    observation: &mut Option<AttestationObservation>,
) -> Result<(), Failure> {
    let mut format = "unsupported";
    for candidate in ["none", "tpm", "packed", "fido-u2f"] {
        if unsafe { literal(output.pwszFormatType, candidate) } {
            format = candidate;
            break;
        }
    }
    *observation = Some(AttestationObservation {
        requested: "direct",
        format,
        decode_type: output.dwAttestationDecodeType,
        statement_bytes: output.cbAttestation,
        object_bytes: output.cbAttestationObject,
        signature_bytes: None,
        cose_algorithm: None,
        certificate_count: None,
        certificate_bytes: None,
        certify_info_bytes: None,
        public_area_bytes: None,
        verification: "not-performed",
        subject: "synthetic-webauthn-prf-credential",
        prf_secret_protection: "not-verified",
        inner_rsa_key: "not-attested",
    });
    bounded(output.pbAttestation, output.cbAttestation, 65_536, true)?;
    bounded(
        output.pbAttestationObject,
        output.cbAttestationObject,
        65_536,
        false,
    )?;
    if format == "unsupported" {
        return Err(invalid("webauthn-attestation-format-unsupported"));
    }
    if format == "none" {
        if output.dwAttestationDecodeType != 0 || !output.pvAttestationDecode.is_null() {
            return Err(invalid("webauthn-attestation-none-decode-mismatch"));
        }
        return Ok(()); // A direct request may legitimately return no attestation.
    }
    if output.cbAttestation == 0 {
        return Err(invalid("webauthn-attestation-statement-missing"));
    }
    if output.dwAttestationDecodeType != WEBAUTHN_ATTESTATION_DECODE_COMMON as u32
        || output.pvAttestationDecode.is_null()
    {
        return Err(invalid("webauthn-attestation-common-decode-unavailable"));
    }
    // Check the version before accessing any later fields; reject future layouts.
    let p = output.pvAttestationDecode as *const WEBAUTHN_COMMON_ATTESTATION;
    if unsafe { (*p).dwVersion } != 1 {
        return Err(invalid("webauthn-attestation-common-version"));
    }
    let value = unsafe { &*p };
    bounded(value.pbSignature, value.cbSignature, 1024, false)?;
    if value.cX5c > 8 || (value.cX5c != 0 && value.pX5c.is_null()) {
        return Err(invalid("webauthn-attestation-certificate-count"));
    }
    let mut total = 0u32;
    for i in 0..value.cX5c as usize {
        let certificate = unsafe { &*value.pX5c.add(i) };
        bounded(certificate.pbData, certificate.cbData, 8192, false)?;
        total = total
            .checked_add(certificate.cbData)
            .ok_or_else(|| invalid("webauthn-attestation-certificate-budget"))?;
        if total > 32_768 {
            return Err(invalid("webauthn-attestation-certificate-budget"));
        }
    }
    if format == "tpm" {
        if !unsafe { literal(value.pwszVer, "2.0") } || value.cX5c == 0 {
            return Err(invalid("webauthn-attestation-tpm-version-or-certificate"));
        }
        bounded(value.pbCertInfo, value.cbCertInfo, 1024, false)?;
        bounded(value.pbPubArea, value.cbPubArea, 1024, false)?;
    } else if value.cbCertInfo != 0 || value.cbPubArea != 0 {
        return Err(invalid("webauthn-attestation-non-tpm-fields"));
    }
    let observation = observation.as_mut().unwrap();
    observation.signature_bytes = Some(value.cbSignature);
    observation.cose_algorithm = Some(value.lAlg);
    observation.certificate_count = Some(value.cX5c);
    observation.certificate_bytes = Some(total);
    if format == "tpm" {
        observation.certify_info_bytes = Some(value.cbCertInfo);
        observation.public_area_bytes = Some(value.cbPubArea);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
