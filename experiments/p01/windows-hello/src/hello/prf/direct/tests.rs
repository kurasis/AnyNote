use super::*;
use std::ptr;

struct Fixture {
    format: Vec<u16>,
    version: Vec<u16>,
    buffer: Vec<u8>,
    certificates: Vec<WEBAUTHN_X5C>,
    common: Box<WEBAUTHN_COMMON_ATTESTATION>,
    output: WEBAUTHN_CREDENTIAL_ATTESTATION,
}
impl Fixture {
    fn new() -> Self {
        let format: Vec<_> = "tpm".encode_utf16().chain(Some(0)).collect();
        let version: Vec<_> = "2.0".encode_utf16().chain(Some(0)).collect();
        // Shape-only software impostor: bytes are deliberately NOT certs/claims.
        let mut buffer = vec![0xAA; 8192];
        let mut certificates = vec![WEBAUTHN_X5C {
            cbData: 64,
            pbData: buffer.as_mut_ptr(),
        }];
        let mut common = Box::new(WEBAUTHN_COMMON_ATTESTATION {
            dwVersion: 1,
            cbSignature: 64,
            pbSignature: buffer.as_mut_ptr(),
            cX5c: 1,
            pX5c: certificates.as_mut_ptr(),
            pwszVer: version.as_ptr(),
            cbCertInfo: 173,
            pbCertInfo: buffer.as_mut_ptr(),
            cbPubArea: 128,
            pbPubArea: buffer.as_mut_ptr(),
            ..Default::default()
        });
        let output = WEBAUTHN_CREDENTIAL_ATTESTATION {
            pwszFormatType: format.as_ptr(),
            cbAttestation: 500,
            pbAttestation: buffer.as_mut_ptr(),
            cbAttestationObject: 700,
            pbAttestationObject: buffer.as_mut_ptr(),
            dwAttestationDecodeType: WEBAUTHN_ATTESTATION_DECODE_COMMON as u32,
            pvAttestationDecode: (&mut *common as *mut WEBAUTHN_COMMON_ATTESTATION).cast(),
            ..Default::default()
        };
        Self {
            format,
            version,
            buffer,
            certificates,
            common,
            output,
        }
    }
    fn format(&mut self, name: &str) {
        self.format = name.encode_utf16().chain(Some(0)).collect();
        self.output.pwszFormatType = self.format.as_ptr();
    }
    fn inspect(&self) -> (Result<(), Failure>, Option<AttestationObservation>) {
        let mut observation = None;
        let result = unsafe { observe_attestation(&self.output, &mut observation) };
        (result, observation)
    }
}

#[test]
fn shape_only_software_tpm_impostor_records_sizes_but_never_enables_unlock() {
    let f = Fixture::new();
    let (result, observation) = f.inspect();
    result.unwrap();
    let json = serde_json::to_value(observation.unwrap()).unwrap();
    assert_eq!(json["format"], "tpm");
    assert_eq!(json["certificateCount"], 1);
    assert_eq!(json["certificateBytes"], 64);
    assert_eq!(json["certifyInfoBytes"], 173);
    assert_eq!(json["verification"], "not-performed");
    assert_eq!(json["prfSecretProtection"], "not-verified");
    assert_eq!(json["innerRsaKey"], "not-attested");
    assert!(json.as_object().unwrap().keys().all(|k| [
        "requested",
        "format",
        "decodeType",
        "statementBytes",
        "objectBytes",
        "signatureBytes",
        "coseAlgorithm",
        "certificateCount",
        "certificateBytes",
        "certifyInfoBytes",
        "publicAreaBytes",
        "verification",
        "subject",
        "prfSecretProtection",
        "innerRsaKey"
    ]
    .contains(&k.as_str())));
    assert_eq!(crate::hello::readiness()["available"], false);
    assert_eq!(crate::hello::enroll().unwrap_err().code, "UNAVAILABLE");
    assert_eq!(crate::hello::unlock().unwrap_err().code, "UNAVAILABLE");
}

#[test]
fn direct_none_is_an_observation_not_tpm_attestation() {
    let mut f = Fixture::new();
    f.format("none");
    f.output.dwAttestationDecodeType = 0;
    f.output.pvAttestationDecode = ptr::null_mut();
    f.output.cbAttestation = 0;
    f.output.pbAttestation = ptr::null_mut();
    let (result, value) = f.inspect();
    result.unwrap();
    let value = value.unwrap();
    assert_eq!(value.format, "none");
    assert_eq!(value.certificate_count, None);
    assert_eq!(value.verification, "not-performed");
    f.output.pvAttestationDecode = (&mut *f.common as *mut WEBAUTHN_COMMON_ATTESTATION).cast();
    assert!(f.inspect().0.is_err());
}

#[test]
fn unknown_format_identity_is_never_copied_and_unknown_decode_or_layout_fails() {
    let mut f = Fixture::new();
    f.format("private-device-identity");
    let (result, value) = f.inspect();
    assert!(result.is_err());
    assert_eq!(value.unwrap().format, "unsupported");
    f.output.pwszFormatType = ptr::null();
    assert!(f.inspect().0.is_err());
    for kind in [0, 2, u32::MAX] {
        let mut f = Fixture::new();
        f.output.dwAttestationDecodeType = kind;
        assert!(f.inspect().0.is_err());
    }
    for version in [0, 2, u32::MAX] {
        let mut f = Fixture::new();
        f.common.dwVersion = version;
        assert!(f.inspect().0.is_err());
    }
    let mut f = Fixture::new();
    f.output.pvAttestationDecode = ptr::null_mut();
    assert!(f.inspect().0.is_err());
}

#[test]
fn native_buffer_shapes_refuse_empty_null_and_oversized_fields() {
    for field in 0..5 {
        for size in [0, 65_537, u32::MAX] {
            let mut f = Fixture::new();
            match field {
                0 => f.output.cbAttestationObject = size,
                1 => f.output.cbAttestation = size,
                2 => f.common.cbSignature = size,
                3 => f.common.cbCertInfo = size,
                _ => f.common.cbPubArea = size,
            }
            assert!(f.inspect().0.is_err());
        }
        let mut f = Fixture::new();
        match field {
            0 => f.output.pbAttestationObject = ptr::null_mut(),
            1 => f.output.pbAttestation = ptr::null_mut(),
            2 => f.common.pbSignature = ptr::null_mut(),
            3 => f.common.pbCertInfo = ptr::null_mut(),
            _ => f.common.pbPubArea = ptr::null_mut(),
        }
        assert!(f.inspect().0.is_err());
    }
}

#[test]
fn certificate_count_individual_and_total_budgets_prevent_unbounded_array_access() {
    for count in [0, 9, u32::MAX] {
        let mut f = Fixture::new();
        f.common.cX5c = count;
        assert!(f.inspect().0.is_err());
    }
    let mut f = Fixture::new();
    f.common.pX5c = ptr::null_mut();
    assert!(f.inspect().0.is_err());
    for size in [0, 8193, u32::MAX] {
        let mut f = Fixture::new();
        f.certificates[0].cbData = size;
        assert!(f.inspect().0.is_err());
    }
    let mut f = Fixture::new();
    f.certificates[0].pbData = ptr::null_mut();
    assert!(f.inspect().0.is_err());
    let mut f = Fixture::new();
    f.certificates = vec![
        WEBAUTHN_X5C {
            cbData: 8192,
            pbData: f.buffer.as_mut_ptr()
        };
        5
    ];
    f.common.cX5c = 5;
    f.common.pX5c = f.certificates.as_mut_ptr();
    assert!(f.inspect().0.is_err());
    f.common.cX5c = 4;
    let (result, value) = f.inspect();
    result.unwrap();
    assert_eq!(value.unwrap().certificate_bytes, Some(32_768));
}

#[test]
fn wrong_tpm_version_and_non_tpm_field_substitution_fail_without_fallback() {
    let mut f = Fixture::new();
    f.version = "1.2".encode_utf16().chain(Some(0)).collect();
    f.common.pwszVer = f.version.as_ptr();
    assert!(f.inspect().0.is_err());
    for name in ["packed", "fido-u2f"] {
        let mut f = Fixture::new();
        f.format(name);
        assert!(f.inspect().0.is_err());
        f.common.cbCertInfo = 0;
        f.common.cbPubArea = 0;
        f.common.cX5c = 0;
        f.common.pX5c = ptr::null_mut();
        let (result, value) = f.inspect();
        result.unwrap();
        assert_eq!(value.unwrap().certificate_count, Some(0));
    }
}
