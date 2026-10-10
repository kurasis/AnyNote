use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};

struct Fixture {
    info: Vec<u8>,
    public: Vec<u8>,
    subject: Vec<u8>,
    aik: Vec<u8>,
    #[cfg(windows)]
    other_aik: Vec<u8>,
    signature: Vec<u8>,
    pcp_claim: Vec<u8>,
    nonce: [u8; 32],
}
impl Fixture {
    fn new() -> Self {
        let value: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/hello/tpm-certification.json"
        )))
        .unwrap();
        let bytes = |key: &str| STANDARD.decode(value[key].as_str().unwrap()).unwrap();
        Self {
            info: bytes("certifyInfo"),
            public: bytes("publicArea"),
            subject: bytes("cngSubject"),
            aik: bytes("cngAik"),
            #[cfg(windows)]
            other_aik: bytes("cngOtherAik"),
            signature: bytes("signature"),
            pcp_claim: bytes("pcpWebAuthnClaim"),
            nonce: bytes("nonce").try_into().unwrap(),
        }
    }
    fn inspect(&self) -> Result<UnverifiedCertification<'_>, Error> {
        inspect(
            &self.info,
            &self.signature,
            &self.public,
            &self.subject,
            &self.nonce,
        )
    }
    fn error(&self) -> Error {
        match self.inspect() {
            Err(error) => error,
            Ok(_) => panic!("Rejected fixture accepted"),
        }
    }
    fn rebind_name(&mut self) {
        self.info[105..137].copy_from_slice(&Sha256::digest(&self.public));
    }
}

#[test]
fn pcp_frame_extracts_exact_independently_signed_components_without_trust() {
    let f = Fixture::new();
    assert_eq!(f.pcp_claim.len(), 731);
    let parsed = inspect_pcp_web_authn(&f.pcp_claim, &f.subject, &f.nonce).unwrap();
    assert_eq!(
        parsed.signature_input(),
        (f.info.as_slice(), f.signature.as_slice())
    );
    assert_eq!(
        parsed.signature_input().0.as_ptr(),
        f.pcp_claim[24..].as_ptr()
    );
    assert_eq!(
        parsed.signature_input().1.as_ptr(),
        f.pcp_claim[197..].as_ptr()
    );
    assert_eq!(crate::hello::readiness()["available"], false);
    assert_eq!(crate::hello::enroll().unwrap_err().code, "UNAVAILABLE");
    assert_eq!(crate::hello::unlock().unwrap_err().code, "UNAVAILABLE");
}

#[test]
fn pcp_every_truncation_extra_bytes_and_oversized_claim_fail() {
    let f = Fixture::new();
    for size in 0..f.pcp_claim.len() {
        assert!(inspect_pcp_web_authn(&f.pcp_claim[..size], &f.subject, &f.nonce).is_err());
    }
    let mut extra = f.pcp_claim.clone();
    extra.push(0);
    assert!(matches!(
        inspect_pcp_web_authn(&extra, &f.subject, &f.nonce),
        Err(Error::Length)
    ));
    assert!(matches!(
        inspect_pcp_web_authn(&[0; MAX_CLAIM + 1], &f.subject, &f.nonce),
        Err(Error::Length)
    ));
}

#[test]
fn pcp_rejects_wrong_magic_versions_header_extensions_and_endianness() {
    let f = Fixture::new();
    for (offset, values) in [
        (0, vec![0, 0x4157_414B, 0x5450_4D41]), // unknown/reversed/other provider
        (4, vec![0, 2, u32::MAX]),
        (8, vec![0, 23, 25, u32::MAX]),
    ] {
        for value in values {
            let mut claim = f.pcp_claim.clone();
            claim[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(matches!(
                inspect_pcp_web_authn(&claim, &f.subject, &f.nonce),
                Err(Error::Format)
            ));
        }
    }
    let mut big_endian = f.pcp_claim.clone();
    for field in big_endian[..24].as_chunks_mut::<4>().0 {
        field.reverse();
    }
    assert!(inspect_pcp_web_authn(&big_endian, &f.subject, &f.nonce).is_err());
}

#[test]
fn pcp_hostile_sizes_cannot_shift_or_hide_components() {
    let f = Fixture::new();
    for offset in [12, 16, 20] {
        let original = u32::from_le_bytes(f.pcp_claim[offset..offset + 4].try_into().unwrap());
        for value in [0, original - 1, original + 1, 4097, u32::MAX] {
            let mut claim = f.pcp_claim.clone();
            claim[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(inspect_pcp_web_authn(&claim, &f.subject, &f.nonce).is_err());
        }
    }
    // Preserve total size while stealing signed bytes into a neighboring field.
    let mut claim = f.pcp_claim.clone();
    claim[12..16].copy_from_slice(&172u32.to_le_bytes());
    claim[16..20].copy_from_slice(&257u32.to_le_bytes());
    assert!(inspect_pcp_web_authn(&claim, &f.subject, &f.nonce).is_err());
    // Complete, consistently sized envelopes must still obey component bounds.
    for (info, signature, public) in [
        (vec![0; 1025], f.signature.clone(), f.public.clone()),
        (f.info.clone(), f.signature.clone(), vec![0; 513]),
        (f.info.clone(), vec![0; 255], f.public.clone()),
        (f.info.clone(), vec![0; 257], f.public.clone()),
    ] {
        let mut claim = f.pcp_claim[..24].to_vec();
        for (offset, size) in [(12, info.len()), (16, signature.len()), (20, public.len())] {
            claim[offset..offset + 4].copy_from_slice(&(size as u32).to_le_bytes());
        }
        claim.extend(info);
        claim.extend(signature);
        claim.extend(public);
        assert!(inspect_pcp_web_authn(&claim, &f.subject, &f.nonce).is_err());
    }
}

#[test]
fn pcp_expected_native_key_nonce_and_certified_name_cannot_be_substituted() {
    let f = Fixture::new();
    assert!(matches!(
        inspect_pcp_web_authn(&f.pcp_claim, &f.aik, &f.nonce),
        Err(Error::SubjectMismatch)
    ));
    let mut nonce = f.nonce;
    nonce[0] ^= 1;
    assert!(matches!(
        inspect_pcp_web_authn(&f.pcp_claim, &f.subject, &nonce),
        Err(Error::NonceMismatch)
    ));
    let mut claim = f.pcp_claim.clone();
    claim[24 + 105] ^= 1;
    assert!(matches!(
        inspect_pcp_web_authn(&claim, &f.subject, &f.nonce),
        Err(Error::NameMismatch)
    ));
    let mut claim = f.pcp_claim.clone();
    claim[453 + 23] ^= 1;
    assert!(matches!(
        inspect_pcp_web_authn(&claim, &f.subject, &f.nonce),
        Err(Error::SubjectMismatch)
    ));
}

#[test]
fn pcp_rejects_component_reordering_and_tpm2b_or_tpmt_signature_framing() {
    let f = Fixture::new();
    let mut reordered = f.pcp_claim[..24].to_vec();
    reordered.extend(&f.info);
    reordered.extend(&f.public);
    reordered.extend(&f.signature);
    assert!(inspect_pcp_web_authn(&reordered, &f.subject, &f.nonce).is_err());
    let mut public_framed = f.pcp_claim.clone();
    public_framed[20..24].copy_from_slice(&280u32.to_le_bytes());
    public_framed.splice(453..453, 278u16.to_be_bytes());
    assert!(inspect_pcp_web_authn(&public_framed, &f.subject, &f.nonce).is_err());
    let mut signature_framed = f.pcp_claim.clone();
    signature_framed[16..20].copy_from_slice(&262u32.to_le_bytes());
    signature_framed.splice(197..197, [0, 0x14, 0, 0x0b, 1, 0]);
    assert!(inspect_pcp_web_authn(&signature_framed, &f.subject, &f.nonce).is_err());
}

#[cfg(windows)]
#[test]
fn actual_windows_pcp_signature_pipeline_keeps_valid_software_signer_untrusted() {
    let f = Fixture::new();
    let checked = inspect_pcp_web_authn(&f.pcp_claim, &f.subject, &f.nonce)
        .unwrap()
        .check_signature(&f.aik, || true)
        .unwrap();
    assert_eq!(
        checked.untrusted_certification().signature_input().0,
        f.info
    );
    assert_eq!(crate::hello::readiness()["available"], false);
    assert_eq!(crate::hello::enroll().unwrap_err().code, "UNAVAILABLE");
    assert_eq!(crate::hello::unlock().unwrap_err().code, "UNAVAILABLE");
}

#[cfg(windows)]
#[test]
fn actual_windows_pcp_pipeline_rejects_substitution_wrong_signer_and_stale_sessions() {
    let f = Fixture::new();
    for offset in [24 + 80, 197 + 100] {
        // Structurally valid clock or signature change.
        let mut claim = f.pcp_claim.clone();
        claim[offset] ^= 1;
        assert!(matches!(
            inspect_pcp_web_authn(&claim, &f.subject, &f.nonce)
                .unwrap()
                .check_signature(&f.aik, || true),
            Err(Error::Signature)
        ));
    }
    assert!(matches!(
        inspect_pcp_web_authn(&f.pcp_claim, &f.subject, &f.nonce)
            .unwrap()
            .check_signature(&f.other_aik, || true),
        Err(Error::Signature)
    ));
    for allowed in 0..3 {
        let calls = std::cell::Cell::new(0);
        assert!(matches!(
            inspect_pcp_web_authn(&f.pcp_claim, &f.subject, &f.nonce)
                .unwrap()
                .check_signature(&f.aik, || {
                    let old = calls.get();
                    calls.set(old + 1);
                    old < allowed
                }),
            Err(Error::SessionChanged)
        ));
    }
}

#[test]
fn independent_software_impostor_is_only_an_unverified_candidate() {
    let f = Fixture::new();
    assert_eq!(f.info.len(), 173);
    assert_eq!(f.public.len(), 278);
    let parsed = f.inspect().unwrap();
    assert_eq!(
        parsed.signature_input(),
        (f.info.as_slice(), f.signature.as_slice())
    );
    // Perfectly declared TPM metadata can be fabricated by software. Parsing
    // can never enable any vault path, including direct enrollment/unlock calls.
    assert_eq!(crate::hello::readiness()["available"], false);
    assert_eq!(crate::hello::enroll().unwrap_err().code, "UNAVAILABLE");
    assert_eq!(crate::hello::unlock().unwrap_err().code, "UNAVAILABLE");
}

#[test]
fn every_truncation_is_rejected_without_panicking() {
    let f = Fixture::new();
    for size in 0..f.info.len() {
        assert!(inspect(
            &f.info[..size],
            &f.signature,
            &f.public,
            &f.subject,
            &f.nonce
        )
        .is_err());
    }
    for size in 0..f.public.len() {
        assert!(inspect(
            &f.info,
            &f.signature,
            &f.public[..size],
            &f.subject,
            &f.nonce
        )
        .is_err());
    }
    for size in 0..f.subject.len() {
        assert!(inspect(
            &f.info,
            &f.signature,
            &f.public,
            &f.subject[..size],
            &f.nonce
        )
        .is_err());
    }
    for size in 0..f.signature.len() {
        assert!(inspect(
            &f.info,
            &f.signature[..size],
            &f.public,
            &f.subject,
            &f.nonce
        )
        .is_err());
    }
}

#[test]
fn oversized_trailing_and_hostile_length_inputs_are_rejected() {
    for component in 0..4 {
        let mut f = Fixture::new();
        match component {
            0 => f.info.push(0),
            1 => f.public.push(0),
            2 => f.subject.push(0),
            _ => f.signature.push(0),
        }
        assert!(f.inspect().is_err());
    }
    let mut f = Fixture::new();
    f.info = vec![0; 1025];
    assert_eq!(f.error(), Error::Length);
    let mut f = Fixture::new();
    f.public = vec![0; 513];
    assert_eq!(f.error(), Error::Length);
    for offset in [6, 42, 101, 137] {
        let mut f = Fixture::new();
        f.info[offset..offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(f.inspect().is_err());
    }
    let mut f = Fixture::new();
    f.public[20..22].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(f.error(), Error::Length);
}

#[test]
fn incorrect_magic_tag_nonce_names_and_unsafe_clock_fail() {
    for (offset, expected) in [
        (0, Error::Format),
        (4, Error::Format),
        (44, Error::NonceMismatch),
        (105, Error::NameMismatch),
        (8, Error::UnsupportedProfile),
        (139, Error::UnsupportedProfile),
        (92, Error::UnsupportedProfile),
    ] {
        let mut f = Fixture::new();
        f.info[offset] ^= 1;
        assert_eq!(f.error(), expected);
    }
    let mut f = Fixture::new();
    f.nonce[31] ^= 1;
    assert_eq!(f.error(), Error::NonceMismatch);
}

#[test]
fn a_different_real_rsa_subject_cannot_match_the_app_key() {
    let mut f = Fixture::new();
    f.subject = f.aik.clone();
    assert_eq!(f.error(), Error::SubjectMismatch);
    let mut f = Fixture::new();
    f.public[23] ^= 1;
    f.rebind_name();
    assert_eq!(f.error(), Error::SubjectMismatch);
}

#[test]
fn migratable_imported_signing_restricted_or_reserved_templates_fail() {
    for attributes in [
        0x20072 & !2,
        0x20072 & !16,
        0x20072 & !32,
        0x20072 & !0x20000,
        0x20072 | 0x40000,
        0x20072 | 0x10000,
        0x20072 | 0x800,
        0x20072 | 1,
        0x20072 | 0x80000,
    ] {
        let mut f = Fixture::new();
        f.public[4..8].copy_from_slice(&u32::to_be_bytes(attributes));
        f.rebind_name(); // Even a correctly hashed forged template fails.
        assert_eq!(f.error(), Error::UnsupportedProfile);
    }
}

#[test]
fn unsupported_tpm_algorithms_parameters_and_policy_sizes_fail() {
    for offset in [0, 2, 10, 12, 14, 16] {
        let mut f = Fixture::new();
        f.public[offset] ^= 1;
        f.rebind_name();
        assert_eq!(f.error(), Error::UnsupportedProfile);
    }
    for size in [1, 31, 33] {
        let mut f = Fixture::new();
        let policy: Vec<_> = (size as u16)
            .to_be_bytes()
            .into_iter()
            .chain(vec![0; size])
            .collect();
        f.public.splice(8..10, policy);
        f.rebind_name();
        assert_eq!(f.error(), Error::UnsupportedProfile);
    }
}

#[test]
fn exact_public_area_hash_binds_policy_and_exponent_encoding() {
    let mut f = Fixture::new();
    f.public
        .splice(8..10, 32u16.to_be_bytes().into_iter().chain([0x55; 32]));
    assert_eq!(f.error(), Error::NameMismatch);
    f.rebind_name();
    assert!(f.inspect().is_ok()); // Still an unsigned candidate.
    f.public[10] ^= 1;
    assert_eq!(f.error(), Error::NameMismatch);
    let mut f = Fixture::new();
    f.public[16..20].copy_from_slice(&65537u32.to_be_bytes());
    assert_eq!(f.error(), Error::NameMismatch);
    f.rebind_name();
    assert!(f.inspect().is_ok());
    // A Name must hash TPMT_PUBLIC, not its TPM2B size prefix.
    let mut f = Fixture::new();
    let framed: Vec<_> = (f.public.len() as u16)
        .to_be_bytes()
        .into_iter()
        .chain(f.public.iter().copied())
        .collect();
    f.info[105..137].copy_from_slice(&Sha256::digest(framed));
    assert_eq!(f.error(), Error::NameMismatch);
}

#[test]
fn noncanonical_private_or_unsupported_cng_public_blobs_fail() {
    for offset in [0, 4, 8, 12, 16, 20, 24, 27, 282] {
        let mut f = Fixture::new();
        if offset == 27 {
            f.subject[offset] &= 0x7F;
        } else {
            f.subject[offset] ^= 1;
        }
        assert_eq!(f.error(), Error::UnsupportedProfile);
    }
}

#[cfg(windows)]
#[test]
fn actual_windows_signature_check_never_promotes_a_software_impostor() {
    let f = Fixture::new();
    let checked = f
        .inspect()
        .unwrap()
        .check_signature(&f.aik, || true)
        .unwrap();
    assert_eq!(
        checked.untrusted_certification().signature_input().0,
        f.info
    );
    assert_eq!(crate::hello::readiness()["available"], false);
    assert_eq!(crate::hello::enroll().unwrap_err().code, "UNAVAILABLE");
    assert_eq!(crate::hello::unlock().unwrap_err().code, "UNAVAILABLE");
}

#[cfg(windows)]
#[test]
fn actual_windows_rejects_bad_signatures_wrong_aik_and_signed_data_substitution() {
    let mut f = Fixture::new();
    f.signature[100] ^= 1;
    assert!(matches!(
        f.inspect().unwrap().check_signature(&f.aik, || true),
        Err(Error::Signature)
    ));
    let f = Fixture::new();
    assert!(matches!(
        f.inspect().unwrap().check_signature(&f.other_aik, || true),
        Err(Error::Signature)
    ));
    let mut f = Fixture::new();
    f.info[80] ^= 1; // Clock bytes structurally valid.
    assert!(matches!(
        f.inspect().unwrap().check_signature(&f.aik, || true),
        Err(Error::Signature)
    ));
    let mut f = Fixture::new();
    f.public
        .splice(8..10, 32u16.to_be_bytes().into_iter().chain([0x55; 32]));
    f.rebind_name();
    assert!(matches!(
        f.inspect().unwrap().check_signature(&f.aik, || true),
        Err(Error::Signature)
    ));
}

#[cfg(windows)]
#[test]
fn actual_windows_signature_work_rejects_stale_sessions_before_and_after_calls() {
    for allowed in 0..3 {
        let f = Fixture::new();
        let calls = std::cell::Cell::new(0);
        let result = f.inspect().unwrap().check_signature(&f.aik, || {
            let old = calls.get();
            calls.set(old + 1);
            old < allowed
        });
        assert!(matches!(result, Err(Error::SessionChanged)));
        assert_eq!(calls.get(), allowed + 1);
    }
}
