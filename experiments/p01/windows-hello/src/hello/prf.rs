//! Fixed synthetic WebAuthn PRF experiments; never vault enrollment or unlock.
use super::proof::{Failure, Outcome};
use serde::Serialize;
use sha2::{Digest, Sha256};

const RP: &str = "p01.anynote.desktop.invalid";

#[cfg(all(windows, test))]
mod abi;
#[cfg(windows)]
#[allow(
    dead_code,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    clippy::upper_case_acronyms
)]
mod bindings;
#[cfg(windows)]
mod direct;
#[cfg(windows)]
pub(super) mod windows;
#[cfg(windows)]
pub use windows::run;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Experiment {
    Capability,
    Synthetic,
    DirectAttestation,
}

const CAPABILITY: [&str; 4] = [
    "webauthn-load",
    "webauthn-api",
    "hello-platform",
    "hello-route",
];
const SYNTHETIC: [&str; 9] = [
    "webauthn-load",
    "webauthn-api",
    "hello-platform",
    "hello-route",
    "prf-create",
    "prf-first",
    "prf-repeat",
    "prf-changed",
    "prf-roundtrip",
];
const DIRECT: [&str; 5] = [
    "webauthn-load",
    "webauthn-api",
    "hello-platform",
    "hello-route",
    "webauthn-direct-create",
];

/// Bounded native API observations only. No raw claim, certificate, identity,
/// credential ID, challenge or PRF output is serializable through this type.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationObservation {
    pub requested: &'static str,
    pub format: &'static str,
    pub decode_type: u32,
    pub statement_bytes: u32,
    pub object_bytes: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_bytes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cose_algorithm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_bytes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certify_info_bytes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_area_bytes: Option<u32>,
    pub verification: &'static str,
    pub subject: &'static str,
    pub prf_secret_protection: &'static str,
    pub inner_rsa_key: &'static str,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_build: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hello_candidates: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hello_locked: Option<bool>,
    pub routing: &'static str,
    pub tpm_binding: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrfCheck {
    pub test: &'static str,
    pub status: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<&'static str>,
    pub purpose: &'static str,
    pub algorithm: &'static str,
    pub eligible: bool,
    pub enrolled: bool,
    pub unlocked: bool,
    pub outcome: &'static str,
    pub checks: Vec<PrfCheck>,
    pub webauthn: Capability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_attestation: Option<AttestationObservation>,
    pub remaining: [&'static str; 4],
}

pub(super) trait Provider {
    fn step(&mut self, step: &'static str) -> Result<(), Failure>;
    fn cleanup(&mut self) -> Result<(), Failure>;
    fn capability(&self) -> Capability;
    fn attestation(&self) -> Option<AttestationObservation> {
        None
    }
}

pub(super) fn check(test: &'static str, result: Result<(), Failure>) -> PrfCheck {
    match result {
        Ok(()) => PrfCheck {
            test,
            status: Outcome::Passed,
            native_code: None,
            operation: None,
        },
        Err(e) => PrfCheck {
            test,
            status: e.status,
            native_code: e.code.map(|c| format!("0x{c:08X}")),
            operation: e.operation,
        },
    }
}

pub(super) fn exercise(
    provider: &mut impl Provider,
    current: impl Fn() -> bool,
    experiment: Experiment,
) -> Report {
    let mut report = Report {
        version: 1,
        source_commit: option_env!("PASSKEY_SOURCE_COMMIT"),
        purpose: match experiment {
            Experiment::Capability => "webauthn-prf-capability",
            Experiment::Synthetic => "synthetic-webauthn-prf",
            Experiment::DirectAttestation => "synthetic-webauthn-direct-attestation",
        },
        algorithm: if experiment == Experiment::DirectAttestation {
            "webauthn-es256-direct-attestation"
        } else {
            "webauthn-prf-aes256gcm"
        },
        eligible: false,
        enrolled: false,
        unlocked: false,
        outcome: "blocked",
        checks: Vec::new(),
        webauthn: Capability::default(),
        direct_attestation: None,
        remaining: [
            "per-key-tpm-proof",
            "fresh-authorization-proof",
            "fresh-process-proof",
            "account-machine-copy-proof",
        ],
    };
    let steps = match experiment {
        Experiment::Capability => &CAPABILITY[..],
        Experiment::Synthetic => &SYNTHETIC[..],
        Experiment::DirectAttestation => &DIRECT[..],
    };
    let mut running = true;
    for step in steps {
        if !running {
            report.checks.push(PrfCheck {
                test: step,
                status: Outcome::NotRun,
                native_code: None,
                operation: None,
            });
            continue;
        }
        let result = if current() {
            provider.step(step)
        } else {
            Err(interrupted("prf-session-changed"))
        };
        let result = if result.is_ok() && !current() {
            Err(interrupted("prf-session-changed"))
        } else {
            result
        };
        let value = check(step, result);
        running = value.status == Outcome::Passed;
        if !running {
            report.outcome = match value.status {
                Outcome::Cancelled => "cancelled",
                Outcome::Interrupted => "interrupted",
                _ => "blocked",
            };
        }
        report.checks.push(value);
    }
    if experiment != Experiment::Capability {
        let cleanup = check("test-passkey-delete", provider.cleanup());
        if cleanup.status != Outcome::Passed {
            running = false;
            report.outcome = "blocked";
        }
        report.checks.push(cleanup);
    }
    report.webauthn = provider.capability();
    report.direct_attestation = provider.attestation();
    if running && !current() {
        running = false;
        report.outcome = "interrupted";
    }
    if running {
        report.outcome = match experiment {
            Experiment::Capability => "webauthn-capability-observed",
            Experiment::Synthetic => "prf-roundtrip-passed",
            Experiment::DirectAttestation => match report.direct_attestation.as_ref() {
                Some(value) if value.format == "none" => "direct-attestation-not-provided",
                Some(_) => "direct-attestation-returned-unverified",
                None => "blocked",
            },
        };
    }
    report
}

pub(super) fn interrupted(operation: &'static str) -> Failure {
    Failure {
        status: Outcome::Interrupted,
        code: None,
        operation: Some(operation),
    }
}
pub(super) fn invalid(operation: &'static str) -> Failure {
    Failure::failed().at(operation)
}

#[cfg(test)]
fn auth_context(data: &[u8], credential: Option<&[u8]>) -> std::result::Result<(), Failure> {
    auth_context_for(RP, data, credential)
}
fn auth_context_for(
    rp: &str,
    data: &[u8],
    credential: Option<&[u8]>,
) -> std::result::Result<(), Failure> {
    if data.len() < 37
        || data[..32] != Sha256::digest(rp.as_bytes())[..]
        || data[32] & 5 != 5
        || data[32] & 0x18 != 0
    {
        return Err(invalid("prf-rp-user-verification-or-backup-flags"));
    }
    if let Some(id) = credential {
        // W3C: rpIdHash(32) + flags(1) + signCount(4) + AAGUID(16)
        // + credentialIdLength(2). The ID begins immediately after byte 54.
        const CREDENTIAL_START: usize = 32 + 1 + 4 + 16 + 2;
        const LENGTH_START: usize = CREDENTIAL_START - 2;
        if data.len() < CREDENTIAL_START || data[32] & 0x40 == 0 {
            return Err(invalid("prf-created-credential-context"));
        }
        let len = u16::from_be_bytes([data[LENGTH_START], data[LENGTH_START + 1]]) as usize;
        let end = CREDENTIAL_START + len;
        if len == 0
            || len != id.len()
            || data.get(CREDENTIAL_START..end) != Some(id)
            || data.len() <= end
        {
            return Err(invalid("prf-created-credential-context"));
        }
    }
    Ok(())
}

fn roundtrip(secret: &[u8; 32]) -> Result<(), Failure> {
    use libsodium_rs::crypto_aead::aes256gcm as aes;
    use zeroize::Zeroizing;
    if !aes::is_available() {
        return Err(invalid("aes256gcm-unavailable"));
    }
    let key = aes::Key::from_bytes(secret).map_err(|_| invalid("aes256gcm-key"))?;
    let nonce = aes::Nonce::generate();
    let mut message = Zeroizing::new([0u8; 32]);
    libsodium_rs::random::fill_bytes(message.as_mut_slice());
    let aad = b"PassKey Local synthetic PRF v1";
    let mut encrypted = aes::encrypt(message.as_slice(), Some(aad), &nonce, &key)
        .map_err(|_| invalid("prf-aes256gcm-encrypt"))?;
    let decrypted = Zeroizing::new(
        aes::decrypt(&encrypted, Some(aad), &nonce, &key)
            .map_err(|_| invalid("prf-aes256gcm-decrypt"))?,
    );
    if !libsodium_rs::utils::memcmp(&decrypted, message.as_slice()) {
        return Err(invalid("prf-aes256gcm-secret-mismatch"));
    }
    if aes::decrypt(&encrypted, Some(b"changed binding"), &nonce, &key).is_ok() {
        return Err(invalid("prf-aes256gcm-aad-accepted"));
    }
    let other = aes::Key::generate();
    if aes::decrypt(&encrypted, Some(aad), &nonce, &other).is_ok() {
        return Err(invalid("prf-aes256gcm-wrong-key-accepted"));
    }
    encrypted[0] ^= 1;
    if aes::decrypt(&encrypted, Some(aad), &nonce, &key).is_ok() {
        return Err(invalid("prf-aes256gcm-tamper-accepted"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        calls: Vec<&'static str>,
        failure: Option<&'static str>,
        delete_failure: bool,
        attestation: Option<AttestationObservation>,
    }
    impl Provider for Fake {
        fn step(&mut self, s: &'static str) -> Result<(), Failure> {
            self.calls.push(s);
            if self.failure == Some(s) {
                Err(invalid("synthetic-failure"))
            } else {
                Ok(())
            }
        }
        fn cleanup(&mut self) -> Result<(), Failure> {
            self.calls.push("delete");
            if self.delete_failure {
                Err(invalid("synthetic-delete-failure"))
            } else {
                Ok(())
            }
        }
        fn capability(&self) -> Capability {
            Capability {
                api_version: Some(9),
                routing: "display-name-candidate",
                tpm_binding: "not-verified",
                ..Default::default()
            }
        }
        fn attestation(&self) -> Option<AttestationObservation> {
            self.attestation.clone()
        }
    }
    fn fake() -> Fake {
        Fake {
            calls: Vec::new(),
            failure: None,
            delete_failure: false,
            attestation: None,
        }
    }
    fn direct_observation(format: &'static str) -> AttestationObservation {
        AttestationObservation {
            requested: "direct",
            format,
            decode_type: 0,
            statement_bytes: 1,
            object_bytes: 64,
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
        }
    }
    #[test]
    fn direct_mode_has_only_creation_and_exact_cleanup_never_prf_assertions() {
        let mut p = fake();
        let r = exercise(&mut p, || true, Experiment::DirectAttestation);
        assert_eq!(
            p.calls,
            DIRECT.into_iter().chain(["delete"]).collect::<Vec<_>>()
        );
        assert_eq!(r.checks.len(), 6);
        assert_eq!(r.purpose, "synthetic-webauthn-direct-attestation");
        assert_eq!(r.algorithm, "webauthn-es256-direct-attestation");
        assert_eq!(
            r.outcome, "blocked",
            "Missing observation cannot be success"
        );
    }
    #[test]
    fn direct_none_or_tpm_observations_never_claim_hardware_or_prf_trust() {
        for format in ["none", "tpm", "packed", "fido-u2f"] {
            let mut p = fake();
            p.attestation = Some(direct_observation(format));
            let r = exercise(&mut p, || true, Experiment::DirectAttestation);
            assert_eq!(
                r.outcome,
                if format == "none" {
                    "direct-attestation-not-provided"
                } else {
                    "direct-attestation-returned-unverified"
                }
            );
            assert!(!r.eligible && !r.enrolled && !r.unlocked);
            assert_eq!(r.remaining.len(), 4);
            let json = serde_json::to_value(r).unwrap();
            assert_eq!(json["directAttestation"]["verification"], "not-performed");
            assert_eq!(
                json["directAttestation"]["prfSecretProtection"],
                "not-verified"
            );
            assert_eq!(json["directAttestation"]["innerRsaKey"], "not-attested");
            assert_eq!(json["webauthn"]["tpmBinding"], "not-verified");
        }
    }
    #[test]
    fn direct_every_failure_and_deletion_failure_are_visible_and_stop_later_work() {
        for (i, stage) in DIRECT.iter().enumerate() {
            let mut p = fake();
            p.failure = Some(stage);
            let r = exercise(&mut p, || true, Experiment::DirectAttestation);
            assert_eq!(&p.calls[..i + 1], &DIRECT[..i + 1]);
            assert_eq!(p.calls.last(), Some(&"delete"));
            assert!(r.checks[i + 1..5]
                .iter()
                .all(|c| c.status == Outcome::NotRun));
            assert_eq!(r.outcome, "blocked");
        }
        let mut p = fake();
        p.attestation = Some(direct_observation("none"));
        p.delete_failure = true;
        let r = exercise(&mut p, || true, Experiment::DirectAttestation);
        assert_eq!(r.outcome, "blocked");
        assert_eq!(r.checks.last().unwrap().status, Outcome::Failed);
    }
    #[test]
    fn direct_invalidation_before_after_every_stage_and_during_cleanup_discards_success() {
        for limit in 0..=DIRECT.len() * 2 {
            let calls = std::cell::Cell::new(0);
            let mut p = fake();
            p.attestation = Some(direct_observation("none"));
            let r = exercise(
                &mut p,
                || {
                    let n = calls.get();
                    calls.set(n + 1);
                    n < limit
                },
                Experiment::DirectAttestation,
            );
            assert_eq!(r.outcome, "interrupted");
            assert_eq!(p.calls.last(), Some(&"delete"));
            assert!(!r.eligible && !r.enrolled && !r.unlocked);
        }
    }
    #[test]
    fn capability_never_creates_or_deletes_a_credential() {
        let mut p = fake();
        let r = exercise(&mut p, || true, Experiment::Capability);
        assert_eq!(p.calls, CAPABILITY);
        assert_eq!(r.checks.len(), 4);
        assert_eq!(r.outcome, "webauthn-capability-observed");
        assert!(!r.eligible && !r.enrolled && !r.unlocked);
        assert_eq!(r.remaining.len(), 4);
    }
    #[test]
    fn every_failure_stops_later_operations_but_always_cleans_up() {
        for (i, stage) in SYNTHETIC.iter().enumerate() {
            let mut p = fake();
            p.failure = Some(stage);
            let r = exercise(&mut p, || true, Experiment::Synthetic);
            assert_eq!(&p.calls[..i + 1], &SYNTHETIC[..i + 1]);
            assert_eq!(p.calls.last(), Some(&"delete"));
            assert!(r.checks[i + 1..9]
                .iter()
                .all(|c| c.status == Outcome::NotRun));
            assert_eq!(r.outcome, "blocked");
            assert!(!r.eligible && !r.enrolled && !r.unlocked);
        }
    }
    #[test]
    fn invalidated_request_does_no_crypto_and_delete_failure_cannot_be_success() {
        let mut p = fake();
        let r = exercise(&mut p, || false, Experiment::Synthetic);
        assert_eq!(p.calls, ["delete"]);
        assert_eq!(r.outcome, "interrupted");
        let mut p = fake();
        p.delete_failure = true;
        let r = exercise(&mut p, || true, Experiment::Synthetic);
        assert_eq!(r.outcome, "blocked");
        assert_eq!(r.checks.last().unwrap().status, Outcome::Failed);
    }
    #[test]
    fn invalidation_at_each_pre_and_post_step_always_stops_and_cleans_up() {
        use std::cell::Cell;
        for limit in 0..SYNTHETIC.len() * 2 {
            let calls = Cell::new(0);
            let mut p = fake();
            let r = exercise(
                &mut p,
                || {
                    let n = calls.get();
                    calls.set(n + 1);
                    n < limit
                },
                Experiment::Synthetic,
            );
            assert_eq!(r.outcome, "interrupted");
            assert_eq!(p.calls.last(), Some(&"delete"));
            assert_eq!(p.calls.len() - 1, limit.div_ceil(2));
            assert!(!r.eligible && !r.enrolled && !r.unlocked);
        }
    }
    #[test]
    fn successful_prf_report_keeps_all_security_gates_unresolved() {
        let mut p = fake();
        let r = exercise(&mut p, || true, Experiment::Synthetic);
        assert_eq!(r.outcome, "prf-roundtrip-passed");
        let value = serde_json::to_value(&r).unwrap();
        assert_eq!(value["webauthn"]["tpmBinding"], "not-verified");
        assert_eq!(value["remaining"].as_array().unwrap().len(), 4);
        assert!(!r.eligible && !r.enrolled && !r.unlocked);
        // The report type has no credential, challenge, salt or secret field.
        let keys: Vec<_> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert!(keys.iter().all(|k| [
            "version",
            "sourceCommit",
            "purpose",
            "algorithm",
            "eligible",
            "enrolled",
            "unlocked",
            "outcome",
            "checks",
            "webauthn",
            "remaining"
        ]
        .contains(k)));
    }
    #[test]
    fn actual_authenticated_encryption_roundtrip_and_negative_controls() {
        libsodium_rs::ensure_init().unwrap();
        if libsodium_rs::crypto_aead::aes256gcm::is_available() {
            roundtrip(&[7; 32]).unwrap();
        } else {
            assert!(roundtrip(&[7; 32]).is_err());
        }
    }
    fn wire_fixture() -> (Vec<u8>, Vec<u8>) {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/hello/authenticator-data.json"
        )))
        .unwrap();
        let decode = |key| STANDARD.decode(fixture[key].as_str().unwrap()).unwrap();
        (decode("authenticatorData"), decode("credentialId"))
    }
    #[test]
    fn independent_w3c_creation_fixture_binds_the_exact_returned_credential() {
        let (data, credential) = wire_fixture();
        assert!(auth_context(&data, Some(&credential)).is_ok());
    }

    #[test]
    fn independent_creation_fixture_rejects_wrong_ids_lengths_and_every_truncation() {
        let (data, credential) = wire_fixture();
        let mut wrong = credential.clone();
        wrong[0] ^= 1;
        assert!(auth_context(&data, Some(&wrong)).is_err());
        // Keep the full valid ID but remove its following public-key bytes.
        assert!(auth_context(&data[..55 + credential.len()], Some(&credential)).is_err());
        for n in 0..55 + credential.len() + 1 {
            assert!(
                auth_context(&data[..n], Some(&credential)).is_err(),
                "prefix {n}"
            );
        }
        for len in [0u16, 1, 15, 17, 0x0100, u16::MAX] {
            let mut changed = data.clone();
            changed[53..55].copy_from_slice(&len.to_be_bytes());
            assert!(
                auth_context(&changed, Some(&credential)).is_err(),
                "length {len}"
            );
        }
        let mut missing_at = data;
        missing_at[32] &= !0x40;
        assert!(auth_context(&missing_at, Some(&credential)).is_err());
    }
    #[test]
    fn independent_assertion_fixture_still_requires_rp_presence_uv_and_no_backup_flags() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/hello/authenticator-data.json"
        )))
        .unwrap();
        let data = STANDARD
            .decode(fixture["assertionData"].as_str().unwrap())
            .unwrap();
        assert!(auth_context(&data, None).is_ok());
        for n in 0..data.len() {
            assert!(auth_context(&data[..n], None).is_err());
        }
        for flags in [0, 1, 4, 0x0d, 0x1d] {
            let mut changed = data.clone();
            changed[32] = flags;
            assert!(auth_context(&changed, None).is_err());
        }
        let mut wrong_rp = data;
        wrong_rp[0] ^= 1;
        assert!(auth_context(&wrong_rp, None).is_err());
    }
    #[test]
    fn network_order_credential_length_accepts_a_length_above_one_byte() {
        let (data, _) = wire_fixture();
        let credential = vec![7; 256];
        let mut extended = data[..53].to_vec();
        extended.extend_from_slice(&[1, 0]);
        extended.extend_from_slice(&credential);
        extended.extend_from_slice(&data[71..]);
        assert!(auth_context(&extended, Some(&credential)).is_ok());
    }
}
