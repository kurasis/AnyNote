//! Synthetic Platform KSP inner-envelope measurements, not Hello authorization.
use super::{
    prf::{check, interrupted, PrfCheck},
    proof::{ExportCheck, Failure, Outcome},
};
use serde::Serialize;

#[cfg(any(windows, test))]
mod read_public;

#[cfg(windows)]
pub(super) mod windows;
#[cfg(windows)]
pub use windows::run;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Experiment {
    Capability,
    Synthetic,
    LocalBinding,
}

const STEPS: [&str; 10] = [
    "tpm-provider-open",
    "tpm-provider-properties",
    "tpm-key-create",
    "tpm-key-policy",
    "tpm-key-readback",
    "tpm-public-wrap",
    "tpm-unwrap-first",
    "tpm-reopen-unwrap",
    "tpm-negative-controls",
    "private-export",
];

const LOCAL_STEPS: [&str; 11] = [
    "tpm-provider-open",
    "tpm-provider-properties",
    "tpm-key-create",
    "tpm-key-policy",
    "tpm-key-readback",
    "tpm-read-public",
    "tpm-public-wrap",
    "tpm-unwrap-first",
    "tpm-reopen-unwrap",
    "tpm-reopen-read-public",
    "tpm-negative-controls",
];

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation_flags: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpm_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_name_bytes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_policy: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_usage: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_length_bits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcp_key_usage: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcp_usage_kind: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcp_usage_flags: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_attributes: Option<u32>,
}

// Pinned Microsoft SDK and PCP sample: usage is the low word; the SDK
// separately defines NCRYPT_TPM12_PROVIDER. Neither is per-key attestation.
const PCP_USAGE_KIND_MASK: u32 = 0x0000ffff;
const PCP_ENCRYPTION_KIND: u32 = 2;
const PCP_TPM12_PROVIDER_FLAG: u32 = 0x00010000;

fn pcp_policy_matches(raw: u32) -> Result<(), Failure> {
    if raw & PCP_USAGE_KIND_MASK != PCP_ENCRYPTION_KIND {
        return Err(super::prf::invalid("tpm-pcp-key-usage-mismatch"));
    }
    if raw & !(PCP_USAGE_KIND_MASK | PCP_TPM12_PROVIDER_FLAG) != 0 {
        return Err(super::prf::invalid("tpm-pcp-key-usage-flags-unsupported"));
    }
    Ok(())
}

fn policy_matches(export: u32, usage: u32, length: u32) -> Result<(), Failure> {
    // Common CNG usage values differ from Platform KSP usage values.
    if export != 0 {
        return Err(super::prf::invalid("tpm-export-policy-mismatch"));
    }
    if usage != 1 {
        return Err(super::prf::invalid("tpm-key-usage-mismatch"));
    }
    if length != 2048 {
        return Err(super::prf::invalid("tpm-key-length-mismatch"));
    }
    Ok(())
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
    pub tpm: Metadata,
    pub per_key_tpm_evidence: &'static str,
    pub authorization: &'static str,
    pub process_scope: &'static str,
    pub export_checks: Vec<ExportCheck>,
    pub remaining: [&'static str; 4],
}

trait Provider {
    fn step(&mut self, step: &'static str) -> Result<(), Failure>;
    fn cleanup(&mut self) -> Result<(), Failure>;
    fn metadata(&self) -> Metadata;
    fn exports(&self) -> Vec<ExportCheck>;
}

fn exercise(
    provider: &mut impl Provider,
    current: impl Fn() -> bool,
    experiment: Experiment,
) -> Report {
    let mut report = Report {
        version: 1,
        source_commit: option_env!("PASSKEY_SOURCE_COMMIT"),
        purpose: match experiment {
            Experiment::Capability => "tpm-inner-capability",
            Experiment::Synthetic => "synthetic-tpm-inner",
            Experiment::LocalBinding => "synthetic-tpm-local-binding",
        },
        algorithm: "platform-rsa-oaep-sha256",
        eligible: false,
        enrolled: false,
        unlocked: false,
        outcome: "blocked",
        checks: Vec::new(),
        tpm: Metadata::default(),
        per_key_tpm_evidence: "not-verified",
        authorization: "no-hello-authorization",
        process_scope: "same-process",
        export_checks: Vec::new(),
        remaining: [
            "per-key-tpm-proof",
            "fresh-authorization-proof",
            "fresh-process-proof",
            "account-machine-copy-proof",
        ],
    };
    let steps = match experiment {
        Experiment::Capability => &STEPS[..2],
        Experiment::Synthetic => &STEPS[..],
        Experiment::LocalBinding => &LOCAL_STEPS[..],
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
            Err(interrupted("tpm-session-changed"))
        };
        let result = if result.is_ok() && !current() {
            Err(interrupted("tpm-session-changed"))
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
        let cleanup = check("test-key-delete", provider.cleanup());
        if cleanup.status != Outcome::Passed {
            running = false;
            report.outcome = "blocked";
        }
        report.checks.push(cleanup);
    }
    report.tpm = provider.metadata();
    report.export_checks = provider.exports();
    if running && !current() {
        running = false;
        report.outcome = "interrupted";
    }
    if running {
        report.outcome = match experiment {
            Experiment::Capability => "tpm-capability-observed",
            Experiment::Synthetic => "tpm-inner-roundtrip-passed",
            Experiment::LocalBinding => {
                report.per_key_tpm_evidence = "local-read-public-observed";
                "tpm-local-binding-observed"
            }
        };
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pcp_readback_separates_usage_from_only_the_sdk_defined_provider_marker() {
        for flags in [0, PCP_TPM12_PROVIDER_FLAG] {
            assert!(pcp_policy_matches(flags | PCP_ENCRYPTION_KIND).is_ok());
            for kind in [0, 1, 3, 4, 8, 16, 0xffff] {
                assert_eq!(
                    pcp_policy_matches(flags | kind).unwrap_err().operation,
                    Some("tpm-pcp-key-usage-mismatch")
                );
            }
            for bit in 0..16 {
                if 1 << bit != PCP_ENCRYPTION_KIND {
                    assert!(pcp_policy_matches(flags | PCP_ENCRYPTION_KIND | (1 << bit)).is_err());
                }
            }
        }
        // The owner's raw observation must pass kind validation without discarding
        // the provider marker, treating it as TPM 2 evidence or enabling unlock.
        assert!(pcp_policy_matches(65538).is_ok());
        for bit in 17..32 {
            assert_eq!(
                pcp_policy_matches(PCP_ENCRYPTION_KIND | (1 << bit))
                    .unwrap_err()
                    .operation,
                Some("tpm-pcp-key-usage-flags-unsupported")
            );
            assert!(pcp_policy_matches(65538 | (1 << bit)).is_err());
        }
        let r = exercise(&mut fake(None), || true, Experiment::Synthetic);
        assert!(!r.eligible && !r.enrolled && !r.unlocked);
        assert_eq!(r.per_key_tpm_evidence, "not-verified");
        assert_eq!(r.remaining.len(), 4);
    }
    #[test]
    fn policy_readback_rejects_every_broader_usage_export_and_wrong_length() {
        assert!(policy_matches(0, 1, 2048).is_ok());
        for export in [1, 2, 4, 8, u32::MAX] {
            assert_eq!(
                policy_matches(export, 1, 2048).unwrap_err().operation,
                Some("tpm-export-policy-mismatch")
            );
        }
        for usage in [0, 2, 3, 4, 16, 0x00ffffff, u32::MAX] {
            assert_eq!(
                policy_matches(0, usage, 2048).unwrap_err().operation,
                Some("tpm-key-usage-mismatch")
            );
        }
        for length in [0, 1024, 2047, 2049, 4096] {
            assert_eq!(
                policy_matches(0, 1, length).unwrap_err().operation,
                Some("tpm-key-length-mismatch")
            );
        }
    }
    struct Fake {
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
    }
    impl Provider for Fake {
        fn step(&mut self, s: &'static str) -> Result<(), Failure> {
            self.calls.push(s);
            if self.fail == Some(s) {
                Err(Failure::failed())
            } else {
                Ok(())
            }
        }
        fn cleanup(&mut self) -> Result<(), Failure> {
            self.step("test-key-delete")
        }
        fn metadata(&self) -> Metadata {
            Metadata::default()
        }
        fn exports(&self) -> Vec<ExportCheck> {
            vec![]
        }
    }
    fn fake(fail: Option<&'static str>) -> Fake {
        Fake {
            calls: vec![],
            fail,
        }
    }
    #[test]
    fn capability_never_creates_or_deletes_a_key() {
        let mut p = fake(None);
        let r = exercise(&mut p, || true, Experiment::Capability);
        assert_eq!(p.calls, &STEPS[..2]);
        assert_eq!(r.outcome, "tpm-capability-observed");
    }
    #[test]
    fn each_failure_stops_later_operations_and_always_cleans_up() {
        for failed in STEPS.into_iter().chain(["test-key-delete"]) {
            let mut p = fake(Some(failed));
            let r = exercise(&mut p, || true, Experiment::Synthetic);
            assert_eq!(r.outcome, "blocked");
            assert_eq!(p.calls.last(), Some(&"test-key-delete"));
            let i = r.checks.iter().position(|c| c.test == failed).unwrap();
            assert_eq!(r.checks[i].status, Outcome::Failed);
            if i < r.checks.len() - 1 {
                assert!(r.checks[i + 1..r.checks.len() - 1]
                    .iter()
                    .all(|c| c.status == Outcome::NotRun));
            }
        }
    }
    #[test]
    fn pre_and_post_stage_invalidation_cannot_publish_success() {
        // Also invalidate during cleanup, after the last private stage.
        for invalid_at in 0..=STEPS.len() * 2 {
            let calls = std::cell::Cell::new(0);
            let mut p = fake(None);
            let r = exercise(
                &mut p,
                || {
                    let n = calls.get();
                    calls.set(n + 1);
                    n < invalid_at
                },
                Experiment::Synthetic,
            );
            assert_eq!(r.outcome, "interrupted");
            assert_eq!(p.calls.last(), Some(&"test-key-delete"));
            if invalid_at < STEPS.len() * 2 {
                assert!(r.checks.iter().any(|c| c.status == Outcome::Interrupted));
            } else {
                // Operations completed, but lock during cleanup still invalidates
                // the final outcome. Do not invent a failed native operation.
                assert!(r.checks.iter().all(|c| c.status == Outcome::Passed));
            }
        }
    }
    #[test]
    fn success_keeps_authorization_and_hardware_gates_open() {
        let r = exercise(&mut fake(None), || true, Experiment::Synthetic);
        assert_eq!(r.outcome, "tpm-inner-roundtrip-passed");
        assert!(!r.eligible && !r.enrolled && !r.unlocked);
        assert_eq!(r.remaining.len(), 4);
        let value = serde_json::to_value(r).unwrap();
        assert_eq!(value["perKeyTpmEvidence"], "not-verified");
        assert_eq!(value["authorization"], "no-hello-authorization");
        assert_eq!(value["processScope"], "same-process");
    }
    #[test]
    fn local_binding_has_its_own_contract_without_reclassifying_private_export() {
        let mut p = fake(None);
        let r = exercise(&mut p, || true, Experiment::LocalBinding);
        assert_eq!(r.purpose, "synthetic-tpm-local-binding");
        assert_eq!(r.outcome, "tpm-local-binding-observed");
        assert_eq!(r.per_key_tpm_evidence, "local-read-public-observed");
        assert_eq!(&p.calls[..LOCAL_STEPS.len()], &LOCAL_STEPS);
        assert!(!p.calls.contains(&"private-export"));
        assert!(!r.eligible && !r.enrolled && !r.unlocked);
        assert_eq!(r.remaining.len(), 4);
        assert!(r.export_checks.is_empty());
        for failed in LOCAL_STEPS.into_iter().chain(["test-key-delete"]) {
            let mut p = fake(Some(failed));
            let r = exercise(&mut p, || true, Experiment::LocalBinding);
            assert_eq!(r.outcome, "blocked");
            assert_eq!(r.per_key_tpm_evidence, "not-verified");
            assert_eq!(p.calls.last(), Some(&"test-key-delete"));
            let i = r.checks.iter().position(|c| c.test == failed).unwrap();
            if i < r.checks.len() - 1 {
                assert!(r.checks[i + 1..r.checks.len() - 1]
                    .iter()
                    .all(|c| c.status == Outcome::NotRun));
            }
        }
    }
    #[test]
    fn local_binding_invalidation_including_cleanup_never_publishes_evidence() {
        for invalid_at in 0..=LOCAL_STEPS.len() * 2 {
            let calls = std::cell::Cell::new(0);
            let mut p = fake(None);
            let r = exercise(
                &mut p,
                || {
                    let n = calls.get();
                    calls.set(n + 1);
                    n < invalid_at
                },
                Experiment::LocalBinding,
            );
            assert_eq!(r.outcome, "interrupted");
            assert_eq!(r.per_key_tpm_evidence, "not-verified");
            assert_eq!(p.calls.last(), Some(&"test-key-delete"));
        }
    }
}
