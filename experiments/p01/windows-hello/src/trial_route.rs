//! SPDX-License-Identifier: GPL-3.0-only
//! Admission to a synthetic trial, never proof of credential security eligibility.
use serde_json::Value;

pub fn available(capability: &Value) -> bool {
    let report = &capability["report"];
    let api = &report["webauthn"];
    let steps = [
        "webauthn-load",
        "webauthn-api",
        "hello-platform",
        "hello-route",
    ];
    capability["status"] == "CAPABILITY_ONLY"
        && capability["native_objects_created"] == false
        && capability["physical_acceptance"] == false
        && report["purpose"] == "webauthn-prf-capability"
        && report["outcome"] == "webauthn-capability-observed"
        && api["apiVersion"].as_u64().is_some_and(|v| v >= 9)
        && api["platformAvailable"] == true
        && api["helloCandidates"].as_u64().is_some_and(|v| v > 0)
        && api["helloLocked"] == false
        && api["routing"] == "display-name-candidate"
        && report["checks"].as_array().is_some_and(|checks| {
            checks.len() == steps.len()
                && checks
                    .iter()
                    .zip(steps)
                    .all(|(check, step)| check["test"] == step && check["status"] == "passed")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn owner() -> Value {
        let trial: Value = serde_json::from_str(include_str!(
            "../../../../docs/evidence/p01-owner-windows-v0.1.0.json"
        ))
        .unwrap();
        trial["capability"]["report"].clone()
    }

    #[test]
    fn observed_owner_route_can_start_without_claiming_key_eligibility() {
        let cap = owner();
        assert!(available(&cap));
        assert_eq!(cap["report"]["eligible"], false);
        assert_eq!(cap["report"]["enrolled"], false);
        assert_eq!(cap["report"]["unlocked"], false);
    }

    #[test]
    fn incomplete_or_blocked_routes_fail_closed() {
        for (pointer, value) in [
            ("/status", json!("FAIL")),
            ("/native_objects_created", json!(true)),
            ("/physical_acceptance", json!(true)),
            ("/report/outcome", json!("blocked")),
            ("/report/purpose", json!("synthetic-webauthn-prf")),
            ("/report/webauthn/apiVersion", json!(7)),
            ("/report/webauthn/apiVersion", json!("9")),
            ("/report/webauthn/platformAvailable", json!(false)),
            ("/report/webauthn/helloCandidates", json!(0)),
            ("/report/webauthn/helloLocked", json!(true)),
            ("/report/webauthn/helloLocked", Value::Null),
            ("/report/webauthn/routing", json!("unknown")),
            ("/report/checks/3/status", json!("not-run")),
            ("/report/checks", json!([])),
        ] {
            let mut cap = owner();
            *cap.pointer_mut(pointer).unwrap() = value;
            assert!(!available(&cap), "{pointer}");
        }
        assert!(!available(&Value::Null));
    }
}
