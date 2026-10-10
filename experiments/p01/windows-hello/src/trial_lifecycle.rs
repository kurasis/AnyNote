//! SPDX-License-Identifier: GPL-3.0-only
//! Content-free native event evidence; STALE alone is not a lock observation.
use serde::Serialize;
use serde_json::Value;
use std::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Copy)]
pub enum Event {
    Lock,
    Unlock,
    Suspend,
    OwnerClose,
}
impl Event {
    pub fn invalidates(self) -> bool {
        !matches!(self, Self::Unlock)
    }
}
pub struct Events {
    lock: AtomicU32,
    unlock: AtomicU32,
    suspend: AtomicU32,
    close: AtomicU32,
}
#[derive(Serialize)]
pub struct Snapshot {
    pub wts_session_lock: u32,
    pub wts_session_unlock: u32,
    pub suspend: u32,
    pub owner_window_close: u32,
}
impl Events {
    pub const fn new() -> Self {
        Self {
            lock: AtomicU32::new(0),
            unlock: AtomicU32::new(0),
            suspend: AtomicU32::new(0),
            close: AtomicU32::new(0),
        }
    }
    pub fn record(&self, event: Event) {
        let counter = match event {
            Event::Lock => &self.lock,
            Event::Unlock => &self.unlock,
            Event::Suspend => &self.suspend,
            Event::OwnerClose => &self.close,
        };
        counter.fetch_add(1, Ordering::AcqRel);
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            wts_session_lock: self.lock.load(Ordering::Acquire),
            wts_session_unlock: self.unlock.load(Ordering::Acquire),
            suspend: self.suspend.load(Ordering::Acquire),
            owner_window_close: self.close.load(Ordering::Acquire),
        }
    }
}
pub fn lock_observed_and_rejected(operation: &Value) -> bool {
    matches!(
        operation["operation"].as_str(),
        Some("unlock" | "unlock-lock-trial")
    ) && operation["exit_code"] == 1
        && operation["report"]["status"] == "FAIL_OR_UNAVAILABLE"
        && operation["report"]["code"] == "STALE"
        && operation["report"]["actual_vault_authenticated"] != true
        && operation["report"]["lifecycle"]["wts_session_lock"]
            .as_u64()
            .is_some_and(|count| count > 0)
}
pub fn lock_request_status(value: u32) -> &'static str {
    match value {
        0 => "NOT_REQUESTED",
        1 => "OS_REQUEST_ACCEPTED_NOT_LOCK_PROOF",
        2 => "OS_REQUEST_DENIED",
        _ => "TIMER_UNAVAILABLE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reported_legacy_stale_cannot_prove_a_native_lock_event() {
        let report: Value = serde_json::from_str(include_str!(
            "../../../../docs/evidence/p01-owner-windows-v0.1.1.json"
        ))
        .unwrap();
        assert_eq!(report["operations"][3]["report"]["code"], "STALE");
        assert!(!lock_observed_and_rejected(&report["operations"][3]));
    }

    #[test]
    fn cancellation_suspend_close_or_timeout_cannot_be_called_session_lock() {
        let events = Events::new();
        for event in [Event::Unlock, Event::Suspend, Event::OwnerClose] {
            events.record(event);
        }
        let mut operation = json!({"operation":"unlock","exit_code":1,
            "report":{"status":"FAIL_OR_UNAVAILABLE","code":"STALE","lifecycle":events.snapshot()}});
        assert!(!lock_observed_and_rejected(&operation));
        events.record(Event::Lock);
        operation["report"]["lifecycle"] = serde_json::to_value(events.snapshot()).unwrap();
        assert!(lock_observed_and_rejected(&operation));
        for (pointer, value) in [
            ("/report/code", json!("HELLO_CANCELLED")),
            ("/exit_code", json!(0)),
            ("/report/status", json!("PASS_SYNTHETIC_UNLOCK")),
            ("/report/actual_vault_authenticated", json!(true)),
            ("/report/lifecycle/wts_session_lock", json!("1")),
        ] {
            let mut bad = operation.clone();
            if pointer == "/report/actual_vault_authenticated" {
                bad["report"]["actual_vault_authenticated"] = value;
            } else {
                *bad.pointer_mut(pointer).unwrap() = value;
            }
            assert!(!lock_observed_and_rejected(&bad), "{pointer}");
        }
        assert!(Event::Lock.invalidates());
        assert!(Event::Suspend.invalidates());
        assert!(Event::OwnerClose.invalidates());
        assert!(!Event::Unlock.invalidates());
    }
    #[test]
    fn owner_cancelled_012_trial_and_accepted_os_request_are_not_lock_proof() {
        let report: Value = serde_json::from_str(include_str!(
            "../../../../docs/evidence/p01-owner-windows-v0.1.2.json"
        ))
        .unwrap();
        let mut operation = report["operations"][3].clone();
        assert!(!lock_observed_and_rejected(&operation));
        operation["operation"] = json!("unlock-lock-trial");
        operation["report"]["lock_request"] = json!(lock_request_status(1));
        assert!(!lock_observed_and_rejected(&operation));
        operation["report"]["code"] = json!("STALE");
        operation["report"]["lifecycle"]["wts_session_lock"] = json!(1);
        assert!(lock_observed_and_rejected(&operation));
        assert_eq!(lock_request_status(0), "NOT_REQUESTED");
        assert_eq!(lock_request_status(2), "OS_REQUEST_DENIED");
    }
}
