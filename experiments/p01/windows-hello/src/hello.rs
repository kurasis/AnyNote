//! SPDX-License-Identifier: GPL-3.0-only
//! Imported providers are reference adapters, not production enrollment APIs.
#![allow(dead_code)]
use crate::storage::{Error, Result};
use serde_json::{json, Value};
pub mod attestation;
pub mod enrollment;
pub mod prf;
pub mod proof;
pub mod tpm;

pub fn readiness() -> Value {
    json!({"available":false})
}
pub fn enroll() -> Result<Value> {
    Err(Error::new("UNAVAILABLE"))
}
pub fn unlock() -> Result<Value> {
    Err(Error::new("UNAVAILABLE"))
}

#[cfg(windows)]
static AUTHENTICATING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(windows)]
pub(crate) struct Attempt;
#[cfg(windows)]
impl Attempt {
    pub(crate) fn begin() -> Result<Self> {
        use std::sync::atomic::Ordering;
        AUTHENTICATING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::new("BUSY"))?;
        Ok(Self)
    }
}
#[cfg(windows)]
impl Drop for Attempt {
    fn drop(&mut self) {
        AUTHENTICATING.store(false, std::sync::atomic::Ordering::Release);
    }
}

// Kept solely for unexposed imported Passport diagnostic code. It has no key access.
#[cfg(windows)]
pub mod diagnostics {
    pub fn check() -> serde_json::Value {
        use windows::Security::Credentials::UI::UserConsentVerifier;
        let available = UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|op| op.join())
            .map(|r| r.0 == 0)
            .unwrap_or(false);
        serde_json::json!({"helloConfiguration":if available {"available"} else {"unavailable"}})
    }
}
