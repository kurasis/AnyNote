use super::*;
use std::cell::Cell;
#[derive(Default)]
struct Fake {
    deleted: bool,
    id: String,
    prompts: usize,
    deny: bool,
    delete_error: bool,
    create_error: bool,
}
impl Protection for Fake {
    fn create(&mut self, h: &mut Header) -> Result<Zeroizing<[u8; 32]>> {
        assert!(h.key_name().starts_with("AnyNote.P01.Hello."));
        assert_ne!(h.user(), [0; 32]);
        self.id = h.id.clone();
        self.deleted = false;
        if self.create_error {
            return Err(Error::new("HELLO_CANCELLED"));
        }
        h.credential = vec![1; 32];
        h.public = vec![2; 256];
        h.name = vec![3; 34];
        self.prompts += 1;
        Ok(Zeroizing::new([7; 32]))
    }
    fn reopen(&mut self, h: &Header) -> Result<()> {
        if self.deleted || h.id != self.id {
            Err(invalid())
        } else {
            Ok(())
        }
    }
    fn authorize(&mut self) -> Result<Zeroizing<[u8; 32]>> {
        self.prompts += 1;
        if self.deny {
            Err(Error::new("HELLO_CANCELLED"))
        } else {
            Ok(Zeroizing::new([7; 32]))
        }
    }
    fn wrap(&mut self, c: &[u8; 32]) -> Result<Vec<u8>> {
        let mut b = vec![0; 256];
        b[..32].copy_from_slice(c);
        Ok(b)
    }
    fn unwrap(&mut self, c: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if self.deleted {
            return Err(invalid());
        }
        Ok(Zeroizing::new(c[..32].to_vec()))
    }
    fn delete(&mut self) -> Result<()> {
        if self.delete_error {
            return Err(Error::new("WRITE_FAILED"));
        }
        self.deleted = true;
        Ok(())
    }
}
fn binding() -> Binding {
    Binding {
        vault: uuid::Uuid::new_v4().to_string(),
        key_epoch: 0,
        generation: 1,
        sha256: "a".repeat(64),
    }
}
fn setup() -> (tempfile::TempDir, Journal, Manager, Fake, Binding) {
    libsodium_rs::ensure_init().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let j = Journal::open(dir.path()).unwrap();
    (dir, j, Manager::default(), Fake::default(), binding())
}
#[test]
fn remembered_roundtrip_reopens_across_manager_restart_without_plaintext_or_verifier() {
    let (_d, j, mut m, mut b, v) = setup();
    let context = || Ok((v.clone(), 1000));
    m.enroll(&j, &mut b, &v, Mode::Remember24, &[42; 32], &context)
        .unwrap();
    assert_eq!(b.prompts, 2);
    let disk = io::read(&j.path, MAX_RECORD).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&disk).unwrap();
    assert!(parsed.get("local_key").is_none());
    assert!(parsed["header"].get("expected").is_none());
    let mut restarted = Manager::default();
    assert_eq!(
        *restarted.unlock(&j, &mut b, &v, &context).unwrap(),
        vec![42; 32]
    );
    assert_eq!(
        *restarted.unlock(&j, &mut b, &v, &context).unwrap(),
        vec![42; 32]
    );
    assert_eq!(b.prompts, 4);
}
#[test]
fn session_envelope_is_memory_only_and_restart_requires_cleanup() {
    let (_d, j, mut m, mut b, v) = setup();
    let context = || Ok((v.clone(), 1000));
    m.enroll(&j, &mut b, &v, Mode::Session, &[9; 32], &context)
        .unwrap();
    let disk = j.read().unwrap().unwrap();
    assert!(!disk.ready);
    assert!(disk.ciphertext.is_empty());
    assert_eq!(
        m.unlock(&j, &mut b, &v, &context).unwrap().as_slice(),
        [9; 32]
    );
    let mut restarted = Manager::default();
    assert_eq!(
        restarted.status(&j, &v, 1000).unwrap().state,
        "cleanup-required"
    );
    assert!(restarted.unlock(&j, &mut b, &v, &context).is_err());
    restarted.revoke(&j, &mut b, disk).unwrap();
    assert!(j.read().unwrap().is_none());
}
#[test]
fn generation_changes_allow_saved_content_but_rotation_and_wrong_vault_refuse_before_prompt() {
    let (_d, j, mut m, mut b, mut v) = setup();
    m.enroll(&j, &mut b, &v, Mode::Remember6, &[8; 32], &|| {
        Ok((v.clone(), 1000))
    })
    .unwrap();
    v.generation += 1;
    v.sha256 = "b".repeat(64);
    assert!(m.unlock(&j, &mut b, &v, &|| Ok((v.clone(), 2000))).is_ok());
    let prompts = b.prompts;
    v.key_epoch += 1;
    assert!(m.unlock(&j, &mut b, &v, &|| Ok((v.clone(), 3000))).is_err());
    v.key_epoch -= 1;
    v.vault = uuid::Uuid::new_v4().to_string();
    assert!(m.unlock(&j, &mut b, &v, &|| Ok((v.clone(), 3000))).is_err());
    assert_eq!(b.prompts, prompts);
}
#[test]
fn cancellation_returns_no_local_key_and_does_not_retry() {
    let (_d, j, mut m, mut b, v) = setup();
    let context = || Ok((v.clone(), 1000));
    m.enroll(&j, &mut b, &v, Mode::Remember12, &[8; 32], &context)
        .unwrap();
    b.deny = true;
    assert_eq!(
        m.unlock(&j, &mut b, &v, &context).unwrap_err().code,
        "HELLO_CANCELLED"
    );
    assert_eq!(b.prompts, 3);
    assert_eq!(m.status(&j, &v, 1000).unwrap().state, "enabled");
}
#[test]
fn expiry_backward_clock_and_context_change_during_prompt_return_no_local_key() {
    let (_d, j, mut m, mut b, v) = setup();
    m.enroll(&j, &mut b, &v, Mode::Remember6, &[8; 32], &|| {
        Ok((v.clone(), 1000))
    })
    .unwrap();
    let calls = Cell::new(0);
    let context = || {
        calls.set(calls.get() + 1);
        let mut next = v.clone();
        if calls.get() > 1 {
            next.generation += 1;
        }
        Ok((next, 2000))
    };
    assert_eq!(
        m.unlock(&j, &mut b, &v, &context).unwrap_err().code,
        "STALE"
    );
    assert_eq!(b.prompts, 3);
    assert!(m
        .unlock(&j, &mut b, &v, &|| Err(Error::new("STALE")))
        .is_err());
    assert!(m
        .unlock(&j, &mut b, &v, &|| Ok((v.clone(), 1000 + 6 * 3_600_000)))
        .is_err());
    assert!(!j.read().unwrap().unwrap().ready);
    // Returning the clock to the formerly valid interval cannot re-enable it.
    assert!(m.unlock(&j, &mut b, &v, &|| Ok((v.clone(), 3000))).is_err());
    assert_eq!(b.prompts, 3);
}
#[test]
fn revoked_envelope_replay_cannot_reopen_deleted_key() {
    let (_d, j, mut m, mut b, v) = setup();
    let context = || Ok((v.clone(), 1000));
    m.enroll(&j, &mut b, &v, Mode::Remember24, &[8; 32], &context)
        .unwrap();
    let old = j.read().unwrap().unwrap();
    m.revoke(&j, &mut b, old.clone()).unwrap();
    assert!(b.deleted);
    j.save(&old).unwrap();
    assert!(m.unlock(&j, &mut b, &v, &context).is_err());
}
#[test]
fn failed_deletion_is_nonresumable_and_retryable() {
    let (_d, j, mut m, mut b, v) = setup();
    let context = || Ok((v.clone(), 1000));
    m.enroll(&j, &mut b, &v, Mode::Session, &[8; 32], &context)
        .unwrap();
    let r = m.read(&j).unwrap().unwrap();
    b.delete_error = true;
    assert!(m.revoke(&j, &mut b, r).is_err());
    assert!(m.session.is_none());
    assert!(!j.read().unwrap().unwrap().ready);
    assert!(m.unlock(&j, &mut b, &v, &context).is_err());
    b.delete_error = false;
    m.revoke(&j, &mut b, j.read().unwrap().unwrap()).unwrap();
    assert!(j.read().unwrap().is_none());
}
#[test]
fn failed_creation_cleans_journal_and_failed_cleanup_keeps_ownership() {
    let (_d, j, mut m, mut b, v) = setup();
    let context = || Ok((v.clone(), 1000));
    b.create_error = true;
    assert!(m
        .enroll(&j, &mut b, &v, Mode::Session, &[8; 32], &context)
        .is_err());
    assert!(b.deleted);
    assert!(j.read().unwrap().is_none());
    b.delete_error = true;
    assert_eq!(
        m.enroll(&j, &mut b, &v, Mode::Session, &[8; 32], &context)
            .unwrap_err()
            .code,
        "HELLO_CLEANUP_REQUIRED"
    );
    assert!(j.read().unwrap().is_some());
    assert!(m.session.is_none());
}
#[test]
fn tampered_cipher_and_authenticated_metadata_fail_closed() {
    let (_d, j, mut m, mut b, v) = setup();
    let context = || Ok((v.clone(), 1000));
    m.enroll(&j, &mut b, &v, Mode::Remember24, &[8; 32], &context)
        .unwrap();
    let old = j.read().unwrap().unwrap();
    let mut r = old.clone();
    r.ciphertext[0] ^= 1;
    j.save(&r).unwrap();
    assert!(m.unlock(&j, &mut b, &v, &context).is_err());
    let mut r = old;
    r.header.salt[0] ^= 1;
    j.save(&r).unwrap();
    assert!(m.unlock(&j, &mut b, &v, &context).is_err());
}
#[test]
fn stale_enrollment_never_becomes_enabled() {
    let (_d, j, mut m, mut b, v) = setup();
    let calls = Cell::new(0);
    let context = || {
        calls.set(calls.get() + 1);
        if calls.get() > 1 {
            Err(Error::new("STALE"))
        } else {
            Ok((v.clone(), 1000))
        }
    };
    assert!(m
        .enroll(&j, &mut b, &v, Mode::Remember24, &[8; 32], &context)
        .is_err());
    assert!(b.deleted);
    assert!(j.read().unwrap().is_none());
}

#[test]
fn backward_clock_observation_stays_disabled_after_clock_recovers() {
    let (_d, j, mut m, mut b, v) = setup();
    m.enroll(&j, &mut b, &v, Mode::Remember6, &[8; 32], &|| {
        Ok((v.clone(), 1000))
    })
    .unwrap();
    assert_eq!(m.status(&j, &v, 999).unwrap().state, "cleanup-required");
    assert_eq!(m.status(&j, &v, 2000).unwrap().state, "cleanup-required");
    assert!(m.unlock(&j, &mut b, &v, &|| Ok((v.clone(), 2000))).is_err());
    assert_eq!(b.prompts, 2);
}
#[test]
fn credential_changing_storage_operations_require_prior_invalidation() {
    use serde_json::json;
    assert!(!credential_write(
        "commit",
        &json!({"expectedGeneration":2,"keyEpoch":null,"confirmedReplacement":false})
    ));
    assert!(credential_write("commit", &json!({"keyEpoch":1})));
    assert!(credential_write(
        "commit",
        &json!({"confirmedReplacement":true})
    ));
    assert!(credential_write("restoreBlob", &json!({"blobId":"opaque"})));
    assert!(!credential_write("readBlob", &json!({})));
}

#[test]
fn ipc_accepts_only_fixed_actions_and_bounded_mode_choices() {
    for json in [
        r#"{"operation":"decrypt","ciphertext":[1]}"#,
        r#"{"operation":"unlock","key":"arbitrary"}"#,
        r#"{"operation":"enroll","mode":"forever","generation":1,"sha256":"a","local_key":[]}"#,
    ] {
        assert!(
            serde_json::from_str::<Action>(json).is_err(),
            "accepted {json}"
        );
    }
    for operation in ["status", "unlock", "revoke"] {
        let valid = serde_json::json!({"operation":operation});
        assert!(serde_json::from_value::<Action>(valid).is_ok());
        let extra = serde_json::json!({"operation":operation,"local_key":vec![0;32]});
        assert!(serde_json::from_value::<Action>(extra).is_err());
    }
    for mode in ["session", "remember6", "remember12", "remember24"] {
        let input = serde_json::json!({"operation":"enroll","mode":mode,"generation":1,"sha256":"a".repeat(64),"local_key":vec![0;32]});
        assert!(serde_json::from_value::<Action>(input).is_ok());
    }
}
