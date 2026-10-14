//! Native lifecycle signing stays under the current vault capability. No raw key/SQL/path route.
use super::*;
use crate::device_roster::{Roster, digest, signed};

fn common(purpose: &str, pins: &Value) -> Value {
    json!({"purpose":purpose,"contract":"p02-state-c1","protocol":"anynote","protocol_version":1,"service_id":pins["service_id"],"account_id":pins["account_id"],"root_fingerprint":pins["root_fingerprint"]})
}
fn sign(codec: &Codec, profile: &str, kind: &str, body: Value, key: &[u8]) -> Result<Value> {
    codec.validate(profile, &format!("{kind}-body"), &body)?;
    let out = json!({"signature":anynote_crypto_core::crypto::sign(&codec.signing(profile,&format!("{kind}-body"),&body)?,key)?,"body":body});
    codec.validate(profile, kind, &out)?;
    Ok(out)
}
fn public_device(scope: &Scope, secret: &Secrets) -> Result<Value> {
    let signing = libsodium_rs::crypto_sign::KeyPair::from_seed(&secret.signing[..32])
        .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    check(
        signing.secret_key.as_ref() == secret.signing.as_slice(),
        "INVALID_KEY_LENGTH",
    )?;
    let encryption =
        libsodium_rs::crypto_scalarmult::curve25519::scalarmult_base(&secret.encryption)
            .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    Ok(
        json!({"device_id":scope.device_id,"signing_key":b64(signing.public_key.as_ref()),"encryption_key":b64(&encryption),"capabilities":["delegate-device","distribute-group-key","receive-group-key","sign-content"]}),
    )
}
fn certificate_body(
    pins: &Value,
    device: &Value,
    generation: &str,
    head: &Value,
    issuer: Value,
    transcript: String,
) -> Value {
    json!({"purpose":"provisional-device-certificate","contract":"p02-identity-c1","protocol":"anynote","protocol_version":1,"service_id":pins["service_id"],"account_id":pins["account_id"],"root_fingerprint":pins["root_fingerprint"],"recovery_generation":generation,"predecessor_roster":head,"issuer":issuer,"device_id":device["device_id"],"device_signing_key":device["signing_key"],"device_encryption_key":device["encryption_key"],"capabilities":device["capabilities"],"pairing_transcript_digest":transcript})
}
fn possession(
    codec: &Codec,
    scope: &Scope,
    secret: &Secrets,
    pins: &Value,
    challenge: &Value,
    session_id: &str,
    intent: &str,
) -> Result<Value> {
    codec.validate("p02-state-c1", "challenge", challenge)?;
    let c = &challenge["context"];
    check(
        valid_id(session_id)
            && c["device"] == public_device(scope, secret)?
            && c["intent"] == intent
            && c["session_binding"]
                == hash(format!("AnyNote/P06/session-binding\0{session_id}").as_bytes()),
        "SESSION_BINDING_MISMATCH",
    )?;
    for field in ["service_id", "account_id", "root_fingerprint"] {
        check(c[field] == pins[field], "ROOT_PIN_MISMATCH")?;
    }
    let expiry: u64 = text(&c["expires_at"])?
        .parse()
        .map_err(|_| Error("INVALID_CHALLENGE"))?;
    let t = now()?;
    check(expiry > t && expiry - t <= 60000, "TRANSITION_EXPIRED")?;
    let pk = libsodium_rs::crypto_box::PublicKey::from_bytes(&un64(text(
        &c["device"]["encryption_key"],
    )?)?)
    .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    let sk = libsodium_rs::crypto_box::SecretKey::from_bytes(&secret.encryption)
        .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
    let plain = Zeroizing::new(
        libsodium_rs::crypto_box::open_sealed_box(
            &un64(text(&challenge["sealed_challenge"])?)?,
            &pk,
            &sk,
        )
        .map_err(|_| Error("INTEGRITY_FAILURE"))?,
    );
    let mut p = codec.decode("p02-state-c1", "challenge-plaintext", &plain)?;
    let result = (|| {
        check(
            p["context"] == *c
                && challenge["challenge_digest"]
                    == digest("p02-state-c1", "challenge-plaintext", &p)?,
            "INNER_CONTEXT_MISMATCH",
        )?;
        let mut body = common("device-possession-proof", pins);
        body["challenge_digest"] = json!(digest("p02-state-c1", "challenge", challenge)?);
        body["device_id"] = json!(scope.device_id);
        body["session_binding"] = c["session_binding"].clone();
        body["challenge_response"] = p["secret"].clone();
        sign(codec, "p02-state-c1", "possession", body, &secret.signing)
    })();
    wipe_value(&mut p);
    result
}

impl Vault {
    pub fn initialize_device_phrase(
        &self,
        phrase: &str,
        pins: Value,
        explicit_phrase_choice: bool,
    ) -> Result<Value> {
        let signing = libsodium_rs::crypto_sign::KeyPair::generate()
            .map_err(|_| Error("CRYPTO_UNAVAILABLE"))?;
        let encryption = libsodium_rs::crypto_box::KeyPair::generate();
        let mut data = json!({"device_signing_secret":b64(signing.secret_key.as_ref()),"device_encryption_secret":b64(encryption.secret_key.as_ref()),"group_keys":[]});
        let result = self.initialize_phrase(
            phrase,
            &Zeroizing::new(canonical(&data)?),
            pins,
            explicit_phrase_choice,
        );
        wipe_value(&mut data);
        result?;
        Ok(
            json!({"device_id":self.scope.device_id,"signing_key":b64(signing.public_key.as_ref()),"encryption_key":b64(encryption.public_key.as_ref()),"capabilities":["delegate-device","distribute-group-key","receive-group-key","sign-content"]}),
        )
    }
    pub fn initialize_device_hello(&self, hwnd: usize, pins: Value) -> Result<Value> {
        let signing = libsodium_rs::crypto_sign::KeyPair::generate()
            .map_err(|_| Error("CRYPTO_UNAVAILABLE"))?;
        let encryption = libsodium_rs::crypto_box::KeyPair::generate();
        let mut data = json!({"device_signing_secret":b64(signing.secret_key.as_ref()),"device_encryption_secret":b64(encryption.secret_key.as_ref()),"group_keys":[]});
        let result = self.initialize_hello(hwnd, &Zeroizing::new(canonical(&data)?), pins);
        wipe_value(&mut data);
        result?;
        Ok(
            json!({"device_id":self.scope.device_id,"signing_key":b64(signing.public_key.as_ref()),"encryption_key":b64(encryption.public_key.as_ref())}),
        )
    }
    pub fn native_pairing_qr(&self, cap: &Capability, record: &Value, mode: &str) -> Result<Value> {
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (_, roster) = self.device_saved(&mut i, &s)?;
        let roster = roster.ok_or(Error("ROSTER_PROOF_REQUIRED"))?;
        check(
            ["new-device-offer", "existing-device-invitation"].contains(&mode),
            "UNSUPPORTED_PURPOSE",
        )?;
        let device = public_device(&self.scope, i.secrets.as_ref().unwrap())?;
        let kind = if mode == "new-device-offer" {
            "offer"
        } else {
            "invitation"
        };
        signed(
            &self.codec,
            "p02-state-c1",
            kind,
            record,
            text(&device["signing_key"])?,
        )?;
        for f in ["service_id", "account_id", "root_fingerprint"] {
            check(record["body"][f] == s.pins[f], "ROOT_PIN_MISMATCH")?;
        }
        check(
            record["body"]["roster"] == roster.head
                && record["body"]["generation"] == roster.generation,
            "ROSTER_CHANGED",
        )?;
        if mode == "new-device-offer" {
            check(
                record["body"]["device"] == device
                    && !roster.devices.contains_key(&self.scope.device_id),
                "DEVICE_KEY_MISMATCH",
            )?;
        } else {
            let actor = roster.active(&self.scope.device_id, Some("delegate-device"))?;
            check(
                record["body"]["approver"]
                    == json!({"device_id":self.scope.device_id,"certificate_digest":actor.digest}),
                "ISSUER_CONTEXT_MISMATCH",
            )?;
        }
        let key = Zeroizing::new(libsodium_rs::random::bytes(32));
        let qr = json!({"purpose":"pairing-qr","contract":"p02-state-c1","protocol":"anynote","protocol_version":1,"mode":mode,"channel_key":b64(&key),"record":record});
        let handle = random_id();
        check(i.device_channels.len() < 4, "RESOURCE_LIMIT")?;
        i.device_channels.insert(
            handle.clone(),
            crate::device_pairing::Channel::from_qr(
                &self.codec,
                &qr,
                mode == "new-device-offer",
                cap.generation,
            )?,
        );
        self.authorize(&mut i, cap)?;
        Ok(json!({"handle":handle,"qr":qr}))
    }
    pub fn native_pairing_scan(
        &self,
        cap: &Capability,
        qr: &Value,
        new_device: bool,
    ) -> Result<Value> {
        self.codec.validate("p02-state-c1", "qr", qr)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (_, roster) = self.device_saved(&mut i, &s)?;
        let roster = roster.ok_or(Error("ROSTER_PROOF_REQUIRED"))?;
        let b = &qr["record"]["body"];
        for f in ["service_id", "account_id", "root_fingerprint"] {
            check(b[f] == s.pins[f], "ROOT_PIN_MISMATCH")?;
        }
        check(
            b["roster"] == roster.head && b["generation"] == roster.generation,
            "ROSTER_CHANGED",
        )?;
        if new_device {
            check(
                qr["mode"] == "existing-device-invitation"
                    && !roster.devices.contains_key(&self.scope.device_id),
                "CHANNEL_REFLECTION",
            )?;
            let actor =
                roster.active(text(&b["approver"]["device_id"])?, Some("delegate-device"))?;
            check(
                b["approver"]["certificate_digest"] == actor.digest,
                "ISSUER_CONTEXT_MISMATCH",
            )?;
            signed(
                &self.codec,
                "p02-state-c1",
                "invitation",
                &qr["record"],
                text(&actor.certificate["body"]["device_signing_key"])?,
            )?;
        } else {
            check(qr["mode"] == "new-device-offer", "CHANNEL_REFLECTION")?;
            roster.active(&self.scope.device_id, Some("delegate-device"))?;
            signed(
                &self.codec,
                "p02-state-c1",
                "offer",
                &qr["record"],
                text(&b["device"]["signing_key"])?,
            )?;
        }
        let expiry = text(&b["expires_at"])?
            .parse::<u64>()
            .map_err(|_| Error("INVALID_CHALLENGE"))?;
        let t = now()?;
        check(expiry > t && expiry - t <= 600000, "ENROLLMENT_EXPIRED")?;
        let handle = random_id();
        check(i.device_channels.len() < 4, "RESOURCE_LIMIT")?;
        i.device_channels.insert(
            handle.clone(),
            crate::device_pairing::Channel::from_qr(&self.codec, qr, new_device, cap.generation)?,
        );
        Ok(json!({"handle":handle}))
    }
    #[allow(clippy::too_many_arguments)] // Closed purpose/direction/anchor arguments, never arbitrary signing.
    pub fn native_pairing_frame(
        &self,
        cap: &Capability,
        handle: &str,
        message: &str,
        value: &Value,
        anchor: &str,
        seal: bool,
    ) -> Result<Value> {
        check(valid_id(handle), "INVALID_CHANNEL")?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        self.authorize(&mut i, cap)?;
        let channel = i
            .device_channels
            .get_mut(handle)
            .ok_or(Error("CHANNEL_CLOSED"))?;
        check(channel.generation() == cap.generation, "STALE_CAPABILITY")?;
        let result = if seal {
            channel.seal(&self.codec, message, value, anchor)
        } else {
            channel.open(&self.codec, value, message, anchor)
        };
        self.authorize(&mut i, cap)?;
        result
    }
    pub fn device_response(
        &self,
        cap: &Capability,
        offer: &Value,
        invitation: Option<&Value>,
    ) -> Result<Value> {
        self.codec.validate("p02-state-c1", "offer", offer)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (_, roster) = self.device_saved(&mut i, &s)?;
        let roster = roster.ok_or(Error("ROSTER_PROOF_REQUIRED"))?;
        let actor = roster.active(&self.scope.device_id, Some("delegate-device"))?;
        let o = &offer["body"];
        for f in ["service_id", "account_id", "root_fingerprint"] {
            check(o[f] == s.pins[f], "ROOT_PIN_MISMATCH")?;
        }
        check(
            o["generation"] == roster.generation && o["roster"] == roster.head,
            "ROSTER_CHANGED",
        )?;
        signed(
            &self.codec,
            "p02-state-c1",
            "offer",
            offer,
            text(&o["device"]["signing_key"])?,
        )?;
        let mut body = common("pairing-response", &s.pins);
        body["operation_id"] = o["operation_id"].clone();
        body["generation"] = json!(roster.generation);
        body["roster"] = roster.head.clone();
        body["approver"] =
            json!({"device_id":self.scope.device_id,"certificate_digest":actor.digest});
        body["offer_digest"] = json!(digest("p02-state-c1", "offer", offer)?);
        body["invitation_digest"] = o["invitation_digest"].clone();
        body["nonce"] = json!(b64(&libsodium_rs::random::bytes(32)));
        body["expires_at"] = o["expires_at"].clone();
        let response = sign(
            &self.codec,
            "p02-state-c1",
            "response",
            body,
            &i.secrets.as_ref().unwrap().signing,
        )?;
        self.authorize(&mut i, cap)?;
        Ok(
            json!({"response":response,"transcript":{"purpose":"pairing-transcript","contract":"p02-state-c1","protocol":"anynote","protocol_version":1,"invitation":invitation,"offer":offer,"response":response}}),
        )
    }
    pub fn device_approval(
        &self,
        cap: &Capability,
        transcript: &Value,
        user_confirmed: bool,
    ) -> Result<Value> {
        check(user_confirmed, "USER_CONFIRMATION_REQUIRED")?;
        self.codec
            .validate("p02-state-c1", "transcript", transcript)?;
        let fence = self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (mut control, roster) = self.device_saved(&mut i, &s)?;
        let roster = roster.ok_or(Error("ROSTER_PROOF_REQUIRED"))?;
        let actor = roster.active(&self.scope.device_id, Some("delegate-device"))?;
        check(
            transcript["response"]["body"]["approver"]
                == json!({"device_id":self.scope.device_id,"certificate_digest":actor.digest}),
            "ISSUER_CONTEXT_MISMATCH",
        )?;
        let offer = &transcript["offer"]["body"];
        let tdigest = digest("p02-state-c1", "transcript", transcript)?;
        let secret = i.secrets.as_ref().unwrap();
        let certificate = sign(
            &self.codec,
            "p02-identity-c1",
            "certificate",
            certificate_body(
                &s.pins,
                &offer["device"],
                &roster.generation,
                &roster.head,
                json!({"kind":"device","device_id":self.scope.device_id,"certificate_digest":actor.digest}),
                tdigest.clone(),
            ),
            &secret.signing,
        )?;
        let mut plain = json!({"purpose":"pairing-encryption-proof","transcript_digest":tdigest,"device_id":offer["device"]["device_id"],"secret":b64(&libsodium_rs::random::bytes(32))});
        let pk = libsodium_rs::crypto_box::PublicKey::from_bytes(&un64(text(
            &offer["device"]["encryption_key"],
        )?)?)
        .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
        let sealed = libsodium_rs::crypto_box::seal_box(&Zeroizing::new(canonical(&plain)?), &pk)
            .map_err(|_| Error("CRYPTO_FAILURE"))?;
        let pdigest = digest("p02-state-c1", "pairing-proof-plaintext", &plain)?;
        wipe_value(&mut plain);
        let mut body = common("enrollment-approval", &s.pins);
        body["operation_id"] = offer["operation_id"].clone();
        body["generation"] = json!(roster.generation);
        body["roster"] = roster.head.clone();
        body["session_binding"] = offer["session_binding"].clone();
        body["transcript_digest"] = json!(tdigest);
        body["certificate"] = certificate;
        body["sealed_challenge"] = json!(b64(&sealed));
        body["challenge_digest"] = json!(pdigest);
        body["expires_at"] = offer["expires_at"].clone();
        let approval = sign(
            &self.codec,
            "p02-state-c1",
            "approval",
            body,
            &secret.signing,
        )?;
        roster.approval(&self.codec, transcript, &approval, Some(now()?))?;
        control["pending"] = json!({"operation_id":offer["operation_id"],"expires_at":offer["expires_at"],"mode":if transcript["invitation"].is_null(){"new-device-offer"}else{"existing-device-invitation"},"invitation":transcript["invitation"],"offer":transcript["offer"],"response":transcript["response"],"approval":approval,"event":null});
        self.store_device_control(&mut i, cap, &s, fence, &control, None)?;
        Ok(approval)
    }
    pub(crate) fn device_saved(&self, i: &mut Inner, s: &State) -> Result<(Value, Option<Roster>)> {
        let id = crate::device_local::control_id(&self.scope)?;
        let exists: Option<Vec<u8>> = db(i
            .conn
            .query_row("SELECT frame FROM records WHERE id=?1", [&id], |r| r.get(0))
            .optional())?;
        let Some(bytes) = exists else {
            return Ok((Value::Null, None));
        };
        let control = crate::device_local::open(
            &self.scope,
            &s.pins,
            &id,
            "device-control",
            &strict(&bytes, 1048576)?,
            &i.secrets.as_ref().unwrap().key,
        )?;
        check(
            control["purpose"] == "p08-installation-control" && control["version"] == 1,
            "INTEGRITY_FAILURE",
        )?;
        let pages = control["pages"]
            .as_array()
            .ok_or(Error("INTEGRITY_FAILURE"))?;
        check(pages.len() <= 1000, "RESOURCE_LIMIT")?;
        if control["head"].is_null() {
            return Ok((control, None));
        }
        let mut events = Vec::new();
        let mut count = 0;
        for page_id in pages {
            let page_id = text(page_id)?;
            let p = crate::device_local::open(
                &self.scope,
                &s.pins,
                page_id,
                "roster-page",
                &frame(&i.conn, page_id)?,
                &i.secrets.as_ref().unwrap().key,
            )?;
            check(
                p["purpose"] == "p08-roster-page" && p["version"] == 1,
                "INTEGRITY_FAILURE",
            )?;
            let rows = p["events"].as_array().ok_or(Error("INTEGRITY_FAILURE"))?;
            count += canonical(&p)?.len();
            check(count <= 33554432 && rows.len() <= 20, "RESOURCE_LIMIT")?;
            events.extend(rows.iter().cloned());
        }
        let snapshot = json!({"identity":control["identity"],"head":control["head"],"generation":control["generation"],"events":events});
        let anchor = i.device_anchor.as_ref();
        let roster = Roster::replay(&self.codec, &snapshot, &s.pins, anchor)?;
        Ok((control, Some(roster)))
    }
    pub(crate) fn store_device_control(
        &self,
        i: &mut Inner,
        cap: &Capability,
        before: &State,
        fence: u64,
        control: &Value,
        snapshot: Option<&Value>,
    ) -> Result<()> {
        let key = Zeroizing::new(i.secrets.as_ref().unwrap().key.to_vec());
        let old = self.device_saved(i, before)?.0;
        let tx = db(i
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut s = state(&tx, &self.codec, &self.scope)?;
        self.fence(&s, fence)?;
        check(
            s.epoch == before.epoch
                && s.revision == before.revision
                && self.signal.generation() == cap.generation,
            "STALE_WRITER",
        )?;
        let mut control = control.clone();
        if let Some(snapshot) = snapshot {
            let events = snapshot["events"]
                .as_array()
                .ok_or(Error("INTEGRITY_FAILURE"))?;
            let mut pages = Vec::new();
            for values in events.chunks(20) {
                let id = random_id();
                let data = json!({"purpose":"p08-roster-page","version":1,"events":values});
                let f = crate::device_local::seal(
                    &self.scope,
                    &s.pins,
                    &id,
                    "roster-page",
                    &data,
                    &key,
                )?;
                db(tx.execute(
                    "INSERT INTO records(id,frame) VALUES(?1,?2)",
                    params![id, canonical(&f)?],
                ))?;
                pages.push(id);
            }
            control["pages"] = json!(pages);
            for id in old["pages"].as_array().unwrap_or(&Vec::new()) {
                let id = text(id)?;
                check(valid_id(id) && id != s.vault_id, "RESERVED_RECORD")?;
                db(tx.execute("DELETE FROM records WHERE id=?1", [id]))?;
            }
        }
        let id = crate::device_local::control_id(&self.scope)?;
        let f =
            crate::device_local::seal(&self.scope, &s.pins, &id, "device-control", &control, &key)?;
        db(tx.execute("INSERT INTO records(id,frame) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET frame=excluded.frame",params![id,canonical(&f)?]))?;
        s.revision += 1;
        put_state(&tx, &s)?;
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        db(tx.commit())?;
        i.observed_revision = s.revision;
        Ok(())
    }
    pub fn record_device_snapshot(&self, cap: &Capability, snapshot: &Value) -> Result<Value> {
        let fence = self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (old, _) = self.device_saved(&mut i, &s)?;
        let anchor = i
            .device_anchor
            .as_ref()
            .or_else(|| old.get("head").filter(|v| !v.is_null()));
        let roster = Roster::replay(&self.codec, snapshot, &s.pins, anchor)?;
        let mut control = if old.is_null() {
            json!({"purpose":"p08-installation-control","version":1,"identity":null,"head":null,"generation":null,"pages":[],"staging":null,"pending":null,"kit_verified":false})
        } else {
            old
        };
        control["identity"] = snapshot["identity"].clone();
        control["head"] = snapshot["head"].clone();
        control["generation"] = snapshot["generation"].clone();
        self.store_device_control(&mut i, cap, &s, fence, &control, Some(snapshot))?;
        i.device_anchor = Some(roster.head.clone());
        self.authorize(&mut i, cap)?;
        Ok(roster.summary())
    }
    pub fn device_public(&self, cap: &Capability) -> Result<Value> {
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        self.authorize(&mut i, cap)?;
        public_device(&self.scope, i.secrets.as_ref().unwrap())
    }
    pub fn device_invitation(&self, cap: &Capability) -> Result<Value> {
        let fence = self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (mut control, roster) = self.device_saved(&mut i, &s)?;
        let roster = roster.ok_or(Error("ROSTER_PROOF_REQUIRED"))?;
        let actor = roster.active(&self.scope.device_id, Some("delegate-device"))?;
        check(
            actor.certificate["body"]["device_signing_key"]
                == public_device(&self.scope, i.secrets.as_ref().unwrap())?["signing_key"],
            "DEVICE_KEY_MISMATCH",
        )?;
        let mut body = common("pairing-invitation", &s.pins);
        body["operation_id"] = json!(random_id());
        body["generation"] = json!(roster.generation);
        body["roster"] = roster.head.clone();
        body["approver"] =
            json!({"device_id":self.scope.device_id,"certificate_digest":actor.digest});
        body["nonce"] = json!(b64(&libsodium_rs::random::bytes(32)));
        body["expires_at"] = json!((now()? + 540000).to_string());
        let record = sign(
            &self.codec,
            "p02-state-c1",
            "invitation",
            body,
            &i.secrets.as_ref().unwrap().signing,
        )?;
        control["pending"] = json!({"operation_id":record["body"]["operation_id"],"expires_at":record["body"]["expires_at"],"mode":"existing-device-invitation","invitation":record,"offer":null,"response":null,"approval":null,"event":null});
        self.store_device_control(&mut i, cap, &s, fence, &control, None)?;
        Ok(record)
    }
    pub fn device_offer(
        &self,
        cap: &Capability,
        session_id: &str,
        invitation: Option<&Value>,
    ) -> Result<Value> {
        check(valid_id(session_id), "INVALID_SESSION")?;
        let fence = self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (mut control, roster) = self.device_saved(&mut i, &s)?;
        let roster = roster.ok_or(Error("ROSTER_PROOF_REQUIRED"))?;
        check(
            !roster.devices.contains_key(&self.scope.device_id),
            "DEVICE_ALREADY_REGISTERED",
        )?;
        let device = public_device(&self.scope, i.secrets.as_ref().unwrap())?;
        let (operation_id, expires, invite_digest) = if let Some(invite) = invitation {
            let b = &invite["body"];
            let actor =
                roster.active(text(&b["approver"]["device_id"])?, Some("delegate-device"))?;
            signed(
                &self.codec,
                "p02-state-c1",
                "invitation",
                invite,
                text(&actor.certificate["body"]["device_signing_key"])?,
            )?;
            for k in ["service_id", "account_id", "root_fingerprint"] {
                check(b[k] == s.pins[k], "ROOT_PIN_MISMATCH")?;
            }
            check(
                b["generation"] == roster.generation
                    && b["roster"] == roster.head
                    && b["approver"]["certificate_digest"] == actor.digest,
                "ROSTER_CHANGED",
            )?;
            (
                text(&b["operation_id"])?.to_owned(),
                text(&b["expires_at"])?
                    .parse::<u64>()
                    .map_err(|_| Error("INVALID_CHALLENGE"))?,
                json!(digest("p02-state-c1", "invitation", invite)?),
            )
        } else {
            (random_id(), now()? + 540000, Value::Null)
        };
        let t = now()?;
        check(expires > t && expires - t <= 600000, "ENROLLMENT_EXPIRED")?;
        let mut body = common("pairing-offer", &s.pins);
        body["operation_id"] = json!(operation_id);
        body["generation"] = json!(roster.generation);
        body["roster"] = roster.head.clone();
        body["session_binding"] = json!(hash(
            format!("AnyNote/P06/session-binding\0{session_id}").as_bytes()
        ));
        body["device"] = device;
        body["nonce"] = json!(b64(&libsodium_rs::random::bytes(32)));
        body["expires_at"] = json!(expires.to_string());
        body["invitation_digest"] = invite_digest;
        let record = sign(
            &self.codec,
            "p02-state-c1",
            "offer",
            body,
            &i.secrets.as_ref().unwrap().signing,
        )?;
        control["pending"] = json!({"operation_id":record["body"]["operation_id"],"expires_at":record["body"]["expires_at"],"mode":if invitation.is_some(){"existing-device-invitation"}else{"new-device-offer"},"invitation":invitation,"offer":record,"response":null,"approval":null,"event":null});
        self.store_device_control(&mut i, cap, &s, fence, &control, None)?;
        Ok(record)
    }
    pub fn device_confirmation(
        &self,
        cap: &Capability,
        transcript: &Value,
        approval: &Value,
        session_id: &str,
        user_confirmed: bool,
    ) -> Result<Value> {
        check(
            user_confirmed && valid_id(session_id),
            "USER_CONFIRMATION_REQUIRED",
        )?;
        let fence = self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (mut control, roster) = self.device_saved(&mut i, &s)?;
        let roster = roster.ok_or(Error("ROSTER_PROOF_REQUIRED"))?;
        roster.approval(&self.codec, transcript, approval, Some(now()?))?;
        let d = &transcript["offer"]["body"]["device"];
        let secret = i.secrets.as_ref().unwrap();
        check(
            *d == public_device(&self.scope, secret)?
                && transcript["offer"]["body"]["session_binding"]
                    == hash(format!("AnyNote/P06/session-binding\0{session_id}").as_bytes()),
            "SESSION_BINDING_MISMATCH",
        )?;
        let pk =
            libsodium_rs::crypto_box::PublicKey::from_bytes(&un64(text(&d["encryption_key"])?)?)
                .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
        let sk = libsodium_rs::crypto_box::SecretKey::from_bytes(&secret.encryption)
            .map_err(|_| Error("INVALID_KEY_LENGTH"))?;
        let plain = Zeroizing::new(
            libsodium_rs::crypto_box::open_sealed_box(
                &un64(text(&approval["body"]["sealed_challenge"])?)?,
                &pk,
                &sk,
            )
            .map_err(|_| Error("INTEGRITY_FAILURE"))?,
        );
        let mut p = self
            .codec
            .decode("p02-state-c1", "pairing-proof-plaintext", &plain)?;
        let result = (|| {
            check(
                p["transcript_digest"] == digest("p02-state-c1", "transcript", transcript)?
                    && p["device_id"] == self.scope.device_id
                    && digest("p02-state-c1", "pairing-proof-plaintext", &p)?
                        == approval["body"]["challenge_digest"],
                "INNER_CONTEXT_MISMATCH",
            )?;
            let mut body = common("enrollment-confirmation", &s.pins);
            body["operation_id"] = transcript["offer"]["body"]["operation_id"].clone();
            body["generation"] = json!(roster.generation);
            body["roster"] = roster.head.clone();
            body["session_binding"] = transcript["offer"]["body"]["session_binding"].clone();
            body["transcript_digest"] = approval["body"]["transcript_digest"].clone();
            body["certificate_digest"] = json!(digest(
                "p02-identity-c1",
                "device-certificate",
                &approval["body"]["certificate"]
            )?);
            body["approval_digest"] = json!(digest("p02-state-c1", "approval", approval)?);
            body["challenge_response"] = p["secret"].clone();
            let confirmation = sign(
                &self.codec,
                "p02-state-c1",
                "confirmation",
                body,
                &secret.signing,
            )?;
            let mut event = common("device-roster-event", &s.pins);
            event["operation_id"] = confirmation["body"]["operation_id"].clone();
            event["generation"] = json!(roster.generation);
            event["version"] = json!(
                (text(&roster.head["version"])?
                    .parse::<u64>()
                    .map_err(|_| Error("SCHEMA_MISMATCH"))?
                    + 1)
                .to_string()
            );
            event["predecessor"] = roster.head.clone();
            event["kind"] = json!("enroll");
            event["signer"] = json!(self.scope.device_id);
            event["payload"] =
                json!({"transcript":transcript,"approval":approval,"confirmation":confirmation});
            sign(&self.codec, "p02-state-c1", "event", event, &secret.signing)
        })();
        wipe_value(&mut p);
        let event = result?;
        control["pending"]["event"] = event.clone();
        self.store_device_control(&mut i, cap, &s, fence, &control, None)?;
        Ok(event)
    }
    pub fn device_recovery_reset(
        &self,
        cap: &Capability,
        kit: &Value,
        challenge: &Value,
        session_id: &str,
        user_confirmed: bool,
    ) -> Result<Value> {
        check(user_confirmed, "USER_CONFIRMATION_REQUIRED")?;
        let fence = self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (mut control, roster) = self.device_saved(&mut i, &s)?;
        let roster = roster.ok_or(Error("ROSTER_PROOF_REQUIRED"))?;
        check(
            challenge["context"]["generation"] == roster.generation
                && challenge["context"]["roster"] == roster.head
                && !roster.devices.contains_key(&self.scope.device_id),
            "ROSTER_CHANGED",
        )?;
        let root = objects::recover_root(
            &self.codec,
            &Zeroizing::new(canonical(kit)?),
            &canonical(&s.pins)?,
        )?;
        let generation = (roster
            .generation
            .parse::<u64>()
            .map_err(|_| Error("SCHEMA_MISMATCH"))?
            + 1)
        .to_string();
        let secret = i.secrets.as_ref().unwrap();
        let confirmation = possession(
            &self.codec,
            &self.scope,
            secret,
            &s.pins,
            challenge,
            session_id,
            "reset",
        )?;
        let certificate = sign(
            &self.codec,
            "p02-identity-c1",
            "certificate",
            certificate_body(
                &s.pins,
                &public_device(&self.scope, secret)?,
                &generation,
                &roster.head,
                json!({"kind":"root","root_fingerprint":s.pins["root_fingerprint"]}),
                digest("p02-state-c1", "challenge", challenge)?,
            ),
            root.0.secret_key.as_ref(),
        )?;
        let mut body = common("device-roster-event", &s.pins);
        body["operation_id"] = json!(random_id());
        body["kind"] = json!("reset");
        body["signer"] = json!("root");
        body["generation"] = json!(generation);
        body["version"] = json!(
            (text(&roster.head["version"])?
                .parse::<u64>()
                .map_err(|_| Error("SCHEMA_MISMATCH"))?
                + 1)
            .to_string()
        );
        body["predecessor"] = roster.head;
        body["payload"] = json!({"challenge":challenge,"certificate":certificate,"confirmation":confirmation,"active_device_limit":roster.limit});
        let event = sign(
            &self.codec,
            "p02-state-c1",
            "event",
            body,
            root.0.secret_key.as_ref(),
        )?;
        control["pending"] = json!({"operation_id":event["body"]["operation_id"],"expires_at":challenge["context"]["expires_at"],"mode":"recovery","event":event});
        self.store_device_control(&mut i, cap, &s, fence, &control, None)?;
        Ok(event)
    }
    pub fn device_revoke(
        &self,
        cap: &Capability,
        targets: &[String],
        user_confirmed: bool,
    ) -> Result<Value> {
        check(
            user_confirmed && !targets.is_empty(),
            "USER_CONFIRMATION_REQUIRED",
        )?;
        let fence = self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (mut control, roster) = self.device_saved(&mut i, &s)?;
        let roster = roster.ok_or(Error("ROSTER_PROOF_REQUIRED"))?;
        roster.active(&self.scope.device_id, Some("delegate-device"))?;
        let mut targets = targets.to_vec();
        targets.sort();
        check(
            targets.windows(2).all(|v| v[0] != v[1]),
            "UNORDERED_OR_DUPLICATE",
        )?;
        let affected = roster.descendants(&targets)?;
        check(
            !affected.contains(&self.scope.device_id),
            "REVOKER_IN_CLOSURE",
        )?;
        let mut body = common("device-roster-event", &s.pins);
        body["operation_id"] = json!(random_id());
        body["kind"] = json!("revoke");
        body["signer"] = json!(self.scope.device_id);
        body["generation"] = json!(roster.generation);
        body["version"] = json!(
            (text(&roster.head["version"])?
                .parse::<u64>()
                .map_err(|_| Error("SCHEMA_MISMATCH"))?
                + 1)
            .to_string()
        );
        body["predecessor"] = roster.head;
        body["payload"] = json!({"targets":targets,"affected_devices":affected});
        let event = sign(
            &self.codec,
            "p02-state-c1",
            "event",
            body,
            &i.secrets.as_ref().unwrap().signing,
        )?;
        control["revoke_request"] = json!({"version":1,"event":event});
        self.store_device_control(&mut i, cap, &s, fence, &control, None)?;
        Ok(event)
    }
    pub fn device_retry(&self, cap: &Capability, recovery: bool) -> Result<Value> {
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let (control, _) = self.device_saved(&mut i, &s)?;
        let event = if recovery {
            &control["pending"]["event"]
        } else {
            &control["revoke_request"]["event"]
        };
        self.codec.validate("p02-state-c1", "event", event)?;
        Ok(event.clone())
    }
}
