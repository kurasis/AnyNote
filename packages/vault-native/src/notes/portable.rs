//! Trusted native portable operations; there are no renderer key/signature commands.
use super::*;
impl Vault {
    pub fn portable_public(&self, cap: &Capability, groups: &[String]) -> Result<Value> {
        self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let snapshot = self.snapshot_for_groups(&mut i, &s)?;
        let roster = Roster::replay(&self.codec, &snapshot, &s.pins, i.device_anchor.as_ref())?;
        let signer = author(&roster, &self.scope, &i.secrets.as_ref().unwrap().signing)?;
        let control = self.note_control(&i.conn, &s, &i.secrets.as_ref().unwrap().key)?;
        let mut proofs = Vec::new();
        let mut accounts = BTreeMap::new();
        accounts.insert(
            self.scope.account_id.clone(),
            json!({"pins":s.pins,"snapshot":snapshot}),
        );
        let mut pins = Vec::new();
        check(groups.len() <= 200, "RESOURCE_LIMIT")?;
        for group in groups {
            let reference = find(&control, "groups", "group_id", group)?;
            let data = self.note_read(
                &mut i,
                &s,
                &control,
                text(&reference["record_id"])?,
                "group-evidence",
            )?;
            let mut proof = if data["purpose"] == "p10-group-proof" {
                self.note_shared_proof(&mut i, &s, &control, &snapshot, &data)?
                    .0
            } else {
                let evidence = &data["evidence"];
                json!({"pin":crate::shared::pin(evidence)?,"journal":{"version":1,"group_id":group,"genesis":evidence,"events":[],"pending":null},"accounts":[{"pins":s.pins,"snapshot":snapshot}]})
            };
            if data["purpose"] != "p10-group-proof" {
                let records = self.note_history_records(&mut i, &s, &control, group)?;
                let local = json!({"purpose":"p10-group-proof","version":1,"proof":proof,"attempt":null,"pending_key":null});
                let mut secrets =
                    self.secret_plain(&i.conn, &s, &i.secrets.as_ref().unwrap().key)?;
                let outcome = crate::shared::command(
                    &self.codec,
                    &crate::shared::Request::History {
                        group_id: group.clone(),
                    },
                    &self.scope,
                    &s.pins,
                    &snapshot,
                    Some(&local),
                    &records,
                    &i.secrets.as_ref().unwrap().signing,
                    &i.secrets.as_ref().unwrap().encryption,
                    &secrets["data"],
                );
                wipe_value(&mut secrets);
                let outcome = outcome?;
                let h = &outcome.result["body"];
                let head = json!({"version":h["history"]["body"]["sequence"],"digest":digest("p02-group-c2","history",&h["history"])?});
                proof["pin"]["history"] = head;
                proof["journal"]["events"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"kind":"history","history":h["history"],"pages":h["pages"]}));
            }
            proof["journal"]["pending"] = Value::Null;
            let verified = crate::shared::verify(&self.codec, &proof, &s.pins, None, &[], false)?;
            let reference=proof["journal"]["events"].as_array().unwrap().iter().rev().find(|e|e["kind"]=="history").map(|e|Ok::<_,Error>(json!({"version":e["history"]["body"]["sequence"],"digest":digest("p02-group-c2","history",&e["history"])?}))).transpose()?.unwrap_or(Value::Null);
            proof["pin"]["history"] = reference.clone();
            pins.push(json!({"group_id":group,"genesis_digest":proof["pin"]["genesis_digest"],"policy":verified.policy,"epoch":verified.epoch_head,"history":reference}));
            for a in proof["accounts"].as_array().unwrap() {
                let account = text(&a["pins"]["account_id"])?;
                if let Some(old) = accounts.get(account) {
                    check(old["pins"] == a["pins"], "ROOT_PIN_MISMATCH")?;
                }
                accounts.insert(account.into(), a.clone());
            }
            proofs.push(proof);
        }
        Ok(
            json!({"pins":pins,"signer":signer,"root_fingerprint":s.pins["root_fingerprint"],"document":{"profile":"p13-public-proof-v1","version":1,"accounts":accounts.values().collect::<Vec<_>>(),"groups":proofs}}),
        )
    }
    pub fn portable_selected_key(
        &self,
        cap: &Capability,
        item: &Value,
        record: &Value,
    ) -> Result<Value> {
        let context = &record["envelope"]["header"]["context"];
        let file = item["object_kind"] == "file-manifest";
        check(
            context["service_id"] == self.scope.service_id
                && item["group_id"] == context["group_id"]
                && item["object_id"] == context[if file { "file_id" } else { "object_id" }]
                && item["revision_id"]
                    == context[if file {
                        "file_version_id"
                    } else {
                        "revision_id"
                    }]
                && item["envelope_digest"]
                    == digest(
                        if file { "p02-file-c1" } else { "p02-v1" },
                        if file { "file-envelope" } else { "envelope" },
                        &record["envelope"],
                    )?
                && item["payload_status"] != "pruned",
            "EXPORT_SOURCE_MISMATCH",
        )?;
        if file {
            let _ = self.file_reader(cap, record)?;
        }
        self.lease(cap)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let control = self.note_control(&i.conn, &s, &i.secrets.as_ref().unwrap().key)?;
        let snapshot = self.snapshot_for_groups(&mut i, &s)?;
        let group = text(&context["group_id"])?;
        if !file {
            let roster = Roster::replay(&self.codec, &snapshot, &s.pins, i.device_anchor.as_ref())?;
            let request = json!({"group_id":group,"object_id":context["object_id"],"revision_id":context["revision_id"],"object_kind":context["object_kind"],"thread_id":context["thread_id"],"bundle":record});
            let mut opened = self.note_verify_payload(
                &mut i,
                &s,
                &control,
                (&snapshot, &roster),
                &request,
                false,
            )?;
            wipe_value(&mut opened);
        }
        let (_, _, mut info) = self.note_info(&mut i, &s, &control, &snapshot, group)?;
        info["policy"] = context["policy"].clone();
        info["epoch_digest"] = context["policy"]["epoch_digest"].clone();
        let group_key = self.note_key(&i, &s, group, &info)?;
        let aad = if file {
            anynote_crypto_core::files::aad(
                &record["envelope"]["header"],
                "file-manifest-key-wrap",
                0,
            )?
        } else {
            objects::aad("object-key-wrap", &json!({"context":context}))?
        };
        let key = anynote_crypto_core::crypto::decrypt(
            &un64(text(&record["wrap"]["ciphertext"])?)?,
            &aad,
            &un64(text(&record["wrap"]["nonce"])?)?,
            &group_key,
        )?;
        let mut file_key = Value::Null;
        if file {
            let plain = anynote_crypto_core::crypto::decrypt(
                &un64(text(&record["manifest_ciphertext"])?)?,
                &anynote_crypto_core::files::aad(
                    &record["envelope"]["header"],
                    "file-manifest",
                    0,
                )?,
                &un64(text(&record["envelope"]["header"]["manifest_nonce"])?)?,
                &key,
            )?;
            let mut manifest = self.codec.decode("p02-file-c1", "manifest", &plain)?;
            file_key = manifest["file_data_key"].clone();
            wipe_value(&mut manifest);
        }
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        Ok(
            json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"export-selected-key","service_id":context["service_id"],"group_id":group,"object_id":if file{&context["file_id"]}else{&context["object_id"]},"revision_id":item["revision_id"],"key_kind":if file{"manifest-and-file-deks"}else{"object-dek"},"object_dek":b64(&key),"file_data_dek":file_key}),
        )
    }
    pub fn sign_portable_footer(
        &self,
        cap: &Capability,
        body: &Value,
        expected: &Value,
    ) -> Result<Vec<u8>> {
        check(body == expected, "EXPORT_SOURCE_MISMATCH")?;
        self.codec.validate("p02-v1", "export-footer-body", body)?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        let snap = self.snapshot_for_groups(&mut i, &s)?;
        let roster = Roster::replay(&self.codec, &snap, &s.pins, i.device_anchor.as_ref())?;
        check(
            body["signer"] == author(&roster, &self.scope, &i.secrets.as_ref().unwrap().signing)?,
            "ROSTER_CHANGED",
        )?;
        un64(&anynote_crypto_core::crypto::sign(
            &self.codec.signing("p02-v1", "export-footer-body", body)?,
            &i.secrets.as_ref().unwrap().signing,
        )?)
    }
}
