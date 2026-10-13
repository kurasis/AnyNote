//! Additive encrypted secret inventory. Older readers fail before unlocking a new root.
use super::*;
type Prepared = (Value, Vec<(String, Vec<u8>)>, Vec<String>);
impl Vault {
    pub(crate) fn secret_plain(&self, conn: &Connection, s: &State, key: &[u8]) -> Result<Value> {
        let f = frame(conn, &s.vault_id)?;
        if f["contract"] != "p11-local-v1" {
            return objects::open_local(
                &self.codec,
                &canonical(&f)?,
                key,
                &canonical(&self.context("vault-secrets", &s.vault_id)?)?,
            );
        }
        let data = paged_local::open(
            &self.codec,
            conn,
            &self.scope,
            &s.pins,
            (&s.vault_id, "vault-secrets"),
            &f,
            key,
        )?;
        self.codec.validate("p11-sync", "secrets", &data)?;
        Ok(
            json!({"contract":"p02-v1","protocol":"anynote","protocol_version":1,"purpose":"local-record-plaintext","context":self.context("vault-secrets",&s.vault_id)?,"data":data}),
        )
    }
    pub(crate) fn prepare_secret_pages(
        &self,
        conn: &Connection,
        s: &State,
        key: &[u8],
        data: &Value,
    ) -> Result<Prepared> {
        self.codec.validate("p11-sync", "secrets", data)?;
        let keys = data["group_keys"]
            .as_array()
            .ok_or(Error("INTEGRITY_FAILURE"))?;
        let mut seen = std::collections::BTreeSet::new();
        for k in keys {
            check(
                k["service_id"] == self.scope.service_id
                    && seen.insert((text(&k["group_id"])?, text(&k["key_epoch"])?)),
                "INTEGRITY_FAILURE",
            )?;
        }
        let old = frame(conn, &s.vault_id)?;
        let mut remove = Vec::new();
        if old["contract"] == "p11-local-v1" {
            let mut m = paged_local::manifest(
                &self.codec,
                &self.scope,
                &s.pins,
                &s.vault_id,
                "vault-secrets",
                &old,
                key,
            )?;
            for p in m["parts"].as_array().ok_or(Error("INTEGRITY_FAILURE"))? {
                remove.push(text(&p["record_id"])?.into());
            }
            wipe_value(&mut m);
        }
        let (root, parts) = paged_local::prepare(
            &self.codec,
            &self.scope,
            &s.pins,
            &s.vault_id,
            "vault-secrets",
            data,
            key,
        )?;
        Ok((root, parts, remove))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paged_secret_inventory_crosses_660_without_identity_or_plaintext_loss() {
        libsodium_rs::ensure_init().unwrap();
        let id = || b64(&libsodium_rs::random::bytes(16));
        let scope = Scope {
            service_id: id(),
            account_id: id(),
            device_id: id(),
            profile_id: id(),
        };
        let pins = json!({"service_id":scope.service_id,"account_id":scope.account_id,"root_fingerprint":hash(&libsodium_rs::random::bytes(32))});
        let root = std::env::temp_dir().join(format!("anynote-p11-secret-{}", id()));
        let path = root.join("vault.sqlite");
        let signing = libsodium_rs::crypto_sign::KeyPair::generate().unwrap();
        let encryption = libsodium_rs::crypto_box::KeyPair::generate();
        let data = json!({"device_signing_secret":b64(signing.secret_key.as_ref()),"device_encryption_secret":b64(encryption.secret_key.as_ref()),"group_keys":[]});
        let phrase = "public synthetic purple harbor paper lantern";
        let vault = Vault::open(&path, scope.clone()).unwrap();
        vault
            .initialize_phrase(phrase, &canonical(&data).unwrap(), pins, true)
            .unwrap();
        let cap = vault.unlock_phrase(phrase).unwrap();
        let expected = {
            let mut i = vault.inner.lock().unwrap();
            let s = vault.authorize(&mut i, &cap).unwrap();
            let key = Zeroizing::new(i.secrets.as_ref().unwrap().key.to_vec());
            let mut p = vault.secret_plain(&i.conn, &s, &key).unwrap();
            let group = id();
            p["data"]["group_keys"]=json!((0..661).map(|n|json!({"service_id":scope.service_id,"group_id":group,"key_epoch":n.to_string(),"epoch_digest":hash(&libsodium_rs::random::bytes(32)),"group_secret":b64(&libsodium_rs::random::bytes(32))})).collect::<Vec<_>>());
            assert!(
                vault
                    .codec
                    .validate("p02-v1", "vault-secrets", &p["data"])
                    .is_err()
            );
            let (frame, parts, remove) = vault
                .prepare_secret_pages(&i.conn, &s, &key, &p["data"])
                .unwrap();
            assert!(remove.is_empty());
            let tx = i.conn.transaction().unwrap();
            for (id, bytes) in parts {
                tx.execute(
                    "INSERT INTO records(id,frame) VALUES(?1,?2)",
                    params![id, bytes],
                )
                .unwrap();
            }
            tx.execute(
                "UPDATE records SET frame=?1 WHERE id=?2",
                params![canonical(&frame).unwrap(), s.vault_id],
            )
            .unwrap();
            tx.commit().unwrap();
            let expected = p["data"].clone();
            wipe_value(&mut p);
            expected
        };
        vault.lock_all().unwrap();
        drop(vault);
        let reopened = Vault::open(&path, scope).unwrap();
        let cap = reopened.unlock_phrase(phrase).unwrap();
        {
            let mut i = reopened.inner.lock().unwrap();
            let s = reopened.authorize(&mut i, &cap).unwrap();
            let mut p = reopened
                .secret_plain(&i.conn, &s, &i.secrets.as_ref().unwrap().key)
                .unwrap();
            assert_eq!(p["data"], expected);
            wipe_value(&mut p);
        }
        for path in [&path, &PathBuf::from(format!("{}-wal", path.display()))] {
            if let Ok(bytes) = std::fs::read(path) {
                for marker in [
                    expected["device_signing_secret"].as_str().unwrap(),
                    expected["group_keys"][660]["group_secret"]
                        .as_str()
                        .unwrap(),
                ] {
                    assert!(!bytes.windows(marker.len()).any(|b| b == marker.as_bytes()));
                }
            }
        }
        let mut expected = expected;
        wipe_value(&mut expected);
        reopened.lock_all().unwrap();
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }
}
