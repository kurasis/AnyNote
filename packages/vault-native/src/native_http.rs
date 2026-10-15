//! Native-only fixed product transport with credentials opened only under L.
use super::*;
impl Vault {
    /// Nonsecret lifetime only; bearer and refresh credentials never leave native custody.
    pub fn native_credentials_expires_at(
        &self,
        cap: &Capability,
        credential_id: &str,
    ) -> Result<u64> {
        check(valid_id(credential_id), "INVALID_SESSION")?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        let s = self.authorize(&mut i, cap)?;
        check(s.rotation.is_none(), "REAUTH_REQUIRED")?;
        let record = frame(&i.conn, credential_id)?;
        let mut plain = objects::open_local(
            &self.codec,
            &canonical(&record)?,
            &i.secrets.as_ref().unwrap().key,
            &canonical(&self.context("session", credential_id)?)?,
        )?;
        let result = text(&plain["data"]["expires_at"])
            .and_then(|v| v.parse::<u64>().map_err(|_| Error("INVALID_SESSION")));
        wipe_value(&mut plain);
        result
    }
    pub(crate) fn refresh_native_credentials(
        &self,
        cap: &Capability,
        credential_id: &str,
        adapter: &anynote_auth_native::Adapter,
    ) -> Result<()> {
        if now()?.saturating_add(60000) >= self.native_credentials_expires_at(cap, credential_id)? {
            // The maintained durable rotation marker admits one refresh. Unknown
            // responses require fresh login and are never automatically replayed.
            self.rotate_credentials(cap, credential_id, adapter)?;
        }
        Ok(())
    }
    #[cfg(feature = "integration-harness")]
    pub fn synthetic_expire_native_session(
        &self,
        cap: &Capability,
        credential_id: &str,
    ) -> Result<u64> {
        let before = self.native_credentials_expires_at(cap, credential_id)?;
        let mut data = {
            let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
            self.authorize(&mut i, cap)?;
            let record = frame(&i.conn, credential_id)?;
            let mut plain = objects::open_local(
                &self.codec,
                &canonical(&record)?,
                &i.secrets.as_ref().unwrap().key,
                &canonical(&self.context("session", credential_id)?)?,
            )?;
            let data = plain["data"].take();
            wipe_value(&mut plain);
            data
        };
        // Shorten the synthetic cached lifetime; never extend server authorization.
        data["expires_at"] = json!(now()?.to_string());
        let mut records = [Record {
            id: credential_id.to_owned(),
            kind: "session".into(),
            data,
        }];
        let result = self
            .lease(cap)
            .and_then(|fence| self.save_batch(cap, fence, &records));
        wipe_value(&mut records[0].data);
        result?;
        Ok(before)
    }
    /// Public profile pins, returned only after the encrypted native vault is authorized.
    pub fn native_profile_pins(&self, cap: &Capability) -> Result<Value> {
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        Ok(self.authorize(&mut i, cap)?.pins)
    }
    pub fn export_chunk_http(
        &self,
        cap: &Capability,
        credential_id: &str,
        adapter: &anynote_auth_native::Adapter,
        snapshot: &str,
        version: &str,
        index: u8,
    ) -> Result<anynote_auth_native::FileResponse> {
        self.control_http(
            cap,
            credential_id,
            adapter,
            anynote_auth_native::control::Route::ExportChunk,
            Some(snapshot),
            Some(version),
            &[("index", &index.to_string())],
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn control_http(
        &self,
        cap: &Capability,
        credential_id: &str,
        adapter: &anynote_auth_native::Adapter,
        route: anynote_auth_native::control::Route,
        a: Option<&str>,
        b: Option<&str>,
        query: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<anynote_auth_native::FileResponse> {
        check(valid_id(credential_id), "INVALID_SESSION")?;
        // Serialize credential rotation with in-flight native requests as well.
        let _transport = self
            .credential_refresh
            .lock()
            .map_err(|_| Error("VAULT_BUSY"))?;
        self.refresh_native_credentials(cap, credential_id, adapter)?;
        let credentials = {
            let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
            let s = self.authorize(&mut i, cap)?;
            check(s.rotation.is_none(), "REAUTH_REQUIRED")?;
            let f = frame(&i.conn, credential_id)?;
            let mut p = objects::open_local(
                &self.codec,
                &canonical(&f)?,
                &i.secrets.as_ref().unwrap().key,
                &canonical(&self.context("session", credential_id)?)?,
            )?;
            let result = anynote_auth_native::Credentials {
                access: Zeroizing::new(text(&p["data"]["access_credential"])?.into()),
                refresh: Zeroizing::new(text(&p["data"]["refresh_credential"])?.into()),
                session_id: text(&p["data"]["session_id"])?.into(),
                state: "trusted".into(),
            };
            wipe_value(&mut p);
            result
        };
        let result = adapter
            .control(Some(&credentials), route, a, b, query, body)
            .map_err(|_| Error("TRANSPORT_UNAVAILABLE"))?;
        check(
            self.signal.generation() == cap.generation,
            "STALE_CAPABILITY",
        )?;
        let mut i = self.inner.lock().map_err(|_| Error("VAULT_BUSY"))?;
        self.authorize(&mut i, cap)?;
        Ok(result)
    }
}
