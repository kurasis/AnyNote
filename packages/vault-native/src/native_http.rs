//! Native-only fixed product transport with credentials opened only under L.
use super::*;
impl Vault {
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
