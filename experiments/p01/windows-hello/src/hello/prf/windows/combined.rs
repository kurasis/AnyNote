//! Recovery is restricted to one dedicated RP and the pre-journaled synthetic user.
use super::*;
pub(crate) const RP: &str = "p01.anynote.desktop.invalid";

pub(crate) struct Credential<'a>(Probe<'a>);
impl<'a> Credential<'a> {
    pub(crate) fn new(
        hwnd: usize,
        current: &'a (dyn Fn() -> bool + Sync),
        salt: [u8; 32],
        user: [u8; 32],
    ) -> Self {
        Self::for_rp(hwnd, current, salt, user, RP)
    }
    pub(crate) fn enrollment(
        hwnd: usize,
        current: &'a (dyn Fn() -> bool + Sync),
        salt: [u8; 32],
        user: [u8; 32],
    ) -> Self {
        Self::for_rp(hwnd, current, salt, user, "p01.anynote.desktop.invalid")
    }
    pub(crate) fn for_rp(
        hwnd: usize,
        current: &'a (dyn Fn() -> bool + Sync),
        salt: [u8; 32],
        user: [u8; 32],
        rp: &'static str,
    ) -> Self {
        Self(Probe {
            rp,
            user: Some(user),
            api: None,
            cap: Capability {
                routing: "display-name-candidate",
                tpm_binding: "not-verified",
                ..Default::default()
            },
            route: vec![],
            credential: None,
            creation_without_id: false,
            salt: Zeroizing::new(salt),
            changed: Zeroizing::new([0; 32]),
            created: None,
            first: None,
            hwnd,
            current,
            attestation: None,
        })
    }
    pub(crate) fn initialize(&mut self) -> std::result::Result<(), Failure> {
        for stage in [
            "webauthn-load",
            "webauthn-api",
            "hello-platform",
            "hello-route",
        ] {
            self.0.step(stage)?;
        }
        // Resolve and exercise the cleanup API before creating anything.
        if !self.ids()?.is_empty() {
            return Err(invalid("combined-user-already-exists"));
        }
        Ok(())
    }
    pub(crate) fn reopen(&mut self, id: &[u8]) -> std::result::Result<(), Failure> {
        self.0.credential = None;
        self.0.created = None;
        for stage in [
            "webauthn-load",
            "webauthn-api",
            "hello-platform",
            "hello-route",
        ] {
            self.0.step(stage)?;
        }
        let ids = self.ids()?;
        if ids.is_empty() {
            return Err(invalid("combined-credential-missing"));
        }
        if ids != [id.to_vec()] {
            return Err(invalid("combined-credential-identity-mismatch"));
        }
        self.0.credential = Some(id.to_vec());
        Ok(())
    }
    pub(crate) fn reopen_for_copy(&mut self, id: &[u8]) -> std::result::Result<(), Failure> {
        self.0.credential = None;
        self.0.created = None;
        let ids = self.ids()?;
        if ids.is_empty() {
            return Err(invalid("combined-credential-missing"));
        }
        if ids != [id.to_vec()] {
            return Err(invalid("combined-credential-identity-mismatch"));
        }
        self.reopen(id)
    }
    pub(crate) fn create(
        &mut self,
    ) -> std::result::Result<(Vec<u8>, Zeroizing<[u8; 32]>), Failure> {
        self.0.create(false)?;
        let id = self
            .0
            .credential
            .as_ref()
            .ok_or_else(|| invalid("combined-created-id-missing"))?
            .clone();
        if self.ids()? != [id.clone()] {
            return Err(invalid("combined-credential-recovery-unavailable"));
        }
        Ok((
            id,
            self.0
                .created
                .take()
                .ok_or_else(|| invalid("combined-created-prf-missing"))?,
        ))
    }
    pub(crate) fn authorize(&mut self) -> std::result::Result<Zeroizing<[u8; 32]>, Failure> {
        self.0.assert(false)
    }
    fn ids(&mut self) -> std::result::Result<Vec<Vec<u8>>, Failure> {
        if self.0.api.is_none() {
            self.0.api = Some(Api::load()?);
        }
        let api = self.0.api.as_ref().unwrap();
        let get: WebAuthNGetPlatformCredentialList =
            api.module.symbol(b"WebAuthNGetPlatformCredentialList\0")?;
        let free: WebAuthNFreePlatformCredentialList =
            api.module.symbol(b"WebAuthNFreePlatformCredentialList\0")?;
        let rp = wide(self.0.rp);
        let opts = WEBAUTHN_GET_CREDENTIALS_OPTIONS {
            dwVersion: 1,
            pwszRpId: rp.as_ptr(),
            bBrowserInPrivateMode: 0,
        };
        struct List {
            p: *mut WEBAUTHN_CREDENTIAL_DETAILS_LIST,
            free: WebAuthNFreePlatformCredentialList,
        }
        impl Drop for List {
            fn drop(&mut self) {
                if !self.p.is_null() {
                    unsafe { (self.free)(self.p) }
                }
            }
        }
        let mut list = List {
            p: ptr::null_mut(),
            free,
        };
        let hr = unsafe { get(&opts, &mut list.p) };
        if hr as u32 == 0x80090011 {
            return Ok(vec![]);
        } // documented NTE_NOT_FOUND
        status(hr, "combined-list-owned-credential")?;
        unsafe { owned_ids_for_rp(list.p, &self.0.user.unwrap(), self.0.rp) }
    }
    pub(crate) fn cleanup(&mut self) -> std::result::Result<(), Failure> {
        self.0.created = None;
        // Even a crash before MakeCredential returned an ID can be recovered by
        // exact RP + random user handle written before the call. Never list all RPs.
        let ids = self.ids()?;
        for id in ids {
            status(
                unsafe { (self.0.api.as_ref().unwrap().delete)(id.len() as u32, id.as_ptr()) },
                "combined-delete-owned-passkey",
            )?;
        }
        if !self.ids()?.is_empty() {
            return Err(invalid("combined-passkey-delete-readback"));
        }
        self.0.credential = None;
        Ok(())
    }
}
// The durable coordinator owns cleanup. A dropped assertion handle must not
// delete the persisted credential while the application is awaiting restart.
impl Drop for Credential<'_> {
    fn drop(&mut self) {
        self.0.credential = None;
    }
}

unsafe fn exact_rp(p: *const u16, rp: &str) -> bool {
    if p.is_null() {
        return false;
    }
    let expected = wide(rp);
    expected
        .iter()
        .enumerate()
        .all(|(i, c)| unsafe { p.add(i).read() == *c })
}
#[cfg(test)]
unsafe fn owned_ids(
    list: *const WEBAUTHN_CREDENTIAL_DETAILS_LIST,
    user: &[u8; 32],
) -> std::result::Result<Vec<Vec<u8>>, Failure> {
    unsafe { owned_ids_for_rp(list, user, RP) }
}
unsafe fn owned_ids_for_rp(
    list: *const WEBAUTHN_CREDENTIAL_DETAILS_LIST,
    user: &[u8; 32],
    expected_rp: &str,
) -> std::result::Result<Vec<Vec<u8>>, Failure> {
    if list.is_null() {
        return Err(invalid("combined-credential-list-null"));
    }
    let list = unsafe { &*list };
    if list.cCredentialDetails > 256
        || (list.cCredentialDetails > 0 && list.ppCredentialDetails.is_null())
    {
        return Err(invalid("combined-credential-list-bounds"));
    }
    let mut ids = vec![];
    for i in 0..list.cCredentialDetails as usize {
        let p = unsafe { list.ppCredentialDetails.add(i).read() };
        if p.is_null() || unsafe { (*p).dwVersion } < 1 {
            return Err(invalid("combined-credential-entry"));
        }
        let (rp, u) = unsafe { ((*p).pRpInformation, (*p).pUserInformation) };
        if rp.is_null() || u.is_null() {
            return Err(invalid("combined-credential-owner-missing"));
        }
        if !unsafe { exact_rp((*rp).pwszId, expected_rp) } {
            continue;
        }
        let uid = unsafe { bytes((*u).pbId, (*u).cbId, 64) }?;
        if uid != user {
            continue;
        }
        ids.push(unsafe { bytes((*p).pbCredentialID, (*p).cbCredentialID, MAX_ID) }?.to_vec());
    }
    if ids.len() > 1 {
        return Err(invalid("combined-credential-owner-ambiguous"));
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_selector_requires_both_exact_rp_and_journaled_user() {
        let rp = wide(RP);
        let other = wide("other.invalid");
        let mut uid = [7; 32];
        let mut id = [1, 2, 3];
        let mut rp_info = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: 1,
            pwszId: rp.as_ptr(),
            ..Default::default()
        };
        let mut user_info = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: 1,
            cbId: 32,
            pbId: uid.as_mut_ptr(),
            ..Default::default()
        };
        let mut entry = WEBAUTHN_CREDENTIAL_DETAILS {
            dwVersion: 1,
            cbCredentialID: 3,
            pbCredentialID: id.as_mut_ptr(),
            pRpInformation: &mut rp_info,
            pUserInformation: &mut user_info,
            ..Default::default()
        };
        let mut entries = [&mut entry as *mut _];
        let list = WEBAUTHN_CREDENTIAL_DETAILS_LIST {
            cCredentialDetails: 1,
            ppCredentialDetails: entries.as_mut_ptr(),
        };
        assert_eq!(
            unsafe { owned_ids(&list, &[7; 32]) }.unwrap(),
            vec![id.to_vec()]
        );
        assert!(unsafe { owned_ids(&list, &[8; 32]) }.unwrap().is_empty());
        rp_info.pwszId = other.as_ptr();
        // The native-shaped list observes this mutation through a raw pointer.
        std::hint::black_box(&rp_info);
        assert!(unsafe { owned_ids(&list, &[7; 32]) }.unwrap().is_empty());
        let oversized = WEBAUTHN_CREDENTIAL_DETAILS_LIST {
            cCredentialDetails: 257,
            ppCredentialDetails: ptr::null_mut(),
        };
        assert!(unsafe { owned_ids(&oversized, &[7; 32]) }.is_err());
    }
}
