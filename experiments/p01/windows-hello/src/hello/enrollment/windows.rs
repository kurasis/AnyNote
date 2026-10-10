use super::*;
use crate::hello::{
    prf::windows::combined::Credential,
    proof::{Failure, Outcome},
    tpm::windows::combined::Key,
};
fn mapped(f: Failure) -> Error {
    Error::new(match f.status {
        Outcome::Cancelled => "HELLO_CANCELLED",
        Outcome::Interrupted => "STALE",
        _ => "HELLO_UNAVAILABLE",
    })
}
struct Native<'a> {
    hwnd: usize,
    current: &'a (dyn Fn() -> bool + Sync),
    credential: Option<Credential<'a>>,
    key: Option<Key<'a>>,
}
impl<'a> Native<'a> {
    fn configure(&mut self, h: &Header) {
        self.credential = Some(Credential::enrollment(
            self.hwnd,
            self.current,
            h.salt,
            h.user(),
        ));
        self.key = Some(Key::new(&h.key_name(), self.current));
    }
}
impl Protection for Native<'_> {
    fn create(&mut self, h: &mut Header) -> Result<Zeroizing<[u8; 32]>> {
        self.configure(h);
        self.credential
            .as_mut()
            .unwrap()
            .initialize()
            .map_err(mapped)?;
        (h.public, h.name) = self.key.as_mut().unwrap().prepare().map_err(mapped)?;
        let (id, prf) = self.credential.as_mut().unwrap().create().map_err(mapped)?;
        h.credential = id;
        Ok(prf)
    }
    fn reopen(&mut self, h: &Header) -> Result<()> {
        self.configure(h);
        self.key
            .as_mut()
            .unwrap()
            .reopen(&h.public, &h.name)
            .map_err(mapped)?;
        self.credential
            .as_mut()
            .unwrap()
            .reopen(&h.credential)
            .map_err(mapped)
    }
    fn authorize(&mut self) -> Result<Zeroizing<[u8; 32]>> {
        self.credential
            .as_mut()
            .ok_or_else(invalid)?
            .authorize()
            .map_err(mapped)
    }
    fn wrap(&mut self, c: &[u8; 32]) -> Result<Vec<u8>> {
        self.key
            .as_mut()
            .ok_or_else(invalid)?
            .wrap(c)
            .map_err(mapped)
    }
    fn unwrap(&mut self, c: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.key
            .as_mut()
            .ok_or_else(invalid)?
            .unwrap(c)
            .map_err(mapped)
    }
    fn delete(&mut self) -> Result<()> {
        let a = self
            .credential
            .as_mut()
            .ok_or_else(invalid)?
            .cleanup()
            .map_err(mapped);
        let b = self
            .key
            .as_mut()
            .ok_or_else(invalid)?
            .cleanup()
            .map_err(mapped);
        a?;
        b
    }
}
// Secret-bearing native reply is deliberately not serializable.
pub struct Reply {
    pub status: Status,
    pub local_key: Option<Vec<u8>>,
    pub binding: Option<Binding>,
}
impl Drop for Reply {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(c) = &mut self.local_key {
            c.zeroize()
        }
    }
}
impl Manager {
    pub fn run(
        &mut self,
        root: &Path,
        hwnd: usize,
        current: &(dyn Fn() -> bool + Sync),
        context: &dyn Fn() -> Result<(Binding, i64)>,
        action: &Action,
    ) -> Result<Reply> {
        let _attempt = crate::hello::Attempt::begin()?;
        libsodium_rs::ensure_init().map_err(|_| Error::new("UNAVAILABLE"))?;
        let j = Journal::open(root)?;
        let mut b = Native {
            hwnd,
            current,
            credential: None,
            key: None,
        };
        if matches!(action, Action::Revoke {}) {
            if let Some(r) = self.read(&j)? {
                b.configure(&r.header);
                self.revoke(&j, &mut b, r)?;
            }
            return Ok(Reply {
                status: Status::off(),
                local_key: None,
                binding: None,
            });
        }
        let (binding, now) = context()?;
        let mut reply = Reply {
            status: self.status(&j, &binding, now)?,
            local_key: None,
            binding: None,
        };
        match action {
            Action::Status {} => {}
            Action::Revoke {} => unreachable!(),
            Action::Enroll {
                mode,
                generation,
                sha256,
                local_key,
            } => {
                if *generation != binding.generation || *sha256 != binding.sha256 {
                    return Err(Error::new("CONFLICT"));
                }
                let mut secret = Zeroizing::new([0; 32]);
                secret.copy_from_slice(local_key);
                reply.status = self.enroll(&j, &mut b, &binding, *mode, &secret, context)?;
            }
            Action::Unlock {} => {
                reply.local_key = Some(self.unlock(&j, &mut b, &binding, context)?.to_vec());
                reply.binding = Some(binding);
            }
        }
        Ok(reply)
    }
}
