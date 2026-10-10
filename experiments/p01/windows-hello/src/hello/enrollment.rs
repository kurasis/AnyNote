//! Application-owned vault envelopes. No plaintext or password verifier is persisted.
use crate::{
    filesystem as io,
    storage::{Error, Result},
};
use libsodium_rs::crypto_aead::aes256gcm as aes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
#[cfg(test)]
mod tests;
#[cfg(windows)]
pub mod windows;
pub fn credential_write(operation: &str, args: &serde_json::Value) -> bool {
    operation == "restoreBlob"
        || operation == "commit"
            && (args.get("keyEpoch").is_some_and(|v| !v.is_null())
                || args.get("confirmedReplacement") == Some(&serde_json::Value::Bool(true)))
}
const DOMAIN: &str = "AnyNote.P01.LocalVaultHello.v1";
const MAX_RECORD: usize = 16384;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub vault: String,
    pub key_epoch: u64,
    pub generation: u64,
    pub sha256: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Session,
    Remember6,
    Remember12,
    Remember24,
}
impl Mode {
    fn duration(self) -> i64 {
        (match self {
            Self::Remember6 => 6,
            Self::Remember12 => 12,
            _ => 24,
        }) * 3_600_000
    }
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Action {
    Status {},
    Enroll {
        mode: Mode,
        generation: u64,
        sha256: String,
        local_key: [u8; 32],
    },
    Unlock {},
    Revoke {},
}
impl Drop for Action {
    fn drop(&mut self) {
        if let Self::Enroll { local_key, .. } = self {
            use zeroize::Zeroize;
            local_key.zeroize()
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    domain: String,
    version: u32,
    id: String,
    vault: String,
    epoch: u64,
    mode: Mode,
    created: i64,
    expires: i64,
    salt: [u8; 32],
    credential: Vec<u8>,
    public: Vec<u8>,
    name: Vec<u8>,
}
impl Header {
    fn key_name(&self) -> String {
        format!("AnyNote.P01.Hello.{}", self.id)
    }
    fn user(&self) -> [u8; 32] {
        Sha256::digest(format!("{DOMAIN}:{}", self.id)).into()
    }
    fn aad(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("fixed metadata")
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    header: Header,
    ready: bool,
    last_seen: i64,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}
fn uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|v| v.get_version_num() == 4 && v.to_string() == s)
}
fn invalid() -> Error {
    Error::new("INVALID_STATE")
}
impl Record {
    fn new(b: &Binding, mode: Mode, now: i64) -> Self {
        let mut salt = [0; 32];
        libsodium_rs::random::fill_bytes(&mut salt);
        Self {
            header: Header {
                domain: DOMAIN.into(),
                version: 1,
                id: uuid::Uuid::new_v4().to_string(),
                vault: b.vault.clone(),
                epoch: b.key_epoch,
                mode,
                created: now,
                expires: now + mode.duration(),
                salt,
                credential: vec![],
                public: vec![],
                name: vec![],
            },
            ready: false,
            last_seen: now,
            nonce: [0; 12],
            ciphertext: vec![],
        }
    }
    fn validate(&self) -> Result<()> {
        let h = &self.header;
        if h.domain != DOMAIN
            || h.version != 1
            || !uuid(&h.id)
            || !uuid(&h.vault)
            || h.created < 0
            || h.expires.checked_sub(h.created) != Some(h.mode.duration())
            || self.last_seen < h.created
            || h.credential.len() > 4096
            || h.public.len() > 2048
            || h.name.len() > 68
            || self.ciphertext.len() > 272
            || (self.ready
                && (h.credential.is_empty()
                    || h.public.is_empty()
                    || h.name.len() != 34
                    || self.ciphertext.len() != 272))
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn permitted(&self, b: &Binding, now: i64) -> bool {
        self.ready
            && self.header.vault == b.vault
            && self.header.epoch == b.key_epoch
            && now >= self.last_seen
            && now >= self.header.created
            && now < self.header.expires
    }
    fn key(&self, prf: &[u8; 32]) -> Result<aes::Key> {
        let mut key = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<Sha256>::new(Some(&self.header.salt), prf)
            .expand(DOMAIN.as_bytes(), key.as_mut_slice())
            .map_err(|_| invalid())?;
        aes::Key::from_bytes(key.as_slice()).map_err(|_| invalid())
    }
    fn seal(&mut self, inner: &[u8], prf: &[u8; 32]) -> Result<()> {
        if inner.len() != 256 {
            return Err(invalid());
        }
        let nonce = aes::Nonce::generate();
        self.nonce.copy_from_slice(nonce.as_ref());
        self.ciphertext = aes::encrypt(inner, Some(&self.header.aad()), &nonce, &self.key(prf)?)
            .map_err(|_| invalid())?;
        Ok(())
    }
    fn open(&self, prf: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        let inner = Zeroizing::new(
            aes::decrypt(
                &self.ciphertext,
                Some(&self.header.aad()),
                &aes::Nonce::from_bytes(self.nonce),
                &self.key(prf)?,
            )
            .map_err(|_| invalid())?,
        );
        if inner.len() != 256 {
            return Err(invalid());
        }
        Ok(inner)
    }
}
struct Journal {
    path: PathBuf,
    _pins: Vec<fs::File>,
}
impl Journal {
    fn open(root: &Path) -> Result<Self> {
        let root = io::child(root, "hello-local-key")?;
        io::reject_links(&root)?;
        fs::create_dir_all(&root)?;
        io::secure_directory(&root)?;
        Ok(Self {
            path: io::child(&root, "enrollment.json")?,
            _pins: io::pin_directory(&root)?,
        })
    }
    fn read(&self) -> Result<Option<Record>> {
        match fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
        let r: Record = serde_json::from_slice(&io::read(&self.path, MAX_RECORD)?)?;
        r.validate()?;
        if r.header.mode == Mode::Session && r.ready {
            return Err(invalid());
        }
        Ok(Some(r))
    }
    fn save(&self, r: &Record) -> Result<()> {
        r.validate()?;
        let bytes = serde_json::to_vec(r)?;
        if bytes.len() > MAX_RECORD {
            return Err(invalid());
        }
        io::atomic_json(&self.path, &bytes)
    }
    fn remove(&self) -> Result<()> {
        let bytes = io::read(&self.path, MAX_RECORD)?;
        if io::remove_verified(&self.path, &crate::storage::hash(&bytes))? {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}
// Fixed native objects only. Test doubles exist only under cfg(test).
trait Protection {
    fn create(&mut self, h: &mut Header) -> Result<Zeroizing<[u8; 32]>>;
    fn reopen(&mut self, h: &Header) -> Result<()>;
    fn authorize(&mut self) -> Result<Zeroizing<[u8; 32]>>;
    fn wrap(&mut self, local_key: &[u8; 32]) -> Result<Vec<u8>>;
    fn unwrap(&mut self, cipher: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn delete(&mut self) -> Result<()>;
}
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub state: &'static str,
    pub mode: Option<Mode>,
    pub expires_at: Option<i64>,
}
impl Status {
    fn off() -> Self {
        Self {
            state: "off",
            mode: None,
            expires_at: None,
        }
    }
}
#[derive(Default)]
pub struct Manager {
    session: Option<Record>,
}
impl Manager {
    fn read(&self, j: &Journal) -> Result<Option<Record>> {
        let disk = j.read()?;
        Ok(match (&self.session, disk) {
            (Some(s), Some(d)) if s.header.id == d.header.id && !d.ready => Some(s.clone()),
            (_, d) => d,
        })
    }
    fn persist(&self, j: &Journal, r: &Record) -> Result<()> {
        let mut disk = r.clone();
        if disk.header.mode == Mode::Session {
            disk.ready = false;
            disk.ciphertext.clear();
            disk.nonce = [0; 12];
        }
        j.save(&disk)
    }
    fn revoke(&mut self, j: &Journal, b: &mut impl Protection, mut r: Record) -> Result<()> {
        self.session = None;
        r.ready = false;
        r.ciphertext.clear();
        r.nonce = [0; 12];
        // Durable invalidation precedes deletion. Failed deletion remains retryable.
        j.save(&r)?;
        b.delete()
            .map_err(|_| Error::new("HELLO_CLEANUP_REQUIRED"))?;
        j.remove()
    }
    fn invalidate_record(&mut self, j: &Journal, mut r: Record) -> Result<()> {
        self.session = None;
        r.ready = false;
        r.ciphertext.clear();
        r.nonce = [0; 12];
        j.save(&r)
    }
    fn status(&mut self, j: &Journal, binding: &Binding, now: i64) -> Result<Status> {
        let Some(r) = self.read(j)? else {
            return Ok(Status::off());
        };
        let enabled = r.permitted(binding, now);
        let status = Status {
            state: if enabled {
                "enabled"
            } else {
                "cleanup-required"
            },
            mode: Some(r.header.mode),
            expires_at: Some(r.header.expires),
        };
        if !enabled && r.ready {
            self.invalidate_record(j, r)?;
        }
        Ok(status)
    }
    fn enroll(
        &mut self,
        j: &Journal,
        b: &mut impl Protection,
        binding: &Binding,
        mode: Mode,
        local_key: &[u8; 32],
        context: &dyn Fn() -> Result<(Binding, i64)>,
    ) -> Result<Status> {
        if self.read(j)?.is_some() {
            return Err(Error::new("HELLO_CLEANUP_REQUIRED"));
        }
        let (observed, now) = context()?;
        if &observed != binding {
            return Err(Error::new("CONFLICT"));
        }
        let mut r = Record::new(binding, mode, now);
        j.save(&r)?;
        // Backend object identity is chosen from the durable record, before creation.
        let result = (|| {
            let prf = b.create(&mut r.header)?;
            j.save(&r)?;
            let inner = b.wrap(local_key)?;
            r.seal(&inner, &prf)?;
            drop(prf);
            let prf = b.authorize()?;
            let inner = r.open(&prf)?;
            drop(prf);
            let recovered = b.unwrap(&inner)?;
            if recovered.len() != 32 || !libsodium_rs::utils::memcmp(&recovered, local_key) {
                return Err(invalid());
            }
            let (next, time) = context()?;
            if next != *binding || time < now || time >= r.header.expires {
                return Err(Error::new("STALE"));
            }
            r.ready = true;
            r.last_seen = time;
            self.persist(j, &r)?;
            if mode == Mode::Session {
                self.session = Some(r.clone());
            }
            self.status(j, binding, time)
        })();
        if result.is_err() && self.revoke(j, b, r).is_err() {
            return Err(Error::new("HELLO_CLEANUP_REQUIRED"));
        }
        result
    }
    fn unlock(
        &mut self,
        j: &Journal,
        b: &mut impl Protection,
        binding: &Binding,
        context: &dyn Fn() -> Result<(Binding, i64)>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut r = self.read(j)?.ok_or_else(invalid)?;
        let (next, now) = context()?;
        if next != *binding {
            return Err(Error::new("STALE"));
        }
        if !r.permitted(binding, now) {
            self.invalidate_record(j, r)?;
            return Err(Error::new("HELLO_EXPIRED"));
        }
        r.last_seen = now;
        self.persist(j, &r)?;
        if r.header.mode == Mode::Session {
            self.session = Some(r.clone())
        }
        b.reopen(&r.header)?;
        let prf = b.authorize()?;
        let inner = r.open(&prf)?;
        drop(prf);
        let secret = b.unwrap(&inner)?;
        let (next, time) = context()?;
        if secret.len() != 32 || next != *binding {
            return Err(Error::new("STALE"));
        }
        if !r.permitted(binding, time) {
            self.invalidate_record(j, r)?;
            return Err(Error::new("HELLO_EXPIRED"));
        }
        r.last_seen = time;
        self.persist(j, &r)?;
        if r.header.mode == Mode::Session {
            self.session = Some(r)
        }
        Ok(secret)
    }
}
