//! One sequential chunk per call; ciphertext persistence/transport is P12.
use crate::{Error, Result, require};
use crate::{
    codec::{Codec, canonical, domain, num, text},
    crypto::*,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
const CHUNK: u64 = 8388608;
pub fn nonce(prefix: &[u8], index: u64) -> Result<Vec<u8>> {
    require(prefix.len() == 16 && index < 120, "INVALID_CHUNK_INDEX")?;
    let mut n = prefix.to_vec();
    n.extend_from_slice(&index.to_le_bytes());
    Ok(n)
}
pub fn aad(h: &Value, purpose: &str, index: u64) -> Result<Vec<u8>> {
    let v = match purpose {
        "file-manifest-key-wrap" => json!({"purpose":purpose,"context":h["context"]}),
        "file-manifest" => json!({"purpose":purpose,"context":h["context"],"framing":h["framing"]}),
        "file-chunk" => {
            let count = num(&h["framing"]["chunk_count"])?;
            require(index < count, "INVALID_CHUNK_INDEX")?;
            let size = num(&h["framing"]["plaintext_bytes"])?;
            json!({"purpose":purpose,"context":h["context"],"chunk_index":index.to_string(),"plaintext_chunk_bytes":(size-index*CHUNK).min(CHUNK).to_string(),"chunk_count":count.to_string()})
        }
        _ => return Err(Error("UNSUPPORTED_PURPOSE")),
    };
    Ok(domain("p02-file-c1", "aad", purpose, &canonical(&v)?))
}
pub struct FileWriter {
    context: Value,
    size: u64,
    next: u64,
    parts: Vec<Value>,
    file_key: Zeroizing<Vec<u8>>,
    manifest_key: Zeroizing<Vec<u8>>,
    prefix: Vec<u8>,
    plain_hash: Sha256,
    source_digest: Option<String>,
}
impl FileWriter {
    pub fn new(c: &Codec, context: &[u8], size: u64) -> Result<Self> {
        require(size <= 1000000000, "RESOURCE_LIMIT")?;
        Ok(Self {
            context: c.decode("p02-file-c1", "context", context)?,
            size,
            next: 0,
            parts: vec![],
            file_key: random_key()?,
            manifest_key: random_key()?,
            prefix: libsodium_rs::random::bytes(16),
            plain_hash: Sha256::new(),
            source_digest: None,
        })
    }
    /// Custody-only checkpoint: callers must encrypt it, never return it to a renderer.
    pub fn checkpoint(&self, source_digest: &str) -> Result<Value> {
        require(un64(source_digest)?.len() == 32, "SOURCE_IDENTITY_REQUIRED")?;
        Ok(
            json!({"context":self.context,"size":self.size,"next":self.next,"parts":self.parts,
            "file_key":b64(&self.file_key),"manifest_key":b64(&self.manifest_key),"prefix":b64(&self.prefix),"source_digest":source_digest}),
        )
    }
    pub fn resume(c: &Codec, state: &Value) -> Result<Self> {
        let size = state["size"].as_u64().ok_or(Error("INTEGRITY_FAILURE"))?;
        let next = state["next"].as_u64().ok_or(Error("INTEGRITY_FAILURE"))?;
        let parts = state["parts"]
            .as_array()
            .ok_or(Error("INTEGRITY_FAILURE"))?
            .clone();
        require(
            size <= 1000000000 && next <= size.div_ceil(CHUNK) && parts.len() as u64 == next,
            "INTEGRITY_FAILURE",
        )?;
        let file_key = un64(text(&state["file_key"])?)?;
        let manifest_key = un64(text(&state["manifest_key"])?)?;
        let prefix = un64(text(&state["prefix"])?)?;
        let digest = text(&state["source_digest"])?;
        require(
            file_key.len() == 32
                && manifest_key.len() == 32
                && prefix.len() == 16
                && un64(digest)?.len() == 32,
            "INTEGRITY_FAILURE",
        )?;
        Ok(Self {
            context: c.decode("p02-file-c1", "context", &canonical(&state["context"])?)?,
            size,
            next,
            parts,
            file_key: Zeroizing::new(file_key),
            manifest_key: Zeroizing::new(manifest_key),
            prefix,
            plain_hash: Sha256::new(),
            source_digest: Some(digest.to_owned()),
        })
    }
    fn header(&self) -> Value {
        json!({"context":self.context,"framing":{"plaintext_bytes":self.size.to_string(),"chunk_plaintext_bytes":CHUNK.to_string(),"chunk_count":self.size.div_ceil(CHUNK).to_string(),"parts":self.parts}})
    }
    pub fn encrypt_next(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        require(self.next < self.size.div_ceil(CHUNK), "INVALID_CHUNK_INDEX")?;
        require(
            plain.len() as u64 == (self.size - self.next * CHUNK).min(CHUNK),
            "INVALID_CHUNK_LENGTH",
        )?;
        let cipher = encrypt(
            plain,
            &aad(&self.header(), "file-chunk", self.next)?,
            &nonce(&self.prefix, self.next)?,
            &self.file_key,
        )?;
        self.plain_hash.update(plain);
        self.parts.push(json!({"index":self.next.to_string(),"ciphertext_bytes":cipher.len().to_string(),"ciphertext_digest":hash(&cipher)}));
        self.next += 1;
        Ok(cipher)
    }
    pub fn finish(
        self,
        c: &Codec,
        name: &str,
        media: &str,
        group: &[u8],
        signing: &[u8],
    ) -> Result<Value> {
        require(self.next == self.size.div_ceil(CHUNK), "INCOMPLETE_FILE")?;
        let mut h = self.header();
        h["purpose"] = json!("file-manifest");
        let wn = libsodium_rs::random::bytes(24);
        let mn = libsodium_rs::random::bytes(24);
        let plain_digest = self
            .source_digest
            .unwrap_or_else(|| b64(&self.plain_hash.finalize()));
        let mut manifest = json!({"purpose":"file-manifest-plaintext","context":self.context,"framing":h["framing"],"file_data_key":b64(&self.file_key),"nonce_prefix":b64(&self.prefix),"original_name":name,"client_media_type":media,"plaintext_digest":plain_digest});
        c.validate("p02-file-c1", "manifest", &manifest)?;
        let wrap = json!({"purpose":"file-manifest-key-wrap","context":h["context"],"nonce":b64(&wn),"ciphertext":b64(&encrypt(&self.manifest_key,&aad(&h,"file-manifest-key-wrap",0)?,&wn,group)?)});
        let plain = Zeroizing::new(canonical(&manifest)?);
        if let Some(Value::String(mut encoded)) =
            manifest.as_object_mut().unwrap().remove("file_data_key")
        {
            use zeroize::Zeroize;
            encoded.zeroize();
        }
        let cipher = encrypt(
            &plain,
            &aad(&h, "file-manifest", 0)?,
            &mn,
            &self.manifest_key,
        )?;
        h["manifest_nonce"] = json!(b64(&mn));
        h["manifest_ciphertext_bytes"] = json!(cipher.len().to_string());
        h["manifest_ciphertext_digest"] = json!(hash(&cipher));
        h["key_wrap_digest"] = json!(hash(&domain(
            "p02-file-c1",
            "hash",
            "key-wrap",
            &canonical(&wrap)?
        )));
        let e =
            json!({"signature":sign(&c.signing("p02-file-c1","header",&h)?,signing)?,"header":h});
        c.validate("p02-file-c1", "envelope", &e)?;
        Ok(
            json!({"record_kind":"file-manifest","envelope":e,"wrap":wrap,"manifest_ciphertext":b64(&cipher)}),
        )
    }
}
pub struct FileReader {
    header: Value,
    manifest: Value,
    key: Zeroizing<Vec<u8>>,
    prefix: Vec<u8>,
    next: u64,
    hash: Sha256,
}
impl FileReader {
    pub fn open(
        c: &Codec,
        record: &[u8],
        group: &[u8],
        public: &[u8],
        expected: &[u8],
    ) -> Result<Self> {
        let r = c.decode("p02-v1", "export-file-record", record)?;
        let h = &r["envelope"]["header"];
        let w = &r["wrap"];
        require(
            h["context"] == c.decode("p02-file-c1", "context", expected)?,
            "CONTEXT_MISMATCH",
        )?;
        verify(
            &c.signing("p02-file-c1", "header", h)?,
            text(&r["envelope"]["signature"])?,
            public,
        )?;
        require(
            hash(&domain("p02-file-c1", "hash", "key-wrap", &canonical(w)?))
                == h["key_wrap_digest"],
            "KEY_WRAP_MISMATCH",
        )?;
        let cipher = un64(text(&r["manifest_ciphertext"])?)?;
        require(
            cipher.len() as u64 == num(&h["manifest_ciphertext_bytes"])?
                && hash(&cipher) == h["manifest_ciphertext_digest"],
            "CIPHERTEXT_MISMATCH",
        )?;
        let key = decrypt(
            &un64(text(&w["ciphertext"])?)?,
            &aad(h, "file-manifest-key-wrap", 0)?,
            &un64(text(&w["nonce"])?)?,
            group,
        )?;
        let plain = decrypt(
            &cipher,
            &aad(h, "file-manifest", 0)?,
            &un64(text(&h["manifest_nonce"])?)?,
            &key,
        )?;
        let mut manifest = c.decode("p02-file-c1", "manifest", &plain)?;
        require(
            manifest["context"] == h["context"] && manifest["framing"] == h["framing"],
            "CONTEXT_MISMATCH",
        )?;
        let key = Zeroizing::new(un64(text(&manifest["file_data_key"])?)?);
        if let Some(Value::String(mut encoded)) =
            manifest.as_object_mut().unwrap().remove("file_data_key")
        {
            use zeroize::Zeroize;
            encoded.zeroize();
        }
        let prefix = un64(text(&manifest["nonce_prefix"])?)?;
        Ok(Self {
            header: h.clone(),
            manifest,
            key,
            prefix,
            next: 0,
            hash: Sha256::new(),
        })
    }
    /// Authenticated display fields only. This never returns a DEK or nonce prefix,
    /// and manifest verification does not claim full-file stream completion.
    pub fn metadata(&self) -> Value {
        json!({"name":self.manifest["original_name"],"media":self.manifest["client_media_type"],"plaintext_bytes":self.header["framing"]["plaintext_bytes"]})
    }
    pub fn decrypt_next(&mut self, cipher: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        require(
            self.next < num(&self.header["framing"]["chunk_count"])?,
            "INVALID_CHUNK_INDEX",
        )?;
        let plain = self.decrypt_at(self.next, cipher)?;
        self.hash.update(&plain);
        self.next += 1;
        Ok(plain)
    }
    pub fn decrypt_at(&self, index: u64, cipher: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        require(
            index < num(&self.header["framing"]["chunk_count"])?,
            "INVALID_CHUNK_INDEX",
        )?;
        let part = &self.header["framing"]["parts"][index as usize];
        require(
            cipher.len() as u64 == num(&part["ciphertext_bytes"])?
                && hash(cipher) == part["ciphertext_digest"],
            "CHUNK_DIGEST_MISMATCH",
        )?;
        let plain = decrypt(
            cipher,
            &aad(&self.header, "file-chunk", index)?,
            &nonce(&self.prefix, index)?,
            &self.key,
        )?;
        Ok(plain)
    }
    pub fn finish(self) -> Result<()> {
        require(
            self.next == num(&self.header["framing"]["chunk_count"])?,
            "INCOMPLETE_FILE",
        )?;
        if !self.manifest["plaintext_digest"].is_null() {
            require(
                b64(&self.hash.finalize()) == self.manifest["plaintext_digest"],
                "PLAINTEXT_MISMATCH",
            )?;
        }
        Ok(())
    }
}
