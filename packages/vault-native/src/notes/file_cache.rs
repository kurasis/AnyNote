//! Replaceable downloaded ciphertext only; never source handles, names, keys or unsent work.
use super::*;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};

pub const DEFAULT_BYTES: u64 = 5368709120;
pub struct CipherCache {
    root: PathBuf,
    budget: u64,
}
pub struct CacheJob {
    directory: PathBuf,
    metadata: Value,
}
impl CacheJob {
    pub fn pin(&mut self, additional_budget: u64, confirmed: bool) -> Result<()> {
        check(
            confirmed
                && additional_budget
                    >= self.metadata["bytes"]
                        .as_u64()
                        .ok_or(Error("INTEGRITY_FAILURE"))?,
            "CONFIRMATION_REQUIRED",
        )?;
        let mut next = self.metadata.clone();
        next["pinned"] = json!(true);
        next["additional_budget"] = json!(additional_budget);
        atomic(&self.directory.join("manifest.json"), &canonical(&next)?)?;
        self.metadata = next;
        Ok(())
    }
}
fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(Error("STORAGE_UNAVAILABLE"))?;
    let temporary = parent.join(format!("{}.incomplete", random_id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| Error("INSUFFICIENT_STORAGE"))?;
        file.write_all(bytes)
            .map_err(|_| Error("INSUFFICIENT_STORAGE"))?;
        file.sync_all().map_err(|_| Error("INSUFFICIENT_STORAGE"))?;
        drop(file);
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
            };
            let source: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
            let destination: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            // SAFETY: both owned NUL-terminated buffers remain live for this synchronous call.
            check(
                unsafe {
                    MoveFileExW(
                        source.as_ptr(),
                        destination.as_ptr(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                    )
                } != 0,
                "STORAGE_UNAVAILABLE",
            )?;
        }
        #[cfg(not(windows))]
        fs::rename(&temporary, path).map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        #[cfg(unix)]
        File::open(parent)
            .map_err(|_| Error("STORAGE_UNAVAILABLE"))?
            .sync_all()
            .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        Ok(())
    })();
    if temporary.exists() {
        let _ = fs::remove_file(temporary);
    }
    result
}
impl CipherCache {
    pub fn for_vault(vault: &Vault) -> Result<Self> {
        let root = vault
            .path()
            .parent()
            .ok_or(Error("STORAGE_UNAVAILABLE"))?
            .join(format!(
                "p12-downloaded-ciphertext-{}",
                vault.scope.profile_id
            ));
        fs::create_dir_all(&root).map_err(|_| Error("INSUFFICIENT_STORAGE"))?;
        Ok(Self {
            root,
            budget: DEFAULT_BYTES,
        })
    }
    fn name(group: &str, version: &str) -> Result<String> {
        check(valid_id(group) && valid_id(version), "INVALID_RECORD")?;
        Ok(format!("{group}_{version}"))
    }
    fn metadata(path: &Path) -> Result<Value> {
        let file =
            File::open(path.join("manifest.json")).map_err(|_| Error("OFFLINE_UNAVAILABLE"))?;
        let mut bytes = Vec::new();
        file.take(262145)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        strict(&bytes, 262144)
    }
    pub fn begin(&self, codec: &Codec, record: &Value) -> Result<CacheJob> {
        codec.validate("p02-v1", "export-file-record", record)?;
        let h = &record["envelope"]["header"];
        let name = Self::name(
            text(&h["context"]["group_id"])?,
            text(&h["context"]["file_version_id"])?,
        )?;
        let bytes = anynote_crypto_core::codec::num(&h["manifest_ciphertext_bytes"])?
            + 48
            + values(&h["framing"], "parts")?
                .iter()
                .map(|p| anynote_crypto_core::codec::num(&p["ciphertext_bytes"]))
                .collect::<Result<Vec<_>>>()?
                .iter()
                .sum::<u64>();
        let mut entries = Vec::new();
        let mut used = 0;
        for entry in fs::read_dir(&self.root).map_err(|_| Error("STORAGE_UNAVAILABLE"))? {
            let entry = entry.map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
            let path = entry.path();
            if !entry
                .file_type()
                .map_err(|_| Error("STORAGE_UNAVAILABLE"))?
                .is_dir()
            {
                continue;
            }
            if let Ok(metadata) = Self::metadata(&path) {
                if metadata["name"] == name {
                    continue;
                }
                let size = metadata["bytes"]
                    .as_u64()
                    .ok_or(Error("INTEGRITY_FAILURE"))?;
                used += size;
                entries.push((
                    metadata["touched"].as_u64().unwrap_or(0),
                    path,
                    size,
                    metadata["pinned"] == true,
                ));
            }
        }
        entries.sort_by_key(|e| e.0);
        for (_, path, size, pinned) in entries {
            if used + bytes <= self.budget {
                break;
            }
            if !pinned {
                fs::remove_dir_all(path).map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
                used -= size;
            }
        }
        check(used + bytes <= self.budget, "INSUFFICIENT_STORAGE")?;
        let directory = self.root.join(&name);
        fs::create_dir_all(&directory).map_err(|_| Error("INSUFFICIENT_STORAGE"))?;
        let metadata = json!({"version":1,"name":name,"bytes":bytes,"touched":now()?,"pinned":false,"complete":false,"record":record,"parts":[]});
        atomic(&directory.join("manifest.json"), &canonical(&metadata)?)?;
        Ok(CacheJob {
            directory,
            metadata,
        })
    }
    pub fn put(&self, job: &mut CacheJob, index: usize, cipher: &[u8]) -> Result<()> {
        let part = &job.metadata["record"]["envelope"]["header"]["framing"]["parts"][index];
        check(
            cipher.len() <= 8388624
                && anynote_crypto_core::codec::num(&part["index"])? == index as u64
                && part["ciphertext_digest"] == hash(cipher)
                && anynote_crypto_core::codec::num(&part["ciphertext_bytes"])?
                    == cipher.len() as u64,
            "INTEGRITY_FAILURE",
        )?;
        atomic(&job.directory.join(index.to_string()), cipher)?;
        let parts = job.metadata["parts"]
            .as_array_mut()
            .ok_or(Error("INTEGRITY_FAILURE"))?;
        if !parts.contains(&json!(index)) {
            parts.push(json!(index));
        }
        atomic(
            &job.directory.join("manifest.json"),
            &canonical(&job.metadata)?,
        )
    }
    pub fn finish(&self, job: &mut CacheJob) -> Result<()> {
        check(
            values(&job.metadata, "parts")?.len()
                == values(
                    &job.metadata["record"]["envelope"]["header"]["framing"],
                    "parts",
                )?
                .len(),
            "INCOMPLETE_FILE",
        )?;
        let mut complete = job.metadata.clone();
        complete["complete"] = json!(true);
        atomic(&job.directory.join("manifest.json"), &canonical(&complete)?)?;
        job.metadata = complete;
        Ok(())
    }
    pub fn verify(
        &self,
        vault: &Vault,
        cap: &Capability,
        group: &str,
        version: &str,
    ) -> Result<()> {
        let path = self.root.join(Self::name(group, version)?);
        let metadata = Self::metadata(&path)?;
        check(metadata["complete"] == true, "OFFLINE_UNAVAILABLE")?;
        let mut reader = vault.file_reader(cap, &metadata["record"])?;
        let count = anynote_crypto_core::codec::num(
            &metadata["record"]["envelope"]["header"]["framing"]["chunk_count"],
        )?;
        for index in 0..count {
            let mut file = File::open(path.join(index.to_string()))
                .map_err(|_| Error("OFFLINE_UNAVAILABLE"))?;
            let mut bytes = Vec::new();
            std::io::Read::by_ref(&mut file)
                .take(8388625)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
            check(
                bytes.len() <= 8388624 && vault.signal.generation() == cap.generation,
                "STALE_CAPABILITY",
            )?;
            let _verified = reader.decrypt_next(&bytes)?;
        }
        reader.finish()
    }
    pub fn ciphertext_digest(path: &Path) -> Result<String> {
        let mut file = File::open(path).map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        let mut digest = Sha256::new();
        let mut bytes = [0u8; 65536];
        loop {
            let n = file
                .read(&mut bytes)
                .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
            if n == 0 {
                break;
            }
            digest.update(&bytes[..n]);
        }
        Ok(b64(&digest.finalize()))
    }
}
