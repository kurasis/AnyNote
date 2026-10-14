//! Real native selected-handle jobs; only counters cross the renderer boundary.
use crate::*;
use crate::{
    host::Host,
    selection::{Destination, Source},
};
use anynote_local_vault::notes::{
    file_cache::CipherCache,
    files::{Network, SelectedSource},
};
use std::{path::Path, sync::Arc};
impl Host {
    pub fn start_upload(
        self: &Arc<Self>,
        g: u64,
        group: String,
        source: Source,
        resume: Option<String>,
    ) -> Result<String> {
        id(&group)?;
        if let Some(ref id) = resume {
            crate::id(id)?;
        }
        let cap = self.capability(g)?;
        let job = self.jobs.start(g)?;
        let jid = job.id.clone();
        let host = self.clone();
        std::thread::spawn(move || {
            let mut source = source;
            let result = (|| {
                host.prove(&cap)?;
                host.group(&cap, &group)?;
                job.check(host.current())?;
                source.check()?;
                host.vault.upload_file_with_progress(
                    &cap,
                    Network {
                        credential_id: &host.profile.credential_id,
                        adapter: &host.adapter,
                    },
                    SelectedSource {
                        group: &group,
                        file: &mut source.file,
                        name: &source.name,
                        media: "application/octet-stream",
                        resume: resume.as_deref(),
                    },
                    |bytes, total| {
                        job.check(host.current())?;
                        job.progress(bytes, total);
                        Ok(())
                    },
                )
            })();
            job.finish(result);
        });
        Ok(jid)
    }
    pub fn start_download(
        self: &Arc<Self>,
        g: u64,
        group: String,
        version: String,
        path: &Path,
        offline: bool,
    ) -> Result<String> {
        id(&group)?;
        id(&version)?;
        let cap = self.capability(g)?;
        let mut destination = Destination::create(path)?;
        let job = self.jobs.start(g)?;
        let jid = job.id.clone();
        let host = self.clone();
        let output = path.to_owned();
        std::thread::spawn(move || {
            let result = (|| {
                job.check(host.current())?;
                if offline {
                    drop(destination);
                    CipherCache::for_vault(&host.vault)?.atomic_export(
                        &host.vault,
                        &cap,
                        &group,
                        &version,
                        &output,
                        false,
                    )?;
                } else {
                    host.prove(&cap)?;
                    host.group(&cap, &group)?;
                    let result = host.vault.download_file(
                        &cap,
                        Network {
                            credential_id: &host.profile.credential_id,
                            adapter: &host.adapter,
                        },
                        &group,
                        &version,
                        destination.writer()?,
                    )?;
                    job.check(host.current())?;
                    destination.finish()?;
                    return Ok(result);
                }
                Ok(serde_json::json!({"state":"COMPLETE"}))
            })();
            job.finish(result);
        });
        Ok(jid)
    }
    pub fn read_preview(&self, g: u64, group: &str, version: &str) -> Result<Vec<u8>> {
        use anynote_auth_native::FileOperation;
        let cap = self.capability(g)?;
        self.group(&cap, group)?;
        let response = self.vault.file_http(
            &cap,
            &self.profile.credential_id,
            &self.adapter,
            FileOperation::Manifest { version },
        )?;
        check(response.status == 200, "API_DENIED")?;
        let record = anynote_crypto_core::codec::strict(&response.bytes, 1048576)?;
        let metadata = self.vault.file_metadata(&cap, &record)?;
        let size = record["envelope"]["header"]["framing"]["plaintext_bytes"]
            .as_str()
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or(Error("INVALID_REQUEST"))?;
        check(size <= 16777216, "SAFE_DOWNLOAD_REQUIRED")?;
        let mut parts = (0..size.div_ceil(8388608)).map(|i| {
            self.vault
                .file_http(
                    &cap,
                    &self.profile.credential_id,
                    &self.adapter,
                    FileOperation::Chunk {
                        version,
                        index: i as u8,
                    },
                )
                .and_then(|r| {
                    check(r.status == 200, "API_DENIED")?;
                    Ok(r.bytes)
                })
        });
        let mut sink = Vec::with_capacity(size);
        let mut reader = self.vault.file_reader(&cap, &record)?;
        for part in &mut parts {
            check(self.current() == g, "STALE_CAPABILITY")?;
            let plain = zeroize::Zeroizing::new(reader.decrypt_next(&part?)?);
            sink.extend_from_slice(&plain);
        }
        reader.finish()?;
        let _ = metadata;
        check(self.current() == g, "STALE_CAPABILITY")?;
        Ok(sink)
    }
}
