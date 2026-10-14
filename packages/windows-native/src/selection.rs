//! Native-selected paths never enter renderer requests. Handles are generation bound.
use crate::*;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::Zeroizing;
pub struct Source {
    pub file: File,
    pub name: String,
    pub size: u64,
    pub modified: Option<std::time::SystemTime>,
}
impl Source {
    pub fn open(path: &Path, limit: u64) -> Result<Self> {
        check(
            !std::fs::symlink_metadata(path)
                .map_err(|_| Error("SOURCE_UNAVAILABLE"))?
                .file_type()
                .is_symlink(),
            "SOURCE_UNAVAILABLE",
        )?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(1);
        }
        let file = options
            .open(path)
            .map_err(|_| Error("SOURCE_UNAVAILABLE"))?;
        let m = file.metadata().map_err(|_| Error("SOURCE_UNAVAILABLE"))?;
        check(m.is_file() && m.len() <= limit, "FILE_LIMIT_EXCEEDED")?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(Error("INVALID_FILENAME"))?
            .to_owned();
        Ok(Self {
            file,
            name,
            size: m.len(),
            modified: m.modified().ok(),
        })
    }
    pub fn check(&self) -> Result<()> {
        let m = self
            .file
            .metadata()
            .map_err(|_| Error("SOURCE_UNAVAILABLE"))?;
        check(
            m.len() == self.size && m.modified().ok() == self.modified,
            "SOURCE_CHANGED",
        )
    }
    pub fn small(&mut self, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
        self.check()?;
        check(self.size <= limit, "RESOURCE_LIMIT")?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error("SOURCE_UNAVAILABLE"))?;
        let mut b = Zeroizing::new(Vec::new());
        (&mut self.file)
            .take(limit + 1)
            .read_to_end(&mut b)
            .map_err(|_| Error("SOURCE_UNAVAILABLE"))?;
        check(b.len() as u64 <= limit, "RESOURCE_LIMIT")?;
        Ok(b)
    }
}
pub struct Selections {
    sources: Mutex<BTreeMap<String, (u64, Source)>>,
}
impl Default for Selections {
    fn default() -> Self {
        Self {
            sources: Mutex::new(BTreeMap::new()),
        }
    }
}
impl Selections {
    pub fn insert(&self, generation: u64, source: Source) -> Result<String> {
        let mut rows = self.sources.lock().map_err(|_| Error("HOST_BUSY"))?;
        check(rows.len() < 8, "RESOURCE_LIMIT")?;
        let h = random_id();
        rows.insert(h.clone(), (generation, source));
        Ok(h)
    }
    pub fn take(&self, generation: u64, handle: &str) -> Result<Source> {
        id(handle)?;
        let mut rows = self.sources.lock().map_err(|_| Error("HOST_BUSY"))?;
        let (g, s) = rows
            .remove(handle)
            .ok_or(Error("SOURCE_RESELECT_REQUIRED"))?;
        check(g == generation, "STALE_CAPABILITY")?;
        s.check()?;
        Ok(s)
    }
    pub fn clear(&self) {
        if let Ok(mut rows) = self.sources.lock() {
            rows.clear();
        }
    }
}
pub struct Destination {
    target: PathBuf,
    partial: PathBuf,
    file: Option<File>,
    complete: bool,
}
impl Destination {
    pub fn create(target: &Path) -> Result<Self> {
        check(!target.exists(), "DESTINATION_EXISTS")?;
        let parent = target.parent().ok_or(Error("INVALID_DESTINATION"))?;
        check(
            parent.is_dir()
                && !std::fs::symlink_metadata(parent)
                    .map_err(|_| Error("INVALID_DESTINATION"))?
                    .file_type()
                    .is_symlink(),
            "INVALID_DESTINATION",
        )?;
        let partial = parent.join(format!(".anynote-{}.partial", random_id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)
            .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        Ok(Self {
            target: target.into(),
            partial,
            file: Some(file),
            complete: false,
        })
    }
    pub fn writer(&mut self) -> Result<&mut File> {
        self.file.as_mut().ok_or(Error("EXPORT_CLOSED"))
    }
    pub fn finish(mut self) -> Result<()> {
        self.writer()?
            .sync_all()
            .map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        self.file.take();
        check(!self.target.exists(), "DESTINATION_EXISTS")?;
        #[cfg(not(windows))]
        {
            std::fs::hard_link(&self.partial, &self.target)
                .map_err(|_| Error("DESTINATION_UNAVAILABLE"))?;
            std::fs::remove_file(&self.partial).map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let a = self
                .partial
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let b = self
                .target
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            check(
                unsafe {
                    windows_sys::Win32::Storage::FileSystem::MoveFileExW(a.as_ptr(), b.as_ptr(), 8)
                } != 0,
                "DESTINATION_UNAVAILABLE",
            )?;
        }
        self.complete = true;
        Ok(())
    }
    pub fn encrypted_path(&self) -> &Path {
        &self.partial
    }
}
impl Write for Destination {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("EXPORT_CLOSED"))?
            .write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("EXPORT_CLOSED"))?
            .flush()
    }
}
impl Drop for Destination {
    fn drop(&mut self) {
        self.file.take();
        if !self.complete {
            let _ = std::fs::remove_file(&self.partial);
        }
    }
}
