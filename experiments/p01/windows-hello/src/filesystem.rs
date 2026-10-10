//! Windows replacements never delete the destination first. Keep a journal and
//! reconcile by read-back after *every* result, including partial Windows errors.
use crate::storage::{Error, Result, MAX_BYTES};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub fn reject_links(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if let Ok(m) = fs::symlink_metadata(ancestor) {
            if m.file_type().is_symlink() {
                return Err(Error::new("UNAVAILABLE"));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if m.file_attributes() & 0x400 != 0 {
                    #[cfg(test)]
                    eprintln!("Windows test rejected reparse ancestor: {ancestor:?}");
                    return Err(Error::new("UNAVAILABLE"));
                }
            }
        }
    }
    Ok(())
}

/// Pin directory names against replacement on Windows; keep these handles alive
/// throughout operations using absolute names (including ReplaceFileW).
pub fn pin_directory(path: &Path) -> Result<Vec<File>> {
    reject_links(path)?;
    let mut handles = Vec::new();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        for ancestor in path.ancestors() {
            let f = OpenOptions::new()
                .read(true)
                .share_mode(1 | 2)
                .custom_flags(0x02000000 | 0x00200000)
                .open(ancestor)?;
            // OPEN_REPARSE_POINT makes checking the opened object authoritative.
            use std::os::windows::fs::MetadataExt;
            if f.metadata()?.file_attributes() & 0x400 != 0 {
                return Err(Error::new("UNAVAILABLE"));
            }
            handles.push(f);
        }
    }
    #[cfg(not(windows))]
    {
        handles.push(File::open(path)?);
    }
    Ok(handles)
}

pub fn child(root: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || name.contains(['/', '\\', ':'])
        || name == "."
        || name == ".."
        || name.len() > 160
    {
        return Err(Error::new("INVALID_STATE"));
    }
    let p = root.join(name);
    reject_links(&p)?;
    Ok(p)
}

pub fn user_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(Error::new("INVALID_STATE"));
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        match path.components().next() {
            Some(Component::Prefix(p))
                if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) => {}
            _ => return Err(Error::new("INVALID_STATE")),
        }
        for component in path.components().skip(1) {
            let s = component.as_os_str().to_string_lossy();
            let base = s.split('.').next().unwrap_or("").to_ascii_uppercase();
            if s.contains(':')
                || s.ends_with([' ', '.'])
                || [
                    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
                    "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
                    "LPT8", "LPT9",
                ]
                .contains(&base.as_str())
            {
                return Err(Error::new("INVALID_STATE"));
            }
        }
    }
    reject_links(path)?;
    Ok(path.to_path_buf())
}

pub fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    reject_links(path)?;
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.share_mode(1).custom_flags(0x00200000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(0x20000); // O_NOFOLLOW on Linux; native release is Windows-only.
    }
    let file = opts.open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > limit as u64 {
        return Err(Error::new("CORRUPT"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if file.metadata()?.file_attributes() & 0x400 != 0 {
            return Err(Error::new("UNAVAILABLE"));
        }
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::new("CORRUPT"));
    }
    Ok(bytes)
}

pub fn exclusive_write(path: &Path, bytes: &[u8]) -> Result<()> {
    reject_links(path)?;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.share_mode(0)
            .access_mode(0x40000000 | 0x00040000 | 0x00020000)
            .custom_flags(0x00200000);
    }
    let mut file = opts.open(path)?;
    // Managed folders already have a protected per-user inheritable DACL.
    // User exports acquire the same explicit ACL while the file is exclusive.
    #[cfg(windows)]
    secure_file_handle(&file, false)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if read(path, bytes.len())? != bytes {
        return Err(Error::new("READBACK_FAILED"));
    }
    Ok(())
}

pub fn replace(from: &Path, to: &Path, backup: Option<&Path>, first: bool) -> Result<()> {
    reject_links(from)?;
    reject_links(to)?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, ReplaceFileW, MOVEFILE_WRITE_THROUGH,
        };
        let w = |p: &Path| {
            p.as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>()
        };
        let a = w(from);
        let b = w(to);
        let prior = backup.map(w);
        let ok = unsafe {
            if !first {
                ReplaceFileW(
                    b.as_ptr(),
                    a.as_ptr(),
                    prior.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            } else {
                MoveFileExW(a.as_ptr(), b.as_ptr(), MOVEFILE_WRITE_THROUGH)
            }
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(backup) = backup {
            if to.exists() {
                fs::copy(to, backup)?;
                File::open(backup)?.sync_all()?;
            }
        }
        if first {
            fs::hard_link(from, to)?;
            fs::remove_file(from)?;
        } else {
            fs::rename(from, to)?;
        }
        if let Some(parent) = to.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

pub fn atomic_json(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_file_name(format!("metadata-{}.tmp", uuid::Uuid::new_v4()));
    exclusive_write(&tmp, bytes)?;
    let result = replace(&tmp, path, None, !path.exists());
    // A ReplaceFileW error can have moved names. A matching read-back wins.
    if read(path, 256 * 1024).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    result?;
    Err(Error::new("READBACK_FAILED"))
}

pub fn read_import(path: &Path) -> Result<Vec<u8>> {
    let path = user_path(path)?;
    let _pins = pin_directory(path.parent().ok_or(Error::new("INVALID_STATE"))?)?;
    read(&path, MAX_BYTES)
}

#[cfg(windows)]
pub fn secure_file_handle(file: &File, directory: bool) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
        },
        Security::{
            GetSecurityDescriptorControl, GetTokenInformation, TokenUser,
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY,
            TOKEN_USER,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut size = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size);
        let mut data = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        let ok = GetTokenInformation(token, TokenUser, data.as_mut_ptr().cast(), size, &mut size);
        windows_sys::Win32::Foundation::CloseHandle(token);
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let user = &*(data.as_ptr().cast::<TOKEN_USER>());
        let mut sid = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid) == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut len = 0;
        while *sid.add(len) != 0 {
            len += 1;
        }
        let sid_string = String::from_utf16_lossy(std::slice::from_raw_parts(sid, len));
        LocalFree(sid.cast());
        let inherit = if directory { "OICI" } else { "" };
        let sddl = format!("D:P(A;{inherit};FA;;;SY)(A;{inherit};FA;;;{sid_string})")
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = std::ptr::null_mut();
        let got = windows_sys::Win32::Security::GetSecurityDescriptorDacl(
            descriptor,
            &mut present,
            &mut dacl,
            &mut defaulted,
        );
        let result = if got == 0 {
            1
        } else {
            SetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        if result != 0 {
            #[cfg(test)]
            eprintln!("Windows test SetSecurityInfo failed with code {result}");
            LocalFree(descriptor);
            return Err(Error::new("UNAVAILABLE"));
        }
        // Request READ_CONTROL as well as WRITE_DAC when opening the handle:
        // Windows must read the existing security descriptor for propagation,
        // and the caller must verify the resulting protected DACL.
        let mut actual_descriptor = std::ptr::null_mut();
        let mut actual_dacl = std::ptr::null_mut();
        let read_result = GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut actual_dacl,
            std::ptr::null_mut(),
            &mut actual_descriptor,
        );
        let mut control = 0;
        let mut revision = 0;
        let verified = read_result == 0 && !actual_dacl.is_null() && !dacl.is_null()
            && GetSecurityDescriptorControl(actual_descriptor, &mut control, &mut revision) != 0
            && control & 0x1000 != 0 // SE_DACL_PROTECTED
            && (*actual_dacl).AclSize == (*dacl).AclSize
            && std::slice::from_raw_parts(actual_dacl.cast::<u8>(), (*actual_dacl).AclSize as usize)
                == std::slice::from_raw_parts(dacl.cast::<u8>(), (*dacl).AclSize as usize);
        if !actual_descriptor.is_null() {
            LocalFree(actual_descriptor);
        }
        LocalFree(descriptor);
        if !verified {
            #[cfg(test)]
            eprintln!("Windows test protected DACL readback failed with code {read_result}");
            return Err(Error::new("UNAVAILABLE"));
        }
    }
    Ok(())
}

pub fn secure_directory(path: &Path) -> Result<()> {
    reject_links(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let f = OpenOptions::new()
            .read(true)
            .access_mode(0x00040000 | 0x00020000 | 0x80)
            .share_mode(1 | 2)
            .custom_flags(0x02000000 | 0x00200000)
            .open(path)?;
        secure_file_handle(&f, true)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Identity detects a replaced backup folder/volume at the same pathname.
pub fn identity(path: &Path) -> Result<String> {
    reject_links(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1 | 2)
            .custom_flags(0x02000000 | 0x00200000)
            .open(path)?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(format!(
            "{}:{}:{}",
            info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
        ))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path)?;
        Ok(format!("{}:{}", metadata.dev(), metadata.ino()))
    }
}

/// Prune only bytes still owned by this app. Windows deletes the exact opened
/// object, without a hash-check/close/path-delete race or following reparse points.
pub fn remove_verified(path: &Path, expected_hash: &str) -> Result<bool> {
    reject_links(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
        };
        let file = OpenOptions::new()
            .read(true)
            .access_mode(0x80000000 | 0x00010000)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(path)?;
        if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_BYTES as u64 {
            return Ok(false);
        }
        use std::os::windows::fs::MetadataExt;
        if file.metadata()?.file_attributes() & 0x400 != 0 {
            return Err(Error::new("UNAVAILABLE"));
        }
        let mut bytes = Vec::new();
        file.try_clone()?
            .take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if crate::storage::hash(&bytes) != expected_hash {
            return Ok(false);
        }
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle().cast(),
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        drop(file);
        Ok(true)
    }
    #[cfg(not(windows))]
    {
        if crate::storage::hash(&read(path, MAX_BYTES)?) != expected_hash {
            return Ok(false);
        }
        fs::remove_file(path)?;
        Ok(true)
    }
}
