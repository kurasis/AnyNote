//! Microsoft's documented provider TBS context / virtualized key handle route.
//! The provider owns both handles: never close, flush, recreate or persist them.
use super::*;
use crate::hello::tpm::read_public as wire;
use std::ffi::c_void;
use windows_sys::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
};

fn property<const N: usize>(
    handle: usize,
    kind: PCWSTR,
    operation: &'static str,
) -> std::result::Result<Vec<u8>, Failure> {
    let mut data = vec![0; N];
    let mut actual = 0;
    unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(handle),
            kind,
            Some(&mut data),
            &mut actual,
            OBJECT_SECURITY_INFORMATION(NCRYPT_SILENT_FLAG.0),
        )
    }
    .map_err(|e| failed(e, operation))?;
    if actual == 0 || actual as usize > N {
        return Err(invalid("tpm-read-public-property-length"));
    }
    data.truncate(actual as usize);
    Ok(data)
}

fn submit(context: usize, key: u32) -> std::result::Result<Vec<u8>, Failure> {
    struct Module(*mut c_void);
    impl Drop for Module {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.0);
            }
        }
    }
    let module = unsafe {
        LoadLibraryExW(
            windows_sys::core::w!("tbs.dll"),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return Err(Failure {
            status: Outcome::Failed,
            code: Some(unsafe { GetLastError() }),
            operation: Some("tpm-read-public-load-tbs"),
        });
    }
    let module = Module(module);
    let address = unsafe { GetProcAddress(module.0, c"Tbsip_Submit_Command".as_ptr().cast()) }
        .ok_or_else(|| invalid("tpm-read-public-resolve-submit"))?;
    // Same ABI as maintained windows-sys TpmBaseServices, native pointer context.
    let submit: unsafe extern "system" fn(
        *const c_void,
        u32,
        u32,
        *const u8,
        u32,
        *mut u8,
        *mut u32,
    ) -> u32 = unsafe { std::mem::transmute(address) };
    let command = wire::command(key);
    let mut response = vec![0; wire::MAX_RESPONSE];
    let mut actual = response.len() as u32;
    let status = unsafe {
        submit(
            context as *const c_void,
            TBS_COMMAND_LOCALITY_ZERO,
            TBS_COMMAND_PRIORITY_NORMAL,
            command.as_ptr(),
            command.len() as u32,
            response.as_mut_ptr(),
            &mut actual,
        )
    };
    if status != 0 {
        return Err(Failure {
            status: Outcome::Failed,
            code: Some(status),
            operation: Some("tpm-read-public-submit"),
        });
    }
    if actual as usize > response.len() {
        return Err(invalid("tpm-read-public-response-length"));
    }
    response.truncate(actual as usize);
    Ok(response)
}

pub(super) fn measure(
    provider: usize,
    key: usize,
) -> std::result::Result<(Vec<u8>, Vec<u8>, u32), Failure> {
    // Only live handles created by this native probe, never supplied by the renderer.
    let context = property::<{ std::mem::size_of::<usize>() }>(
        provider,
        NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
        "tpm-read-public-provider-context",
    )?;
    let context = usize::from_ne_bytes(
        context
            .try_into()
            .map_err(|_| invalid("tpm-read-public-context-width"))?,
    );
    let handle = number(
        key,
        NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
        "tpm-read-public-key-handle",
    )?;
    if context == 0 || handle == 0 {
        return Err(invalid("tpm-read-public-null-handle"));
    }
    let name = property::<34>(
        key,
        NCRYPT_PCP_TPM2BNAME_PROPERTY,
        "tpm-read-public-provider-name",
    )?;
    let mut public = vec![0; 24 + 3 + 256];
    let mut actual = 0;
    unsafe {
        NCryptExportKey(
            NCRYPT_KEY_HANDLE(key),
            None,
            BCRYPT_RSAPUBLIC_BLOB,
            None,
            Some(&mut public),
            &mut actual,
            NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|e| failed(e, "tpm-read-public-export-public"))?;
    if actual as usize != public.len() {
        return Err(invalid("tpm-read-public-cng-public-length"));
    }
    let response = submit(context, handle)?;
    let attributes = wire::inspect(&response, &public, &name)?;
    Ok((public, name, attributes))
}
