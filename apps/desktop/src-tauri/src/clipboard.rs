//! Explicit plaintext handoff; clear only our unchanged clipboard value, never another app's copy.
#[cfg(windows)]
mod windows {
    use std::{
        ffi::c_void,
        sync::{Mutex, OnceLock},
    };
    use zeroize::Zeroizing;
    #[link(name = "user32")]
    unsafe extern "system" {
        fn OpenClipboard(window: isize) -> i32;
        fn CloseClipboard() -> i32;
        fn EmptyClipboard() -> i32;
        fn SetClipboardData(format: u32, memory: *mut c_void) -> *mut c_void;
        fn GetClipboardData(format: u32) -> *mut c_void;
        fn GetClipboardSequenceNumber() -> u32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GlobalAlloc(flags: u32, bytes: usize) -> *mut c_void;
        fn GlobalFree(memory: *mut c_void) -> *mut c_void;
        fn GlobalLock(memory: *mut c_void) -> *mut c_void;
        fn GlobalUnlock(memory: *mut c_void) -> i32;
        fn GlobalSize(memory: *mut c_void) -> usize;
    }
    struct Open;
    impl Drop for Open {
        fn drop(&mut self) {
            unsafe {
                CloseClipboard();
            }
        }
    }
    struct Marker {
        sequence: u32,
        text: Zeroizing<Vec<u16>>,
    }
    static OWNED: OnceLock<Mutex<Option<Marker>>> = OnceLock::new();
    fn marker() -> &'static Mutex<Option<Marker>> {
        OWNED.get_or_init(|| Mutex::new(None))
    }
    pub fn clear() {
        clear_if(None);
    }
    fn clear_if(expected: Option<u32>) {
        let Ok(mut owned) = marker().lock() else {
            return;
        };
        let Some(value) = owned.as_ref() else { return };
        if expected.is_some_and(|sequence| sequence != value.sequence) {
            return;
        }
        unsafe {
            if GetClipboardSequenceNumber() != value.sequence {
                *owned = None;
                return;
            }
            if OpenClipboard(0) == 0 {
                return;
            }
            let _open = Open;
            let memory = GetClipboardData(13);
            if memory.is_null() {
                *owned = None;
                return;
            }
            let size = GlobalSize(memory);
            if size < value.text.len() * 2 || size > 2097152 {
                *owned = None;
                return;
            }
            let data = GlobalLock(memory) as *const u16;
            if data.is_null() {
                return;
            }
            let matches =
                std::slice::from_raw_parts(data, value.text.len()) == value.text.as_slice();
            GlobalUnlock(memory);
            if matches && GetClipboardSequenceNumber() == value.sequence {
                EmptyClipboard();
            }
            *owned = None;
        }
    }
    pub fn copy(window: usize, text: &str) -> Result<(), String> {
        if text.len() > 1048576 || text.contains('\0') {
            return Err("CLIPBOARD_RESOURCE_LIMIT".into());
        }
        let mut encoded = Zeroizing::new(text.encode_utf16().collect::<Vec<_>>());
        encoded.push(0);
        let mut owned = marker().lock().map_err(|_| "CLIPBOARD_UNAVAILABLE")?;
        unsafe {
            let memory = GlobalAlloc(2, encoded.len() * 2);
            if memory.is_null() {
                return Err("CLIPBOARD_UNAVAILABLE".into());
            }
            let data = GlobalLock(memory) as *mut u16;
            if data.is_null() {
                GlobalFree(memory);
                return Err("CLIPBOARD_UNAVAILABLE".into());
            }
            std::ptr::copy_nonoverlapping(encoded.as_ptr(), data, encoded.len());
            GlobalUnlock(memory);
            if OpenClipboard(window as isize) == 0 {
                GlobalFree(memory);
                return Err("CLIPBOARD_UNAVAILABLE".into());
            }
            let _open = Open;
            if EmptyClipboard() == 0 || SetClipboardData(13, memory).is_null() {
                GlobalFree(memory);
                return Err("CLIPBOARD_UNAVAILABLE".into());
            }
            *owned = Some(Marker {
                sequence: GetClipboardSequenceNumber(),
                text: encoded,
            });
        }
        let sequence = owned.as_ref().ok_or("CLIPBOARD_UNAVAILABLE")?.sequence;
        drop(owned);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(30));
            clear_if(Some(sequence));
        });
        Ok(())
    }
}
#[cfg(windows)]
pub use windows::{clear, copy};
#[cfg(not(windows))]
pub fn clear() {}
#[cfg(not(windows))]
pub fn copy(_: usize, _: &str) -> Result<(), String> {
    Err("CLIPBOARD_UNAVAILABLE".into())
}
