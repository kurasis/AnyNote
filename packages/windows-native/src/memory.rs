//! Content-free OS process counters. Never substitute heap estimates for observed process peaks.
use std::sync::atomic::{AtomicU64, Ordering};
static HELPER_PEAK: AtomicU64 = AtomicU64::new(0);
pub fn observe_helper(pid: u32) {
    if let Some(bytes) = peak(pid) {
        HELPER_PEAK.fetch_max(bytes, Ordering::Relaxed);
    }
}
pub fn report() -> serde_json::Value {
    serde_json::json!({"native_peak_bytes":peak(std::process::id()),"helper_peak_bytes":HELPER_PEAK.load(Ordering::Relaxed),"source":"OS peak working set / VmHWM","webview2":"NOT_ATTRIBUTED_BY_CORE"})
}
#[cfg(windows)]
fn peak(pid: u32) -> Option<u64> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::{
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
        },
    };
    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if process.is_null() {
        return None;
    }
    let mut counters = std::mem::MaybeUninit::<PROCESS_MEMORY_COUNTERS>::zeroed();
    let ok = unsafe {
        GetProcessMemoryInfo(
            process,
            counters.as_mut_ptr(),
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    unsafe {
        CloseHandle(process);
    };
    if ok == 0 {
        None
    } else {
        Some(unsafe { counters.assume_init() }.PeakWorkingSetSize as u64)
    }
}
#[cfg(not(windows))]
fn peak(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let row = text.lines().find(|l| l.starts_with("VmHWM:"))?;
    row.split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}
