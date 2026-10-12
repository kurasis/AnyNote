//! The host installs this hook on its actual main HWND and pumps the OS queue.
//! WTS lock, suspend, shutdown and close invalidate native crypto before any UI event.
use super::LockSignal;
pub enum Boundary {
    SessionLock,
    Suspend,
    Background,
    Logout,
    Close,
    Idle,
}
pub fn invalidate(signal: &LockSignal, _reason: Boundary) {
    signal.invalidate();
}
#[cfg(windows)]
pub struct WindowsHook {
    hwnd: usize,
    signal: LockSignal,
}
#[cfg(windows)]
impl WindowsHook {
    pub fn attach(hwnd: usize, signal: LockSignal) -> super::Result<Self> {
        use windows_sys::Win32::{
            System::RemoteDesktop::{NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification},
            UI::WindowsAndMessaging::IsWindow,
        };
        super::check(unsafe { IsWindow(hwnd as _) } != 0, "INVALID_NATIVE_WINDOW")?;
        super::check(
            unsafe { WTSRegisterSessionNotification(hwnd as _, NOTIFY_FOR_THIS_SESSION) } != 0,
            "WTS_UNAVAILABLE",
        )?;
        Ok(Self { hwnd, signal })
    }
    /// Called by the trusted native WndProc; frontend JSON cannot mint an OS event.
    pub fn message(&self, message: u32, wparam: usize) {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            PBT_APMSUSPEND, WM_CLOSE, WM_DESTROY, WM_ENDSESSION, WM_POWERBROADCAST,
            WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK,
        };
        if (message == WM_WTSSESSION_CHANGE && wparam == WTS_SESSION_LOCK as usize)
            || (message == WM_POWERBROADCAST && wparam == PBT_APMSUSPEND as usize)
            || [WM_CLOSE, WM_DESTROY, WM_ENDSESSION].contains(&message)
        {
            self.signal.invalidate();
        }
    }
}
#[cfg(windows)]
impl Drop for WindowsHook {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::RemoteDesktop::WTSUnRegisterSessionNotification(
                self.hwnd as _,
            );
        }
        self.signal.invalidate();
    }
}
