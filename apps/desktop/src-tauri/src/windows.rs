//! Real main-HWND session/power hooks. Native generation fencing precedes UI events.
use super::*;
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, WPARAM},
    System::{
        RemoteDesktop::{
            NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification,
            WTSUnRegisterSessionNotification,
        },
        SystemInformation::GetTickCount64,
    },
    UI::{
        Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
        Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass},
        WindowsAndMessaging::{
            PBT_APMSUSPEND, WM_ENDSESSION, WM_NCDESTROY, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE,
            WTS_SESSION_LOCK,
        },
    },
};
struct Hook {
    state: Arc<State>,
    app: tauri::AppHandle,
}
unsafe extern "system" fn subclass(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    id: usize,
    data: usize,
) -> LRESULT {
    let hook = unsafe { &*(data as *const Hook) };
    if (msg == WM_WTSSESSION_CHANGE && wparam == WTS_SESSION_LOCK as usize)
        || (msg == WM_POWERBROADCAST && wparam == PBT_APMSUSPEND as usize)
        || msg == WM_ENDSESSION
    {
        if let Ok(host) = hook.state.host() {
            host.invalidate();
            std::thread::spawn(move || host.finish_lock());
        }
        clipboard::clear();
        hook.state.mask();
        let _ = hook
            .app
            .emit("vault-locked", json!({"reason":"session-or-power"}));
    }
    let result = unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) };
    if msg == WM_NCDESTROY {
        unsafe {
            RemoveWindowSubclass(hwnd, Some(subclass), id);
            WTSUnRegisterSessionNotification(hwnd);
            drop(Box::from_raw(data as *mut Hook));
        }
    }
    result
}
pub fn attach(
    window: &tauri::WebviewWindow,
    state: Arc<State>,
) -> Result<(), Box<dyn std::error::Error>> {
    let hwnd = window.hwnd()?.0 as HWND;
    if unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) } == 0 {
        return Err("WTS_UNAVAILABLE".into());
    }
    let hook = Box::into_raw(Box::new(Hook {
        state: state.clone(),
        app: window.app_handle().clone(),
    }));
    if unsafe { SetWindowSubclass(hwnd, Some(subclass), 0x414e, hook as usize) } == 0 {
        unsafe {
            drop(Box::from_raw(hook));
            WTSUnRegisterSessionNotification(hwnd);
        }
        return Err("LIFECYCLE_HOOK_UNAVAILABLE".into());
    }
    let app = window.app_handle().clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let mut input = LASTINPUTINFO {
                cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
                dwTime: 0,
            };
            if unsafe { GetLastInputInfo(&mut input) } != 0 {
                let idle = (unsafe { GetTickCount64() } as u32).wrapping_sub(input.dwTime);
                if idle >= 300000
                    && let Ok(host) = state.host()
                    && host.vault.status().ok() == Some("unlocked")
                {
                    host.lock();
                    clipboard::clear();
                    state.mask();
                    let _ = app.emit("vault-locked", json!({"reason":"idle"}));
                }
            }
        }
    });
    Ok(())
}

pub fn owns_foreground() -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowThreadProcessId,
    };
    let foreground = unsafe { GetForegroundWindow() };
    if foreground.is_null() {
        return false;
    }
    let mut pid = 0;
    unsafe {
        GetWindowThreadProcessId(foreground, &mut pid);
    };
    pid == std::process::id()
}
