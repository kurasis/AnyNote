//! SPDX-License-Identifier: GPL-3.0-only
//! Native-only synthetic local-key admission; no password/KDBX assumptions.
use crate::{
    filesystem as io, hello,
    storage::{Error, Result},
};
use hello::enrollment::{Action, Binding, Manager, Mode};
use libsodium_rs::{crypto_aead::xchacha20poly1305 as aead, random, utils};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::{
    core::w,
    Win32::{
        Foundation::*,
        System::{LibraryLoader::GetModuleHandleW, RemoteDesktop::*},
        UI::WindowsAndMessaging::*,
    },
};
use zeroize::Zeroizing;

static ACTIVE: AtomicBool = AtomicBool::new(true);
static GENERATION: AtomicU64 = AtomicU64::new(0);
static EVENTS: crate::trial_lifecycle::Events = crate::trial_lifecycle::Events::new();
static LOCK_REQUEST: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static LOCK_TRIAL_PENDING: AtomicBool = AtomicBool::new(false);
const FINISHED: u32 = WM_APP + 1;
const ARM_LOCK: u32 = WM_APP + 2;
const LOCK_TIMER: usize = 1;
const MARKER: &[u8] = b"AnyNote P01 authenticated synthetic local vault";
const AAD: &[u8] = b"AnyNote.P01.SyntheticLocalVault.v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vault {
    id: String,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}
fn now() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new("CLOCK"))?
        .as_millis()
        .try_into()
        .map_err(|_| Error::new("CLOCK"))
}
fn root() -> Result<PathBuf> {
    let base =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or_else(|| Error::new("UNAVAILABLE"))?);
    if !base.is_absolute() {
        return Err(Error::new("UNAVAILABLE"));
    }
    let root = io::child(&base, "AnyNoteP01Hello")?;
    io::reject_links(&root)?;
    fs::create_dir_all(&root)?;
    io::secure_directory(&root)?;
    Ok(root)
}
fn binding(root: &Path) -> Result<Binding> {
    let bytes = io::read(&io::child(root, "synthetic-vault.json")?, 16_384)?;
    let vault: Vault = serde_json::from_slice(&bytes)?;
    if uuid::Uuid::parse_str(&vault.id).is_err() || vault.ciphertext.len() != MARKER.len() + 16 {
        return Err(Error::new("CORRUPT"));
    }
    Ok(Binding {
        vault: vault.id,
        key_epoch: 1,
        generation: 1,
        sha256: crate::storage::hash(&bytes),
    })
}
fn authenticate(root: &Path, local_key: &[u8]) -> Result<()> {
    let vault: Vault = serde_json::from_slice(&io::read(
        &io::child(root, "synthetic-vault.json")?,
        16_384,
    )?)?;
    let key = aead::Key::from_bytes(local_key).map_err(|_| Error::new("CORRUPT"))?;
    let clear = Zeroizing::new(
        aead::decrypt(
            &vault.ciphertext,
            Some(AAD),
            &aead::Nonce::from_bytes(vault.nonce),
            &key,
        )
        .map_err(|_| Error::new("CORRUPT"))?,
    );
    if !utils::memcmp(&clear, MARKER) {
        return Err(Error::new("CORRUPT"));
    }
    Ok(())
}
fn run(hwnd: usize, command: &str) -> Result<Value> {
    libsodium_rs::ensure_init().map_err(|_| Error::new("UNAVAILABLE"))?;
    let generation = GENERATION.load(Ordering::Acquire);
    let current = || {
        ACTIVE.load(Ordering::Acquire)
            && GENERATION.load(Ordering::Acquire) == generation
            && unsafe { IsWindow(hwnd as HWND) } != 0
    };
    if command == "capabilities" {
        let report = hello::prf::run(hwnd, current, hello::prf::Experiment::Capability)?;
        return Ok(
            json!({"status":"CAPABILITY_ONLY","report":report,"physical_acceptance":false,
            "key_creation":false,"upstream_source":"c18894e210a07546ba66cf178b8048ae5c40ac61"}),
        );
    }
    let root = root()?;
    let _pins = io::pin_directory(&root)?;
    let context = || {
        if !current() {
            return Err(Error::new("STALE"));
        }
        Ok((binding(&root)?, now()?))
    };
    let mut manager = Manager::default();
    if command == "cleanup" {
        manager.run(&root, hwnd, &current, &context, &Action::Revoke {})?;
        let path = io::child(&root, "synthetic-vault.json")?;
        if path.exists() {
            let bytes = io::read(&path, 16_384)?;
            if !io::remove_verified(&path, &crate::storage::hash(&bytes))? {
                return Err(Error::new("STALE"));
            }
        }
        return Ok(
            json!({"status":"PASS","exact_owned_objects_deleted":true,"physical_acceptance":false}),
        );
    }
    if matches!(command, "roundtrip" | "enroll") {
        // Refuse overwrite of the only ciphertext or outstanding ownership journal.
        let journal = io::child(&io::child(&root, "hello-local-key")?, "enrollment.json")?;
        if journal.exists() {
            return Err(Error::new("HELLO_CLEANUP_REQUIRED"));
        }
        let path = io::child(&root, "synthetic-vault.json")?;
        if path.exists() {
            return Err(Error::new("HELLO_CLEANUP_REQUIRED"));
        }
        let local_key = Zeroizing::new(random::bytes(32));
        let key = aead::Key::from_bytes(&local_key).map_err(|_| Error::new("UNAVAILABLE"))?;
        let nonce = aead::Nonce::generate();
        let ciphertext = aead::encrypt(MARKER, Some(AAD), &nonce, &key)
            .map_err(|_| Error::new("UNAVAILABLE"))?;
        let vault = Vault {
            id: uuid::Uuid::new_v4().to_string(),
            nonce: *nonce.as_bytes(),
            ciphertext,
        };
        io::atomic_json(&path, &serde_json::to_vec(&vault)?)?;
        let before = binding(&root)?;
        let mut value = [0; 32];
        value.copy_from_slice(&local_key);
        let action = Action::Enroll {
            mode: if command == "roundtrip" {
                Mode::Session
            } else {
                Mode::Remember6
            },
            generation: before.generation,
            sha256: before.sha256.clone(),
            local_key: value,
        };
        // Action owns/zeroizes the copy. Retain no serialized key-bearing reply.
        value.fill(0);
        let enrollment = manager.run(&root, hwnd, &current, &context, &action)?;
        if enrollment.status.state != "enabled" {
            return Err(Error::new("UNAVAILABLE"));
        }
        if command == "enroll" {
            return Ok(
                json!({"status":"PASS_SYNTHETIC_ENROLLMENT","mode":"remember6",
                "fresh_unlock":"NOT RUN; use a new process with unlock","physical_acceptance":false}),
            );
        }
    }
    let expected = binding(&root)?;
    if command == "unlock-lock-trial" {
        // Only this explicitly selected synthetic command arms the one-shot OS lock.
        LOCK_TRIAL_PENDING.store(true, Ordering::Release);
        if unsafe { PostMessageW(hwnd as HWND, ARM_LOCK, 0, 0) } == 0 {
            LOCK_TRIAL_PENDING.store(false, Ordering::Release);
            return Err(Error::new("LOCK_TIMER_UNAVAILABLE"));
        }
    }
    let result = (|| {
        let reply = manager.run(&root, hwnd, &current, &context, &Action::Unlock {});
        LOCK_TRIAL_PENDING.store(false, Ordering::Release);
        let reply = reply?;
        let local_key = reply
            .local_key
            .as_ref()
            .ok_or_else(|| Error::new("CORRUPT"))?;
        authenticate(&root, local_key)?;
        if !current() || binding(&root)? != expected {
            return Err(Error::new("STALE"));
        }
        // Publishing a test success requires actual AEAD authentication above.
        Ok(
            json!({"status":"PASS_SYNTHETIC_UNLOCK","actual_vault_authenticated":true,
            "fresh_prf_and_exact_tpm_reopen":true,"physical_acceptance":false}),
        )
    })();
    if command == "roundtrip" {
        // Attempt cleanup even after cancellation/late reply; durable retry journal survives failure.
        manager.run(&root, hwnd, &current, &context, &Action::Revoke {})?;
        let path = io::child(&root, "synthetic-vault.json")?;
        let bytes = io::read(&path, 16_384)?;
        if !io::remove_verified(&path, &crate::storage::hash(&bytes))? {
            return Err(Error::new("STALE"));
        }
    }
    result
}

fn lifecycle_event(message: u32, wp: WPARAM) -> Option<crate::trial_lifecycle::Event> {
    use crate::trial_lifecycle::Event;
    match (message, wp) {
        (WM_WTSSESSION_CHANGE, value) if value == WTS_SESSION_LOCK as usize => Some(Event::Lock),
        (WM_WTSSESSION_CHANGE, value) if value == WTS_SESSION_UNLOCK as usize => {
            Some(Event::Unlock)
        }
        (WM_POWERBROADCAST, 4) => Some(Event::Suspend),
        (WM_CLOSE, _) => Some(Event::OwnerClose),
        _ => None,
    }
}
unsafe extern "system" fn window_proc(hwnd: HWND, message: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if message == ARM_LOCK {
        if unsafe { SetTimer(hwnd, LOCK_TIMER, 8000, None) } == 0 {
            LOCK_REQUEST.store(3, Ordering::Release);
        }
        return 0;
    }
    if message == WM_TIMER && wp == LOCK_TIMER {
        unsafe { KillTimer(hwnd, LOCK_TIMER) };
        if ACTIVE.load(Ordering::Acquire)
            && LOCK_TRIAL_PENDING.load(Ordering::Acquire)
            && EVENTS.snapshot().wts_session_lock == 0
        {
            let accepted = unsafe { windows_sys::Win32::System::Shutdown::LockWorkStation() } != 0;
            LOCK_REQUEST.store(if accepted { 1 } else { 2 }, Ordering::Release);
        }
        return 0;
    }
    if let Some(event) = lifecycle_event(message, wp) {
        EVENTS.record(event);
        if event.invalidates() {
            GENERATION.fetch_add(1, Ordering::AcqRel);
        }
    }
    if message == WM_CLOSE || message == FINISHED {
        unsafe { KillTimer(hwnd, LOCK_TIMER) };
        ACTIVE.store(false, Ordering::Release);
        if message == FINISHED {
            GENERATION.fetch_add(1, Ordering::AcqRel);
        }
        unsafe { DestroyWindow(hwnd) };
        return 0;
    }
    if message == WM_DESTROY {
        unsafe { PostQuitMessage(0) };
        return 0;
    }
    unsafe { DefWindowProcW(hwnd, message, wp, lp) }
}
pub fn main() -> std::result::Result<(), &'static str> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2
        || !matches!(
            args[1].as_str(),
            "capabilities" | "roundtrip" | "enroll" | "unlock" | "unlock-lock-trial" | "cleanup"
        )
    {
        return Err(
            "usage: anynote-p01-windows-hello capabilities|roundtrip|enroll|unlock|unlock-lock-trial|cleanup",
        );
    }
    if args[1] == "capabilities" {
        libsodium_rs::ensure_init().map_err(|_| "sodium unavailable")?;
        let report = hello::prf::run(0, || true, hello::prf::Experiment::Capability)
            .map_err(|_| "capability API failed")?;
        let mut capability = json!({"status":"CAPABILITY_ONLY","report":report,"native_objects_created":false,
            "source_commit":option_env!("ANYNOTE_PROBE_SOURCE"),"physical_acceptance":false});
        capability["trial_route_available"] = json!(crate::trial_route::available(&capability));
        println!("{capability}");
        return Ok(());
    }
    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: w!("AnyNoteP01HelloWindow"),
            ..Default::default()
        };
        if RegisterClassW(&class) == 0 {
            return Err("window class unavailable");
        }
        let hwnd = CreateWindowExW(
            0,
            class.lpszClassName,
            w!("AnyNote P01 - synthetic Hello probe; closing cancels"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            680,
            160,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return Err("native HWND unavailable");
        }
        if WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) == 0 {
            DestroyWindow(hwnd);
            return Err("session notification unavailable");
        }
        let window = hwnd as usize;
        let command = args[1].clone();
        let task = std::thread::spawn(move || {
            let result = run(window, &command);
            PostMessageW(window as HWND, FINISHED, 0, 0);
            result
        });
        let mut message = MSG::default();
        while GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        WTSUnRegisterSessionNotification(hwnd);
        match task.join().map_err(|_| "native probe thread failed")? {
            Ok(mut report) => {
                report["lifecycle"] = json!(EVENTS.snapshot());
                report["lock_request"] = json!(crate::trial_lifecycle::lock_request_status(
                    LOCK_REQUEST.load(Ordering::Acquire)
                ));
                println!("{report}");
                Ok(())
            }
            Err(error) => {
                eprintln!(
                    "{}",
                    json!({"status":"FAIL_OR_UNAVAILABLE","code":error.code,
                "physical_acceptance":false,"lifecycle":EVENTS.snapshot(),
                "lock_request":crate::trial_lifecycle::lock_request_status(LOCK_REQUEST.load(Ordering::Acquire)),
                "cleanup":"Run cleanup; a retained journal must not be discarded"})
                );
                Err("native probe did not pass")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_message_mapping_distinguishes_unlock_suspend_close_and_internal_finish() {
        assert!(
            lifecycle_event(WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK as usize)
                .unwrap()
                .invalidates()
        );
        assert!(
            !lifecycle_event(WM_WTSSESSION_CHANGE, WTS_SESSION_UNLOCK as usize)
                .unwrap()
                .invalidates()
        );
        assert!(lifecycle_event(WM_POWERBROADCAST, 4).unwrap().invalidates());
        assert!(lifecycle_event(WM_CLOSE, 0).unwrap().invalidates());
        assert!(lifecycle_event(FINISHED, 0).is_none());
        assert!(lifecycle_event(WM_POWERBROADCAST, 0).is_none());
    }
}
