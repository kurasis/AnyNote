//! SPDX-License-Identifier: GPL-3.0-only
//! Double-click guided synthetic trial; one binary, fresh subprocess per operation.
use crate::filesystem as io;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::windows::process::CommandExt;
use std::{fs::File, io::Read, path::PathBuf, process::Command};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDOK, MB_ICONINFORMATION, MB_OK, MB_OKCANCEL,
};

fn dialog(text: &str, cancel: bool) -> bool {
    let text: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    let title: Vec<u16> = "AnyNote P01 device test"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_ICONINFORMATION | if cancel { MB_OKCANCEL } else { MB_OK },
        ) == IDOK
    }
}

fn observe(command: &str) -> Result<Value, &'static str> {
    let output = Command::new(std::env::current_exe().map_err(|_| "Executable unavailable")?)
        .arg(command)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|_| "Child process unavailable")?;
    // Child output uses the native content-free report vocabulary, never secrets.
    let bytes = if output.status.success() {
        &output.stdout
    } else {
        &output.stderr
    };
    let parsed = std::str::from_utf8(bytes).ok().and_then(|text| {
        text.lines()
            .find_map(|line| serde_json::from_str::<Value>(line).ok())
    });
    Ok(json!({"operation":command,"exit_code":output.status.code(),
        "report":parsed.unwrap_or_else(|| json!({"status":"FAIL","reason":"Missing native report"}))}))
}

fn executable_hash() -> Result<String, &'static str> {
    let mut file = File::open(std::env::current_exe().map_err(|_| "Executable unavailable")?)
        .map_err(|_| "Executable unreadable")?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "Executable unreadable")?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn observe_or_failure(command: &str) -> Value {
    observe(command).unwrap_or_else(|reason| {
        json!({"operation":command,"exit_code":null,
        "report":{"status":"FAIL","reason":reason}})
    })
}

fn save(record: &Value) -> Result<PathBuf, &'static str> {
    let base = PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA unavailable")?);
    if !base.is_absolute() {
        return Err("Invalid report root");
    }
    let directory = io::child(&base, "AnyNoteP01Reports").map_err(|_| "Invalid report root")?;
    io::reject_links(&directory).map_err(|_| "Unsafe report directory")?;
    std::fs::create_dir_all(&directory).map_err(|_| "Report directory unavailable")?;
    io::secure_directory(&directory).map_err(|_| "Report ACL unavailable")?;
    let _pins = io::pin_directory(&directory).map_err(|_| "Cannot pin report directory")?;
    let path = io::child(&directory, &format!("trial-{}.json", uuid::Uuid::new_v4()))
        .map_err(|_| "Invalid report name")?;
    io::atomic_json(
        &path,
        &serde_json::to_vec_pretty(record).map_err(|_| "Report serialization failed")?,
    )
    .map_err(|_| "Report write/readback failed")?;
    Ok(path)
}

pub fn main() -> Result<(), &'static str> {
    struct OwnedMutex(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for OwnedMutex {
        fn drop(&mut self) {
            unsafe {
                windows_sys::Win32::System::Threading::ReleaseMutex(self.0);
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
    let _single_trial = unsafe {
        use windows_sys::Win32::{
            Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0},
            System::Threading::{CreateMutexW, WaitForSingleObject},
        };
        let name: Vec<u16> = "Local\\AnyNote.P01.DeviceKit"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let handle = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
        if handle.is_null() {
            return Err("Native trial mutex unavailable");
        }
        let result = WaitForSingleObject(handle, 0);
        if result != WAIT_OBJECT_0 && result != WAIT_ABANDONED {
            windows_sys::Win32::Foundation::CloseHandle(handle);
            dialog("Another AnyNote device test is already running. Close that test before starting a new one.",false);
            return Err("Device trial already running");
        }
        OwnedMutex(handle)
    };
    let argument = std::env::args().nth(1);
    let hosted = matches!(
        argument.as_deref(),
        Some("--hosted-report" | "--hosted-local-report")
    );
    let capability = observe("capabilities")?;
    if capability["exit_code"] != 0 || capability["report"]["native_objects_created"] != false {
        return Err("Capability observation failed");
    }
    let eligible = capability["report"]["report"]["eligible"] == true;
    let mut record = json!({"version":1,"purpose":"AnyNote P01 synthetic device kit",
        "environment_kind":if hosted { "hosted" } else { "owner_device" },
        "source_commit":option_env!("ANYNOTE_PROBE_SOURCE"),"executable_sha256":executable_hash()?,
        "capability":capability,"status":if eligible { "NOT RUN" } else { "BLOCKED" },
        "physical_acceptance":false,"operations":[],
        "remaining":["Real lock/suspend with a pending prompt", "TPM/provider changes", "Other-account denial", "Windows file/memory/WebView2 integration"],
        "license":"GPL-3.0-only; corresponding source and license accompany the GitHub test release",
        "timestamp_unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "Clock unavailable")?.as_millis()});
    if !hosted && dialog(
        "Start the synthetic device test?\n\n1. Crypto, public 64 MiB Argon2id and an exact 1 GB local disk round-trip run automatically (about 3.1 GB free space required).\n2. Confirm Windows Hello when asked, if the native route is eligible.\n3. Follow the cancellation/lock instructions.\n4. Test objects are removed and one JSON report is saved.\n\nNo administrator access, passwords, real vaults or extra programs are needed.", true) {
        record["local_checks"]=json!(local_suite());
        if eligible {
        let mut operations = Vec::new();
        let enrollment = observe_or_failure("enroll");
        let enrolled = enrollment["exit_code"] == 0 && enrollment["report"]["status"] == "PASS_SYNTHETIC_ENROLLMENT";
        let needs_cleanup = enrollment["report"]["code"] == "HELLO_CLEANUP_REQUIRED";
        operations.push(enrollment);
        let mut authenticated = false;
        if enrolled {
            let unlock = observe_or_failure("unlock");
            authenticated = unlock["exit_code"] == 0 && unlock["report"]["actual_vault_authenticated"] == true;
            operations.push(unlock);
            if authenticated && dialog("The fresh-process unlock passed.\n\nOn the NEXT Windows Hello prompt, press Cancel. This records the native rejection without claiming that every failure means cancellation.", true) {
                let cancel = observe_or_failure("unlock");
                record["guided_cancel"] = json!({"instruction":"Owner requested to cancel the next prompt",
                    "status":if cancel["report"]["code"] == "HELLO_CANCELLED" { "PASS_NATIVE_CANCELLED" } else { "FAIL_OR_UNAVAILABLE: inspect original native code" },
                    "physical_cancel_classification":"Only explicit HELLO_CANCELLED is cancellation"});
                operations.push(cancel);
            }
            if authenticated && dialog("Next: lock while authorization is pending.\n\nAfter the NEXT Hello prompt opens, press Win+L. Sign back in to Windows. The old request must be rejected as STALE.\n\nPress OK to start, or Cancel to leave this physical test NOT RUN.", true) {
                let locked=observe_or_failure("unlock");
                record["guided_lock"]=json!({"status":if locked["report"]["code"] == "STALE" { "PASS_STALE_REJECTED" } else { "FAIL_OR_UNAVAILABLE: inspect original native code" }});
                operations.push(locked);
            }
        }
        // Retry only exact owned-object cleanup. Retained journals are never deleted blindly.
        let cleanup = observe_or_failure("cleanup");
        let clean = cleanup["exit_code"] == 0 && cleanup["report"]["exact_owned_objects_deleted"] == true;
        operations.push(cleanup);
        record["operations"] = json!(operations);
        record["status"] = json!(if !clean { "CLEANUP_REQUIRED: run this EXE again" }
            else if needs_cleanup { "PREVIOUS_TEST_CLEANED: run this EXE again" }
            else if authenticated { "PASS_SYNTHETIC_FRESH_PROCESS_UNLOCK" } else { "FAIL_OR_UNAVAILABLE" });
        }
    }
    if hosted {
        // CI may exercise the native reporting path but can never enroll or unlock.
        if argument.as_deref() == Some("--hosted-local-report") {
            record["local_checks"] = local_suite();
        }
        println!("{record}");
        return Ok(());
    }
    let path = save(&record)?;
    println!("Report: {}", path.display());
    dialog(&format!("Result: {}\n\nSend this one report back:\n{}\n\nYou can press Ctrl+C in this dialog to copy its text.\n\nBLOCKED means the actual native API/Hello provider is unavailable; there is no software fallback. Physical acceptance remains open.", record["status"].as_str().unwrap_or("FAIL"), path.display()), false);
    Ok(())
}

fn local_suite() -> Value {
    let run = || -> Result<Value, Box<dyn std::error::Error>> {
        let base =
            PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA unavailable")?);
        if !base.is_absolute() {
            return Err("Invalid test directory".into());
        }
        let mut cleaned_orphans = 0;
        for entry in std::fs::read_dir(&base)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(id) = name.strip_prefix("AnyNoteP01Trial-") else {
                continue;
            };
            if uuid::Uuid::parse_str(id).is_err() || !entry.file_type()?.is_dir() {
                continue;
            }
            let path = entry.path();
            if io::reject_links(&path).is_err() {
                continue;
            }
            let marker = io::child(&path, "purpose.marker").map_err(|_| "Invalid marker")?;
            if io::read(&marker, 128).ok().as_deref()
                != Some(b"AnyNote P01 disposable native file trial".as_slice())
            {
                continue;
            }
            std::fs::remove_dir_all(&path)?;
            cleaned_orphans += 1;
        }
        let root = io::child(&base, &format!("AnyNoteP01Trial-{}", uuid::Uuid::new_v4()))
            .map_err(|_| "Invalid owner")?;
        let path: Vec<u16> = base
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut available = 0u64;
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                path.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
            || available < 3_100_000_000
        {
            return Ok(
                json!({"status":"BLOCKED","reason":"Need about 3.1 GB free for exact 1 GB trial; no reduced-size substitution"}),
            );
        }
        let crypto = crate::local_checks::primitives()?;
        std::fs::create_dir(&root)?;
        let initialized = (|| -> Result<(), Box<dyn std::error::Error>> {
            io::secure_directory(&root).map_err(|_| "Synthetic root ACL unavailable")?;
            use std::io::Write;
            let mut marker = std::fs::File::create_new(root.join("purpose.marker"))?;
            marker.write_all(b"AnyNote P01 disposable native file trial")?;
            marker.sync_all()?;
            Ok(())
        })();
        if initialized.is_err() {
            std::fs::remove_dir_all(&root)?;
            initialized?;
        }
        eprintln!("Running bounded synthetic 1 GB disk trial; please wait...");
        let result = crate::local_checks::file_roundtrip(&root.join("file"), 1_000_000_000);
        // This random directory was created exclusively by this invocation.
        let cleanup = if root.exists() {
            std::fs::remove_dir_all(&root)
        } else {
            Ok(())
        };
        cleanup?;
        Ok(
            json!({"status":"PASS","crypto":crypto,"file":result?,"synthetic_disk_cleanup":"PASS","cleaned_orphans":cleaned_orphans}),
        )
    };
    run().unwrap_or_else(|_|json!({"status":"FAIL","reason":"Native local test failed; no success or physical acceptance inferred"}))
}
