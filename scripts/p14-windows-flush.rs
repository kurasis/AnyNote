//! CI-only durability helper. It cannot write bytes, dismount, format or select an arbitrary path.
#[cfg(windows)]
fn main() {
    use std::{
        fs::OpenOptions,
        os::windows::fs::OpenOptionsExt,
        path::{Component, Prefix},
    };
    let run = || -> std::io::Result<()> {
        if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
            || std::env::args_os().len() != 1
        {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        let executable = std::env::current_exe()?.canonicalize()?;
        let root = executable
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        let marker = std::fs::read_to_string(root.join(".local/p14-windows-services/owner.json"))?;
        if marker.len() > 65536 || !marker.contains("AnyNote P14 disposable Windows backend") {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        let letter = match executable.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
                _ => return Err(std::io::ErrorKind::Unsupported.into()),
            },
            _ => return Err(std::io::ErrorKind::Unsupported.into()),
        };
        let volume = format!("\\\\.\\{}:", letter as char);
        let handle = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .open(volume)?;
        // std::fs::File::sync_all calls the real kernel32 FlushFileBuffers API.
        // Volume flushing makes the already-fsynced file and its directory metadata durable.
        handle.sync_all()
    };
    if let Err(error) = run() {
        eprintln!(
            "{{\"status\":\"FAIL\",\"win32_error\":{}}}",
            error.raw_os_error().unwrap_or(0)
        );
        std::process::exit(1);
    }
    println!("{{\"status\":\"PASS\",\"primitive\":\"Windows FlushFileBuffers volume\"}}");
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows synthetic CI only");
    std::process::exit(1);
}
