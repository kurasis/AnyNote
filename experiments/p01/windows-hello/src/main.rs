//! SPDX-License-Identifier: GPL-3.0-only
//! Explicit synthetic experiment only. No renderer/IPC/raw-key interface.
#[allow(dead_code)]
mod filesystem;
mod hello;
#[cfg(windows)]
mod probe;
mod storage;

fn main() {
    #[cfg(windows)]
    if let Err(message) = probe::main() {
        eprintln!("P01 Hello: {message}");
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    {
        println!("{{\"status\":\"BLOCKED\",\"reason\":\"Windows native provider required\",\"physical_acceptance\":false}}");
        std::process::exit(2);
    }
}
