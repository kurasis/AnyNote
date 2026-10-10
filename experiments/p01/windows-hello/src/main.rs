//! SPDX-License-Identifier: GPL-3.0-only
//! Explicit synthetic experiment only. No renderer/IPC/raw-key interface.
#[cfg(windows)]
mod device_kit;
#[allow(dead_code)]
mod filesystem;
mod hello;
#[cfg_attr(not(windows), allow(dead_code))]
mod local_checks;
#[cfg(windows)]
mod probe;
mod storage;
#[cfg_attr(not(windows), allow(dead_code))]
mod trial_lifecycle;
#[cfg_attr(not(windows), allow(dead_code))]
mod trial_route;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--license") {
        println!("{}", include_str!("../LICENSE"));
        return;
    }
    #[cfg(windows)]
    if let Err(message) = if std::env::args().len() == 1
        || matches!(
            std::env::args().nth(1).as_deref(),
            Some("--hosted-report" | "--hosted-local-report")
        ) {
        device_kit::main()
    } else {
        probe::main()
    } {
        eprintln!("P01 Hello: {message}");
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    {
        println!("{{\"status\":\"BLOCKED\",\"reason\":\"Windows native provider required\",\"physical_acceptance\":false}}");
        std::process::exit(2);
    }
}
