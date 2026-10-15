//! Windows CI executable-name adapter; all operations use the actual maintained Python runtime.
fn main() {
    let Some(python) = std::env::var_os("ANYNOTE_TEST_PYTHON") else {
        std::process::exit(2)
    };
    let result = std::process::Command::new(python)
        .args(std::env::args_os().skip(1))
        .status();
    std::process::exit(result.ok().and_then(|s| s.code()).unwrap_or(1));
}
