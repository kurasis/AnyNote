//! Independent standard-age interoperability harness. Never used as renderer IPC.
//! Output is provisional plaintext sent only to the test pipe and discarded.
use std::io::{BufRead, Read};
use zeroize::Zeroize;
fn main() {
    if run().is_err() {
        eprintln!("AGE_INTEROPERABILITY_FAILED");
        std::process::exit(1);
    }
}
fn run() -> std::io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let mut identity = String::new();
    let result = (|| {
        std::io::stdin().lock().take(513).read_line(&mut identity)?;
        if identity.len() > 512 || !identity.ends_with('\n') {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        anynote_content_native::decrypt_stream(
            std::fs::File::open(&args[0])?,
            std::io::stdout().lock(),
            identity.trim_end(),
        )
    })();
    identity.zeroize();
    result.map(|_| ())
}
