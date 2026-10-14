//! Bounded anonymous-pipe transport to the bundled, hash-verified portable helper.
use crate::*;
use std::{
    io::{Read, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;
pub struct Assets<'a> {
    pub node: &'a Path,
    pub script: &'a Path,
    pub node_sha: &'a str,
    pub script_sha: &'a str,
}
fn file_hash(p: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(p).map_err(|_| Error("RUNTIME_UNAVAILABLE"))?;
    let mut h = Sha256::new();
    let mut b = [0u8; 65536];
    loop {
        let n = f.read(&mut b).map_err(|_| Error("RUNTIME_UNAVAILABLE"))?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(anynote_crypto_core::crypto::b64(&h.finalize()))
}
pub struct Bridge {
    child: Arc<Mutex<Child>>,
    pub input: ChildStdin,
    output: ChildStdout,
    stop: Arc<AtomicBool>,
}
impl Bridge {
    pub fn spawn(assets: &Assets, interrupted: impl Fn() -> bool + Send + 'static) -> Result<Self> {
        check(
            file_hash(assets.node)? == assets.node_sha
                && file_hash(assets.script)? == assets.script_sha,
            "RUNTIME_INTEGRITY_FAILURE",
        )?;
        let mut cmd = Command::new(assets.node);
        cmd.arg("--no-addons")
            .arg("--disable-proto=throw")
            .arg("--permission")
            .arg(format!(
                "--allow-fs-read={}",
                assets.script.to_str().ok_or(Error("RUNTIME_UNAVAILABLE"))?
            ))
            .arg(assets.script)
            .env_clear()
            .env("NODE_NO_WARNINGS", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(root) = std::env::var_os("SystemRoot") {
            cmd.env("SystemRoot", root);
        }
        let mut child = cmd.spawn().map_err(|_| Error("RUNTIME_UNAVAILABLE"))?;
        let input = child.stdin.take().ok_or(Error("RUNTIME_UNAVAILABLE"))?;
        let output = child.stdout.take().ok_or(Error("RUNTIME_UNAVAILABLE"))?;
        let child = Arc::new(Mutex::new(child));
        let weak = Arc::downgrade(&child);
        let stop = Arc::new(AtomicBool::new(false));
        let ended = stop.clone();
        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while !ended.load(Ordering::SeqCst) {
                if interrupted() || start.elapsed() > Duration::from_secs(86400) {
                    if let Some(c) = weak.upgrade()
                        && let Ok(mut c) = c.lock()
                    {
                        let _ = c.kill();
                    }
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Ok(Self {
            child,
            input,
            output,
            stop,
        })
    }
    pub fn send(&mut self, kind: u32, bytes: &[u8]) -> Result<()> {
        check(bytes.len() <= 16777216, "RESOURCE_LIMIT")?;
        self.input
            .write_all(&kind.to_be_bytes())
            .and_then(|_| self.input.write_all(&(bytes.len() as u32).to_be_bytes()))
            .and_then(|_| self.input.write_all(bytes))
            .and_then(|_| self.input.flush())
            .map_err(|_| Error("BRIDGE_CLOSED"))
    }
    pub fn json(&mut self, kind: u32, v: &Value) -> Result<()> {
        let b = Zeroizing::new(anynote_crypto_core::codec::canonical(v)?);
        self.send(kind, &b)
    }
    pub fn receive(&mut self) -> Result<(u32, Zeroizing<Vec<u8>>)> {
        let mut h = [0u8; 8];
        self.output
            .read_exact(&mut h)
            .map_err(|_| Error("BRIDGE_CLOSED"))?;
        let kind = u32::from_be_bytes(h[..4].try_into().unwrap());
        let n = u32::from_be_bytes(h[4..].try_into().unwrap()) as usize;
        check(n <= 16777216, "RESOURCE_LIMIT")?;
        let mut b = Zeroizing::new(vec![0; n]);
        self.output
            .read_exact(&mut b)
            .map_err(|_| Error("BRIDGE_CLOSED"))?;
        if kind == 10 {
            return Err(Error("OFFLINE_INTEGRITY_FAILURE"));
        }
        Ok((kind, b))
    }
    pub fn ack(&mut self) -> Result<()> {
        self.send(9, &[])
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
