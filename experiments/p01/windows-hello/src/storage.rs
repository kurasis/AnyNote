//! Narrow fixed error vocabulary for the isolated reference adapters.
#[derive(Debug)]
pub struct Error {
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub code: &'static str,
}
impl Error {
    pub fn new(code: &'static str) -> Self {
        Self { code }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
pub const MAX_BYTES: usize = 16_384;
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::new(if matches!(error.raw_os_error(), Some(28) | Some(112)) {
            "QUOTA"
        } else if error.kind() == std::io::ErrorKind::NotFound {
            "NOT_FOUND"
        } else {
            "WRITE_FAILED"
        })
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::new("CORRUPT")
    }
}
pub fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
