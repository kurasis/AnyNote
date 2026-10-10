//! Synthetic Argon2id v1.3 profiles; validation precedes costly native work.
use libsodium_rs::{crypto_pwhash::argon2id, version};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    profile_version: u32,
    algorithm: String,
    phrase: String,
    salt_hex: String,
    opslimit: u64,
    memlimit: usize,
}
impl Request {
    pub fn derive(&self) -> Result<Value, &'static str> {
        if self.profile_version != 1
            || self.algorithm != "argon2id13"
            || !(3..=10).contains(&self.opslimit)
            || !(67_108_864..=268_435_456).contains(&self.memlimit)
            || self.phrase.len() < 16
            || self.phrase.len() > 1024
            || self.salt_hex.len() != 32
            || !self
                .salt_hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("invalid bounded P01 KDF profile");
        }
        let salt = hex::decode(&self.salt_hex).map_err(|_| "invalid salt")?;
        let started = Instant::now();
        let mut key = argon2id::pwhash(
            32,
            self.phrase.as_bytes(),
            &salt,
            self.opslimit,
            self.memlimit,
        )
        .map_err(|_| "KDF failed; cost was not reduced")?;
        let output = json!({"derived_hex":hex::encode(&key), "elapsed_ms":started.elapsed().as_millis(),
            "memlimit":self.memlimit,"opslimit":self.opslimit,"algorithm":"argon2id13",
            "sodium_version":version::version_string(),"warning":"PUBLIC SYNTHETIC KDF VECTOR; NEVER USE THIS KEY"});
        key.fill(0);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsafe_profiles_are_rejected_before_hashing() {
        for (ops, mem, version, algorithm) in [
            (2, 67_108_864, 1, "argon2id13"),
            (11, 67_108_864, 1, "argon2id13"),
            (3, 67_108_863, 1, "argon2id13"),
            (3, 268_435_457, 1, "argon2id13"),
            (3, usize::MAX, 1, "argon2id13"),
            (3, 67_108_864, 2, "argon2id13"),
            (3, 67_108_864, 1, "argon2i13"),
        ] {
            assert!(
                Request {
                    profile_version: version,
                    algorithm: algorithm.into(),
                    phrase: "public synthetic phrase".into(),
                    salt_hex: "00".repeat(16),
                    opslimit: ops,
                    memlimit: mem
                }
                .derive()
                .is_err()
            );
        }
    }
}
