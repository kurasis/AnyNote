//! Signed updater policy: operator-installed trust only; no key or endpoint from API/UI.
use crate::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub protocol: String,
    pub application_id: String,
    pub version: String,
    pub platform: String,
    pub channel: String,
    pub url: String,
    pub artifact_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePolicy {
    pub endpoint: String,
    pub public_key: String,
    pub channel: String,
}
impl UpdatePolicy {
    /// Standard minisign over the canonical public claims; separate from Tauri's payload signature.
    pub fn signed_claims(
        &self,
        current: &str,
        version: &str,
        url: &str,
        value: &Value,
        signature: &str,
    ) -> Result<Claims> {
        self.validate()?;
        check(signature.len() <= 16384, "UPDATE_INTEGRITY_FAILURE")?;
        let public = STANDARD
            .decode(&self.public_key)
            .map_err(|_| Error("INVALID_UPDATE_POLICY"))?;
        let public = std::str::from_utf8(&public).map_err(|_| Error("INVALID_UPDATE_POLICY"))?;
        let signature = STANDARD
            .decode(signature)
            .map_err(|_| Error("UPDATE_INTEGRITY_FAILURE"))?;
        let signature =
            std::str::from_utf8(&signature).map_err(|_| Error("UPDATE_INTEGRITY_FAILURE"))?;
        let key = minisign_verify::PublicKey::decode(public)
            .map_err(|_| Error("INVALID_UPDATE_POLICY"))?;
        let signature = minisign_verify::Signature::decode(signature)
            .map_err(|_| Error("UPDATE_INTEGRITY_FAILURE"))?;
        let bytes = anynote_crypto_core::codec::canonical(value)?;
        check(bytes.len() <= 16384, "UPDATE_INTEGRITY_FAILURE")?;
        key.verify(&bytes, &signature, true)
            .map_err(|_| Error("UPDATE_INTEGRITY_FAILURE"))?;
        let claims: Claims =
            serde_json::from_value(value.clone()).map_err(|_| Error("UPDATE_SCOPE_MISMATCH"))?;
        check(
            claims.protocol == "anynote-update-v1"
                && claims.application_id == "org.anynote.desktop"
                && claims.version == version
                && claims.url == url
                && anynote_crypto_core::crypto::un64(&claims.artifact_sha256)
                    .is_ok_and(|b| b.len() == 32),
            "UPDATE_SCOPE_MISMATCH",
        )?;
        let parsed = url::Url::parse(&claims.url).map_err(|_| Error("UPDATE_SCOPE_MISMATCH"))?;
        check(
            parsed.scheme() == "https"
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.fragment().is_none(),
            "UPDATE_SCOPE_MISMATCH",
        )?;
        self.version(current, &claims.version, &claims.platform, &claims.channel)?;
        Ok(claims)
    }
    pub fn validate(&self) -> Result<()> {
        let u = url::Url::parse(&self.endpoint).map_err(|_| Error("INVALID_UPDATE_POLICY"))?;
        let key = STANDARD
            .decode(&self.public_key)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or(Error("INVALID_UPDATE_POLICY"))?;
        let lines = key.lines().collect::<Vec<_>>();
        check(
            lines.len() == 2
                && lines[0].starts_with("untrusted comment:")
                && STANDARD
                    .decode(lines[1])
                    .is_ok_and(|b| b.len() == 42 && b[..2] == *b"Ed"),
            "INVALID_UPDATE_POLICY",
        )?;
        check(
            u.scheme() == "https"
                && u.username().is_empty()
                && u.password().is_none()
                && u.fragment().is_none()
                && self.public_key.len() <= 4096
                && ["stable", "candidate"].contains(&self.channel.as_str()),
            "INVALID_UPDATE_POLICY",
        )
    }
    pub fn version(&self, current: &str, next: &str, platform: &str, channel: &str) -> Result<()> {
        self.validate()?;
        check(
            platform == "windows-x86_64" && channel == self.channel,
            "UPDATE_SCOPE_MISMATCH",
        )?;
        fn parts(v: &str) -> Result<Vec<u64>> {
            v.split('.')
                .map(|n| n.parse().map_err(|_| Error("INVALID_UPDATE_VERSION")))
                .collect()
        }
        let a = parts(current)?;
        let b = parts(next)?;
        check(
            a.len() == 3 && b.len() == 3 && b > a,
            "UPDATE_DOWNGRADE_DENIED",
        )
    }
}
