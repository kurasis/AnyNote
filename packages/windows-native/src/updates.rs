//! Signed updater policy: operator-installed trust only; no key or endpoint from API/UI.
use crate::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePolicy {
    pub endpoint: String,
    pub public_key: String,
    pub channel: String,
}
impl UpdatePolicy {
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
