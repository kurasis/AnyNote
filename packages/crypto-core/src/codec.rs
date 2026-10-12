//! Strict raw JSON, maintained RFC8785, offline schemas and frozen invariants.
use crate::crypto::{hash, un64};
use crate::{Error, Result, require};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

struct Seed(usize);
impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed {
    type Value = Value;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("strict JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("nonfinite"))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        if self.0 >= 32 {
            return Err(de::Error::custom("depth"));
        }
        let mut out = Vec::new();
        while let Some(v) = a.next_element_seed(Seed(self.0 + 1))? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        if self.0 >= 32 {
            return Err(de::Error::custom("depth"));
        }
        let mut out = Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if out.contains_key(&k) {
                return Err(de::Error::custom("duplicate"));
            }
            out.insert(k, a.next_value_seed(Seed(self.0 + 1))?);
        }
        Ok(Value::Object(out))
    }
}
pub fn strict(bytes: &[u8], limit: usize) -> Result<Value> {
    require(bytes.len() <= limit, "RESOURCE_LIMIT")?;
    let s = std::str::from_utf8(bytes).map_err(|_| Error("INVALID_UTF8"))?;
    require(!s.starts_with('\u{feff}'), "INVALID_JSON")?;
    let mut d = serde_json::Deserializer::from_str(s);
    let v = Seed(0)
        .deserialize(&mut d)
        .map_err(|_| Error("INVALID_JSON"))?;
    d.end().map_err(|_| Error("INVALID_JSON"))?;
    Ok(v)
}
pub fn canonical(v: &Value) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(v).map_err(|_| Error("INVALID_JSON"))
}
pub fn jcs(bytes: &[u8]) -> Result<Vec<u8>> {
    canonical(&strict(bytes, 16_777_216)?)
}
pub fn domain(profile: &str, family: &str, purpose: &str, bytes: &[u8]) -> Vec<u8> {
    let mut v = format!("AnyNote/{profile}/{family}/{purpose}\0").into_bytes();
    v.extend_from_slice(bytes);
    v
}
pub fn limit(profile: &str, kind: &str) -> usize {
    match profile {
        "p02-identity-c1" => 16384,
        "p02-file-c1" => 1048576,
        "p08-local-v1" => 524288,
        "p02-state-c1" => {
            if kind == "qr" {
                8192
            } else {
                65536
            }
        }
        "p02-group-c2" => match kind {
            "grant-page" => 1048576,
            "epoch-intent" | "epoch-intent-body" | "epoch-commit" | "epoch-commit-body" => 262144,
            _ => 65536,
        },
        _ => match kind {
            "local-envelope" => 6291456,
            "bundle" | "payload" | "local-plaintext" | "outbox" | "draft" | "cache" | "search"
            | "transfer" | "vault-secrets" => 4194304,
            "snapshot-page" | "export-page" | "sync-page" | "export-public-event" => 1048576,
            "export-account-evidence" | "export-group-evidence" | "export-evidence" => 16777216,
            _ => 65536,
        },
    }
}
pub struct Codec {
    validators: BTreeMap<(String, String), jsonschema::Validator>,
}
impl Codec {
    pub fn new() -> Result<Self> {
        libsodium_rs::ensure_init().map_err(|_| Error("CRYPTO_UNAVAILABLE"))?;
        let schemas = [
            (
                "p02-file-c1",
                include_str!("../../contracts/p02-file-c1.schema.json"),
            ),
            (
                "p02-identity-c1",
                include_str!("../../contracts/p02-identity-c1.schema.json"),
            ),
            (
                "p02-state-c1",
                include_str!("../../contracts/p02-state-c1.schema.json"),
            ),
            (
                "p02-group-c2",
                include_str!("../../contracts/p02-group-c2.schema.json"),
            ),
            ("p02-v1", include_str!("../../contracts/p02-v1.schema.json")),
            (
                "p08-local-v1",
                include_str!("../../contracts/p08-devices.schema.json"),
            ),
        ];
        let values: Vec<_> = schemas
            .iter()
            .map(|(p, s)| {
                (
                    *p,
                    serde_json::from_str::<Value>(s).expect("compiled schema"),
                )
            })
            .collect();
        let auth_schema: Value =
            serde_json::from_str(include_str!("../../contracts/p06-auth.schema.json"))
                .map_err(|_| Error("SCHEMA_CONFIGURATION"))?;
        let mut registry = jsonschema::Registry::new()
            .add("urn:anynote:p06:auth:v1", auth_schema)
            .map_err(|_| Error("SCHEMA_CONFIGURATION"))?;
        for (_, s) in &values {
            registry = registry
                .add(s["$id"].as_str().unwrap(), s.clone())
                .map_err(|_| Error("SCHEMA_CONFIGURATION"))?;
        }
        let registry = registry
            .prepare()
            .map_err(|_| Error("SCHEMA_CONFIGURATION"))?;
        let mut validators = BTreeMap::new();
        for (profile, s) in &values {
            for kind in s["$defs"].as_object().unwrap().keys() {
                let mut options = jsonschema::options()
                    .offline()
                    .with_registry(&registry)
                    .should_validate_formats(true);
                for n in [12, 16, 24, 32, 48, 64] {
                    options = options.with_format(format!("base64url-{n}"), move |s: &str| {
                        un64(s).is_ok_and(|b| b.len() == n)
                    });
                }
                options = options.with_format("base64url-variable", |s: &str| un64(s).is_ok());
                options = options.with_format("base64url-sealed", |s: &str| {
                    (64..=5462).contains(&s.len()) && un64(s).is_ok_and(|b| b.len() <= 4096)
                });
                for n in [4096, 16384] {
                    options = options.with_format(format!("bounded-binary-{n}"), move |s: &str| {
                        s.len() >= if n == 4096 { 64 } else { 24 }
                            && un64(s).is_ok_and(|b| b.len() <= n)
                    });
                }
                for n in [
                    119_u64,
                    120,
                    199,
                    200,
                    65536,
                    100000,
                    8388608,
                    8388624,
                    1000000000,
                    9223372036854775807,
                ] {
                    options =
                        options.with_format(format!("decimal-{n}"), move |s: &str| counter(s, n));
                }
                options =
                    options.with_format("decimal-u63", |s: &str| counter(s, 9223372036854775807));
                let validator = options
                    .build(&json!({"$ref":format!("{}#/$defs/{kind}",s["$id"].as_str().unwrap())}))
                    .map_err(|_| Error("SCHEMA_CONFIGURATION"))?;
                validators.insert((profile.to_string(), kind.to_string()), validator);
            }
        }
        Ok(Self { validators })
    }
    pub fn decode(&self, p: &str, k: &str, b: &[u8]) -> Result<Value> {
        let validator = self
            .validators
            .get(&(p.into(), k.into()))
            .ok_or(Error("UNSUPPORTED_SCHEMA"))?;
        let value = strict(b, limit(p, k))?;
        require(validator.is_valid(&value), "SCHEMA_MISMATCH")?;
        self.semantics(p, k, &value)?;
        Ok(value)
    }
    pub fn encode(&self, p: &str, k: &str, b: &[u8]) -> Result<Vec<u8>> {
        canonical(&self.decode(p, k, b)?)
    }
    pub fn validate(&self, p: &str, k: &str, v: &Value) -> Result<()> {
        self.decode(p, k, &canonical(v)?).map(|_| ())
    }
    pub fn signing(&self, p: &str, k: &str, v: &Value) -> Result<Vec<u8>> {
        self.validate(p, k, v)?;
        let purpose = match (p, k) {
            ("p02-identity-c1", "identity-body") => "account-root-identity",
            ("p02-identity-c1", "certificate-body") => "provisional-device-certificate",
            ("p02-identity-c1", "grant-body") => "group-key-distribution",
            ("p02-file-c1", "header") => "file-manifest",
            ("p02-file-c1", "checkpoint") => "history-checkpoint",
            ("p02-v1", "header" | "export-footer-body") => text(&v["purpose"])?,
            ("p02-state-c1" | "p02-group-c2", k) if k.ends_with("-body") => text(&v["purpose"])?,
            _ => return Err(Error("UNSUPPORTED_PURPOSE")),
        };
        Ok(domain(p, "sign", purpose, &canonical(v)?))
    }
    fn semantics(&self, p: &str, k: &str, v: &Value) -> Result<()> {
        if p == "p02-file-c1" {
            let c = if k == "context" {
                v
            } else if k == "envelope" {
                &v["header"]["context"]
            } else {
                &v["context"]
            };
            if !c.is_null() {
                ordered(&c["parents"], |x| text(&x["revision_id"]).unwrap().into())?;
                for x in c["parents"].as_array().unwrap() {
                    require(x["revision_id"] != c["file_version_id"], "SELF_PARENT")?;
                }
            }
            let f = if k == "framing" {
                v
            } else if k == "envelope" {
                &v["header"]["framing"]
            } else {
                &v["framing"]
            };
            if !f.is_null() {
                framing(f)?;
            }
            if k == "header" || k == "envelope" {
                let h = if k == "header" { v } else { &v["header"] };
                require(
                    num(&h["manifest_ciphertext_bytes"])? >= 16,
                    "INVALID_MANIFEST_LENGTH",
                )?;
            }
            if k == "chunk-aad" {
                let i = num(&v["chunk_index"])?;
                let n = num(&v["chunk_count"])?;
                let l = num(&v["plaintext_chunk_bytes"])?;
                require(
                    i < n && l > 0 && (i == n - 1 || l == 8388608),
                    "INVALID_CHUNK_LENGTH",
                )?;
            }
            if k == "inventory-record" {
                ordered(&v["parents"], |x| text(&x["revision_id"]).unwrap().into())?;
                for x in v["parents"].as_array().unwrap() {
                    require(x["revision_id"] != v["revision_id"], "SELF_PARENT")?;
                }
            }
            if k == "checkpoint-page" {
                ordered(&v["records"], |x| text(&x["revision_id"]).unwrap().into())?;
                for r in v["records"].as_array().unwrap() {
                    self.validate(p, "inventory-record", r)?;
                }
            }
            if k == "checkpoint" {
                ordered(&v["closed_rosters"], |x| {
                    text(&x["account_id"]).unwrap().into()
                })?;
                let r = num(&v["record_count"])?;
                let n = num(&v["page_count"])?;
                require(
                    (r == 0 && n == 0) || (n > 0 && n <= r && r <= n * 500),
                    "INVALID_PAGE_COUNT",
                )?;
            }
        }
        if p == "p02-identity-c1" && (k == "certificate" || k == "certificate-body") {
            let b = if k == "certificate" { &v["body"] } else { v };
            ordered(&b["capabilities"], |x| x.as_str().unwrap().into())?;
            require(
                b["device_signing_key"] != b["device_encryption_key"],
                "KEY_PURPOSE_COLLISION",
            )?;
            if b["predecessor_roster"].is_null() {
                require(
                    b["issuer"]["kind"] == "root" && b["recovery_generation"] == "0",
                    "INVALID_BOOTSTRAP",
                )?;
            }
            if b["issuer"]["kind"] == "root" {
                require(
                    b["issuer"]["root_fingerprint"] == b["root_fingerprint"],
                    "ISSUER_CONTEXT_MISMATCH",
                )?;
            } else {
                require(
                    b["issuer"]["device_id"] != b["device_id"],
                    "SELF_DELEGATION",
                )?;
            }
        }
        if p == "p02-state-c1" {
            if k == "device" {
                ordered(&v["capabilities"], |x| x.as_str().unwrap().into())?;
                require(
                    v["signing_key"] != v["encryption_key"],
                    "KEY_PURPOSE_COLLISION",
                )?;
            }
            if k == "revoke-payload" {
                for key in ["targets", "affected_devices"] {
                    ordered(&v[key], |x| x.as_str().unwrap().into())?;
                }
            }
        }
        if p == "p02-group-c2" {
            match k {
                "members" => {
                    ordered(v, |x| x["account_id"].as_str().unwrap().into())?;
                    require(
                        v.as_array()
                            .unwrap()
                            .iter()
                            .filter(|x| x["role"] == "owner")
                            .count()
                            == 1,
                        "OWNER_COUNT",
                    )?;
                }
                "rosters" => ordered(v, |x| x["account_id"].as_str().unwrap().into())?,
                "epochs" => {
                    for (i, e) in v.as_array().unwrap().iter().enumerate() {
                        require(
                            num(&e["key_epoch"])? == i as u64,
                            "EPOCH_INVENTORY_MISMATCH",
                        )?;
                    }
                }
                "grant-page" => ordered(&v["records"], |x| {
                    let c = &x["body"]["context"];
                    let r = &c["recipient"];
                    format!(
                        "{:0>19}/{}/{}/{}",
                        c["key_epoch"].as_str().unwrap(),
                        r["account_id"].as_str().unwrap(),
                        r["kind"].as_str().unwrap(),
                        r["device_id"].as_str().unwrap_or("")
                    )
                })?,
                _ => (),
            }
        }
        if p == "p02-v1" {
            self.complete(k, v)?;
        }
        Ok(())
    }
    fn complete(&self, k: &str, v: &Value) -> Result<()> {
        let c = match k {
            "context" => v,
            "header" | "wrap" | "payload" => &v["context"],
            "envelope" => &v["header"]["context"],
            "bundle" => &v["envelope"]["header"]["context"],
            _ => &Value::Null,
        };
        if !c.is_null() {
            ordered(&c["parents"], |x| x["revision_id"].as_str().unwrap().into())?;
            ordered(&c["attachments"], |x| {
                format!(
                    "{}/{}",
                    x["file_id"].as_str().unwrap(),
                    x["file_version_id"].as_str().unwrap()
                )
            })?;
            for r in c["parents"].as_array().unwrap() {
                require(r["revision_id"] != c["revision_id"], "SELF_PARENT")?;
            }
            require(
                (c["object_kind"] == "entry") != c["thread_id"].is_null(),
                "THREAD_CONTEXT_MISMATCH",
            )?;
            require(
                c["object_kind"] == "entry" || c["attachments"].as_array().unwrap().is_empty(),
                "ATTACHMENT_CONTEXT_MISMATCH",
            )?;
            require(
                (c["action"] == "create") == c["parents"].as_array().unwrap().is_empty(),
                "PARENT_CONTEXT_MISMATCH",
            )?;
        }
        match k {
            "payload" => {
                require(canonical(v)?.len() <= 2097152, "RESOURCE_LIMIT")?;
                ordered(&v["tags"], |x| x.as_str().unwrap().into())?;
                ordered(&v["checklist"], |x| x["item_id"].as_str().unwrap().into())?;
                ordered(&v["preferences"], |x| {
                    format!(
                        "{}/{}",
                        x["key"].as_str().unwrap(),
                        x["target_id"].as_str().unwrap()
                    )
                })?;
                if c["action"] == "soft-delete" {
                    require(
                        v["title"] == ""
                            && v["markdown"] == ""
                            && ["tags", "checklist", "preferences"]
                                .iter()
                                .all(|k| v[k].as_array().unwrap().is_empty())
                            && v["summary_entry_id"].is_null(),
                        "TOMBSTONE_PAYLOAD_MISMATCH",
                    )?;
                }
                if c["object_kind"] != "entry" {
                    require(
                        v["markdown"] == "" && v["checklist"].as_array().unwrap().is_empty(),
                        "METADATA_PAYLOAD_MISMATCH",
                    )?;
                } else {
                    require(
                        v["summary_entry_id"].is_null()
                            && v["preferences"].as_array().unwrap().is_empty()
                            && v["metadata_kind"] == "content",
                        "ENTRY_PAYLOAD_MISMATCH",
                    )?;
                }
                if v["metadata_kind"] == "account-preferences" {
                    require(
                        c["object_kind"] == "group-metadata",
                        "PRIVATE_NAMESPACE_REQUIRED",
                    )?;
                }
            }
            "bundle" => require(
                v["envelope"]["header"]["context"] == v["wrap"]["context"],
                "CONTEXT_MISMATCH",
            )?,
            "draft" => {
                self.validate("p02-v1", "payload", &v["payload"])?;
                require(
                    v["context"] == v["payload"]["context"],
                    "LOCAL_CONTEXT_MISMATCH",
                )?;
            }
            "outbox" => {
                self.validate("p02-v1", "bundle", &v["bundle"])?;
                let c = &v["bundle"]["envelope"]["header"]["context"];
                require(
                    v["attempt_id"] == c["operation_id"]
                        && v["revision_id"] == c["revision_id"]
                        && v["attempt_digest"]
                            == hash(&domain(
                                "p02-v1",
                                "hash",
                                "bundle",
                                &canonical(&v["bundle"])?,
                            )),
                    "ATTEMPT_CONTEXT_MISMATCH",
                )?;
                require(
                    (v["state"] == "COMMITTED") != v["receipt"].is_null(),
                    "RECEIPT_STATE_MISMATCH",
                )?;
                if !v["receipt"].is_null() {
                    require(
                        v["receipt"]["operation_id"] == c["operation_id"]
                            && v["receipt"]["revision_id"] == c["revision_id"]
                            && v["receipt"]["envelope_digest"]
                                == hash(&domain(
                                    "p02-v1",
                                    "hash",
                                    "envelope",
                                    &canonical(&v["bundle"]["envelope"])?,
                                )),
                        "RECEIPT_CONTEXT_MISMATCH",
                    )?;
                }
            }
            "phrase-wrapper" | "prf-wrapper" | "native-wrapper" => {
                let method = match k {
                    "phrase-wrapper" => "argon2id13",
                    "prf-wrapper" => "webauthn-prf",
                    _ => "windows-webauthn-prf",
                };
                require(v["context"]["method"] == method, "WRAPPER_METHOD_MISMATCH")?;
                if k == "native-wrapper" {
                    let n = un64(text(&v["tpm_name"])?)?;
                    require(n.len() == 34 && n[..2] == [0, 11], "INVALID_TPM_NAME")?;
                }
            }
            "local-plaintext" => {
                let kind = text(&v["context"]["record_kind"])?;
                let target = if kind == "session" {
                    "session-secret"
                } else {
                    kind
                };
                if [
                    "vault-secrets",
                    "draft",
                    "outbox",
                    "session-secret",
                    "cache",
                    "search",
                    "transfer",
                ]
                .contains(&target)
                {
                    self.validate("p02-v1", target, &v["data"])?;
                } else {
                    require(
                        v["data"].as_object().is_some_and(|o| {
                            o.len() == 1 && o.get("opaque_bytes").is_some_and(Value::is_string)
                        }),
                        "LOCAL_KIND_MISMATCH",
                    )?;
                }
                let c = match kind {
                    "draft" => &v["data"]["context"],
                    "outbox" => &v["data"]["bundle"]["envelope"]["header"]["context"],
                    _ => &Value::Null,
                };
                if !c.is_null() {
                    require(
                        c["service_id"] == v["context"]["service_id"]
                            && c["author"]["account_id"] == v["context"]["account_id"]
                            && c["author"]["device_id"] == v["context"]["device_id"],
                        "LOCAL_CONTEXT_MISMATCH",
                    )?;
                }
            }
            "negotiation" => require(
                v["components"]
                    == json!([
                        "p02-file-c1",
                        "p02-identity-c1",
                        "p02-state-c1",
                        "p02-group-c2",
                        "p02-v1"
                    ]),
                "UNSUPPORTED_SCHEMA",
            )?,
            "export-selection" => ordered(&v["group_ids"], |x| x.as_str().unwrap().into())?,
            "export-file-record" => {
                self.validate("p02-file-c1", "envelope", &v["envelope"])?;
                self.validate("p02-file-c1", "wrap", &v["wrap"])?;
                require(
                    v["envelope"]["header"]["context"] == v["wrap"]["context"],
                    "CONTEXT_MISMATCH",
                )?;
            }
            "export-pruned-record" => {
                let p = if v["record_kind"] == "file-manifest" {
                    "p02-file-c1"
                } else {
                    "p02-v1"
                };
                self.validate(p, "envelope", &v["envelope"])?;
                if p == "p02-v1" {
                    require(
                        v["envelope"]["header"]["context"]["object_kind"] == v["record_kind"],
                        "CONTEXT_MISMATCH",
                    )?;
                }
            }
            "cache" => {
                let kind = match text(&v["cached_kind"])? {
                    "object-bundle" => "bundle",
                    "file-record" => "export-file-record",
                    _ => "export-evidence",
                };
                self.decode("p02-v1", kind, &un64(text(&v["record_bytes"])?)?)?;
            }
            "search" => ordered(&v["documents"], |x| {
                format!(
                    "{}/{}/{}",
                    x["group_id"].as_str().unwrap(),
                    x["object_id"].as_str().unwrap(),
                    x["revision_id"].as_str().unwrap()
                )
            })?,
            "vault-secrets" => ordered(&v["group_keys"], |x| {
                format!(
                    "{}/{:0>19}",
                    x["group_id"].as_str().unwrap(),
                    x["key_epoch"].as_str().unwrap()
                )
            })?,
            "transfer" => {
                ordered(&v["parts"], |x| {
                    format!("{:0>3}", x["index"].as_str().unwrap())
                })?;
                require(
                    num(&v["progress_bytes"])? <= num(&v["source_bytes"])?,
                    "TRANSFER_PROGRESS_MISMATCH",
                )?;
                if v["direction"] != "export" {
                    require(
                        !v["file_id"].is_null()
                            && !v["file_version_id"].is_null()
                            && !v["keys"].is_null(),
                        "TRANSFER_CONTEXT_MISMATCH",
                    )?;
                }
            }
            "export-page" => ordered(&v["items"], |x| x["path"].as_str().unwrap().into())?,
            "export-key" => require(
                (v["key_kind"] == "object-dek") == v["file_data_dek"].is_null(),
                "KEY_PURPOSE_MISMATCH",
            )?,
            "error" | "error-response" => {
                let e: Value =
                    serde_json::from_str(include_str!("../../contracts/p02-errors.json")).unwrap();
                let found = e["errors"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|e| e["code"] == v["error"]["code"])
                    .ok_or(Error("ERROR_SEMANTICS_MISMATCH"))?;
                require(
                    found["retryable"] == v["error"]["retryable"]
                        && found["message_key"] == v["error"]["message_key"],
                    "ERROR_SEMANTICS_MISMATCH",
                )?;
            }
            _ => (),
        }
        Ok(())
    }
}
fn counter(s: &str, max: u64) -> bool {
    s.len() <= max.to_string().len()
        && !s.is_empty()
        && (s == "0" || !s.starts_with('0'))
        && s.bytes().all(|b| b.is_ascii_digit())
        && s.parse::<u64>().is_ok_and(|v| v <= max)
}
pub fn text(v: &Value) -> Result<&str> {
    v.as_str().ok_or(Error("SCHEMA_MISMATCH"))
}
pub fn num(v: &Value) -> Result<u64> {
    text(v)?.parse().map_err(|_| Error("SCHEMA_MISMATCH"))
}
fn ordered(v: &Value, f: impl Fn(&Value) -> String) -> Result<()> {
    require(
        v.as_array()
            .ok_or(Error("SCHEMA_MISMATCH"))?
            .windows(2)
            .all(|w| f(&w[0]) < f(&w[1])),
        "UNORDERED_OR_DUPLICATE",
    )
}
pub fn framing(f: &Value) -> Result<()> {
    let size = num(&f["plaintext_bytes"])?;
    let count = size.div_ceil(8388608);
    let parts = f["parts"].as_array().ok_or(Error("SCHEMA_MISMATCH"))?;
    require(
        num(&f["chunk_count"])? == count && parts.len() == count as usize,
        "INVALID_CHUNK_COUNT",
    )?;
    for (i, p) in parts.iter().enumerate() {
        require(
            num(&p["index"])? == i as u64
                && num(&p["ciphertext_bytes"])? == (size - i as u64 * 8388608).min(8388608) + 16,
            "INVALID_CHUNK_LENGTH",
        )?;
    }
    Ok(())
}
