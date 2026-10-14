//! Trusted native coordinator. Renderer cannot submit index plaintext, keys or raw records.
use anynote_crypto_core::{Error, Result, codec::canonical, crypto::hash};
use anynote_local_vault::{Capability, Record, Vault, content::control_id, notes::NotesRequest};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;
fn check(value: bool, code: &'static str) -> Result<()> {
    if value { Ok(()) } else { Err(Error(code)) }
}
fn tokens(text: &str) -> BTreeSet<String> {
    text.nfkc()
        .flat_map(char::to_lowercase)
        .collect::<String>()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .take(1001)
        .map(str::to_owned)
        .collect()
}
fn fingerprint(summary: &Value) -> Result<String> {
    Ok(hash(&canonical(
        &json!({"groups":summary["groups"],"witnesses":summary["witnesses"],"projection":summary["projection"]}),
    )?))
}
fn wipe(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}
pub struct Search<'a> {
    vault: &'a Vault,
    cap: &'a Capability,
    control_id: String,
}
impl<'a> Search<'a> {
    pub fn new(
        vault: &'a Vault,
        cap: &'a Capability,
        scope: &anynote_local_vault::Scope,
    ) -> Result<Self> {
        Ok(Self {
            vault,
            cap,
            control_id: control_id(scope)?,
        })
    }
    fn summary(&self) -> Result<Value> {
        self.vault.notes_command(self.cap, NotesRequest::Summary {})
    }
    fn control(&self) -> Result<Value> {
        Ok(self.vault.content_read(self.cap,&self.control_id,"content-control")?.data.unwrap_or(json!({"purpose":"p13-native-search","version":1,"pages":[],"failures":[],"source":""})))
    }
    pub fn catalog(&self) -> Result<Value> {
        let summary = self.summary()?;
        Ok(json!({"items":summary["witnesses"],"known_corpus_only":true}))
    }
    pub fn clear(&self, confirmed: bool) -> Result<Value> {
        check(confirmed, "CONFIRMATION_REQUIRED")?;
        let mut control = self.control()?;
        let pages = control["pages"]
            .as_array()
            .ok_or(Error("INTEGRITY_FAILURE"))?
            .clone();
        // Bounded retirement batches; successful prefixes remain coherent after interruption.
        for batch in pages.chunks(31) {
            let ids: Vec<String> = batch
                .iter()
                .map(|p| p["record_id"].as_str().unwrap_or("").to_owned())
                .collect();
            let remaining: Vec<Value> = control["pages"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|p| !ids.iter().any(|id| p["record_id"] == *id))
                .cloned()
                .collect();
            control["pages"] = json!(remaining);
            control["failures"] = json!([]);
            control["source"] = json!(fingerprint(&self.summary()?)?);
            let snap = self
                .vault
                .content_read(self.cap, &self.control_id, "content-control")?;
            self.vault.content_commit(
                self.cap,
                snap.revision,
                &[Record {
                    id: self.control_id.clone(),
                    kind: "content-control".into(),
                    data: control.clone(),
                }],
                &ids,
            )?;
        }
        if pages.is_empty() {
            control["source"] = json!(fingerprint(&self.summary()?)?);
            let snap = self
                .vault
                .content_read(self.cap, &self.control_id, "content-control")?;
            self.vault.content_commit(
                self.cap,
                snap.revision,
                &[Record {
                    id: self.control_id.clone(),
                    kind: "content-control".into(),
                    data: control,
                }],
                &[],
            )?;
        }
        Ok(json!({"cleared_pages":pages.len(),"pending_work_preserved":true}))
    }
    pub fn index(&self, revisions: &[String]) -> Result<Value> {
        check(
            !revisions.is_empty()
                && revisions.len() <= 16
                && revisions.iter().collect::<BTreeSet<_>>().len() == revisions.len(),
            "RESOURCE_LIMIT",
        )?;
        let summary = self.summary()?;
        let source = fingerprint(&summary)?;
        let mut control = self.control()?;
        check(
            control["source"] == source || control["pages"].as_array().is_some_and(Vec::is_empty),
            "INDEX_REBUILD_REQUIRED",
        )?;
        let indexed: BTreeSet<String> = control["pages"]
            .as_array()
            .ok_or(Error("INTEGRITY_FAILURE"))?
            .iter()
            .flat_map(|p| {
                p["revisions"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
            })
            .collect();
        check(
            revisions.iter().all(|r| !indexed.contains(r)),
            "ALREADY_INDEXED",
        )?;
        let mut documents = Vec::new();
        let mut failures = Vec::new();
        for revision in revisions {
            let reference = summary["witnesses"]
                .as_array()
                .ok_or(Error("INTEGRITY_FAILURE"))?
                .iter()
                .find(|r| r["revision_id"] == *revision)
                .ok_or(Error("RECORD_NOT_FOUND"))?;
            let mut verified = match self.vault.notes_command(
                self.cap,
                NotesRequest::Cached {
                    revision_id: revision.clone(),
                },
            ) {
                Ok(v) => v,
                Err(e)
                    if ["PAYLOAD_UNAVAILABLE", "UNANCHORED_HISTORY", "KEYS_PENDING"]
                        .contains(&e.0) =>
                {
                    failures.push(json!({"revision_id":revision,"code":e.0}));
                    continue;
                }
                Err(e) => return Err(e),
            };
            let result = (|| {
                let p = &verified["payload"];
                check(
                    p["context"]["revision_id"] == *revision
                        && verified["envelope_digest"] == reference["envelope_digest"],
                    "CONTEXT_MISMATCH",
                )?;
                let tags = p["tags"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ");
                let checklist = p["checklist"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|x| x["text"].as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                let body = format!(
                    "{} {} {} {}",
                    p["title"].as_str().unwrap_or(""),
                    p["markdown"].as_str().unwrap_or(""),
                    tags,
                    checklist
                );
                let chars = body.chars().take(262144).collect::<String>();
                let tokens = tokens(&chars);
                let bounded = tokens.len() > 1000
                    || body.chars().count() > 262144
                    || tokens.iter().any(|t| t.chars().count() > 64);
                let tokens: Vec<String> = tokens
                    .into_iter()
                    .filter(|t| t.chars().count() <= 64)
                    .take(1000)
                    .collect();
                Ok(
                    json!({"group_id":p["context"]["group_id"],"object_id":p["context"]["object_id"],"revision_id":revision,"envelope_digest":reference["envelope_digest"],"tokens":tokens,"bounded":bounded,"title":p["title"],"snippet":p["markdown"].as_str().unwrap_or("").chars().take(512).collect::<String>()}),
                )
            })();
            wipe(&mut verified);
            documents.push(result?);
        }
        check(source == fingerprint(&self.summary()?)?, "STALE_WRITER")?;
        let pages = control["pages"]
            .as_array_mut()
            .ok_or(Error("INTEGRITY_FAILURE"))?;
        check(pages.len() < 688, "RESOURCE_LIMIT")?;
        let record_id = anynote_crypto_core::crypto::b64(&libsodium_random_id());
        let indexed = documents.len();
        pages.push(json!({"record_id":record_id,"revisions":documents.iter().map(|d|d["revision_id"].clone()).collect::<Vec<_>>()}));
        control["source"] = json!(source);
        control["failures"]
            .as_array_mut()
            .ok_or(Error("INTEGRITY_FAILURE"))?
            .extend(failures);
        let snap = self
            .vault
            .content_read(self.cap, &self.control_id, "content-control")?;
        let mut records = [
            Record {
                id: record_id,
                kind: "search-page".into(),
                data: json!({"purpose":"p13-native-search-page","version":1,"documents":documents}),
            },
            Record {
                id: self.control_id.clone(),
                kind: "content-control".into(),
                data: control,
            },
        ];
        let result = self
            .vault
            .content_commit(self.cap, snap.revision, &records, &[]);
        for r in &mut records {
            wipe(&mut r.data);
        }
        result?;
        Ok(json!({"indexed":indexed,"storage":"protected-native-SQLite"}))
    }
    pub fn search(&self, query: &str, group: Option<&str>) -> Result<Value> {
        check(
            !query.is_empty() && query.chars().count() <= 256,
            "INVALID_SEARCH_QUERY",
        )?;
        let needle = tokens(query);
        check(
            !needle.is_empty() && needle.len() <= 16,
            "INVALID_SEARCH_QUERY",
        )?;
        let summary = self.summary()?;
        let mut control = self.control()?;
        let stale = control["source"] != fingerprint(&summary)?;
        let mut results = Vec::new();
        let mut seen = BTreeSet::new();
        let mut bounded = 0;
        if !stale {
            for page in control["pages"]
                .as_array()
                .ok_or(Error("INTEGRITY_FAILURE"))?
            {
                let id = page["record_id"]
                    .as_str()
                    .ok_or(Error("INTEGRITY_FAILURE"))?;
                let mut value = self
                    .vault
                    .content_read(self.cap, id, "search-page")?
                    .data
                    .ok_or(Error("RECORD_NOT_FOUND"))?;
                for d in value["documents"]
                    .as_array()
                    .ok_or(Error("INTEGRITY_FAILURE"))?
                {
                    let revision = d["revision_id"]
                        .as_str()
                        .ok_or(Error("INTEGRITY_FAILURE"))?;
                    if !seen.insert(revision.to_owned())
                        || group.is_some_and(|g| d["group_id"] != g)
                    {
                        continue;
                    }
                    bounded += usize::from(d["bounded"] == true);
                    let words: BTreeSet<_> = d["tokens"]
                        .as_array()
                        .ok_or(Error("INTEGRITY_FAILURE"))?
                        .iter()
                        .filter_map(Value::as_str)
                        .collect();
                    if needle.iter().all(|q| words.contains(q.as_str())) && results.len() < 100 {
                        // Reverify custody authority at display time; an index is never an access grant.
                        let mut current = self.vault.notes_command(
                            self.cap,
                            NotesRequest::Cached {
                                revision_id: revision.into(),
                            },
                        )?;
                        check(
                            current["envelope_digest"] == d["envelope_digest"],
                            "INTEGRITY_FAILURE",
                        )?;
                        wipe(&mut current);
                        results.push(json!({"group_id":d["group_id"],"object_id":d["object_id"],"revision_id":revision,"title":d["title"],"snippet":d["snippet"]}));
                    }
                }
                wipe(&mut value);
            }
        }
        let failures = control["failures"].clone();
        wipe(&mut control);
        Ok(
            json!({"results":results,"rebuild_required":stale,"known":summary["witnesses"].as_array().map_or(0,Vec::len),"indexed":if stale{0}else{seen.len()},"bounded":bounded,"failures":failures,"known_corpus_only":true}),
        )
    }
}
fn libsodium_random_id() -> Vec<u8> {
    libsodium_rs::random::bytes(16)
}
pub fn encrypt_stream<R: Read, W: Write>(
    mut input: R,
    output: W,
    recipient: &str,
) -> std::io::Result<W> {
    let recipient: age::x25519::Recipient = recipient
        .parse()
        .map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let encrypter =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(std::io::Error::other)?;
    let mut writer = encrypter.wrap_output(output)?;
    std::io::copy(&mut input, &mut writer)?;
    writer.finish()
}
pub fn decrypt_stream<R: Read, W: Write>(
    input: R,
    mut output: W,
    identity: &str,
) -> std::io::Result<W> {
    let identity: age::x25519::Identity = identity
        .parse()
        .map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let decryptor = age::Decryptor::new(input).map_err(std::io::Error::other)?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(std::io::Error::other)?;
    std::io::copy(&mut reader, &mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalization_and_word_boundaries_are_portable() {
        assert_eq!(tokens("ＦＯＯ БАР e\u{301}"), tokens("foo бар é"));
        assert!(tokens("repeat repeat").len() == 1);
        assert!(!tokens("alphabet").contains("alpha"));
    }
    #[test]
    fn standard_age_stream_authenticates_frozen_cross_provider_archive_and_rejects_truncation() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/protocol/p02/v1");
        let corpus: Value =
            serde_json::from_slice(&std::fs::read(root.join("crypto.json")).unwrap()).unwrap();
        let archive = std::fs::read(root.join("rust.age")).unwrap();
        let identity = corpus["objects"]["kit"]["export_identity"]
            .as_str()
            .unwrap();
        let tar = decrypt_stream(archive.as_slice(), Vec::new(), identity).unwrap();
        assert_eq!(hash(&tar), corpus["expected"]["tar_sha256"]);
        assert!(decrypt_stream(&archive[..archive.len() - 1], std::io::sink(), identity).is_err());
    }
}
