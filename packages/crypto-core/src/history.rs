//! An independent pinned checkpoint is required; no timestamp/freshness inference.
use crate::{Result, require};
use crate::{
    codec::{Codec, canonical, domain, num, text},
    crypto::*,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
pub struct HistoryAnchor {
    descriptor: Value,
    records: BTreeMap<String, Value>,
}
impl HistoryAnchor {
    pub fn verify(
        c: &Codec,
        history: &[u8],
        pages: &[Vec<u8>],
        independent_digest: &str,
        signer: &[u8],
    ) -> Result<Self> {
        require(
            pages.len() <= 200 && pages.iter().map(Vec::len).sum::<usize>() <= 33554432,
            "RESOURCE_LIMIT",
        )?;
        let h = c.decode("p02-group-c2", "history", history)?;
        require(
            hash(&domain("p02-group-c2", "hash", "history", &canonical(&h)?)) == independent_digest,
            "HISTORY_PIN_MISMATCH",
        )?;
        verify(
            &c.signing("p02-group-c2", "history-body", &h["body"])?,
            text(&h["signature"])?,
            signer,
        )?;
        let d = &h["body"]["descriptor"];
        c.validate("p02-file-c1", "checkpoint", d)?;
        require(
            h["body"]["service_id"] == d["service_id"] && h["body"]["group_id"] == d["group_id"],
            "CONTEXT_MISMATCH",
        )?;
        require(
            d["predecessor_checkpoint_digest"] == d["closed_policy"]["history_checkpoint_digest"],
            "CHECKPOINT_ANCESTRY_MISMATCH",
        )?;
        verify(
            &c.signing("p02-file-c1", "checkpoint", d)?,
            text(&h["body"]["descriptor_signature"])?,
            signer,
        )?;
        let parsed: Vec<_> = pages
            .iter()
            .map(|p| c.decode("p02-file-c1", "checkpoint-page", p))
            .collect::<Result<_>>()?;
        let count = parsed
            .iter()
            .map(|p| p["records"].as_array().unwrap().len())
            .sum::<usize>();
        require(
            num(&d["record_count"])? == count as u64
                && num(&d["page_count"])? == pages.len() as u64,
            "INVENTORY_MISMATCH",
        )?;
        let mut bytes = (pages.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&(count as u64).to_be_bytes());
        let mut records = BTreeMap::new();
        let mut last: Option<String> = None;
        for (i, p) in parsed.iter().enumerate() {
            require(
                p["service_id"] == d["service_id"]
                    && p["group_id"] == d["group_id"]
                    && num(&p["page_index"])? == i as u64,
                "CONTEXT_MISMATCH",
            )?;
            let canon = canonical(p)?;
            bytes.extend_from_slice(&(i as u32).to_be_bytes());
            bytes.extend_from_slice(&(p["records"].as_array().unwrap().len() as u32).to_be_bytes());
            bytes.extend_from_slice(&(canon.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&un64(&hash(&domain(
                "p02-file-c1",
                "hash",
                "history-page",
                &canon,
            )))?);
            if i + 1 < parsed.len() && p["records"].as_array().unwrap().len() < 500 {
                let mut augmented = p.clone();
                augmented["records"]
                    .as_array_mut()
                    .unwrap()
                    .push(parsed[i + 1]["records"][0].clone());
                require(
                    canonical(&augmented)?.len() > 1048576,
                    "INVALID_PAGE_PACKING",
                )?;
            }
            for r in p["records"].as_array().unwrap() {
                let id = text(&r["revision_id"])?.to_string();
                require(
                    last.as_ref().is_none_or(|old| old < &id),
                    "UNORDERED_OR_DUPLICATE",
                )?;
                last = Some(id.clone());
                records.insert(id, r.clone());
            }
        }
        require(
            hash(&domain("p02-file-c1", "hash", "history-inventory", &bytes))
                == d["inventory_digest"],
            "INVENTORY_MISMATCH",
        )?;
        for r in records.values() {
            for parent in r["parents"].as_array().unwrap() {
                let found = records
                    .get(text(&parent["revision_id"])?)
                    .ok_or(crate::Error("MISSING_OR_WRONG_ANCESTOR"))?;
                require(
                    found["object_id"] == r["object_id"]
                        && found["object_kind"] == r["object_kind"]
                        && found["envelope_digest"] == parent["envelope_digest"],
                    "MISSING_OR_WRONG_ANCESTOR",
                )?;
            }
        }
        let mut done = BTreeSet::new();
        let mut visiting = BTreeSet::new();
        for id in records.keys() {
            let mut stack = vec![(id.clone(), false)];
            while let Some((id, exit)) = stack.pop() {
                if exit {
                    visiting.remove(&id);
                    done.insert(id);
                    continue;
                }
                if done.contains(&id) {
                    continue;
                }
                require(visiting.insert(id.clone()), "CYCLIC_ANCESTRY")?;
                stack.push((id.clone(), true));
                for parent in records[&id]["parents"].as_array().unwrap() {
                    stack.push((text(&parent["revision_id"])?.to_string(), false));
                }
            }
        }
        Ok(Self {
            descriptor: d.clone(),
            records,
        })
    }
    pub fn check_object(&self, c: &Codec, envelope: &[u8], author: &[u8]) -> Result<()> {
        let e = c.decode("p02-v1", "envelope", envelope)?;
        let h = &e["header"];
        let ctx = &h["context"];
        verify(
            &c.signing("p02-v1", "header", h)?,
            text(&e["signature"])?,
            author,
        )?;
        require(
            ctx["service_id"] == self.descriptor["service_id"]
                && ctx["group_id"] == self.descriptor["group_id"],
            "UNANCHORED_HISTORY",
        )?;
        let r = self
            .records
            .get(text(&ctx["revision_id"])?)
            .ok_or(crate::Error("UNANCHORED_HISTORY"))?;
        require(
            r["object_kind"] == ctx["object_kind"]
                && r["object_id"] == ctx["object_id"]
                && r["parents"] == ctx["parents"]
                && r["envelope_digest"]
                    == hash(&domain("p02-v1", "hash", "envelope", &canonical(&e)?)),
            "UNANCHORED_HISTORY",
        )
    }
    pub fn check_file(&self, c: &Codec, envelope: &[u8], author: &[u8]) -> Result<()> {
        let e = c.decode("p02-file-c1", "envelope", envelope)?;
        let h = &e["header"];
        let ctx = &h["context"];
        verify(
            &c.signing("p02-file-c1", "header", h)?,
            text(&e["signature"])?,
            author,
        )?;
        require(
            ctx["service_id"] == self.descriptor["service_id"]
                && ctx["group_id"] == self.descriptor["group_id"],
            "UNANCHORED_HISTORY",
        )?;
        let r = self
            .records
            .get(text(&ctx["file_version_id"])?)
            .ok_or(crate::Error("UNANCHORED_HISTORY"))?;
        require(
            r["object_kind"] == "file-manifest"
                && r["object_id"] == ctx["file_id"]
                && r["parents"] == ctx["parents"]
                && r["envelope_digest"]
                    == hash(&domain(
                        "p02-file-c1",
                        "hash",
                        "file-envelope",
                        &canonical(&e)?,
                    )),
            "UNANCHORED_HISTORY",
        )
    }
}
