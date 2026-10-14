//! Durable group creation: one prepared genesis and metadata draft survive unknown network ACKs.
use crate::{host::Host, *};
use anynote_auth_native::control::Route;
use anynote_local_vault::Capability;
use serde_json::json;
impl Host {
    pub fn prepare_group_creation(
        &self,
        cap: &Capability,
        title: &str,
        shared: bool,
    ) -> Result<Value> {
        check(
            !title.trim().is_empty() && title.chars().count() <= 256,
            "INVALID_TITLE",
        )?;
        self.prove(cap)?;
        let made = self.notes(
            cap,
            json!({"action":if shared{"prepare-shared"}else{"prepare-group"}}),
        )?;
        let group = string(&made, "group_id")?;
        let state = json!({"purpose":"p14-native-group","version":1,"state":"PREPARED","group_id":group,"title":title,"shared":shared,"request":made["request"],"draft_id":null});
        self.save_native_job(cap, group, &state)?;
        Ok(state)
    }
    pub fn create_group(
        &self,
        cap: &Capability,
        title: &str,
        shared: bool,
        resume: Option<&str>,
    ) -> Result<Value> {
        let _writer = self.group_creation.lock().map_err(|_| Error("HOST_BUSY"))?;
        let mut state = if let Some(group) = resume {
            let saved = self
                .vault
                .content_read(cap, id(group)?, "import-state")?
                .data;
            if let Some(state) = saved {
                check(
                    state["purpose"] == "p14-native-group",
                    "LOCAL_CONTEXT_MISMATCH",
                )?;
                state
            } else {
                check(
                    !title.trim().is_empty() && title.chars().count() <= 256,
                    "INVALID_TITLE",
                )?;
                let retry = self.notes(cap, json!({"action":"retry-group","group_id":group}))?;
                let kind =
                    &retry["request"]["commit"]["body"]["policy"]["body"]["payload"]["group_kind"];
                let state = json!({"purpose":"p14-native-group","version":1,"state":"PREPARED","group_id":group,"title":title,"shared":kind=="shared","request":retry["request"],"draft_id":null});
                self.save_native_job(cap, group, &state)?;
                state
            }
        } else {
            self.prepare_group_creation(cap, title, shared)?
        };
        let group = string(&state, "group_id")?.to_owned();
        if state["state"] == "COMPLETE" {
            return self.group(cap, &group);
        }
        self.prove(cap)?;
        let status = self.api(
            cap,
            Route::CreateGroup,
            None,
            None,
            &[],
            Some(&state["request"]),
        )?;
        self.notes(cap, json!({"action":"group","status":status}))?;
        if state["draft_id"].is_null() {
            let summary = self.notes(cap, json!({"action":"summary"}))?;
            if let Some(draft) = summary["drafts"]
                .as_array()
                .ok_or(Error("INTEGRITY_FAILURE"))?
                .iter()
                .find(|d| {
                    d["group_id"] == group
                        && d["object_id"] == group
                        && d["object_kind"] == "group-metadata"
                })
            {
                state["draft_id"] = draft["draft_id"].clone();
            } else {
                let content = json!({"title":state["title"],"markdown":"","metadata_kind":"content","tags":[],"checklist":[],"summary_entry_id":null,"preferences":[]});
                let saved=self.notes(cap,json!({"action":"save","edit":Self::edit(&group,"group-metadata",Some(&group),None,&content,json!([]),"create")}))?;
                state["draft_id"] = saved["draft_id"].clone();
            }
            state["state"] = json!("METADATA_PENDING");
            self.save_native_job(cap, &group, &state)?;
        }
        self.publish(cap, string(&state, "draft_id")?)?;
        state["state"] = json!("COMPLETE");
        self.save_native_job(cap, &group, &state)?;
        Ok(status)
    }
}
