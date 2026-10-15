//! Independently selected public cards and typed shared-group ceremonies. No secret export.
use crate::{host::Host, *};
use anynote_auth_native::control::Route;
use anynote_crypto_core::codec::canonical;
use serde_json::json;
impl Host {
    pub fn saved_ownership_policy(&self, g: u64, group: &str) -> Result<Value> {
        let cap = self.capability(g)?;
        let attempt = self.notes(&cap, json!({"action":"shared-attempt","group_id":group}))?;
        let policy = &attempt["body"]["policy"];
        check(
            policy["body"]["action"] == "transfer",
            "OWNERSHIP_PROPOSAL_REQUIRED",
        )?;
        Ok(policy.clone())
    }
    pub fn account_card(&self, g: u64) -> Result<Value> {
        let cap = self.capability(g)?;
        self.sync_devices(&cap)?;
        Ok(
            json!({"purpose":"p14-public-account-card","version":1,"pins":self.profile.service.pins}),
        )
    }
    pub fn group_card(&self, g: u64, group: &str) -> Result<Value> {
        let cap = self.capability(g)?;
        self.group(&cap, group)?;
        self.shared_proof(&cap, group)?;
        self.notes(
            &cap,
            json!({"action":"shared","request":{"action":"card","group_id":group}}),
        )
    }
    pub fn adopt_group_card(&self, g: u64, mut proof: Value, accept: bool) -> Result<Value> {
        let cap = self.capability(g)?;
        check(canonical(&proof)?.len() <= 4194304, "RESOURCE_LIMIT")?;
        check(
            proof["pin"]["service_id"] == self.profile.scope.service_id,
            "ROOT_PIN_MISMATCH",
        )?;
        let own = json!({"pins":self.profile.service.pins,"snapshot":self.roster(&cap,&self.profile.scope.account_id,string(&self.profile.service.pins,"root_fingerprint")?)?});
        let accounts = proof["accounts"]
            .as_array_mut()
            .ok_or(Error("GROUP_PROOF_REQUIRED"))?;
        if let Some(account) = accounts
            .iter_mut()
            .find(|a| a["pins"]["account_id"] == self.profile.scope.account_id)
        {
            check(account["pins"] == own["pins"], "ROOT_PIN_MISMATCH")?;
            *account = own;
        } else {
            accounts.push(own);
        }
        let group = string(&proof["pin"], "group_id")?.to_owned();
        id(&group)?;
        let invitation = proof["journal"]["pending"]["invitation"].clone();
        self.notes(
            &cap,
            json!({"action":"shared","request":{"action":"adopt","proof":proof}}),
        )?;
        if accept {
            check(invitation.is_object(), "INVITATION_REQUIRED")?;
            let mut after = None::<String>;
            let mut found = false;
            for _ in 0..1000 {
                let query = after
                    .as_ref()
                    .map(|v| vec![("after", v.as_str())])
                    .unwrap_or_default();
                let page = self.api(&cap, Route::Invitations, None, None, &query, None)?;
                if page["invitations"]
                    .as_array()
                    .ok_or(Error("INVALID_PAGE"))?
                    .contains(&invitation)
                {
                    found = true;
                    break;
                }
                if page["next"].is_null() {
                    break;
                }
                let next = string(&page, "next")?.to_owned();
                check(after.as_ref() != Some(&next), "INVALID_PAGE_ORDER")?;
                after = Some(next);
            }
            check(found, "INVITATION_REQUIRED")?;
            let prepared=self.notes(&cap,json!({"action":"shared","request":{"action":"accept","group_id":group,"invitation":invitation,"confirmed":true}}))?;
            self.send_shared(&cap, &group, &prepared)
        } else {
            self.shared_proof(&cap, &group)?;
            self.group(&cap, &group)?;
            self.notes(
                &cap,
                json!({"action":"shared","request":{"action":"details","group_id":group}}),
            )
        }
    }
    pub fn invite_account_card(
        &self,
        g: u64,
        group: &str,
        card: &Value,
        role: &str,
    ) -> Result<Value> {
        check(
            card["purpose"] == "p14-public-account-card" && card["version"] == 1,
            "INVALID_ACCOUNT_CARD",
        )?;
        check(["reader", "editor"].contains(&role), "INVALID_REQUEST")?;
        let cap = self.capability(g)?;
        self.prove(&cap)?;
        self.group(&cap, group)?;
        self.shared_proof(&cap, group)?;
        let pins = &card["pins"];
        check(
            pins["service_id"] == self.profile.scope.service_id,
            "ROOT_PIN_MISMATCH",
        )?;
        let account = string(pins, "account_id")?;
        id(account)?;
        let root = string(pins, "root_fingerprint")?;
        let snapshot = self.roster(&cap, account, root)?;
        let prepared=self.notes(&cap,json!({"action":"shared","request":{"action":"invite","group_id":group,"account":{"pins":pins,"snapshot":snapshot},"expected_root":root,"role":role,"confirmed":true}}))?;
        self.send_shared(&cap, group, &prepared)
    }
    pub fn ownership_proposal(
        &self,
        g: u64,
        group: &str,
        account: &str,
        device: &str,
    ) -> Result<Value> {
        let cap = self.capability(g)?;
        self.prove(&cap)?;
        self.group(&cap, group)?;
        self.shared_proof(&cap, group)?;
        self.notes(&cap,json!({"action":"shared","request":{"action":"transfer-proposal","group_id":group,"account_id":id(account)?,"device_id":id(device)?,"confirmed":true}}))
    }
    pub fn ownership_step(
        &self,
        g: u64,
        group: &str,
        policy: &Value,
        cosign: bool,
    ) -> Result<Value> {
        let cap = self.capability(g)?;
        self.prove(&cap)?;
        self.group(&cap, group)?;
        self.shared_proof(&cap, group)?;
        let prepared=self.notes(&cap,json!({"action":"shared","request":{"action":if cosign{"cosign"}else{"transfer"},"group_id":group,"policy":policy,"confirmed":true}}))?;
        let result = self.send_shared(&cap, group, &prepared)?;
        Ok(json!({"result":result,"policy":prepared["body"]["policy"]}))
    }
}
