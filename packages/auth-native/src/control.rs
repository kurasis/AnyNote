//! Fixed native product control routes. This is not exposed as renderer HTTP IPC.
use super::*;
use serde_json::Value;
#[derive(Clone, Copy)]
pub enum Route {
    Capabilities,
    DeviceEnvelopes,
    Me,
    Challenge,
    Proof,
    Identity,
    Roster,
    Devices,
    Sessions,
    RevokeSession,
    GroupList,
    Group,
    Genesis,
    Journal,
    Envelopes,
    CreateGroup,
    Threads,
    Entries,
    Object,
    Revisions,
    Revision,
    CreateThread,
    CreateEntry,
    Commit,
    Tombstone,
    Restore,
    Receipt,
    Sync,
    SyncAck,
    Snapshot,
    SnapshotCatalog,
    SnapshotPage,
    SnapshotItem,
    SnapshotCancel,
    SnapshotFiles,
    Storage,
    Unattached,
    FileList,
    FileDelete,
    ExportStart,
    ExportStatus,
    ExportCatalog,
    ExportPage,
    ExportHeaders,
    ExportRecord,
    ExportChunk,
    ExportRenew,
    ExportCancel,
    Retention,
    RetentionApply,
    RetentionPin,
    Thumbnail,
    Members,
    Invitations,
    SecurityReceipt,
    Policy,
    OwnerConsent,
    CancelShared,
    Invite,
    Accept,
    History,
    EpochBegin,
    EpochPage,
    EpochCommit,
    Enrollment,
    Relay,
    EnrollmentApprove,
    EnrollmentConfirm,
    RevokeDevice,
    RecoveryChallenge,
    RecoveryReset,
    Logout,
}
impl Route {
    fn path(self, a: Option<&str>, b: Option<&str>) -> Result<(reqwest::Method, String), Error> {
        fn id(v: Option<&str>) -> Result<&str, Error> {
            v.filter(|s| {
                s.len() == 22
                    && s.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            })
            .ok_or(Error::Configuration)
        }
        use Route::*;
        use reqwest::Method;
        let get = Method::GET;
        let post = Method::POST;
        Ok(match self {
            Capabilities => (get, "capabilities".into()),
            DeviceEnvelopes => (get, "me/device-envelopes".into()),
            Me => (get, "me".into()),
            Challenge => (post, "auth/device-challenge".into()),
            Proof => (post, "auth/device-proof".into()),
            Identity => (get, format!("accounts/{}/identity", id(a)?)),
            Roster => (get, format!("accounts/{}/roster", id(a)?)),
            Devices => (get, "me/devices".into()),
            Sessions => (get, "me/sessions".into()),
            RevokeSession => (reqwest::Method::DELETE, format!("me/sessions/{}", id(a)?)),
            GroupList => (get, "groups".into()),
            Group => (get, format!("groups/{}", id(a)?)),
            Genesis => (get, format!("groups/{}/genesis", id(a)?)),
            Journal => (get, format!("groups/{}/journal", id(a)?)),
            Members => (get, format!("groups/{}/journal", id(a)?)),
            Envelopes => (get, format!("groups/{}/key-envelopes", id(a)?)),
            CreateGroup => (post, "groups".into()),
            Threads => (get, format!("groups/{}/threads", id(a)?)),
            Entries => (get, format!("threads/{}/entries", id(a)?)),
            Object => (get, format!("objects/{}", id(a)?)),
            Revisions => (get, format!("objects/{}/revisions", id(a)?)),
            Revision => (get, format!("objects/{}/revisions/{}", id(a)?, id(b)?)),
            CreateThread => (post, format!("groups/{}/threads", id(a)?)),
            CreateEntry => (post, format!("threads/{}/entries", id(a)?)),
            Commit => (post, format!("objects/{}/revisions", id(a)?)),
            Tombstone => (post, format!("objects/{}/tombstone", id(a)?)),
            Restore => (post, format!("objects/{}/restore", id(a)?)),
            Receipt => (get, format!("mutations/{}", id(a)?)),
            Sync => (get, "sync".into()),
            SyncAck => (post, "sync/ack".into()),
            Snapshot => (post, "snapshots".into()),
            SnapshotCatalog => (get, format!("snapshots/{}/catalog", id(a)?)),
            SnapshotPage => (get, format!("snapshots/{}/pages", id(a)?)),
            SnapshotItem => (get, format!("snapshots/{}/revisions/{}", id(a)?, id(b)?)),
            SnapshotFiles => (get, format!("snapshots/{}/files", id(a)?)),
            SnapshotCancel => (Method::DELETE, format!("snapshots/{}", id(a)?)),
            Storage => (get, "me/storage".into()),
            Unattached => (get, "me/unattached-files".into()),
            FileList => (get, format!("groups/{}/files", id(a)?)),
            FileDelete => (Method::DELETE, format!("files/{}/unattached", id(a)?)),
            ExportStart => (post, "exports".into()),
            ExportStatus => (get, format!("exports/{}", id(a)?)),
            ExportCatalog => (get, format!("exports/{}/catalog", id(a)?)),
            ExportPage => (get, format!("exports/{}/pages", id(a)?)),
            ExportHeaders => (get, format!("exports/{}/headers", id(a)?)),
            ExportRecord => (get, format!("exports/{}/records/{}", id(a)?, id(b)?)),
            ExportChunk => (get, format!("exports/{}/files/{}/chunks", id(a)?, id(b)?)),
            ExportRenew => (post, format!("exports/{}/renew", id(a)?)),
            ExportCancel => (Method::DELETE, format!("exports/{}", id(a)?)),
            Retention => (get, format!("groups/{}/retention", id(a)?)),
            RetentionApply => (post, format!("groups/{}/retention", id(a)?)),
            RetentionPin => (post, format!("revisions/{}/retention-pin", id(a)?)),
            Thumbnail => (post, format!("files/{}/thumbnail", id(a)?)),
            Invitations => (get, "me/group-invitations".into()),
            SecurityReceipt => (get, format!("me/group-receipts/{}", id(a)?)),
            Policy => (post, format!("groups/{}/policy", id(a)?)),
            OwnerConsent => (post, format!("groups/{}/owner-consent", id(a)?)),
            CancelShared => (post, format!("groups/{}/cancel", id(a)?)),
            Invite => (post, format!("groups/{}/invites", id(a)?)),
            Accept => (post, format!("groups/{}/accept", id(a)?)),
            History => (post, format!("groups/{}/history", id(a)?)),
            EpochBegin => (post, format!("groups/{}/epoch/begin", id(a)?)),
            EpochPage => (post, format!("groups/{}/epoch/page", id(a)?)),
            EpochCommit => (post, format!("groups/{}/epoch/commit", id(a)?)),
            Enrollment => (post, "me/enrollments".into()),
            Relay => (post, format!("me/enrollments/{}/relay", id(a)?)),
            EnrollmentApprove => (post, format!("me/enrollments/{}/approve", id(a)?)),
            EnrollmentConfirm => (post, format!("me/enrollments/{}/confirm", id(a)?)),
            RevokeDevice => (post, format!("me/devices/{}/revoke", id(a)?)),
            RecoveryChallenge => (post, "me/recovery-challenge".into()),
            RecoveryReset => (post, "me/recovery-reset".into()),
            Logout => (post, "auth/logout".into()),
        })
    }
}
/// Caller is the trusted native coordinator. No arbitrary URL/header/redirect input.
impl Adapter {
    pub fn control(
        &self,
        credentials: Option<&Credentials>,
        route: Route,
        a: Option<&str>,
        b: Option<&str>,
        query: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<FileResponse, Error> {
        let (method, mut path) = route.path(a, b)?;
        let binary = matches!(route, Route::ExportChunk);
        if binary {
            if query.len() != 1 || query[0].0 != "index" {
                return Err(Error::Configuration);
            }
            let n = query[0].1.parse::<u8>().map_err(|_| Error::Configuration)?;
            if n >= 120 {
                return Err(Error::Configuration);
            }
            path.push_str(&format!("/{n}"));
        }
        if query.len() > 3
            || query.iter().any(|(k, v)| {
                !matches!(
                    *k,
                    "after"
                        | "head"
                        | "root"
                        | "cursor"
                        | "start"
                        | "index"
                        | "family"
                        | "limit"
                        | "generation"
                        | "sequence"
                        | "group"
                ) || v.len() > 4096
                    || !v.is_ascii()
            })
        {
            return Err(Error::Configuration);
        }
        let mut request = self
            .http
            .request(method, format!("{}/api/v1/{path}", self.issuer))
            .header(
                "Accept",
                if binary {
                    "application/octet-stream"
                } else {
                    "application/json"
                },
            );
        if !binary {
            request = request.query(query);
        };
        if let Some(c) = credentials {
            request = request.bearer_auth(c.access.as_str());
        }
        if let Some(b) = body {
            if serde_json::to_vec(b).map_err(|_| Error::Denied)?.len() > 33558528 {
                return Err(Error::Denied);
            }
            request = request.json(b);
        }
        let mut response = request.send().map_err(|_| Error::Transport)?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        std::io::Read::take(&mut response, 33558529)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Transport)?;
        if bytes.len() > 33558528 {
            return Err(Error::Denied);
        }
        Ok(FileResponse { status, bytes })
    }
}
