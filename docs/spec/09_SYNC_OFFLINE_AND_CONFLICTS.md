# Synchronization, Offline Operation, and Conflicts

## 1. Guarantees

SYNC-001: A confirmed local save survives ordinary application restart once the local encrypted transaction is durable.

SYNC-002: A server “Synced” acknowledgement means both the mutation and its sync event are committed, and all referenced committed file bytes are durably available.

SYNC-003: Network retries cannot create duplicate entries, versions, reservations, membership operations, or notifications.

SYNC-004: Concurrent edits cannot silently overwrite one another. v1 uses revisions and explicit conflicts, not last-write-wins for note bodies.

SYNC-005: Local data that has never reached the service is not protected by server backup. Browser storage eviction and physical device loss remain possible.

## 2. Local write path

Encrypt draft updates incrementally while editing. Debounce around 300–750 ms as a UX target, flush promptly on explicit Save, and report durable state honestly. Persist ciphertext revision/draft and outbox intent in one local transaction. A lifecycle background/unload event is an additional opportunity, not the sole save trigger.

Outbox records contain a random stable operation ID, encrypted payload, base revision(s), group and policy context, local order, and retry state. Secret/plaintext values are never persisted in a plain outbox field. Retain original local ciphertext until remote commit and verification complete.

## 3. Server delta feed

Use commit-ordered transactional sequence numbers from file 07 for transport ordering only; ordinary AUTO_INCREMENT allocation order is not sufficient. Events are scoped to accessible groups/account namespace. Page at 200 events by default and at most 1,000. Include next cursor, current watermark, and resync requirement. Do not derive consistency from device clocks.

While visible and online, poll roughly every 5 seconds with jitter; after inactivity or failure back off to 15–60 seconds. Trigger immediate catch-up after reconnect/resume, successful local commit, or a push hint. Avoid draining iPhone battery with a permanent tight loop. Server authorization determines visibility; clients independently verify event targets and signed content.

Advance the durable cursor only after the corresponding event page has been safely applied or recorded for retry in a local transaction. A malformed event cannot cause silent cursor skipping. Quarantine it, surface integrity status, and preserve recovery information.

## 4. Bootstrap and full resync

Download identities/policies/keys and a bounded materialized snapshot inventory at a stable committed watermark. Snapshot tokens are bound to the active account/device, expire, and recheck access on every page; immutable referenced content is pinned until expiry. Process concurrent changes after that watermark using the delta feed. Do not assume separately paginated lists form a consistent snapshot without a watermark/continuation contract.

First obtain encrypted catalog/notes, then file manifests on demand, then selected file chunks. Never fetch 100 GB simply to open the app. An expired cursor initiates full resync but retains local encrypted outbox/conflicts and reconciles operation IDs before publishing anything.

Only purge local data absent from a snapshot after snapshot completeness and current authorization are established. A transient partial list is not evidence of deletion.

## 5. Conflicts

If two edits share the same base revision, first commit may become the main head; the second receives STALE_REVISION with current head references. The client retains the second edit and offers: compare/merge text, keep both, or explicitly replace with a new revision whose parents include the versions considered. Never discard an edit automatically.

Checklist toggles use revision-based conflict handling initially. Auto-merging independent toggles may be added only with documented stable item IDs and deterministic conflict tests. Thread ordering/favorites can use account-private preference resolution, but note bodies and file replacements cannot silently use last-write-wins.

Concurrent delete/edit preserves the edit as a recoverable conflict or private draft. A deleted object must not be resurrected merely because an old device uploads its old head. Restore requires an explicit signed operation.

## 6. Authorization changes while offline

Before submitting shared writes, refresh group policy, relevant account rosters, and key epoch. Re-encrypt unsent content with fresh keys under the active epoch when authorized. Because the server has never seen an offline draft, this may create a new signed publication envelope with a link to local draft provenance.

If removed or downgraded, stop publication and preserve unsent work in the account-private encrypted namespace where possible. If the entire device is revoked and cannot upload anywhere, allow explicit local export after local unlock without pretending server access remains valid.

When a group is rekey-required, queued writes stay queued with an explanation. Do not send to old recipients. API rejection and local state transition must be deterministic across all platforms.

## 7. Deletion and retention

Soft deletion creates a signed tombstone and sync event. Current members can inspect/restore within 30-day trash. Purge deletes eligible payloads/chunks after reference checks and retains compact tombstones/integrity ancestry required for old-client reconciliation.

Cache deletion is distinct from content deletion. “Free space on this device” removes replaceable local ciphertext only; it must not create server tombstones. “Delete everywhere” changes shared content and must show the affected group.

For removed members, hide no-longer-authorized shared views on cooperative reconnect. First preserve unsynced work in locally encrypted recovery drafts; ask before deleting the only remaining local copy. No forensic erasure or remote control over an offline stolen device is claimed.

## 8. Search

Build an in-memory index after unlock, or use an encrypted-at-rest local index. Windows may maintain an encrypted native search index; PWA can rebuild from encrypted snapshots. Do not put FTS terms in plaintext SQLite/IndexedDB, URLs, telemetry, or server queries.

Search titles/body/tags of loaded authorized content; support group and type filters. Display “Search covers downloaded notes” if the corpus is incomplete. Full attachment-content search/OCR is later work; filenames and client-created preview metadata are available after decryption.

Drop in-memory index references on lock; acknowledge browser memory-erasure limits. Mark corpus revisions so changed/deleted/revoked content is removed from results promptly.

## 9. Transfers and lifecycle

Transfers have states queued, preparing, uploading/downloading, paused, needs-source, verifying, committed, failed, cancelled. Persist state and acknowledged chunk inventory. Respect bounded concurrency and backpressure. iOS backgrounding may pause/terminate processing; resume must reconcile actual server acknowledgements rather than trust last painted progress.

Lock should pause operations requiring plaintext/keys and safely persist encrypted state. Already encrypted queued chunks may continue only if the platform and explicit transfer policy allow it; do not retain an otherwise unlocked vault solely to finish a hidden transfer.

## 10. Recovery scenarios to implement

Restart during local save; browser killed during upload; lost commit response; repeated same mutation; partial snapshot; DB cursor rollback after restore; simultaneous membership removal/upload commit; expired upload with local ciphertext remaining; changed source on resume; full disk while receiving; invalid remote ciphertext; key not yet delivered; unsupported old client. Each has an acceptance case in file 13 and must preserve user-recoverable work.

## 11. Retry identity, transport cursor, and browser races

Use a stable local draft_id distinct from a publication operation_id. A given operation_id has immutable signed bytes. On ambiguous network failure query/retry its receipt first. Re-encrypting for a new epoch, changing parents after conflict, or changing any signed field creates a new operation_id and usually new immutable revision ID; do not reuse an idempotency key with a changed body. If an old operation already committed, reconcile it before preparing another publication.

A sync page has a captured upper watermark and bounded scanned range. next_cursor represents the last safely scanned position, including inaccessible events filtered on the server, not simply the largest visible ID. Events that exceed byte limits spill to later pages/references. The server must not advance beyond unscanned visible events. Newly granted history is bootstrapped from the group's snapshot; joining cannot rely on old global events whose cursors were previously skipped while unauthorized.

Enforce one active writer/transfer leader per local account profile across tabs/windows where possible, using platform-supported locks or a transactional lease with fencing tokens. Do not assume Web Locks exists everywhere. Read-only followers can render decrypted views only while unlocked and must honor lock broadcasts; late worker/IPC results carry lock-generation IDs and are discarded after lock. Test two PWA windows, service-worker replacement and simultaneous refresh-token rotations.

API 401/403/revoke cannot automatically clear outbox or reset local identity. Malformed signed events are quarantined without a tight infinite retry loop. The UI offers safe diagnostics/recovery while preserving data. File/data integrity loss is not treated as an ordinary network retry.
