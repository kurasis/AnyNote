# Protocol State Transitions and Cross-Component Invariants

Specification version: 1.1.0. This document makes the lifecycle contract explicit. Files 04–10 define cryptographic fields, permissions and storage. P02 must freeze complete byte schemas and fixtures before production implementation; the following states are requirements, not audited protocol code.

## 1. Common transition rules

Each security mutation contains purpose/version, service/account or group context, a random operation ID, expected policy/roster/generation heads, bounded expiry where applicable, immutable payload digests and the authorized signature. A response is successful only after the durable transaction, sync event and immutable receipt commit. The same operation ID with different signed bytes is rejected.

Verify signature and historical/current authority separately. A known certificate is not evidence that its device remains active. An authenticated API session is not device possession. A valid AEAD tag is not proof of writer permission. An encrypted recipient envelope is not proof of sender authenticity or of correct key contents.

Domain locks, quotas, expected heads and receipt uniqueness are checked under one documented lock order. Acquire the transport counter last, then commit without external I/O. Retry deadlocks as entire immutable operations; never retry a partially changed request under the old operation ID. Staging records are inaccessible as live content until activation. Server transactions may validate signatures with public keys; content decryption stays client-side.

Expiry uses server time for honest-service resource management, not cryptographic creation-time evidence. Devices remember verified heads and refuse silent regressions. A fresh device imports checkpoints through authenticated pairing/recovery evidence; a server timestamp cannot establish global freshness.

## 2. Session authorization levels

| Level | Preconditions | Allowed scope |
| --- | --- | --- |
| Anonymous | No authenticated account | Login/registration CSRF setup, bounded public auth challenge, invitation bootstrap |
| Authenticated/restricted | Account login passed | Minimal account security state, pending enrollment, recovery challenge; no group inventory or normal key endpoints |
| Authenticated/trusted | Active certified device plus fresh session-bound possession proof | Current membership-authorized content, key envelopes and sync |
| Recent-auth trusted | Trusted plus recent account verification | Sensitive account actions; still requires any appropriate device/owner signatures |
| Recovery-only restore mode | Special isolated restore policy | Identity recovery and security-state reconciliation; no ordinary restored content sessions |

A device-proof challenge binds service, account, server session identifier or its safe binding digest, fresh nonce, intended device public-key fingerprint, recovery generation and short expiry. It is consumed once. Session renewal/rotation preserves or reestablishes the proof binding under a documented rule; a revoked device never regains trust through refresh. Possession proof does not make bearer tokens immune to theft; storage, TLS, expiry and revocation remain necessary.

## 3. Device enrollment

| State | Valid next state | Mandatory condition |
| --- | --- | --- |
| GENERATED | PENDING | Local independent signing/encryption keys; authenticated restricted account session |
| PENDING | APPROVED | Existing active device verifies authenticated pairing transcript and signs provisional certificate |
| APPROVED | ACTIVE | New device proves key possession and confirms transcript; current approving chain/head revalidated; atomic roster event |
| PENDING / APPROVED | EXPIRED / CANCELLED | Expiry, explicit cancel, approving-chain revocation or consumed session |
| ACTIVE | REVOKED | Valid surviving-device revoke or root reset, including affected descendants |
| REVOKED / EXPIRED / CANCELLED | None | Fresh enrollment requires new session and appropriate fresh device keys |

No group keys or full content session are released in PENDING/APPROVED. A signed provisional certificate cannot be replayed as an active roster event. The activating transaction enforces device count and consumes both approval and confirmation. Only afterward may the existing device release staged group envelopes and the new session become trusted. Loss of the response is resolved through its receipt, not duplicate enrollment.

Every delegated device records its parent device and generation. A compromise revoke computes the transitive descendant closure, cancels pending approvals from that closure, revokes sessions and prevents all affected recipients from future key delivery. Revocation of a parent may therefore revoke innocent descendants too; show the set and re-enroll verified safe hardware with new keys. Historical signatures remain subject to historical verification.

## 4. Root recovery reset

1. Authenticate to the account through a separate supported login/recovery path.
2. Derive account root/recovery keys locally from R and the kit identifiers; verify the expected identity.
3. Generate new device keys. Request a one-use challenge bound to account, session, service, current recovery generation and intended new device keys.
4. Root-sign a reset with expected generation/head and challenge. Server validates against the already anchored root; a supplied replacement public root is not accepted.
5. Atomically advance generation, revoke every previous device and dependent session/approval, activate the new root-certified device, consume the challenge, publish receipt/event and mark affected groups for maintenance. Upgrade only the bound recovery session.
6. Through that active device, obtain its account's recovery envelopes for currently authorized groups. Unwrap locally, persist under L and start required key maintenance. Recovering keys is not a prerequisite to step 5.

Concurrent resets use compare-and-swap; the loser obtains current state and starts an explicit new challenge. A root-secret compromise is outside the protection of generation reset: the attacker can also sign a later reset. Use a fresh identity/migration and independent re-verification, not endless reset races.

## 5. Group membership and epochs

Membership states: ABSENT -> INVITED -> ACCEPTED_PENDING_GRANTS -> ACTIVE -> REMOVED. Expiry/decline leaves no active access. An owner-signed invitation binds exact target root, role, full-history disclosure and expected group policy. The target accepts with a trusted device. Adding the account remains pending until complete authorized key-grant coverage is staged and the admission transaction commits. API cannot cryptographically prove the envelopes contain the correct keys; failed client unwrap enters repair state.

Group write state is separate: WRITABLE, REKEY_REQUIRED, HISTORY_CLOSURE_REQUIRED, ARCHIVED or RECOVERY_QUARANTINE. Reads require current server permission and independently verified historical data. ARCHIVED still permits explicit removal, ownership/key maintenance and owner unarchive; it does not permit content publication.

Removal/revoke commits access denial immediately without waiting for a bulk inventory. It marks affected groups nonwritable. Roster-only maintenance may be performed by any active member, including a reader, but the exact membership and active device recipient set are fixed by already verified state. Membership changes/ownership require the owner; optional rekey requires owner/editor. Reader maintenance never authorizes content writes or historical author certification.

A transition stages bounded inventory/grant pages outside long DB locks. Finalization compares policy and every relevant roster head, validates exact recipient coverage, checks staged digests, and atomically activates the fresh epoch. A head change invalidates affected staging; regenerate key material where an excluded recipient may have obtained it. No partial grant set becomes the live epoch. If history closure is also required, new writes remain blocked until it is complete.

Only one pending membership/epoch transition per group is allowed. A revoke may invalidate/cancel ordinary pending admission/rekey instead of waiting for it. Owner transfer requires both owners' signatures and exactly one resulting owner. A private group cannot be transferred through the shared-group ownership shortcut.

## 6. Historical author closure

Former writers still possess their old signing keys. They can create new signatures that claim old policy versions. Retained-history verification therefore requires an authenticated inventory/witness boundary, not a timestamp or policy number alone.

Candidate v1 bounded checkpoint representation:

- A descriptor binds service/group, checkpoint version, predecessor checkpoint digest, closed policy/epoch/roster heads, exact record count, ordered inventory digest, inclusion rules and authorized owner/editor signer.
- Each inventory record identifies object/revision, signed-envelope digest, parents, object kind and retained-payload/tombstone status. Include file manifest revisions and required compact ancestry; never substitute current object ID for an exact revision digest.
- Pages contain at most 500 records and 1 MiB. Ordering is deterministic by opaque revision identity, with duplicate rejection. Descriptor digest is computed over a versioned length-delimited sequence of ordered page digests and total counts. Its size is independent of record count.
- In the baseline, clients verify the complete paginated inventory once and build a local membership index. Do not claim efficient independent Merkle inclusion proofs without a separate frozen construction. Records are not trusted merely because one unchecked page arrived.
- An authorized writer checks inventory completeness against its known accepted heads/history, then signs the descriptor. A transition binds that descriptor digest and the policy/epoch intent; signatures do not recursively include themselves.

P02 must freeze exact byte encoding, page numbering, counts, parent-closure rules, digest construction and how a client proves a selected record is included. The inventory can retain compact signed evidence after payload pruning; it cannot manufacture missing payloads.

A reader cannot certify unanchored backdated writes. A new/recovered writer with no independently witnessed history also cannot infer trustworthy timing from the same server's archive. Mark unknown history UNANCHORED until reconciled with trusted checkpoints/devices. If no such evidence survives, permit explicit recovery as unverified provenance into fresh current revisions/group after review; do not silently label the old history authenticated before revocation. This is a documented availability/trust limitation, not a reason to accept forged old writes.

Valid signatures/checkpoints cannot prove that the server showed every client the newest state. Known forks or regressions pause publication and require explicit recovery. Globally consistent freshness without an independent witness/consensus service is outside v1 claims.

## 7. Revision publication and idempotency

A local draft has a stable draft_id and may survive many attempts. Each signed publication has a unique immutable operation_id/revision_id. Bind service, group, object kind, thread/parent context, author/device, policy/roster/epoch, parent revision digests, ciphertext/key-wrap digests and attachment version references. Decrypted internal references must agree with public signed routing fields.

Local states: EDITING -> DURABLE_DRAFT -> QUEUED -> SENT_UNKNOWN -> COMMITTED, with recoverable CONFLICT, REKEY_REQUIRED or ACCESS_LOST branches. A changed signature/AAD/body requires a new attempt ID. In SENT_UNKNOWN, resolve the old receipt/object identity before publishing a changed attempt. After receipt retention expires, immutable revision uniqueness still permits status reconciliation; never assume “receipt missing” proves “never committed”.

The server accepts a new head only against expected parents/current permissions. Conflicts preserve the local second edit and return exact competing head references. Do not expose a submitted but rejected branch as an accepted historical server revision. Explicit later conflict publication/merge has its own signed operation and quota effects.

## 8. File publication

Upload states: RESERVED -> RECEIVING -> READY -> COMMITTED_UNATTACHED -> REFERENCED. RECEIVING may pause/resume within the same immutable file version/epoch; cancellation/expiry releases eligible staging. A committed file is no longer cancellable by the upload-cancel endpoint.

Encryption/key path: recipient secret -> group epoch -> wrapped manifest DEK -> encrypted manifest containing the file-data DEK -> authenticated chunks. The file-data key never appears in public inventory. Byte counts and full part inventory are checked before commit, with a zero-byte file represented by zero chunks and a valid manifest.

File commit requires durable bytes then a durable DB transaction, quota conversion, receipt and event. Publishing the containing entry is a second transaction. The client keeps an encrypted publication journal linking both. A crash between them leaves a visible recoverable unattached version. Such versions count against quota and have 30-day recovery retention; live references/pins prevent cleanup.

Network retry resends identical ciphertext. Source modification or an epoch change after preparation requires a new file version, new keys/nonces, new AAD and new reservation lifecycle; old ciphertext cannot be relabeled as fresh confidential content. A source needs strong persisted identity or safe reread/re-encryption. Cancel expired staging idempotently without deleting bytes newly referenced by a commit.

## 9. Snapshot, garbage collection and restore

A snapshot freezes immutable inventory and committed watermark from one read view. Reference pins must become effective before the token is exposed, coordinated with the collector. Pages reauthorize account/device/group membership and honor the lease. A revoked member cannot continue through a previously issued token. No HTTP pagination holds a database transaction open. After the complete snapshot, apply events after its watermark; preserve outbox and independently pinned cryptographic heads.

Collector eligibility includes current references, retained entry history, conflicts, trash, explicit pins, publication recovery and live snapshot/export pins. A soft three-version target does not override these references. Delete in a staged/idempotent manner and reconcile logical versus physical freed bytes. Never infer deletion from an incomplete snapshot or an API error.

Restore starts isolated, revokes all restored credentials/sessions and changes transport generation. Group state is quarantined until signed current security state is reconciled. Previously removed identities must not regain server access solely because the backup contains their old membership. If the current state cannot be established, recover authorized content into explicitly verified fresh state; retain the archive for diagnosis/offline authorized recovery. File 12 defines operational responsibilities.

## 10. Required bounded failures

KEYS_PENDING, REKEY_REQUIRED and HISTORY_CLOSURE_REQUIRED preserve local work and explain the blocked action. ROSTER_CHANGED/POLICY_CHANGED require verified state refresh, not a blind retry loop. INTEGRITY_FAILURE quarantines data; no plaintext fallback. RESTORE_QUARANTINE forbids ordinary publication. RESOURCE_LIMIT/INSUFFICIENT_STORAGE stops before expensive work where possible. ACCESS_REVOKED stops network publication without automatically erasing the only local drafts.

These states must be distinct in typed client contracts and user feedback. File 13's R01–R24 cases test the implementation. “Designed” does not mean “tested”; production status remains governed by files 13–15.
