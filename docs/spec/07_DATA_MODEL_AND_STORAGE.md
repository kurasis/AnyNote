# Data Model, Persistence, and Storage Accounting

## 1. Modeling rules

Use InnoDB transactions, foreign keys where practical, strict SQL modes, UTC server timestamps, and explicit tenant/group authorization. Use random opaque IDs; do not encode names or emails in storage keys. Persist immutable revisions and explicit current-head references. Tombstones represent deletions; hard-deleting a row without synchronization evidence is prohibited.

MariaDB is the authoritative store for server transport state, not the source of cryptographic trust. Clients validate signed chains independently. User content is ciphertext BLOB data. Public headers use typed validated fields; never allow arbitrary mass-assignment from the request into Eloquent models.

## 2. Entity inventory

| Entity | Principal fields and relationships | Confidentiality |
| --- | --- | --- |
| users | id, login handle/contact, status, admin flag, created_at | Operational metadata; contact may use extra server-side protection |
| account_identities | user_id, root fingerprint, public identity record, root signature, recovery generation | Public verification material |
| passkey_credentials | user_id, credential ID, public credential key, counters/flags, timestamps | Authentication metadata; no private passkey |
| account_invites | creator, token hash, expiry, status, intended-recipient binding | Operational; raw token shown once |
| auth_recovery_codes | user_id, code hash, consumed_at | One-way hashes |
| sessions / refresh_tokens | user/device, hashed secret, expiry, rotation family/revocation | Authentication secrets hashed/encrypted as appropriate |
| devices | id, account, public keys, certificate ref, recovery generation, status | Public keys and opaque platform metadata |
| account_roster_events | account, sequence, parent digest, signed event bytes | Signed operational state |
| enrollment_sessions | account, expiry, public commitment, state, opaque relay messages | High-entropy secret stays off server; ciphertext relay |
| groups | id, kind, owner account, policy head, epoch head, state | Routing/ACL metadata |
| group_memberships | group, account, role, joined/removed policy references | Materialized verified authorization view |
| group_policy_events | group, sequence, parent digest, signed policy record | Public/signed membership metadata |
| group_key_epochs | group, epoch, policy/roster checkpoints, signed transition | Public transition, no raw epoch key |
| key_envelopes | group/epoch, recipient kind/key fingerprint, issuer, ciphertext, signature | Encrypted key material |
| threads | id, group, current metadata revision, archive/tombstone refs | Routing plus encrypted title in revisions |
| entries | id, group/thread, current head set, tombstone ref | Routing only |
| object_revisions | object/revision IDs, parents, schema, author, epoch, public header, ciphertext, signature | Content ciphertext |
| object_key_wraps | revision, wrapping epoch, AEAD nonce/ciphertext, signature reference | Encrypted DEKs |
| file_objects | id, group, current version/head, deletion/retention policy | Stable logical file identity; no plaintext name |
| file_versions | file/version/group, manifest revision, state, ciphertext bytes | Ciphertext references and operational sizes |
| file_chunks | file version, index, physical blob ID, ciphertext bytes/hash | Ciphertext and digest only |
| attachment_refs | entry revision or pending draft op, file version, committed state | Same-group references enforced |
| upload_sessions | device/account/group, intended file version, state, reservation, expiry | Operational metadata |
| upload_parts | upload/index, immutable digest/size/blob reference | Ciphertext only |
| quota_ledgers | global/group/account attribution, committed/reserved counters | Operational sizes |
| sync_counters | transport generation, committed sequence value | Transactional commit-order allocator |
| sync_events | sequence, scoped audience/group, entity/version, event kind | Transport hints/references; no content snippets |
| snapshot_sessions / snapshot_items | owner/device, watermark, immutable inventory, expiry, pins | Bounded stable resync/export inventory |
| security_transition_staging | transition ID, expected heads, page digests/counts, status/expiry | Bounded signed policy/key/checkpoint staging |
| membership_invites | group, target root, role, signed intent, acceptance, expiry | Pending admission, not active access |
| publication_journal | account/device, file version, target entry operation, state | Retry/recovery link, no note plaintext |
| mutation_receipts | actor scope, idempotency key, request digest, result, expiry | Content-free result or ciphertext references |
| security_events | actor IDs, action, time, outcome, limited network metadata | Restricted operational log |
| notification_subscriptions | account/device, endpoint and push material, status | Protected operational metadata |

Personal settings, read markers, favorites, drafts, and device labels use an account-private encrypted namespace backed by a hidden private group. Do not add plaintext favorite titles or search phrases to users/settings columns.

## 3. Required indexes and constraints

- Unique (group_id, epoch_number), (account_id, roster_sequence), (group_id, policy_sequence).
- Unique (object_id, revision_id), (file_version_id, chunk_index), (upload_id, chunk_index).
- Unique (actor_scope, idempotency_key); request digest mismatch yields conflict.
- Efficient (group_id, sync_sequence), (group_id, thread_id), (thread_id, event order), (recipient_key_fingerprint, group_id, epoch).
- Queue/cleanup indexes on state and expiry. Paginate revisions, chunks, recipients, devices, and audit events.
- Parent references must belong to the same object/group or the explicit supported copy operation.
- Committed attachment references cannot point to pending/failed or different-group file versions.
- Store counters as 64-bit integers in SQL; serialize large values as decimal strings in protocol JSON.

## 4. Transaction boundaries

Entry commit atomically validates current permission and epoch, inserts immutable ciphertext revision/key wrap, updates head/conflict state, appends sync event, adjusts quota if applicable, and records idempotency result.

Membership/rekey commits validate expected policy and roster heads under concurrency control. Publication of a new key epoch and its required recipient set must be logically atomic; partial recipient uploads remain staged until activated.

File bytes cannot participate in a MariaDB transaction. Use a staged state machine: write immutable ciphertext -> verify durable storage -> DB commit manifest/references/counters -> mark committed -> asynchronous orphan collection. Crash after byte write leaves reclaimable staging; crash after DB commit must leave referenced bytes recoverable. Never acknowledge a committed file before both byte durability and reference commit.

## 5. Blob layout

Use random physical blob IDs with bounded hash/ID-prefix directories, separate staging and committed namespaces, and no user-derived path components. Chunk files contain ciphertext only. Manifest ciphertext can live in MariaDB as a small object revision. Keep an interface allowing private filesystem -> object storage migration without changing the encrypted format.

Blob-store credentials/read permissions do not imply account authorization. Nginx internal locations or short-lived object-store URLs are issued only after authorization. URL TTLs must be short; previously issued URLs create a bounded revocation delay, so local filesystem/internal dispatch is preferred for v1.

## 6. Quota rules

The global 100 GB limit accounts for application-managed committed encrypted payload bytes: object ciphertext/key wraps, group-key envelope ciphertext, file chunks/manifests, previews, retained versions, and trash. Small public DB/index overhead, logs, database pages, and backups require extra physical capacity and are not represented as user content. Document this distinction in the storage screen.

Keep a small operator-controlled security-maintenance reserve outside the user content quota for necessary rekey/recovery envelope overhead. At full content quota, ordinary uploads stop while device revocation, account recovery, and necessary key transitions use the restricted reserve while it and physical storage remain available; file 12 defines safe behavior when they are exhausted. This reserve cannot be consumed by arbitrary user payloads; its bounded accounting and abuse checks are tested.

Reserve estimated maximum ciphertext bytes before accepting upload parts. Actual uploaded bytes must not exceed reservation and format limits. Global, group, and upload-origin account limits are checked in one concurrency-safe accounting decision. Shared bytes count once globally and against their owning group, not once per member. Account attribution remains stable if a contributor leaves.

Reservation conversion on commit and release on cancel/expiry must be idempotent. Do not free capacity until storage is actually eligible for reclamation; distinguish logical freed quota from pending physical deletion and ensure physical reserve prevents disk exhaustion. A reconciliation job compares ledgers to committed/staged references and reports differences before correcting under lock.

Default global pending reservation ceiling is 5 GiB and at most 2 GiB per account, within available global quota and physical free-space limits. A 1 GB upload may require more than exactly 1 GB reservation due to tags/manifests. Refuse early with usable required/available byte values.

## 7. Local stores

Windows: native SQLite holds IDs/public sync state and application-encrypted records; full DB encryption such as SQLCipher may be selected by ADR but does not replace content/key discipline. Search indexes, drafts, tokens, and filenames must not leak through plaintext tables, WAL, temp files, backups, or crash dumps.

PWA: IndexedDB for transactional records and outbox; OPFS where supported for encrypted file chunks. IndexedDB/OPFS availability and quota are capability-tested. Persist a chunk before recording it as locally available. Recover safely from interrupted writes and schema upgrades.

The same account on two installations has independent local vault keys and caches. Local cache eviction may delete downloaded replaceable ciphertext only; never evict unsynced encrypted edits or pending upload material without explicit informed cancellation. Browser-wide eviction can still remove all local state; it cannot be prevented by this application.

## 8. Retention

Trash defaults to 30 days. Three total file versions including current is a soft retention target, not a hard deletion guarantee. Every version referenced by a retained entry revision, current entry, explicit pin, active snapshot/export, conflict, or retained trash is a strong live reference and cannot be pruned. Release references only when that containing revision itself expires under policy; then excess unreferenced versions become eligible. Report why space remains pinned. Do not silently break historical attachments to force the count to three, and never prune current content just to satisfy quota.

For note revisions: keep all for the latest 30 days, then a daily snapshot for 90 days, then a monthly snapshot; keep current, conflict, explicitly pinned, and structurally required revisions. Pruning payloads must preserve compact signed ancestry/hash evidence so verification still works. This compaction algorithm is not enabled until tested; an initial implementation may retain all and enforce quota visibly.

Tombstones and compact security/ancestry records are retained long enough for old-device reconciliation. v1 keeps them indefinitely at small metadata cost; an old client beyond sync-log retention performs full resync without discarding its outbox.

## 9. Commit-order cursors and physical durability

Do not use an ordinary AUTO_INCREMENT event ID as the safe high watermark. Allocation precedes transaction commit: transaction A can allocate N, B commit N+1, a client advance past N+1, then A commit N and become permanently skipped. AUTO_INCREMENT locking is not commit-order serialization [SRC-22].

For this small service, use a single transactional sync_counters row. Each mutation acquires its normal policy/object/quota locks in a fixed documented order, then acquires the counter row lock LAST, increments it, appends all events with allocated contiguous sequence values, and commits without external I/O. The counter lock is held until commit/rollback, so no later allocated event becomes visible before prior committed events. Never wait on an external service while holding these locks. Allocate multiple events in one transaction as a contiguous range. Counter rollback is safe because uncommitted events were never advertised.

State mutations, sync events, quota deltas and receipt publication belong to the same transaction. Set/test MariaDB durability settings appropriate to acknowledged writes (including InnoDB log flush and binlog sync when used). Filesystem acknowledgement requires durable file data and directory/rename metadata under the selected OS/filesystem; a close or atomic rename alone does not prove survival of power loss. Storage-device/controller guarantees remain an operational dependency.

## 10. Bounded snapshot materialization

Create a snapshot inventory and watermark from one consistent MariaDB read view, materialize immutable references, and pin required ciphertext before exposing its token. Do not keep a database transaction open across HTTP page requests. Tokens are bound to account/device/purpose and reauthorize every page; they are not bearer authorization after removal. Resync snapshots expire after 30 minutes. Export snapshots may renew up to 24 hours while authorized, bounded to one active export/account. Cleanup releases pins on expiry/cancel. Old protocol headers/ancestry may remain after payload pruning, but no live strong reference may dangle.

Treat local IndexedDB transaction completion as browser-managed durability subject to the platform's documented guarantees, not an absolute power-loss/fsync promise. Test ordinary process termination separately from device power loss and origin eviction. SQL/global sync durability and browser local durability are different claims.

Snapshot creation and garbage collection share a defined pin/reference synchronization boundary. A consistent read view alone cannot stop a collector from deleting bytes before pins are installed. In the small-service baseline, hold a bounded GC coordination lock while materializing and committing reference pins; collectors acquire the same lock before final eligibility checks/deletion. Do not perform blob downloads or wait across HTTP under that lock. Validate all referenced blobs before exposing the token and fail/retry a snapshot whose inventory cannot be pinned. All lock acquisition follows one documented order, including cleanup, to avoid counter/GC deadlocks.
