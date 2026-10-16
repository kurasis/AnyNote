# Operator handoff and maintenance ownership

The service owner is the accountable operator until named maintainers explicitly
accept custody. P18 supplies software/runbooks; it does not invent an acceptance
signature or authorize production. Read [release eligibility](P18_RELEASE.md) and
the detailed commands in [operations](P16_OPERATIONS.md) before any rollout.

## Responsibilities and custody

| Role | Required responsibility and separate custody |
| --- | --- |
| Service owner | Support contact, supported-device scope, access policy, incident decisions, retention/legal decisions and maintenance appointments |
| API/database operator | HTTPS/DNS/firewall, immutable image, runtime DML-only privileges, explicit migrations, health/capacity, encrypted backup schedule/restore tests |
| Static deployer | Separate app HTTPS origin, reviewed exact static bundle/CSP, deployment credential isolated from PHP/backup; treat origin compromise as content-key exposure |
| Release signer | Offline/controlled Authenticode and updater signing, exact final digest/claims, independent verification; never mount private signer material in runtime/CI artifacts |
| Backup custodian | age decryption identity, separate signing/verification material and append-only witnessed security checkpoints outside the API host |
| User | Independent account root/export kits, device verification, local unlock, plaintext export decisions; administrator custody never substitutes for user content secrets |
| Independent reviewer | Actual review/report/remediation retest; AI checks and advisory scans do not assume this role |

No real secrets go in chat, source, image layers, Actions reports, environment
examples or support attachments. Distinct backup encryption, backup signing,
updater signing, Authenticode, static deployment, OAuth/TLS and user recovery keys
are not interchangeable. Record public verification fingerprints and custody
handover out of band. Retain the exact source/notices/ZIP receipts for every
candidate; Actions artifacts expire after14 days.

## Installation and update plan

1. Complete external release gates and obtain explicit production authorization.
   On an isolated appropriately sized host, verify the review set `SHA256SUMS`,
   source/job/ZIP receipts and all manifests through the trusted channel. The
   candidate verifier authenticates consistency only; production signatures and
   independent trust must come from the release ceremony.
2. Provision distinct trusted app/API HTTPS origins and exact RP/service identity.
   Generate secrets outside the runtime image. Use the reviewed immutable image
   digest, unprivileged UID/read-only filesystems, internal-only DB and bounded
   storage/tmpfs. Render the production templates with `operations.py render`.
   Preserve the10GiB/10% disk reserve and the restricted security reserve.
3. Validate real Nginx/TLS/CORS/health and mTLS plus recent role for administration.
   Run migrations once with the isolated privileged credential, then grant runtime
   only SELECT/INSERT/UPDATE/DELETE. Never ship the P16/P17 fixture control mount,
   synthetic CA/private keys or test operator identity. Start a clean owned
   synthetic acceptance deployment before switching any real traffic.
4. For an update, take/independently verify a consistent encrypted backup and newest
   security checkpoint, record exact image/static/client versions and pause writes
   under the existing operator lock. Rehearse migration/client preserved-state
   update on a separate synthetic/restored environment first. Apply the reviewed
   additive migration explicitly, switch immutable API/static releases and check
   health plus an encrypted synthetic round trip. Existing CI tests actual Windows
   quiet upgrade and PWA waiting-worker activation with preserved drafts/outbox.
5. Monitor readiness, quota/physical space and errors. Record who performed and
   accepted the change, actual start/end/downtime and evidence IDs. On failure,
   stop admission/publication, preserve the failed deployment and use isolated
   recovery. Do not downgrade a local schema or restore an old DB over live trust
   state. Windows downgrade/untrusted signatures must remain rejected. A backward
   binary switch is permitted only after a separately tested schema-compatible
   plan; none is presumed by P18.

An API image archive is a saved Docker image, not a VM or a complete production
host. Validate the image digest before loading/running and review deployment
environment separately. The PWA package is bound to the tested synthetic issuer;
rebuilding it for a real issuer creates new bytes requiring fresh exact-artifact
validation/signing. Never replace the issuer in an already checked archive and
keep its old checksum/evidence claim.

## Backup, retention and recovery

Schedule consistent age-encrypted, separately signed backups on a different
failure domain. The command drains/stops actual API/queue/scheduler writers under
the operator lock and fsyncs before no-replace publication; do not run another SQL
writer during that pause. Independently retain the newest chained security
checkpoint and source/image/static identifiers. Back up operational secrets by a
separate approved encrypted custody procedure; user content kits are never
collected by the operator backup.

Starting retention policy for owner review: daily encrypted restore points30days,
weekly12weeks and monthly12months, with access restricted to the backup custodian.
This schedule is a proposed policy, not a configured job or legal approval. Keep
at least one independently verified complete restore chain and newest security
witness; do not automatically delete the last good backup or independent evidence.
Choose final schedule/off-site costs/legal retention before production and record
who approved it. Test clean-host recovery after dependency/migration changes and
regularly thereafter. The default note/file retention and quota rules in the
frozen specification remain authoritative; a backup policy is not permission for
server/client garbage collection or silent history compaction.

Restore only into a new isolated environment. Verify archive signature/digest,
safe member inventory, exact image and newest independent security checkpoint.
Restore changes transport generation and quarantines all restored credentials/
security. Do not unquarantine from an old DB's own statements. Current signed
security reconciliation is not implemented as an automatic exit. Keep the source
archive and old clients' encrypted drafts/outbox unchanged. The root-kit reader
verifies private epoch-zero content against an independent checkpoint, up to1000
notes/32files; missing/modified material refuses output before publication.

Use the corresponding source, frozen `npm ci` dependencies and documented offline
commands in [P16](P16_OPERATIONS.md) or [P13](P13_CONTENT.md). The server cannot
decrypt without the user's separately held authorized secret. Shared/rotated/
history exports need the portable archive plus its separate kit. Verify first;
plaintext output requires explicit confirmation and a new private directory.
Then authenticate a fresh identity, verify its independent card and copy/import
selected authorized current content into fresh groups/keys. Independently reverify
shared participants; never restore their old access merely because a backup has
it. Measured backup pause, data-loss window and RTO are exact report fields in the
P18 acceptance's inherited P16 receipt, not promised production SLAs.

## Routine checks and incident response

Check operator health, queue/scheduler heartbeat, disk reserve, storage/journal
consistency, backup completion/signature and advisory changes. Keep logs
content-free; disable body/APM capture and restrict operational metadata retention.
Use the existing supervised maintenance command for expired invitations/uploads;
it must preserve committed references. Do not delete blobs/SQL/profile files by
hand to regain space. Optional outbound push stays unsupported404 until its DNS,
private-address and redirect protections are implemented and reviewed.

| Incident | Immediate action | Recovery boundary |
| --- | --- | --- |
| Disk full, DB outage, failed fsync, stopped worker | Stop new admission/writes as needed, preserve journals, restore capacity/service, inspect health and exact error; never acknowledge uncommitted bytes | Reconcile through the maintained quota/reference/receipt flow; do not clear client pending work |
| API/server compromise | Isolate service/network, preserve encrypted evidence, revoke operational credentials through approved custody, rebuild on a clean host | Server control cannot supply missing content secrets; old security state stays quarantined |
| Static origin/release signer compromise | Stop delivery, warn through independent channel, preserve signed inventory and actual bytes, rotate/review custody before a fresh approved release | Malicious unlocked-client code may have read keys/plaintext; E2EE does not remove this exposure |
| Lost/stolen device | User verifies surviving device, reviews descendant revoke set, revokes and completes rekey | Cached old copies cannot be remotely erased; preserve legitimate unsent work privately |
| Lost root/export secret | Inventory surviving trusted devices and independently stored kits; preserve ciphertext | No administrator decryption bypass; if no authorized secret survives, content may be irrecoverable |
| Root secret compromised | Suspend trust and plan fresh identity/content migration with independent verification | Repeated generation resets cannot make a known compromised root secret secret again |
| Integrity failure/rollback/fork | Stop publication and retain ciphertext/checkpoints/attempts; investigate through a trusted channel | Do not ignore signatures, downgrade checkpoints or retry with plaintext fallback |

Support receives version/source, platform, UTC event time, bounded error and saved/
pending/unknown state only. Request a redacted evidence manifest rather than full
databases, note bodies or keys. Owner chooses named support/escalation contacts
before production; P18 does not message or appoint third parties. Future work is
the separately authorized external-gate closure in [NEXT_TASK](NEXT_TASK.md).
