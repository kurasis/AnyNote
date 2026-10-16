# P16 deployment and recovery operations

This is a synthetic evaluation deployment and a set of reviewable production
artifacts. It is not authorization to deploy production. Physical G1, qualified
G2/G3, production signing, owner hardware and 100 GB capacity remain separate.
Exact-source acceptance is recorded in `docs/evidence/p16` after executed CI.

## Deployment boundary

Use `infra/operations/compose.yaml`, `environment.example`, `Dockerfile` and the
Nginx/PHP templates. Build the pinned PHP foundation, frozen Composer dependencies
and static bundle with the documented development tools first. The production
image context is an allowlist: API code, migrations, frozen vendor and public
entry point. It excludes `.env`, user storage, tests, TLS, OAuth and profiles.
The runtime image records its actual build source/input hashes. Composer's
`--no-dev` runs only in the disposable build context; project locks are unchanged.
`pcntl` supplies actual CLI worker signal/timeout handling.

Run FPM, queue and scheduler as an unprivileged UID with a read-only root filesystem,
no capabilities and no privilege escalation. Only storage and bounded temporary
mounts are writable. The separate static release directory is never mounted in
PHP. Its deployment credential must be held separately from API/backup/signing
credentials; the local staging runner necessarily acts as both synthetic operators.
Host root, Docker access, DNS/TLS and shared-host compromise remain outside API-only
isolation. Serve the origins on different hosts, never PHP routes below app origin.

Supply reviewed, externally generated files under the protected secrets directory:
`app_key`, `database_password`, `database_root`, `oauth_private`, `oauth_public`.
FPM/workers receive only the first, second and OAuth pair. The database root
credential is mounted only in MariaDB and an explicit migration one-off. TLS gets
only its server certificate/key, not the test CA private key. Backup decryption
identity, signing key, independent verification key, user root kits and export kits
stay outside these runtime mounts. Keep secret files private and owned for the
chosen UID. No secret values belong in the public environment file or build.

After reviewing the external environment, render without starting anything:

```bash
python3 scripts/operations.py --environment /secure/operator/environment render
```

The renderer requires exact distinct HTTPS origins/RP and immutable image digest.
Validate the generated Nginx configuration on the actual host before publishing
it. Use independently verified certificates, DNS, static release signatures and
image digest. Bind the edge to loopback until the owner's network policy is ready.
Expose HTTPS only; MariaDB has no host port and an internal network. Restrict
operator SSH by key/VPN/firewall, disable routine root/password login and public
DB consoles. The `/api/v1/admin/` path requires a verified operator client certificate
against an independently managed CA, plus the existing recent authenticated
service-admin role. Ordinary clients without that certificate receive404 even
with a valid admin session. A client certificate alone never grants the service
role or group ownership/content keys. Provision only the public operator CA
certificate as `tls/operator-ca.crt` in Nginx; keep operator CA/client private
keys outside runtime mounts and manage short validity/revocation independently.
Prefer VPN/network restrictions in addition to mTLS. Console/bootstrap actions
require controlled host access and also never confer content ownership.

Install migrations through the explicit root-credential one-off used in
`p16-stack.py`, then grant the runtime only SELECT/INSERT/UPDATE/DELETE on this DB.
Never give runtime DDL/GRANT/admin privileges. Test `nginx -t`, actual HTTPS/CORS,
operator health and a synthetic encrypted round trip before switching traffic.

Control JSON is at most 4 MiB; binary chunk bodies are at most 8,388,624 bytes.
Binary ingress streams without Nginx request buffering. Header/body/read timeouts,
32 service connections, 16 per IP, 20 API requests/second plus a 60-request burst,
4 FPM children/128 MiB each and bounded tmpfs mounts limit operational copies.
Select an actual proxy trust/network policy; forwarded headers are not trusted by
default. Optional push is not configured and is never required for synchronization.
Limit egress at the host/network to reviewed DNS, update, backup and optional
mail/push destinations. No arbitrary content-supplied fetch facility is introduced.

Authorized downloads use an internal X-Accel location with generated opaque IDs;
external requests cannot access it. Internal redirects explicitly carry only
API-approved CORS/request-ID headers and HSTS. A durable hard link bridges authorization and
Nginx opening the file, preventing GC from breaking an admitted transfer. At most
1,000 delivery tickets/links exist, with one-hour expiry and bounded collection.
Orphan links retain a grace period; they never grant external URL access. Range
requests remain refused because a partial AEAD frame cannot authenticate. Retained
links can consume physical space after logical collection: include them in sizing.

## Consistent encrypted backup

The operator command takes an exclusive deployment lock, verifies the running API
image, drains/stops FPM and both supervised writers, confirms no one-off writer
remains, reconciles references, exports a security checkpoint, takes an InnoDB SQL
dump and streams that dump plus every private opaque blob into standard age.
The complete encrypted file is signed with a separate Ed25519 key through OpenSSL.
No final backup is published until encryption and signing finish and the output
and containing directory are fsynced. Publication never replaces an existing file.
Normal completion/failure restarts only writers that had been running.

All operator mutation commands must respect that lock; do not open an independent
SQL writer/maintenance container during the pause. Runtime SQL has no external
listener. This is an explicitly measured mutation pause, not an online snapshot
or arbitrary DB/blob-copy claim. Staged metadata and ciphertext are included;
client recovery kits and content private keys are never collected.

```bash
python3 scripts/operations.py --environment /secure/operator/environment backup \
  --output /separate-encrypted-backup-volume/point.age \
  --signing-key /offline-operator/backup-signing.pem \
  --checkpoint-directory /restricted-append/security-checkpoints
```

The public backup recipient and verified age executable are in the environment;
the private identity is not needed for creation. Use an encrypted private working
volume: a bounded SQL dump exists in a mode-0700 temporary directory during creation.
Normal failures remove only that temporary directory; abrupt host/power loss can
leave it, so inspect it privately before exact owned cleanup. SIGTERM interruption
is handled without publishing an incomplete backup. An unpaired signature or
`.partial`/temporary output is never a successful restore point.

The signed encrypted manifest includes source/image, public origin/RP/service
configuration, static asset/Nginx hashes, complete member sizes/digests, DB table
counts/checksums, transport watermark, reference reconciliation and a security-checkpoint
commitment. Reinject operational secrets from independent custody after recovery;
rotate them on suspected compromise. E2EE recovery does not depend on APP_KEY.

Use daily recoverable points, 14 daily and 8 weekly retention, separately budgeted
capacity and periodic sampling. Copy to a different host/provider/media with
restricted deletion credentials and at least one immutable/offline copy where
available. The synthetic fixture's separate directories/filesystems are not proof
of an independent provider or immutable-storage policy. No automatic deletion of
restore points is enabled. Only an explicitly reviewed retention job may delete a
verified redundant point after independent-copy verification.

Run the signed/encrypted `checkpoint` command regularly and following important
revocations, using protected append-only off-host custody. Each point commits to
its predecessor and records current account/roster/device/passkey/group heads.
Pin the latest digest independently; a digest supplied by the restored server is
not a trustworthy latest checkpoint. This export assists honest recovery; it is
not a globally trusted transparency service and has a measured export-lag window.

## Restore and trusted content recovery

Always provision a separate clean target/environment/image with new operational
credentials. The restore command refuses existing DB state or any existing Compose
project containers, authenticates the entire encrypted archive before decryption,
rejects unsafe/duplicate/missing/changed components, verifies authenticated age EOF,
and uses a finite disk reserve before extraction/import. It requires the exact
recorded API image and an independently held latest security-checkpoint digest.

```bash
python3 scripts/operations.py --environment /secure/isolated-clean/environment restore \
  --archive /independent-backup/point.age \
  --verification-key /independent-operator/backup-verification.pem \
  --identity /offline-operator/backup.identity \
  --latest-checkpoint-sha256 INDEPENDENTLY_RECORDED_LATEST_DIGEST
```

A host fence precedes SQL import. Reconciliation then verifies immutable blob
sizes/digests and exact table checksums, retained note wraps, chunk manifests, key-envelope epochs and roster
heads. Restored sessions/refresh families/OAuth grants are revoked; challenges and
approvals expire; every group is quarantined and transport generation changes.
A persistent SQL fence also prevents access if the host fence file disappears.
Every ordinary authentication/content entry point stays denied. An old checkpoint
or a new transport generation alone cannot reauthorize an old member/device/passkey.
There is deliberately no HTTP/CLI “clear quarantine” or admin decryption option.

This implementation selects the specification's conservative recovery-source path:
keep unreconciled restored state quarantined and recover into explicitly verified
fresh identity/group/service state. It does not assert complete latest security
history or silently lower surviving client pins. Publish the exact restore point,
missing later writes and unavailable history before users choose a recovery path.
An unchanged already-running client's encrypted drafts/immutable attempts remain
on that client; selecting another recovery source never clears its outbox or pins.

For a witnessed private epoch-zero group, the operator can export a bounded
ciphertext catalogue from the fenced DB with `operations:catalogue GROUP_ID`.
Transfer only that ciphertext catalogue and matching restored opaque blobs to the
authorized offline user. That user supplies their separately retained root kit
and independently witnessed account/roster/genesis/revision checkpoint. Never take
the checkpoint from the untrusted restored catalogue itself.

```bash
node scripts/p16-recover.mjs --catalogue recovery-catalogue.json \
  --blobs recovered-opaque-blobs --kit account.kit.json --checkpoint witnessed.json
```

The clean process uses existing maintained root/envelope/note/file primitives,
verifies independent pins and every selected signed record/chunk/full file digest,
and has no network or original device cache. Explicit plaintext export requires a
new destination and `--output recovered --plaintext-confirm`; all content validates
before any output directory is published. It never exports root/device keys.
This bounded helper supports private epoch zero, up to 1,000 retained notes and
32 files. Shared/rotated/history recovery uses the existing P13 portable age archive
and separate export recovery document (`scripts/p13-offline.mjs`), preserving full
historical verification. Server backup, user root kit and independent portable
export remain distinct. A root secret cannot override removal from another group.

Copy selected recovered content through the maintained client into a freshly
verified private destination with new IDs/DEKs/current epoch. Retain original
archives as provenance, not newly trusted live history. The executed synthetic
journey also re-encrypts/downloads the recovered 1 GB and verifies its full hash.
If keys/ciphertext/trust cannot be established, preserve the quarantined source
and declare that content unavailable. Never weaken authentication/signatures.

## Maintenance and monitoring

Compose supervises queue/scheduler with graceful stop and bounded job timeout
(150 seconds; retry-after 240; stop grace 190). Heartbeat jobs prove actual queue
processing. A failed-job event records an aggregate timestamp only; production
uses the null failed-job provider to avoid persisting raw payloads/exceptions.
A recent failure makes health unavailable and requires investigation; DB outage
can itself prevent writing the failure marker, so independent health alerts matter.

`operations:maintain` uses a cross-process MariaDB advisory lock and bounded,
idempotent auth/upload/invite/enrollment/delivery collection. It removes only
expired unpublished grant pages after grace, preserving burned commitments and
all committed key envelopes, policy/roster journals and referenced payloads.
Content retention remains report-first and explicitly owner-applied. No automatic
purge of current content or generic old-key deletion is enabled.

Use private `operations:health` and the operator `health` command with verified
backup/drill receipts. Monitor DB durability/availability, real scheduler/queue
heartbeats, queue depth/failure timestamp, delivery count, free blob/DB space,
backup age <=24 hours and drill age <=30 days. Safe request-log tails expose
bounded request/error/latency/signature/rate-limit aggregates without payloads,
URLs, IPs, titles, account/device labels or exception dumps. Diagnostic logs use
30 daily rotations, file mode0600; provision separate bounded log capacity and
restrict ingestion/retention. Never enable HTTP body capture for encryption faults.

Preserve at least max(10 GiB,10% of the data filesystem) beyond ordinary note/file
admission and independent backup/restore working copies. Model DB, logs, indexes,
proxy/PHP temp, export, hard-link grace and backup capacities separately. The
100 MiB logical security allowance is finite, not a physical-space guarantee.
If durable tiny security writes cannot commit, stop writes and enter operator
recovery; do not acknowledge an unpersisted revoke. Do not fill the owner disk for
a test. Capacity results state actual ciphertext, signed rows, request spacing,
latency, disk and memory scope; no sparse/fake100GB inventory is accepted.

## Incidents and updates

| Trigger | Containment and recovery |
| --- | --- |
| DB/blob disclosure | Preserve independent evidence, isolate credentials/backups, rotate operational secrets, identify metadata exposure; validate actual client-key/plaintext scope. E2EE does not hide metadata. |
| API compromise | Stop API/writers, preserve signed checkpoints and offline evidence, rebuild the exact reviewed image on a clean host, revoke sessions and retain restore quarantine; logs may be compromised. |
| Static/PWA/build compromise | Stop unsafe static delivery, warn users not to enter recovery secrets, compare a separately signed complete static manifest, rotate deployment/release credentials and prefer independently verified offline/Windows recovery. Secrets entered in malicious client code may be compromised. |
| Device loss | Current signed device/session revoke, descendant closure/rekey and explicit cached-data limitation. No remote erasure claim. |
| Lost/leaked recovery secret | Missing secret has no administrator escape hatch. Use surviving independently verified device/export custody if available; leaked R requires fresh identity/reverification/epochs and explicit migration, not a password-only change. |
| Disk full/object/fsync/DB failure | Stop ordinary reservations/writes, preserve existing content/quotas, alert on capacity/durability, reclaim only eligible expired staging/cache, then verify reference/quota reconciliation before retry. |
| Interrupted backup/restore | Treat incomplete output as failed; leave restored target fenced, preserve evidence, inspect owned temporary state privately and provision another clean target. Never overwrite live data to retry. |

`verify-static` checks an independently signed complete release manifest against
the exact asset bytes before serving. The drill changes a copied synthetic script,
requires rejection, isolates the actual owned edge/API and proves delivery stops;
it never executes malicious code or publishes a production release.

For updates, verify the new image/static manifest, backup and recovery path first;
drain workers, apply additive migrations with separate credentials, verify health
and switch immutable releases. Never run generic destructive migration rollback.
Rollback requires a reviewed data-preserving plan: new encrypted client state,
signed history and immutable server rows cannot be downgraded by restoring old code.
Source templates and synthetic receipts do not establish production sizing,
independent review, physical iPhone behavior or an online eight-hour recovery SLA.

## Reproducible synthetic acceptance

```bash
source scripts/runtime-env.sh
python3 scripts/check-p16.py
python3 scripts/p16-stack.py build
python3 scripts/p16-drill.py run
node packages/protocol/p16-capacity.mjs
```

Clean acceptance refuses existing source/capacity datadirs or containers; use a
fresh isolated CI host. It never resets retained local staging. The runtime
report observes real scheduler/queue/durability/capacity health before the drill.

The fixture derives mount UID/GID from the actual runner; it never assumes UID1000.

Run destructive/fault suites only in their explicitly marked synthetic databases.
The normal hosted workflow runs operations and capacity on separate clean runners;
all27 inherited gates remain mandatory. Actual1GB/O01–O05 and10-account/50-device/
100,000 signed-revision SQL/HTTP capacity reports are distinct from NOT_RUN100GB
inventory. Local small development fixtures are labelled DEVELOPMENT_PASS and
cannot satisfy the final verifier. Raw receipts retain source commit/input hashes;
public archives contain no user kit, private signing/decryption key or SQL backup.
