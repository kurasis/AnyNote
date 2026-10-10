# Deployment, Backups, and Operations

## 1. Deployment baseline

Use maintained Linux packages/container images and supported Laravel/PHP/MariaDB/Nginx versions recorded in the bill of materials. A single application host is adequate for initial scope. A provisional sizing starting point is 2–4 vCPU, 4–8 GB RAM, and at least 200 GB working disk for a 100 GB content quota, plus separate backup capacity. This is a planning estimate; P16 load/restore tests determine actual capacity.

Prefer a separate static PWA release location with independent deployment credentials. Keep PHP-FPM unable to write application code/static assets. Use a least-privilege runtime user, restricted writable storage directories, and a MariaDB application user without administrative grants. Separate migration credentials from runtime credentials when operationally practical.

## 2. Nginx/PHP-FPM

Serve only Laravel's public entry point and approved static paths. Deny dotfiles, environment files, source/config backups, private storage, and arbitrary PHP execution under uploads. Configure trusted proxies correctly before using forwarded client IPs or rate limiting.

Enforce endpoint-specific request limits, body/header timeouts, connection limits, and TLS settings. Chunk uploads need bounded temporary storage and known buffering behavior. File delivery uses authorization followed by an internal Nginx location/X-Accel-Redirect with a server-generated safe path; an external request cannot access that internal location directly [SRC-16].

Tune PHP-FPM worker count to memory and actual bounded request behavior. No single worker buffers a 1 GB file. Production debug is off; error pages and logs contain request IDs, not application secrets. Workers run under supervision with graceful restart handling for jobs.

## 3. Network and administrative security

Expose only HTTPS and tightly controlled administration. Keep MariaDB private. Use operator SSH keys and appropriate network restrictions; no routine root login or public database admin UI. The app's service-admin role is distinct from Linux/root access and from cryptographic group ownership.

Outbound traffic should be limited to necessary updates, optional mail/push, and backup destinations where practical. No arbitrary server URL fetching from user content. Use separate credentials and least privilege for backups, static deployment, runtime API, and release signing.

## 4. Operational secrets

Inventory Laravel APP_KEY, database credentials, session-signing secrets, email/push credentials, backup encryption secrets, TLS keys, code-signing keys, and updater keys. These are not E2EE content keys. Rotating APP_KEY must be planned for server-managed secrets/sessions but must not be required to decrypt user notes.

Do not store secrets in git, example environment files, build logs, task transcripts, or frontend bundles. Supply .env.example with placeholders. Development uses synthetic accounts/keys; production credentials are injected through the deployment environment. Never copy production data to an AI-accessible test environment without explicit authorization.

## 5. Backup policy

Back up MariaDB, committed ciphertext blobs, necessary staged-state metadata if supporting in-progress restore, public identity/policy/roster history, key envelopes, and application configuration needed to reconstruct the service. Recovery kits are user-held and never collected into the server backup.

Use application-consistent snapshots: briefly pause mutation commits or use a documented watermark/snapshot strategy with immutable blob retention until the DB backup completes. A DB snapshot and unrelated blob copy taken at arbitrary times can produce missing references. Backups must include deleted-but-still-referenced versions as appropriate to that snapshot.

Apply independent backup encryption to protect operational metadata and credentials in addition to E2EE ciphertext. Store backups on another host/provider/media with restricted deletion rights. Maintain at least one offline or immutable copy where practical. Backup capacity and retention are separate from the 100 GB user quota.

Initial policy: daily recoverable backup, retain 14 daily and 8 weekly restore points; use incremental/deduplicating backup of immutable ciphertext if supported safely. Optional MariaDB binlog/PITR can reduce data loss but requires a correspondingly consistent blob strategy. Initial RPO target <=24 hours, RTO target <=8 hours; measure both and do not claim them as met without drills.

## 6. Restore procedure

1. Restore into an isolated clean environment; do not overwrite live service first.
2. Verify backup authenticity/integrity and decrypt the backup layer.
3. Restore DB and matching immutable blobs/configuration.
4. Run reference reconciliation: committed versions/chunks/key envelopes/policy chains exist.
5. Verify synthetic or consenting test users can recover/decrypt representative notes and a 1 GB file from a clean client.
6. In every restore, invalidate restored sessions, refresh families, pending approvals and authentication challenges. If compromise is suspected, also rotate operational credentials. Enable recovery-only access until device, passkey and membership revocations have been reconciled; an old backup must not reactivate revoked access.
7. Establish a new sync transport generation so clients detect old cursors and perform safe reconciliation.
8. Existing clients may know newer cryptographic checkpoints than the restored DB. Show explicit rollback/recovery state; do not silently lower trusted checkpoints. Reconcile from surviving client-held signed data or acknowledge unrecoverable later writes through an explicit operator/user recovery procedure.
9. Re-enable each group only after current signed security state is reconciled and fresh required epochs are committed. If that state cannot be established, preserve the restored data as a quarantined recovery source: authorized users recover selected content into a fresh, explicitly verified group/identity. Never silently reinstate old members, devices or passkeys. Publish the exact recovery point and unavailable changes.

Run a restore drill before release and periodically afterward. A successful archive extraction or DB startup is not a completed restore test.

## 7. Scheduled maintenance

Jobs: expired invitations/enrollment cleanup, expired upload cleanup after 72 hours inactivity, reservation reconciliation, orphan blob collection, trash/version retention, session expiry, notification endpoint cleanup, backup, restore sampling, dependency-update review, and free-space checks.

All jobs are idempotent and concurrency-safe. A cleanup job must not delete a blob referenced by a committed file or a retained snapshot. Use delayed deletion/grace periods for race resistance. Failures raise operational alerts without content payloads.

## 8. Observability

Measure request errors/latency, worker memory, queue depth, failed signature counts, authentication abuse, transfer success/resume rates, committed/reserved bytes, physical free space, backup age, restore-test age, and client protocol distribution. Avoid high-cardinality plaintext labels. Account/device IDs in restricted logs still deserve privacy controls.

Default diagnostic/security-log retention: 30 days unless an incident or explicit policy requires longer. Redact before ingestion, not only in the UI. Never enable full HTTP body capture to debug a production encryption issue. Diagnostic exports are opt-in and previewable, with synthetic reproduction preferred.

## 9. Incident runbooks

Database/blob disclosure: preserve evidence, rotate operational credentials, identify metadata exposure, validate that no plaintext/key material leaked, and communicate actual scope.

API compromise: isolate/rebuild, revoke sessions, compare signed checkpoints, inspect role/device anomalies, and avoid assuming server logs are trustworthy.

Static PWA/build compromise: stop serving unsafe releases, warn users not to enter recovery secrets, inspect release credentials, and treat secrets used in the affected client as potentially compromised. Prefer independently verified Windows recovery. E2EE is not grounds to dismiss this incident.

Lost device: revoke device/session, trigger group rekey, disclose previously cached-data limitation. Leaked R: new account identity/reverification workflow, fresh epochs, and explicit migration; changing login password alone is insufficient.

Disk full: stop new reservations, preserve existing data and DB health, surface actionable capacity status, and reclaim only eligible staging/cache. Never purge current user content automatically.

## 10. Deployment artifacts

Deliver reproducible development setup, production configuration templates, migration/rollback procedure, secrets inventory without values, backup/restore commands, health checks, service-unit/container definitions, signing instructions, update procedure, and operator checklist. Commands must be reviewed in the actual host environment; documentation examples are not permission to deploy or delete production resources automatically.

## 11. Capacity and restore safety refinements

Reserve working space beyond the logical content quota for MariaDB, upload buffering, indexes, binary logs, snapshots, exports and recovery. Stop new data reservations when free data-volume space falls below max(10 GiB, 10% of that volume); tune only with measured evidence. Account for every copy made by proxy/PHP temporary buffering. Separate DB/log capacity from a fillable blob volume where practical. A 200 GB starting disk is not a guarantee that a 100 GB corpus plus every operational copy fits.

The 100 MiB logical security-maintenance allowance is finite and restricted. It does not guarantee operations on a physically full disk. Rate-limit transitions, reclaim only expired unreferenced staging, and reject ordinary content against the main quota. Preserve independent space for tiny revoke/status records. If safe durable commits are impossible, stop writes and enter operator recovery; never acknowledge an unpersisted revocation or silently drop grants.

A backup may precede passkey deletion, device revocation, member removal or account disable. A new transport generation alone cannot repair those security regressions. Restore mode accepts neither restored cookies nor ordinary restored credentials for content access. Reconcile surviving signed roster/policy checkpoints and separately reconcile server authentication state. Root-proof recovery is rate-limited and limited to identity recovery until group authorization is established; possession of a recovery secret does not override a later removal from someone else's group. A user who had already received old ciphertext may still decrypt that historical copy, which no restore procedure can revoke.

Maintain a protected off-host security-event journal/checkpoint export to assist recovery, with integrity protection and restricted append credentials. It improves honest restore completeness; it is not an independent globally trusted transparency service. If recovery-only login cannot be securely established, use offline portable exports and a fresh installation instead of weakening authentication.
