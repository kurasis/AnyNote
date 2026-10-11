# P04 backend model and transactional foundation

P04 provides durable backend service contracts, current authorization, immutable
revision publication, accounting and commit-order event/receipt publication.
P09/P10/P11/P12 own their user-facing HTTP operations and complete workflows.
The only newly served HTTP route is operator-protected `GET /api/v1/health/ready`.
There is no generic execution endpoint, test-session issuer or dummy login.

## Run the actual checks

From the existing checkout, with the P03 pinned tools and owned loopback stack:

```sh
source scripts/runtime-env.sh
python3 scripts/dev-stack.py up
python3 scripts/p04-checks.py
cargo build --manifest-path packages/crypto-native/Cargo.toml --locked -j4
python3 scripts/p04-native-inventory.py
cargo fmt --manifest-path packages/crypto-native/Cargo.toml --check
cargo clippy --manifest-path packages/crypto-native/Cargo.toml --locked --all-targets -j4 -- -D warnings
node experiments/p01/p04-public-signatures.mjs --allow-cloud-sandbox-block
bash scripts/p03-checks.sh
```

P04 SQL checks require Docker/Compose and create/reset **only** the separately
marked `anynote_p04_tests` database inside this checkout's synthetic project.
An existing database without the exact owner marker is refused. The framework
uses the existing synthetic runtime user with grants on that test database.
No product database is automatically migrated; installation remains frozen and
read-only with respect to source, fixtures, generated contracts and lockfiles.
The disposable PUBLIC corpus lives in ignored API storage. Every root/device/
session input is synthetic. Test processes must never point at production data.

Tests install three reviewed migrations, execute PHPUnit against real MariaDB,
then start eight separate PHP child processes for retry/CAS/quota/counter races.
The counter tests observe an uncommitted watermark from another PDO connection,
prove the next allocator waits, and check commit order and safe rollback reuse.
A real SQL trigger faults receipt insertion after quota/revision/event work;
the entire mutation rolls back. The trigger is installed before the test
transaction and removed after rollback, avoiding MariaDB DDL implicit commits.

The test starts separate non-root queue/scheduler containers with a restart
policy, observes actual scheduled/queued heartbeats, kills their own PHP child
processes inside those containers, proves automatic restart and consumes another
maintenance job. It stops only these owned maintenance services in `finally`.
The development API/database stay available. Processes do not survive snapshots.

## Model and invariants

The migrations create 44 application tables; the isolated check also contains
Laravel's migration table and its ownership marker (46 tables inspected).
Threads and entries share the typed `objects` routing table rather than adding
empty duplicate tables; `kind` and same-group `thread_id` preserve that relation.
PUBLIC identities, certificates, policy/roster histories, pending grants/invites,
file/upload/snapshot/pin/journal state and operational authentication metadata
have explicit indexed relational scaffolding. Future phases extend their typed
state machines before exposing writes; an empty table is not a working feature.

IDs use case-sensitive ASCII storage. Foreign keys bind account/device and
revision/object/group relations; file versions, attachments and snapshot pins
also enforce same-group references. Counters have SQL u63 checks, use 64-bit
integers internally and decimal strings on the wire. Quota constraints prevent
negative/overflowed or over-limit totals. Immutable revisions, wraps, parents,
security histories and staged pages reject UPDATE/DELETE through SQL triggers.
Payload pruning is disabled; P13 must preserve signed evidence and live pins
before introducing a separately reviewed compaction migration.

No plaintext title, body, Markdown, filename or search-query columns exist.
Small encrypted object payloads are MEDIUMBLOB; signed headers/encrypted wraps
are separate immutable records. Content keys, R, private device keys and unlock
secrets have no server storage or acceptance path. Queue jobs contain only a
fixed maintenance class without user content. Failed-job raw exception storage
is disabled; content-free logging from P03 remains the sole application logger.

`Actor` is a transaction-local snapshot of freshly loaded SQL state, never a
client token or durable authorization handle. Every externally callable backend
service begins with a canonical 32-byte bearer secret and reloads its hashed
session, active account/device, generation and certified public key. Session
hash/owner is checked again after locking. Root identity and certificate chain
signatures/digests are verified; delegation is bounded/cycle checked and must
have the delegation capability. Current session/device/capability checks are
separate from the mathematical validity of a historical signature.

Repositories reauthorize each call and return bounded references, never an
unbounded collection of encrypted notes. Inaccessible groups/objects/receipts
are concealed. Readers can read currently accessible references but cannot
publish content. Service admin is an operational role without group membership.
Restricted, revoked, expired and disabled sessions/devices cannot use content
services. Current policy, roster, epoch and history heads must match a new
signed publication; pending/rekey/history/restore/archive states block writes.
SQL projections are honest-service authorization, not independent client trust:
P08/P10 must validate signed lifecycle transitions before changing projections;
P05/client history verification remains necessary against a malicious server.

## Atomic publication and accounting

Lock order is account/identity -> session/device -> group -> thread/object/files
-> global quota -> group quota -> account quota -> sync counter LAST. Future
multi-account changes lock related accounts in sorted order before groups;
snapshot/GC coordination follows quota and precedes the counter. No external
I/O occurs while product transaction locks are held. Bootstrap's independent
operator coordination row has no content/quota mutation path.

`ObjectService::commit` consumes closed `P04ApiObjectCommit`, compares the typed
transport route context to signed fields, verifies observed ciphertext length/
digest and complete encrypted-wrap digest, and checks parents against exact
current heads. Parent and attachment IDs cannot override group/thread routing.
Only committed same-group file versions with exact manifest digest can attach.
A successful transaction inserts immutable ciphertext/wrap/parents, replaces the
head set, records tombstone/archive state, charges actual ciphertext bytes,
appends its transport event and records the receipt together. Rejected branches
are not accepted revisions. P11 later adds explicit conflict publication.

Receipts are scoped to account/device/operation (across families), retain at
least 30 days and bind canonical bundle digest plus matching route fields. An
exact retry returns the original result while current read access survives,
without double charging/event publication or requiring old heads to remain
current. New content still requires current writer permission. A changed body
under the same operation fails; immutable IDs prevent re-publication after
receipt removal. Device-scoped receipt reads also reauthorize group access.

Quota ledgers count shared bytes once globally, once by group and once by stable
origin-account attribution. Retained revisions/trash remain charged. Reservations
have global 5 GiB/account 2 GiB pending ceilings, immutable actor/group/size,
idempotent release/conversion and expiry checks. Conversion is transaction-only
and reauthenticates current device/writer state; P12 must include it in the
actual durable file-reference transaction. There is no file durability claim.
The separate 256 MiB security reserve is operator-controlled and unreachable
from ordinary object/upload accounting; P08/P10 must add bounded verified
maintenance admission before using it. Physical free-space and reclamation/
reconciliation belong to P12/P16, not a claim inferred from SQL counters.

A single transactional `sync_counters` row allocates contiguous commit order.
It is not AUTO_INCREMENT. Counter rollback advertises no event and safely reuses
its sequence. MariaDB explicitly uses `innodb_flush_log_at_trx_commit=1` and
`sync_binlog=1`; the latter is configuration for any enabled binlog, not an
assertion that binlog/PITR or hardware power-loss behavior was exercised.

## Public signatures and generated contracts

The seven closed supplemental P04 schemas extend P03 generation to 164 types
and 80 declared operations. OpenAPI exposes explicit internal service request/
result schemas, with future HTTP ownership and no arbitrary execute route.
Operator readiness declares a current NativeBearer session requirement; no
issuer exists until P06. Missing auth, non-admin/stale auth and stale dependency
heartbeats fail closed. Public capabilities continue to report product features
unavailable until the complete user workflows exist.

Native PHP sodium verifies relevant Ed25519 public signatures. Opis JSON Schema
2.6.0 validates the **closed** public DTOs with canonical binary/u63 formats;
strict raw duplicate/UTF-8/depth/size checks precede it. Kanon 1.0.1 provides
canonical serialization for this bounded public subset: ASCII property names,
version numbers/short operational integers, typed ASCII strings, arrays,
booleans and null. It is deliberately not a general arbitrary-payload JCS API:
its ECMAScript float formatting is incomplete. P05 must select/verify general
canonicalization before accepting decrypted payloads or other numeric shapes.
No handwritten serializer or crypto primitive is substituted.

A new browser/Node public-header adapter uses maintained locked Ajv/JCS/sodium,
rejects ambiguous frames and signs/verifies exact P02 domains. A separate native
sodium adapter takes caller-validated canonical public bytes; it does not claim
native JSON decoding or trust establishment. Rust and the real browser worker
sign the same PUBLIC encrypted-object header and cross-verify byte equality with
Node/PHP acceptance. This is the required P05 public-signature fixture slice for
P04, not completion of P05 general codecs/AEAD/local wrappers/performance.
Hosted Chromium must run with sandbox enabled. Local cloud sandbox BLOCKED is
recorded honestly and cannot satisfy that gate; CI uses no allow-block flag.

Composer adds four locked package records without changing the previous 99.
The native adapter has its own frozen Cargo inventory; older P01/P02 locks,
original specification, schemas and fixture corpora remain byte-identical.
The original P02 Composer lock is preserved byte-for-byte at
`docs/reference/p02/composer-p02.lock`; an explicit P04 compatibility receipt
permits precisely four added package records, preserves the original 99 in full,
and rejects baseline/existing-package/new-version/extra-package tampering even
when a changed current-lock hash is recomputed. The frozen P02 registry is
unchanged; its original lock checksum is checked against that preserved baseline.
Thirteen actual isolated drift negatives include new PHP schema/adapters; setup
and CI compare generated bytes, never regenerate them. Primary metadata/license
receipts are in evidence; metadata/self-tests are not an independent audit.

## Boundaries and rollback

This phase does not implement WebAuthn/OAuth/CSRF issuance, enrollment/recovery
ceremonies, group invitation activation/rekey, note UI, full sync/snapshots,
physical files, garbage collection or production deployment. Their APIs remain
unimplemented; durable tables/contracts enable their subsequent implementation.
P01 physical matrix and G2/G3 qualified review remain open. No new owner device
trial is needed to validate this independent backend phase.

For development rollback, stop only owned maintenance services and use the
reviewed reverse migrations on the marked test DB, or reset that disposable DB
through the test wrapper. Never run reverse migrations against user data as an
automatic rollback: tables/immutable history would be lost. Production schema
rollout/backup/restore and migration credentials require the later deployment
phase and separate authorization. Ordinary source rollback is a normal revert.
