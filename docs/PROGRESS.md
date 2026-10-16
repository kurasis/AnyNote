# Implementation progress

Status vocabulary: NOT STARTED, IN PROGRESS, IMPLEMENTED / UNVERIFIED, BLOCKED,
VERIFIED. Evidence outcomes: PASS, FAIL, BLOCKED, NOT RUN. A document or scaffold
does not satisfy a feature gate. Production release is not ready.

P15 postmerge follow-up: the ordinary merged-main cohort finished 25/27, with
PWA unlock and Windows updater-observer failures. Generation fences and
handle-free installer observation are implemented with added runtime regressions;
their clean exact-head CI/merge evidence is separate. See
[postmerge lifecycle evidence](evidence/postmerge-lifecycle/README.md).

| Phase | Status | Evidence / remaining gate |
| --- | --- | --- |
| P00 | VERIFIED | Local baseline and four negative cases passed; scope/version/inventory deliverables complete; remote bootstrap and clean-clone verification passed; both baseline Actions runs verified |
| P01 | IN PROGRESS | Host crypto/KDF/storage/export/fault evidence VERIFIED; owner 0.1.4 fresh-process Hello authentication, WTS lock/STALE, installed-iPhone-PWA selected 1 GB hash and diagnostic recovery PASS; full physical G1/memory/network matrix remains open |
| P02 | VERIFIED | Complete five-component registry, exact note/local/native/sync/snapshot/restore/age formats, frozen bytes and independent PHP/Python/Rust-age/Go-age subsets; external review TRACKED_NOT_BOOKED / NOT_RUN; G2/G3 and product phases remain open |
| P03 | VERIFIED | 79 initial OpenAPI operations / 157 schema-derived types; strict errors/request IDs/content-free logs; frozen setup, drift negatives and actual owned HTTP/SQL integration verified; product operations remain phase-owned |
| P04 | VERIFIED | 21 tests/322 assertions, 578 actual SQL checks, eight-process concurrency/fault recovery and supervised restart; Rust/Node/sandboxed Chromium/PHP public-signature corpus PASS |
| P05 | VERIFIED | Full native/browser core; 146 frozen frames, general RFC8785, fresh two-way Worker/Rust bytes and PHP public signatures; all eight hosted jobs PASS, actual native/Worker 1 GB measurements retained; physical memory and independent review remain open |
| P06 | VERIFIED | 215 actual HTTPS/SQL attack checks, 18 sandboxed strict-CSP browser checks, four native tests on Linux/Windows; all ten hosted gates PASS; exact-source evidence retained |
| P07 | VERIFIED | Five Node custody suites, 28 actual HTTPS/SQL and 28 sandboxed browser checks, fifteen native custody tests per Linux/Windows platform plus explicit official-header ABI; all twelve hosted gates PASS |
| P08 | VERIFIED | Seven Node workflow suites, 16 dense QR round trips, 153 actual HTTPS/SQL checks, 33 sandboxed UI checks and nine native device tests per Linux/Windows; all fourteen hosted gates PASS |
| P09 | VERIFIED | Eight workflow/transport suites, 131 actual HTTPS/SQL checks, 49 sandboxed two-PWA UI checks, six native note tests/platform and 16 native/PWA interop checks/platform; all sixteen hosted gates PASS |
| P10 | VERIFIED | Five protected workflow/transport suites, 407 actual HTTPS/SQL checks, 40 sandboxed three-account PWA checks, three native shared tests and 89 native/portable interop checks/platform; all eighteen hosted gates PASS |
| P11 | VERIFIED | Ten portable suites, 112 actual sync HTTP/SQL checks, 418 membership/lease checks, 45 sandboxed PWA checks, seven native notes and nine new interop checks/platform; all twenty final code jobs PASS; Worker masking and background idle guards verified |
| P12 | VERIFIED | Twelve portable file tests, 368 actual file HTTPS/SQL checks, 452 shared-authority checks, 60 sandboxed PWA checks, native 1 GB/cache/atomic export on Linux/MSVC; all twenty-two software gates PASS; physical G1/U11/U12 and qualified G2/G3 remain open |
| P13 | VERIFIED | Protected content UX, safe previews/thumbnails, reference-safe retention, independent age recovery and fresh standard import; 401 HTTP/SQL, 427 authority, 59 sandboxed UI checks, actual Linux/Windows 1 GB archive and all 24 software gates PASS; physical/review gates remain open |
| P14 | VERIFIED | Native Windows/WebView2 single installer, actual dialogs/SQL/1GB/recovery/upgrade/restart, all 25 software gates; physical and production signing remain open |
| P15 | VERIFIED | Installed PWA shell, EN/RU mobile/keyboard UX, exact 1 GB/API/recovery/import/update/quota software acceptance and all 27 mandatory candidate jobs; final merge is gated by the same exact-head cohort; physical/review/signing/memory gates remain open |
| P16 | NOT STARTED | P04/P08/P11–P13 and appropriately sized synthetic host |
| P17 | NOT STARTED | P02/P08–P16; independent review |
| P18 | NOT STARTED | P14–P17 and release/signing gates |

## Completed task: P00-BASELINE

Establish the empty repository, preserve the owner's specification, lock the
accepted scope, select exact maintained development candidates, document risks
and provide reproducible baseline checks. No wire contract or data migration
changes. Original files: `docs/spec`; new implementation records: `docs`.

Rollback: this initial task adds files only and has no user data to migrate.
Revert its reviewed commit if necessary; do not rewrite published history.

See [test evidence](TEST_EVIDENCE.md) and [next task](NEXT_TASK.md) for exact
commands, outcomes, blocked gates and continuation scope.

## Completed slice: P01-CRYPTO-INTEROP

Isolated Rust/Node/browser-worker primitive and bounded-file feasibility harness.
Pinned Rust/Node installed outside the checkout; Cargo/npm lockfiles preserve
resolved dependencies. No application protocol or migration changes. 663 live/frozen-corpus
primitive checks passed in Rust/Node/real Chromium. Actual native 1 GB disk and
browser generated-stream ciphertext upload/download round-trips passed on hosted
Ubuntu. Native peak RSS: 27,212 KiB; Chrome sampled incremental aggregate RSS:
421,376 KiB, so mobile memory feasibility remains unresolved. The cloud browser
sandbox itself remains blocked; hosted tests retained the sandbox.

The owner supplied Windows 11 Pro 25H2 with Hello planned and iPhone 17 Pro /
iOS 26.7.1 (reported, not inspected). Exact working/current passkeylocal source
snapshots are preserved in docs/reference/passkeylocal and inform ADR-003 and
P01-LOCAL-UNLOCK. Physical G1 and qualified review are not complete. Rollback:
revert this isolated experiment/reference addition; there is no user data or
production-format migration. See evidence and NEXT_TASK.md for continuation.

## Completed slice: P01-LOCAL-UNLOCK

Added bounded Argon2id13 v1 vectors (64 MiB / opslimit 3) across Rust/Node/real
Chromium worker, wrong-phrase and invalid-profile checks, single worker KDF
admission, ciphertext-only IndexedDB/OPFS reopen verification and bounded quota
fault injection. Real selected File upload/download/explicit OPFS export at
decimal 1 GB verified saved length and SHA-256 against independent Node output.
Initial incognito/post-quota-injection export failed with QuotaExceededError;
separate quota fault context and isolated disk-backed profile passed without
reducing the file limit or disabling checks.

The preserved working source now supplies an adapted GPL-3.0-only native
PRF/TPM random-L probe with journal-before-create, independent namespaces,
native HWND/lock generations, exact cleanup and actual encrypted-vault admission.
Portable tests: 70; Windows MSVC: 98 routine plus one explicit official-header
ABI case. Hosted Windows API 7 is below required 9: capability BLOCKED, no
hardware objects created. This is not a physical Hello pass.

Prepared private trusted-HTTPS PWA packaging, selected-file/reselect/lock checks,
an explicit writable sink and experimental verified disk-File Web Share
candidate. Local HTTPS assets and ciphertext transport were exercised with
certificate trust intact, then only the owned server was stopped. Actual
installed-iPhone sharing/Files output, memory and restart/resume remain unrun;
no private HTTPS origin was deployed. No production formats or data migration
changed. Revert this isolated slice to roll back; preserve any physical trial
cleanup journal until its exact native objects are removed.

## Completed slice: P01-PHYSICAL-TRIALS independent host preparation

Selected-file upload and export/readback now have separate sampled desktop RSS
reports. Exact 1 GB saved-file length/SHA-256 match independent Node output.
The initial measured upload increment was 416,692 KiB; export/readback increment
104,976 KiB. These are sampled aggregate desktop process figures, with shared
page double counting and irregular cadence, not an iPhone 64 MiB pass.

Real worker/HTTP/OPFS tests reject corrupt/truncated second parts, decoded gzip
overflow and lock before a delayed second response, abort the uncommitted writer
and preserve its previous output. Exclusive sink denial, verified retry of the
unchanged ciphertext, failed share-preparation cleanup, reload requiring fresh
keys and selective/idempotent marked-orphan cleanup pass. Network faults are
internal runner controls, never HTTP/IPC actions or production features.

The bounded synthetic-file helper passed size/hash/no-overwrite checks locally.
The Windows hash/source collector passed on hosted Windows without creating
objects; actual provider gating remains BLOCKED at API 7. Owner runbooks and
an unfilled physical record template are ready. The owner reports the HTTPS
host is not ready; phone access, actual Windows Hello operations, installed-PWA
Files output/memory and low physical space remain NOT RUN/BLOCKED. No physical
acceptance, production protocol or deployment is claimed. Next independent
development is P03 tooling, while P01 awaits device records. Rollback: revert
the isolated test/helper additions; no production state or format migration.

## P01-DEVICE-KIT — simplified physical trial packaging

The owner requested one executable and one ZIP instead of multiple tools.
Added a double-click native Windows workflow with statically linked CRT, bundled
frozen AEAD/64 MiB Argon2id/exact 1 GB disk checks, fresh subprocess Hello
operations, guided cancel/lock, exact cleanup and one hash/source/native report.
Added a static relative-path iPhone ZIP for `<web-root>/anynote-p01/`, one
automatic runner plus guided Files save/reselect/hash and one report. The
phone generates its own synthetic sources and uses bounded worker OPFS access.
No Node server, backend or account is needed for this local trial.

Portable native tests: 72 PASS, including actual boundary output/oversize
admission and frozen native AEAD/Argon2id corpora. Kit build, ZIP CRC and asset
SHA-256 receipts PASS locally. All three hosted feasibility jobs (existing full interop/network/export/fault
suite, nested-path static kit and MSVC/one-EXE local tests) passed at
`4629afe9a22ddf37ac28a6de8a52771274371481`; raw reports are in docs/evidence.
Final source CI and GitHub test-release publication are pending at this snapshot. Physical
Hello/iPhone, network/resume and device process-memory acceptance stay OPEN;
the Share UI in hosted integration tests is explicitly mocked. No production
format, data migration, signing or site deployment is introduced. Rollback:
revert the isolated kit additions and remove only the test site's kit directory;
preserve outstanding native cleanup journals until exact owned cleanup succeeds.

## P01-DEVICE-KIT publication transport

PR #4 merged after final source 5a09852 passed all four checks. Downloaded
EXE/ZIP hashes, ZIP CRC/asset receipts and system-only Windows PE imports were
verified. Direct cloud release upload then failed with HTTP 401 specifically
at uploads.github.com; the same GitHub API credential supports PR/merge/read.
The CLI rolled back its unsuccessful release, leaving no tag or assets.

An explicit workflow_dispatch-only job now publishes the frozen successful
run 38068299281 using its own scoped Actions token. It rechecks CI success,
source, native report/hash, ZIP receipts and absence of a conflicting release,
then verifies published downloads and the exact source tag. Other dispatch
build jobs are skipped for this publication-only mode; normal PR/main checks
remain unchanged. Publication execution is pending at this initial snapshot;
actual run/download evidence is recorded in the publication PR and release.
No signing, production deployment, user secret or dependency change is added.

## P01 owner feedback — 0.1.1 trial recovery

Owner supplied the 0.1.0 Windows JSON (source 5a09852, released EXE hash matches):
51 native crypto/KDF checks, exact 1 GB/120 chunks and cleanup PASS; actual
API 9, build 26200, Hello platform/candidate checks passed. Operations were
empty because the kit incorrectly gated trial admission on unresolved key
eligibility. A separate fail-closed route predicate now admits the trial without
altering native PRF/TPM/fresh-authentication gates. Owner also reported iPhone
PWA restarting after Save to Files, losing the memory-only diagnostic report.
Persist bounded nonsecret checkpoints before OS handoff, restore the report and
selected-output verification without keys, and clean only marked synthetic
orphans under the trial lock. Saving/downloading diagnostics is independent of
the primary test step. No actual Files hash/Hello enrollment evidence was supplied.

Local portable tests: 74 PASS, strict Clippy PASS. New hosted regression destroys
the actual page while mocked Share remains pending, reloads retained diagnostics,
reselects and hashes the saved 1 GB, preserves pass/failure reports across reopen,
and rejects denied/malformed checkpoint storage. All three hosted jobs and baseline PASS at f92dcb4 (run 38071301931);
raw recovery/browser and Windows records are in docs/evidence. The explicit
publication job uses these frozen verified bytes for v0.1.1-p01-device-kit;
actual publication execution and availability are recorded in PR #6/release.
P01/G1 remains OPEN pending an updated owner run.

## P01 owner 0.1.1 results — lock interpretation and Files selection

Owner supplied both device JSON files. Windows source f92dcb4 and EXE 8aca6b...
match the 0.1.1 release: enrollment, fresh-process actual-vault authentication
with PRF/exact TPM reopen, explicit HELLO_CANCELLED and exact cleanup PASS;
51 crypto/KDF checks and exact 1 GB/120 chunks PASS. Guided lock returned STALE,
and the owner confirmed that Win+L showed the Windows lock screen. Subsequent
fingerprint waiting can be Windows sign-in, not continuing old authorization.
The old report lacks event counters, so retain this as an owner-confirmed lock
plus native rejection, not instrumented proof or complete G1 acceptance.

Phone source f92dcb4: 117 crypto checks, three public Argon2id vectors, negative
profiles/storage/export faults, exact 1 GB/120 chunks and diagnostic recovery
PASS. Saved-output selection failed on length; owner confirms JSON/another
file was selected instead of the .bin. Files bytes/hash are NOT VERIFIED. Report
says installed_pwa=false, so this is physical Safari, not installed-PWA evidence.
Archive only a redacted phone origin; original-upload checksums and exact scope
are recorded separately. Device process memory stays NOT MEASURED.

0.1.2 adds WTS lock/unlock/suspend/close counters and strict lock-plus-STALE
classification, clearer Windows sign-in guidance, wrong-file size telemetry,
retry/recovery without a new automatic trial, and bounded same-origin migration
from the one documented previous diagnostic path. Native imported crypto,
provider checks, cancellation watcher and exact cleanup are unchanged. Local
portable tests 76 PASS and strict Clippy PASS; hosted checks/release execution
are recorded as they complete. P01/G1 remains OPEN; P03 continues independently.

Hosted 0.1.2: all three feasibility jobs and baseline PASS at a225e3f
(run 38074016248). Native 105 routine tests plus explicit C-header ABI PASS;
retry/reload/migration and exact 1 GB output/hash/cleanup PASS. Actual hosted
records are archived in docs/evidence. The publisher selects this frozen source
for v0.1.2-p01-device-kit; execution/availability is recorded on PR #7/release.
Remaining phone Files hash/installed-PWA and full G1 gates remain OPEN.

## P01 owner 0.1.2 feedback — stream download and selected OS lock

The new owner Windows upload matches the exact 0.1.2 source/EXE. Local 51
crypto/KDF, exact 1 GB, enrollment, fresh-process actual-vault authentication,
explicit cancellation and exact cleanup PASS. Lock-step HELLO_CANCELLED with
all four counters zero is NOT PROVEN; owner confirms no lock screen this time.
Keep the earlier 0.1.1 screen/STALE observation as a different run. Owner reports
iPhone 0.1.2 restarts at Save 1 GB to Files; no updated phone JSON was supplied.

0.1.3 adds a scoped single-use service-worker attachment stream from the marked
verified synthetic disk output (256 KiB reads), replacing default 1 GB Web Share.
Retain nonsecret generated owner/name metadata; recovery rechecks size/hash
under the exclusive trial lock, without keys or persisted handles. The stream
holds that lock through completion/cancellation and is never cached. Only
selected size/hash determines saved-file evidence. Windows adds an explicitly
selected one-shot LockWorkStation request after 8 seconds while unlock remains
pending. Ordinary/hosted operations never request lock. API acceptance is not
WTS lock evidence. Hosted checks/publication pending; P01/G1 remains OPEN.

Hosted 0.1.3 source 2cc346e: all three feasibility jobs and baseline PASS
(run 38076184680 / 38076184710). Raw stream/browser and Windows records are
archived. Real 1 GB SW attachment/picker/hash, partial cancellation/retry,
replay/path/marker rejection, recovery and exact cleanup PASS. Windows 106
routine plus explicit C-header ABI PASS; full existing 663-primitive/native/
Node/network/browser/fault suite PASS. Freeze these verified EXE/ZIP bytes for
v0.1.3-p01-device-kit; Actions publisher revalidates runtime/source/receipts
and actual downloads. Publication execution is recorded in PR #8/release.
Actual iOS PWA/Safari and selected Windows lock require owner testing; G1 OPEN.

0.1.3 was published from the verified source. A further lifecycle fix is now
prepared as 0.1.4: store short-lived synthetic download tickets durably in a
dedicated path-scoped IndexedDB table, so idle SW termination does not erase
a prepared URL. Transactions atomically consume tokens; bounded expiry/client
replacement keep the registry small. No export bytes or vault keys are persisted.
Hosted regression stops the real SW after preparation before the 1 GB download.
New validation/publication pending; prior release assets remain immutable.

0.1.4 hosted source 566ec84: all three jobs plus baseline PASS. Real SW stop
followed by exact 1 GB attachment/picker/hash and replay/cancel/recovery checks
PASS; 106 Windows tests plus separate ABI and full 663-primitive/network/fault
suite PASS. Exact raw records and frozen SHA-256 values are archived. Publish
these verified bytes as a new v0.1.4-p01-device-kit tag through Actions; do not
overwrite 0.1.3. Final publication/download evidence is in PR #8/release.
Actual installed-iPhone stream/Files/memory and selected Windows lock still
need owner records; earlier Windows positive findings are preserved.

## P01 owner 0.1.4 results — instrumented lock and installed-PWA export

Both new owner reports identify released source 566ec84; the Windows executable
hash matches the downloaded 0.1.4 release. Enrollment, fresh-process authenticated
PRF/exact-TPM reopen, explicit HELLO_CANCELLED and exact owned cleanup PASS.
The selected automatic lock trial reports one WTS session-lock event and STALE
rejection, satisfying the instrumented lock classifier. API acceptance alone
is not used as proof; prompt visibility/timing is not directly captured.

Phone reports installed_pwa=true. Local crypto/KDF/storage/fault checks and
1 GB/120 chunks PASS; the scoped SW sent 1,000,000,000 bytes and the selected
output matches the expected SHA-256. Diagnostic recovery from the verify stage
restored no keys; the retained export reopened and rehashed, then exact cleanup
PASS. The restart cause and selected destination folder are not captured.
Archive Windows bytes unchanged, redact only the phone's private origin, and
retain original upload checksums and precise scope in the receipt.

These reports supersede the outstanding 0.1.4 owner-run request for these
specific checks. No kit update or repeated whole trial is needed on this evidence.
Process memory, older-phone, network/resume/low-space, passkeys, PWA update and
remaining Windows matrix keep P01/G1 OPEN. P03 tooling remains the next bounded
independent task. No application/source-format/migration change in this slice.
Rollback: revert only this evidence/tracking addition; preserve prior reports.

## Completed slice: P03-TOOLING-FOUNDATION

Minimal apps/api Laravel scaffold, frozen 99-package Composer lock/license
inventory, digest-pinned PHP/FPM/MariaDB/Nginx Compose environment and one-command
owned lifecycle/check tooling. No default auth model/user/password/migration,
product endpoint/schema, content crypto, queue/scheduler or application UI.
Framework APP_KEY and database credentials are disposable ignored local state.
Existing P01 experiments/references/device kit and original specification remain
unchanged. P03 final contracts/types/errors/logging depend on P02, so P03 remains
IN PROGRESS rather than a completed product/API gate.

Local real MariaDB commit/rollback/temporary cleanup and Nginx/FPM/Laravel DB
request PASS. Three PHPUnit tests / seven assertions, strict Composer validation,
native extensions, 20-file Pint and advisory audit PASS. Loopback bindings,
non-root FPM/Nginx, static/API and path/host denial, actual DB outage 503 and
restart recovery PASS. Gitleaks source scan and three fake-token negatives PASS;
only rule/file/checksum-shaped reference/source-input false positives are allowed.
Repeated frozen install and full stop/start/readiness are verified; actual
source-stamped hosted fresh-checkout results are recorded on the foundation PR.
Saved environment fields and exact evidence are recorded in TEST_EVIDENCE.md.

Rollback: revert these foundation additions, stop only the marked synthetic
Compose project and preserve its disposable volume/state. No production data or
protocol-format migration exists. Next: P02-KEY-AND-FILE-CONTRACT; complete P01
physical/memory/network matrix and qualified review remain separate open gates.

Hosted source 76860c8: foundation 38119399644, baseline 38119399647 and all three
P01 jobs 38119399652 PASS. Actual checkout merge ref 1405c76 has the same complete
tree; raw report/source receipts archived, clean tree and no generated cache
tracked. Cloud install_script/start_skill save confirmed; publication/future-task
restoration NOT RUN. This final evidence addition leaves foundation/P01 code
unchanged; final PR-head checks must pass before automatic merge.

## Completed slice: P02-KEY-AND-FILE-CONTRACT

Candidate p02-file-c1 key-custody/file context and bounded checkpoint design,
strict closed schemas, raw-JSON/JCS codecs, exact public boundary fixtures and
independent restricted fixture reference. Distinct AAD/signature/hash domains
bind author/root/generation/roster/policy/epoch/parent context, immutable wrap
bytes and ordered file inventory without circular digests. Complete inventory
consistency rejects bad pages, missing/wrong/cyclic compact ancestry and wrong
predecessors. Authentication/authority is an explicit mandatory next layer,
not a verdict supplied by the codec. No product endpoint or crypto/key operation.

69 Node tests PASS; six deterministic fixtures /125 nonce-AAD pairs and two
independent reference rejection mutations PASS. Frozen seven-package npm lock/
license/integrity inventory and advisory audit PASS. Source scanner allows only
the exact two known public fixture values (also in decoded expected bytes);
four fake-token path negatives plus two changed key/digest-shaped values PASS.
Original specification and P01 experiments remain unchanged. Hosted exact-head
checks and saved environment evidence are tracked in TEST_EVIDENCE.md.

P02/G2 remains IN PROGRESS: full identity/recipient/pairing/roster/policy/epoch/
recovery/local/export protocol, Rust/browser/PHP crypto interoperability and
qualified independent review NOT RUN. R01/R14/R19 have byte/framing/design
evidence only, not full application acceptance. P01/G1 and P03 gates unchanged.
Rollback is a normal revert of candidate additions, no content migration/data.
Next: P02-ROOT-IDENTITY-CONTRACT; no repeated owner device trial required.

## Completed larger slice: P02-IDENTITY-CERTIFICATE-RECIPIENT

Candidate p02-identity-c1 adds exact HKDF/root/recovery kit, noncircular pinned
public identity, provisional root/delegate certificates and signed sealed
recipient contexts/coverage. Private signature proofs explicitly carry
NOT_EVALUATED authorization; no device/session activation or unchecked roster
acceptance. Complete file candidate bytes and original/P01 sources are preserved.

145 Node tests PASS, including external RFC 5869/BIP 350 expected examples,
real deterministic crypto/vector drift and adversarial signature/context/recipient
checks. Both fresh synthetic recipient paths decrypt the same 79-byte file via
G -> manifest DEK -> encrypted manifest/file-data key -> chunk, no uploader DEK
input. Independent PHP 8.4.26/native sodium 1.0.18 reproduces fixture keys/JCS
subset/signatures/sealed/AEAD and tag/AAD negatives. Ten-package frozen inventory,
zero npm advisories and source scanner with ten negatives PASS. Full saved setup
execution/repetition and final source CI are recorded in TEST_EVIDENCE/PR.

P02/G2 remains IN PROGRESS: authenticated pairing, signed roster/activation/
revoke/reset/session and policy/epoch/historical authority, local/export schemas,
full Rust/browser/general PHP compatibility and qualified review are outstanding.
P01/G1 and P03 product gates unchanged. No new owner device action is needed.
Rollback: normal revert of isolated candidate additions, no production migration.
Next larger batch: P02-ROSTER-AND-RECOVERY-STATE.

## Completed larger slice: P02-ROSTER-AND-RECOVERY-STATE

p02-state-c1 adds libsodium secretstream with a random authenticated QR/OOB key,
two pairing directions without a PC camera, full signed transcripts and provisional
approval/dual-key confirmation. Pinned append-only state checks exact predecessor,
generation, cap and delegated ancestry. Compromise revoke includes descendants;
root reset revokes all old devices/sessions/pending and activates only a newly
proved session. Account login/session ledger is explicitly synthetic in-memory;
no actual product auth, SQL transaction or QR/user ceremony is implemented.

189 Node tests PASS; frozen five-event/seven-frame inputs and both QR directions
reproduce in Node and pinned PHP/native sodium. Independent fixture serializer
checks are not a general PHP parser/authorization API. Earlier schema/vector
bytes, original specification, locks, P01 kits/reference remain preserved. Source
scan + six fake-token path/eight changed-key negatives PASS. Setup and hosted
source evidence are recorded in TEST_EVIDENCE and the review PR.

Device roster authority is VERIFIED_FROM_PINNED_CHAIN in new state APIs only;
group authorization remains NOT_EVALUATED and old signature-only APIs unchanged.
P02/G2 stays IN PROGRESS; P01/G1 and product P03 gates remain open. No repeated
owner physical action or deployment. Rollback: normal revert, no production data.
Next larger batch: P02-GROUP-POLICY-EPOCH-HISTORY-CONTRACT.

## Completed larger slice: P02-GROUP-POLICY-EPOCH-HISTORY-CONTRACT

p02-group-c1 adds pinned signed owner/editor/reader policy and invitations,
full-history pending admission, complete retained-epoch device/recovery coverage,
staged pages/finalization/all-head CAS, canceled-key reuse denial, mandatory
reader roster maintenance, immediate revocation/role loss, shared owner co-sign,
archive and independently witnessed historical writer acceptance.

249 Node tests PASS (189 prior + 60 group tests); frozen replay covers eight
policies, six epochs, 105 real sealed grants, five checkpoints, enrollment,
removal/transfer/recovery and a 50-byte historical file through the full key path.
Native PHP independently reproduces that public fixture subset; assertion counts
include serializer checks. New clients without independent history are quarantined.
Partial/stale/forged/expired grants, reader writes/history endorsement, substituted
recipients and new backdated old-key revisions fail. Two-page serialization
coverage does not claim its placeholder records satisfy group authorization.

P02/G2 remains IN PROGRESS: note/local/export formats, complete interoperability,
qualified review and P03 durable account/session/SQL implementation remain open.
Recent-auth ownership transfer is not implemented. Original spec, earlier
schemas/vectors/locks and P01/release/reference bytes preserved. No new owner
physical action/deployment/release. Setup/local evidence in TEST_EVIDENCE; hosted
final source proof on PR. Next larger batch: P02-NOTE-LOCAL-EXPORT-CONTRACT.

## Completed phase: P02 — protocol specification and reviewable security design

Complete the design/fixture scope of original chapter 14 §5. New p02-v1 composes
unchanged file/identity/state contracts with explicit group c2, preserving c1
bytes and resolving the required twenty-member default with separate domains.
Typed encrypted notes/group/thread metadata, tombstones/restore/relationships,
local L and phrase/PRF/native byte wrappers, stable outbox/receipt/CAS, sync,
complete snapshots, restore quarantine, fixed errors/negotiation and strict
standard age v1 USTAR export/import design are frozen. Exact selected source
inventory, cross-account authors, independent history/kit pins and selected-DEK
note/file offline recovery precede any live destination mutation.

Qualified review is concretely tracked in P02_REVIEW.md/p02-review.json; unbooked,
unassigned and NOT_RUN. Correct prior tracking that mistakenly required all
product SQL/adapters or a performed audit to finish P02 design. P05/P07/P13/P17
still own product interoperability/custody/utility/release review, and G2/G3
remain open. No production deployment/migration, site/kit replacement, root-key
custody, physical provider or fresh-task environment-restoration claim.

See P02_COMPLETE_CONTRACT.md for all normative predicates/limits and test evidence
for actual command results, initial failures and corrected boundary cases. Roll
back with an ordinary revert; no production data exists to migrate. Next batch:
finish P03 contract/type/error/logging drift gates, then product P04/P05 in their
documented dependency order. No repeated owner physical trial is requested here.

## Completed phase: P03 contract and request foundation

Complete P03 tooling over frozen P02 without executable dummy auth/crypto. Generate
closed shared TS/PHP transports, initial OpenAPI and hash-bound predicates; check
actual drift/strict types. Public capabilities/liveness expose only minimal safe
foundation state. Common errors conceal resource existence, reject ambiguous raw
control JSON, preserve canonical request IDs through Nginx 413 and never disclose
framework diagnostics. Persisted content-free logs pass hostile-request inspection.
Product routes, SQL tables/authorization and crypto adapters remain P04/P05/P06.
See P03_DEVELOPMENT.md and TEST_EVIDENCE.md for actual outcomes/remaining gates.
Rollback: normal revert; no production migration/deployment or P01 kit change.

## P04 backend foundation

Three product migrations, current durable session/device authorization, bounded
scoped repositories, immutable revision/parent/wrap persistence, CAS/idempotency,
actual quota reservation/conversion and commit-order receipt/events are implemented.
The separately owned disposable test DB checks three accounts/cross-group IDs,
real SQL rollback faults and eight parallel PHP processes. Supervised non-root
maintenance containers execute actual jobs and automatically restart after crash.
Operator readiness is the only new executable route; future product/auth APIs
retain their phase ownership. See P04_BACKEND.md and TEST_EVIDENCE.md.

The required P05 public-signature slice uses native sodium, browser locked
JCS/Ajv/sodium and PHP/Opis over closed public schemas. General arbitrary payload
canonicalization, native JSON/AEAD/custody and independent review remain open.
Local Chromium sandbox remains BLOCKED; the mandatory hosted browser gate passed
with Chromium sandbox enabled. All six source CI jobs passed at dc41686; actual
checkout/full-tree/input-hash evidence is retained. No owner trial, production
migration/deployment, security release or reviewer outreach occurred. Rollback:
normal source revert; reverse/reset schema only on the explicitly owned test DB.

## Completed phase: P05 full client cryptographic core

Native Rust and portable Node/browser modules now implement strict versioned
decoders, maintained general JCS, signatures/AEAD, root/recipient/local/native
wrappers, fresh-key sequential file framing and independently pinned complete
history inclusion. No current authority is inferred from cryptographic validity.
See P05_CRYPTO_CORE.md for caller/lifecycle/resource boundaries. PHP verifies
closed public signatures only. Linux actual Worker and Windows/MSVC CI are
mandatory; local sandbox restrictions cannot satisfy this gate. Frozen prior
locks/corpora remain unchanged, with exact new crate inventory and RFC fixtures.
No production migration/deploy/release, reviewer outreach or owner trial occurs.

Clean source 1ac93ef and actual hosted checkout 38c5e37 have identical complete
trees. All eight source jobs PASS, including sandboxed Chromium and Windows/MSVC.
Native/Node/Worker: 506/527/527 checks; PHP: 377 public-only checks, including
fresh signatures from all three runtimes. Exact 1 GB native round trip: 6,015 ms,
90,616 KiB peak RSS; Worker: 20,727 ms, UI maximum timer lag 5 ms. The full browser
suite's sampled aggregate process RSS is 1,312,508 KiB; Wasm heap is 67,371,008
bytes and one plaintext chunk is at most 8 MiB. This does not close physical
iPhone/WebView2 memory acceptance. Actual reports and input/tree receipts are in
TEST_EVIDENCE.md. Read-only setup extension rerun preserved all 570 Git-visible
files; saved draft revision 13 is not publication or future-task restoration.
Final tracking changes require fresh CI before ordinary automatic merge.
Rollback: ordinary source revert; no production data or format migration.
Next full batch: P06 account authentication and session lifecycle.

## Completed phase: P06 account authentication and session lifecycle

Maintained WebAuthn/League OAuth2 and Rust oauth2 now implement invitation-bound
atomic public-root/first-device registration, multiple passkeys, strict encrypted
PWA sessions/CSRF, native system-browser/PKCE handoff, recovery codes, recent auth,
current-device proof, logout/session management and refresh rotation/reuse.
The browser account-security UI exports the frozen checksummed offline kit with
explicit address/instructions and supports distinct passkey providers.

All ten source jobs PASS at d8198af. Actual hosted checkout 8b12e0d has the same
complete clean Git tree 363f1761. Actual HTTPS/SQL: 215 checks; sandboxed Chromium
with verified TLS/strict CSP: 18 checks; native callback/attack/PKCE: four tests
on each of Linux and Windows/MSVC. Registration, code redemption, refresh and
counter races each have exactly one winner among eight; the 64-request admission
bound permits 60/four denials. Public artifacts, tree and 131 input hashes per
platform are archived in TEST_EVIDENCE.md. Source tracking/evidence changes require
fresh final CI before ordinary automatic merge; no failed gate is bypassed.

Read-only setup repeated on this restored instance preserved all 625 then-visible
files. Complete install/start fields were saved/read back as draft revision 14;
network, credential requirements and repositories are unchanged. The earlier P05
snapshot was published/restored; P06 draft publication and new-task restoration
remain separately NOT_RUN. No owner-device action is needed for software P06.

P07 owns encrypted local custody/locking; P08 owns general pairing/root reset and
private-group genesis. Physical P01 and qualified G2/G3 remain open/unassigned/
unbooked/NOT_RUN. No production migration/deployment, release or reviewer outreach
occurred. Rollback: ordinary source revert; any deployed schema rollback requires
an explicit data-preserving operator plan. Next full batch: complete P07.

## Completed phase: P07 full local custody

Random per-installation L protects device keys, draft/outbox/cache records and
native session credentials in transactional IndexedDB/SQLite. Authenticated
public manifests pin local routing/root; frozen P02/P05 inner frames are unchanged.
Protected native Hello uses fresh PRF plus an actual TPM private operation;
explicit Windows phrase mode adds current-user DPAPI. Optional browser PRF keeps
strong phrase fallback and uses a human platform picker. Worker termination,
shared epochs, native OS/idle generation fences and one-writer leases prevent
stale disclosure/writes while retaining acknowledged work. Wrapper removal rotates
L and all records atomically; unknown refresh outcomes require fresh login.
Lost/unknown browser stores produce recovery/refusal without destructive downgrade.

All twelve source jobs PASS at 28cb562. Actual hosted checkout 1caaa234 and branch
head have the same clean Git tree 407021f7. Five Node suites, 28 actual HTTPS/SQL
checks, 28 sandboxed verified-TLS/strict-CSP browser checks and fifteen native
custody tests on each Linux/Windows platform passed. Preserved provider/container
suite: Linux 71, Windows 99 plus one explicitly executed official-header ABI test.
Exact public reports and 111 raw source hashes per platform are archived in
TEST_EVIDENCE.md. Final tracking changes require fresh CI before ordinary merge.

Published P06 setup was actually restored. The read-only P07 extension preserved
670 then-visible files and all 675 files after archiving reports. Complete
install/start fields were saved and
read back as revision 15, with unrelated configuration unchanged. P07 publication
and fresh-task restoration remain NOT_RUN. No owner action is needed for software
acceptance. Physical P01/Hello/iPhone and qualified G2/G3 remain open/unbooked/
NOT_RUN. No production migration, deployment, release, owner trial or outreach.
Original spec, prior locks and frozen corpora remain unchanged. Rollback: ordinary
source revert, preserving local data and owned pending cleanup journals.
Next full batch: P08 trusted devices and recovery.

## Completed phase: P08 trusted devices and recovery

Both QR directions bind independent root/service/account pins and mutual intent.
Independent device keys remain under L; root/R remain transient. Signed rosters,
atomic CAS/receipts, notifications, cascading descendant/session/code revocation,
root-signed generation reset, private settings group-c2 genesis and same-account
G grants are implemented. Fresh recovery activates before fetching envelopes.
The atomic encrypted public bootstrap journal resolves interrupted registration.
Additive p08-local-v1 keeps frozen P02 schemas, corpora and all prior locks intact.

All fourteen hosted gates PASS at bb41c0cb, clean tree eccb040a: seven Node suites,
sixteen dense QR checks, 153 real HTTPS/SQL checks, 33 sandboxed verified-TLS/CSP
UI checks and nine native device tests per Linux/Windows, alongside inherited
custody/provider/official-header ABI gates. Public reports and 283 raw inputs per
platform are archived in TEST_EVIDENCE.md. Final tracking needs fresh fourteen-job
acceptance before ordinary authorized merge.

Published P07 setup was actually restored. Complete P08 installation ran twice;
the final complete run preserved all 712 then-tracked files. Updated readiness
checks remain read-only. Saving a draft, publishing and fresh restoration are
separate events. No owner action is needed for software P08. Physical P01/Hello/
iPhone and qualified G2/G3 remain open/unbooked/NOT_RUN. No production deployment,
live migration, release, new owner trial or outreach. Rollback: source revert;
preserve encrypted journals and plan any deployed schema rollback explicitly.
Next full batch: P09 private groups and encrypted notes.

## Completed phase: P09 private groups and encrypted notes

Private group-c2 genesis, real scoped P04 publication, protected Worker/native
custody, encrypted metadata/notes/preferences, safe Markdown/checklists and usable
EN/RU private vault are verified. Immutable unknown attempts, exact ACK retirement,
newer text, conflicts, tombstones and explicit restore retain acknowledged work.
Both clients derive rekey blocking from verified signed revoke/reset history,
even if the service clears unsigned flags. Closed transport rejects route/operation
substitution before display. Static-only offline resources have an enumerated worker
CSP, while page/API TLS/CSP/sandbox and local custody guards remain mandatory.

All sixteen hosted gates PASS at a1520167/tree32232245. Eight Node suites,
131 real HTTPS/SQL checks, 49 sandboxed two-enrolled-PWA checks, six actual native
SQLite note tests per Linux/Windows platform and sixteen two-way native/PWA adapter
checks per platform passed. Inherited device/custody/provider/official-header ABI
checks remain passing. Public reports and 307 raw source inputs per platform are
archived in TEST_EVIDENCE. Final tracking/evidence changes require fresh sixteen-job
success before ordinary SHA-guard merge.

Published P08 setup was actually restored. The complete frozen installation
preserved all 747 then-visible source files and the private-note database state;
complete startup/readiness passed again. Saving a P09 draft, publication and
independently observed fresh P09 restoration are separate events. No new owner
hardware action is needed for this software phase. Full physical G1/Hello/iPhone
and qualified G2/G3 remain open/unbooked/NOT_RUN. No production migration/deployment,
release, new owner trial or reviewer outreach occurred. Original specification,
frozen corpora and prior locks remain unchanged. Rollback: ordinary source revert,
preserving encrypted local work and separately planning any deployed schema rollback.
Next full batch: P10 shared groups and membership integrity.

## Completed P10 shared groups and signed membership

Shared owner/editor/reader access, independently verified full-history invitations,
complete atomic grants, role changes, immediate removal and fresh-epoch maintenance,
dual-consent owner transfer and archive/unarchive are implemented in the actual API,
protected Worker/native custody and EN/RU notes UI. Same-account certified devices
receive retained epochs without copying identity secrets. Private-to-shared copy
requires an audience preview and fresh IDs/DEK/context; account closure refuses
unresolved shared membership and queues retained ciphertext for P13.

Security attempts and private candidate keys survive proof refresh/restart under L;
exact receipts atomically acknowledge and install the committed key. Signed history,
independent pins, roster chronology and current roles remain required. Revoking an
actually enrolled recipient after staged pages rejects finalization, preserves the
current epoch and retries with fresh keys excluding the revoked device. Worker input
cleanup cannot erase detached live membership state. Newly introduced identities
require a fresh independently exchanged card rather than unverified API fingerprints.

All eighteen jobs PASS at `fddd9fde0e5158ef7fdefa5396fde51d53865b56`, full tree `b3d7c465f8c4b6c4e0ed2c13b51e02fa387df284`. Public exact-source
reports, artifact digests and raw implementation hashes are in TEST_EVIDENCE.

Complete frozen installation preserved 775 then-visible source files and marked
private/shared content state; complete startup/readiness passed again. Published
P09 restoration was observed. P10 draft saving, publication and fresh restoration
remain separate events. Full physical G1 and qualified G2/G3 stay open/unbooked/
NOT_RUN. No production deployment/migration, release, new owner trial or outreach.
Rollback uses an ordinary source revert while preserving encrypted drafts, security
journals and retained signed evidence; deployed schema rollback requires its own
data-preservation plan. Final tracking needs fresh eighteen-job CI before merge.
Next full batch: P11 incremental sync, conflicts and convergence.

## Initial P11 synchronization code acceptance

Scoped commit-ordered sparse feeds, immutable leased snapshots/pins, verified staged
portable/native application, atomic durable cursors, signed ancestry preservation,
explicit conflict/retry/recovery and foreground-aware EN/RU polling are implemented.
Cache compaction preserves signed headers, current heads and pending work. The
additive encrypted-part profile reads prior local control and scales protected key
and complete signed-roster inventory to 10,000 / 32 MiB. Older clients must refuse
the migrated profile. Bounded catch-up keeps a pending status until its captured
watermark is reached, and key discovery follows the 10,000-record logical bound.
RESTORE_QUARANTINE remains persistent across cancellation,
retry and attempted downgrade; publication is blocked while own drafts and exact
receipt reconciliation survive. Operational restore remains P16.

All twenty mandatory jobs PASS at `fae5e306181c05a9542449e8219706859f4b87a2`, tree `630436bcfdfb2e7c3dbc4a52f80aba7f6b6a805a`. Public initial reports,
GitHub ZIP digests and raw hashes are in evidence/p11/initial and TEST_EVIDENCE.
The complete installer passed with 800 tracked source files and marked
snapshot/pin state preserved. Full owned startup/readiness passed. Published P10
restoration was observed; saving P11 configuration, Publish and independently
observed fresh P11 restoration remain separate. Physical G1/Hello/iPhone/memory/
network and qualified G2/G3 remain open/NOT_RUN. No deployment, production migration,
release, new owner trial or outreach occurred. Final documentation/evidence needs
fresh twenty-job CI before ordinary SHA-guard merge. Next full batch: P12.

Rollback requires an ordinary source revert that preserves encrypted local work,
immutable attempts, signed evidence and parts. A migrated active vault cannot be
opened by a frozen older reader; preserve it for a compatible reader rather than
resetting or silently downgrading data. Deployed schema rollback needs a separate
data-preservation plan.

## Completed P11 follow-up and final code acceptance

All twenty mandatory jobs PASS at `08ca97c7f9b1caff1ffc55b284a2afa7a8f0bb65`, clean tree `e4c7e51a27d386314b792310d115fe3e3c7f62c9`. Latest exact-source
reports are in evidence/p11; original fae5e30 receipts remain in evidence/p11/initial.
The final browser retains every original denial/DOM/draft assertion and records only
closed error/operation/lock-reason/visibility metadata. Worker custody closure now
immediately masks and terminates host access. Existing typed errors, five-minute
expiry, backwards-clock checks and encrypted local state remain preserved.
Background sync cannot extend the host idle deadline; trusted visible user input
and foreground work can. Ten P11 and five P07 suites cover these guards, including
actual encrypted state preservation across idle and clock-regression closure.

The earlier isolated 5116fad VAULT_LOCKED reason was unavailable before diagnostic
instrumentation and is not retrospectively invented. A separate 5563bc0 diagnostic
run passed all twenty. Latest follow-up acceptance passed all twenty with the
additional lifecycle coverage; operational/physical/review limitations remain.
Final tracking requires fresh twenty-job CI and ordinary SHA-guard merge. Full P12
handoff is NEXT_TASK. Draft save, Publish and independent fresh restore are separate.

## P12 development observations before final acceptance

Protected immutable file attempts, bounded ciphertext HTTP/blob storage, actual-byte
reservation conversion, unattached recovery, signed file history and snapshot pins
are under implementation. Dirty-source development checks passed three portable
file suites, eight inherited note suites, 94 real TLS/SQL/blob checks and a separate
341-check run including an incompressible 1,000,000,000-byte HTTP round trip. The
native SQLite/source/resume/export gigabyte test passed with 120 chunks and a
matching final hash. Source changed afterward; these are development observations,
not final exact-source acceptance. Hosted PWA, Windows, complete fault/concurrency
and all inherited final gates remain mandatory. No physical or independent-review
gate is closed. No production operation, release or new owner-device trial occurred.

## Initial P12 code acceptance before the foreground/resync follow-up

All twenty-two code gates passed at `4d6f3c93f54919987f64f669b27e5c1eb0907ec1`, complete clean tree `e5d5f22f3ce758dceb76244bb03fb4284bd1a511`.
Protected immutable source/attempt journals, bounded ciphertext streaming, exact
actual-byte commit/quota/receipts, recoverable attachments, current-authority fences,
signed file ancestry/snapshot pins, GC, cache/offline/pin and explicit atomic export
are integrated. Actual reports: 368 HTTPS/SQL/blob checks (including 1 GB), 452
file membership/security checks, 60 genuine sandboxed PWA checks, twelve portable
file tests and 109/137
actual all-feature native tests on Linux/Windows. Memory observations are retained
with their sampling scope, not promoted to physical iPhone/WebView2 proof.

Public raw receipts, GitHub ZIP digests and complete source-input verification are
in docs/evidence/p12. Frozen spec/P02 corpora and prior dependency locks remain
unchanged. Full physical G1/U11/U12 and qualified G2/G3 remain OPEN/NOT_RUN.
Complete P13 handoff is NEXT_TASK. Final documentation-head CI, ordinary guarded
merge and final configuration persistence require their separate actual outcomes.

P12 final-head follow-up: the shared browser's ROLLBACK_QUARANTINE was reproduced
by staging a revision, reading it in the foreground, then publishing the snapshot.
Both paths verified the same immutable witness but assigned distinct local cache
IDs. Publication now compares every immutable witness field, treating only its
replaceable cache location separately; the staged verified payload replaces the
older location atomically. Existing ancestry, signature/digest, cursor and rollback
checks remain intact. Portable regression and native lock/reopen regression pass.
Initial public receipts are retained unchanged in evidence/p12/initial; corrected
final exact-source and full-hosted acceptance remain required before merge.

## Completed task: P12 encrypted large files and quota lifecycle

All twenty-two code gates passed at `d53b90f1ee3398ea0c784becdd1557e2eac78bd2`, complete clean tree `e6fb1363c2398e5dd4c5182a6709a95720602e14`.
Protected immutable source/attempt journals, bounded ciphertext streaming, exact
actual-byte commit/quota/receipts, recoverable attachments, current-authority fences,
signed file ancestry/snapshot pins, GC, cache/offline/pin and explicit atomic export
are integrated. Actual reports: 368 HTTPS/SQL/blob checks (including 1 GB), 452
file membership/security checks, 60 genuine sandboxed PWA checks, twelve portable
file tests, eleven protected sync tests and 109/137
actual all-feature native tests on Linux/Windows. Memory observations are retained
with their sampling scope, not promoted to physical iPhone/WebView2 proof.

Public raw receipts, GitHub ZIP digests and complete source-input verification are
in docs/evidence/p12. Frozen spec/P02 corpora and prior dependency locks remain
unchanged. Full physical G1/U11/U12 and qualified G2/G3 remain OPEN/NOT_RUN.
Complete P13 handoff is NEXT_TASK. Final documentation-head CI, ordinary guarded
merge and final configuration persistence require their separate actual outcomes.

### P13 component development checkpoint

P13 remains IN PROGRESS. Search, isolated previews, native protected records and
search coordination, captured export leases, report-first note compaction and
pruned full resync, downloaded-cache controls, streaming age/archive primitives
and a clean offline reader now have development checks. Actual Linux 1 GB recovery
and independent Go age interoperability passed without plaintext temporary files.
See [component evidence](evidence/p13/development/DEVELOPMENT.md). Complete product export /
resumable import, derived thumbnails, remaining retention controls and full P13 /
inherited exact-source acceptance remain required. PR26 remains a draft; this is
not the P14 handoff or phase completion.

## Completed task: P13 protected content and independent recovery

All 24 mandatory code jobs passed at `6c520c9867aaaa778de7462de748fa6b1da44625`, clean tree `f31f7c75f00ce66e51f5c2b8bd4ec12698a27952`.
The original 22 gates remain mandatory. New Linux HTTP/browser and Windows
content gates passed; GitHub raw artifact ZIP digests and source input arrays
were independently checked against actual Git blobs. Exact raw public receipts
are retained beside this file. Development observations remain in development/.

Actual execution: seventeen Node protected-content/preview/archive/offline-CLI
checks, four native protected-content checks, 401 export/import
HTTPS/SQL checks, 427 signed-authority/removal checks,
59 genuine sandboxed browser UI checks and nine isolated preview
checks. Both Linux and Windows encrypted and independently decrypted an actual
1,000,000,000-byte file/archive, authenticated every original chunk and full hash,
with no plaintext archive/key temporary files. Linux used pinned Go age; Windows
used maintained Rust age/MSVC. RSS observations keep their process/sampling scope;
they are not iPhone/WebView2 or arbitrary 100 GB memory acceptance.

The content slice includes protected search and coverage/rebuild, safe bounded
previews, separately encrypted signed thumbnails, version compare/restore,
trash/retention report/apply/pins, private favorites/read markers, explicit cache
and completed-job controls, standard streaming age export, separate kit,
pre-start space/time/lease estimates, clean independent recovery and explicit
plaintext export. Standard import validates before any live mutation, defaults
to a new private group, confirms current audience and publishes fresh IDs/DEKs/
signatures. Empty/multi-group/full-history/current-only, wrong kit/altered or
truncated/archive/footer/path failures, quota denial/resume, lost ACK/lock/pause,
cross-root/service recovery, retained ancestry, derived-link protection and
revoked access are covered by the actually executed suites.

Frozen specification/P02 corpora/signatures and all prior dependency locks are
unchanged. New dependencies have separate exact inventories/licenses. See
[content/format guide](P13_CONTENT.md). Complete Windows host/dialog/native
integration is P14; iPhone acceptance is P15; deployment/physical reconciliation
and restore are P16. Physical G1/U11/U12/Hello/TPM/WebView2/iPhone memory and
qualified G2/G3 remain OPEN/NOT_RUN. No owner trial, release, production operation
or reviewer outreach occurred.

Final documentation-head CI, ordinary guarded PR26 merge and configuration
persistence require their separate recorded outcomes. Code acceptance does not
claim Publish or independently observed fresh-task restoration.

## Completed task: P14 native Windows application

All 25 mandatory software jobs pass at `e32fdc623997de1e47608dbf3b8791d294e9c391`. Exact public raw reports,
GitHub artifact ZIP digests and Git-input byte verification are retained in
[evidence/p14](evidence/p14/README.md). This includes all 24 inherited gates.

The client combines native protected SQLite/DPAPI custody, a closed five-command
IPC boundary and a three-pane EN/RU Tauri2/WebView2 interface. It includes native
PKCE login, QR/device management, independently pinned sharing/ownership,
verified note/file/search/preview flows, encrypted drafts and immutable receipt
recovery, streaming standard-age export and complete offline-first fresh import.
Unknown refresh responses require fresh login; control and binary transports
serialize protected one-use refresh before expiry. Windows loopback callbacks
explicitly restore blocking reads before the existing bounded HTTP checks; five
native auth tests cover delayed IPv4/IPv6 headers. Renderer view changes discard
late selection results without misclassifying them as a protected-generation
change. Real generation changes still mask the UI. Clipboard ownership records
the final sequence after CloseClipboard and checks its HWND owner before arming
best-effort clearing, preserving later other-app copies. The bundled Node helper
uses a safe DOS-equivalent spelling of canonical Windows script paths for its
exact-file permission allowlist. A real frozen-archive regression records
BRIDGE_CLOSED before this fix and authenticated plaintext recovery afterwards;
script/runtime pins and held handles remain enforced. Windows updates use the
maintained quiet installer mode after explicit native confirmation, avoiding a
passive language-dialog stall. Crash-restart tests wait for the unchanged short
writer lease before checking signatures. Helper stdout frames use
bounded serialized asynchronous descriptor writes so Windows output backpressure
cannot block the helper from draining native input. A real inherited-pipe test
checks concurrent frame order and full 8 MiB hashes under the same permission
boundary. No frozen format changed.

Actual Windows execution covers 5 empty-profile WebView2/typed-denial checks,
14 native tests, 33 pairing checks, 20 sharing checks, 62 native API checks,
installed WebView2/dialog/SQL/cache/clipboard/lifecycle tests (31,196 assertions,
including repeated encrypted-storage scan assertions),
and incompressible 1,000,000,000-byte upload/download/export/import with complete
hash verification. A live preview is closed by the actual five-minute idle fence.
Software HWND WTS messages retain their scope. An ephemeral signed 0.14.1 installer
rejects metadata/payload tampering, actually installs/restarts and preserves the
exact protected draft and immutable outbox. The single owner NSIS executable
bundles runtime/assets/licenses and bootstraps maintained WebView2 if absent.

Memory results retain their OS process, baseline and sampling scope; see the raw
WebView2 receipt for observed increases and the initial 128 MiB target observation.
They are not physical iPhone, arbitrary 100 GB or unsampled heap guarantees.
Production Authenticode/updater keys, physical G1/U11/U12/Hello/TPM and qualified
G2/G3 remain OPEN/NOT_RUN. No owner trial, release publication, production operation
or reviewer outreach occurred. P15 is the next implementation batch.

The complete preserved-data setup passed at the accepted source, retaining
1023 tracked files,
31 SQL tables and TLS/OAuth bytes. Actual
owned-service startup passed 15 commands at that source. Final documentation-head CI, ordinary guarded PR27 merge and
configuration persistence have separate outcomes; draft save is not Publish or
independently observed fresh restoration.

## Completed phase: P15 independent PWA software

Before implementation, the accepted P14 main `e5fe04d657850189eb956fb802fee9326e486a67`
and all 25 ordinary postmerge jobs were verified; exact receipts remain in
[evidence/p15](evidence/p15/p14-postmerge-cohort.json). No completed phase was restarted.

Candidate `b0d6c2e36680facbd49624c6205a195b2f644464` passes all 27 ordinary gates; exact raw reports,
ZIP/source-input/Git-blob verification and development failures are in
[evidence/p15](evidence/p15/README.md). The final documentation head requires its
own passing 27-job cohort before a guarded merge. Implementation includes the
installed static shell, EN/RU touch/keyboard UX, safe waiting-worker updates,
protected pause/reselect, fresh unlock and actual gigabyte age recovery/import.
A real one-byte-origin-quota write failure retains the prior encrypted acknowledged draft.
All 179 frozen files and dependency locks remain unchanged. P16 independent
staging/backup/restore operations are next; no production or owner trial is
authorized. Revert the reviewed implementation to roll back; preserve all
encrypted local state and journals, and do not purge caches/databases as rollback.
