# Implementation progress

Status vocabulary: NOT STARTED, IN PROGRESS, IMPLEMENTED / UNVERIFIED, BLOCKED,
VERIFIED. Evidence outcomes: PASS, FAIL, BLOCKED, NOT RUN. A document or scaffold
does not satisfy a feature gate. Production release is not ready.

| Phase | Status | Evidence / remaining gate |
| --- | --- | --- |
| P00 | VERIFIED | Local baseline and four negative cases passed; scope/version/inventory deliverables complete; remote bootstrap and clean-clone verification passed; both baseline Actions runs verified |
| P01 | IN PROGRESS | Host crypto/KDF/storage/export/fault evidence VERIFIED; owner 0.1.4 fresh-process Hello authentication, WTS lock/STALE, installed-iPhone-PWA selected 1 GB hash and diagnostic recovery PASS; full physical G1/memory/network matrix remains open |
| P02 | VERIFIED | Complete five-component registry, exact note/local/native/sync/snapshot/restore/age formats, frozen bytes and independent PHP/Python/Rust-age/Go-age subsets; external review TRACKED_NOT_BOOKED / NOT_RUN; G2/G3 and product phases remain open |
| P03 | IN PROGRESS | Laravel/MariaDB/FPM/Nginx tooling and synthetic integration implemented; final contracts/generated types/errors/logging follow P02; evidence below |
| P04 | NOT STARTED | P02/P03; signature acceptance also needs P05 fixtures |
| P05 | NOT STARTED | P01/P02/P03 |
| P06 | NOT STARTED | P04 |
| P07 | NOT STARTED | P05/P06 |
| P08 | NOT STARTED | P05–P07 |
| P09 | NOT STARTED | P04/P07/P08 |
| P10 | NOT STARTED | P09 |
| P11 | NOT STARTED | P09/P10 |
| P12 | NOT STARTED | P04/P05/P10/P11 |
| P13 | NOT STARTED | P11/P12 |
| P14 | NOT STARTED | P07–P13 and actual Windows evidence |
| P15 | NOT STARTED | P01/P07–P13 and actual iPhone evidence |
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
