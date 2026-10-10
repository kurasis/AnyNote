# Implementation progress

Status vocabulary: NOT STARTED, IN PROGRESS, IMPLEMENTED / UNVERIFIED, BLOCKED,
VERIFIED. Evidence outcomes: PASS, FAIL, BLOCKED, NOT RUN. A document or scaffold
does not satisfy a feature gate. Production release is not ready.

| Phase | Status | Evidence / remaining gate |
| --- | --- | --- |
| P00 | VERIFIED | Local baseline and four negative cases passed; scope/version/inventory deliverables complete; remote bootstrap and clean-clone verification passed; both baseline Actions runs verified |
| P01 | IN PROGRESS | Crypto/KDF/storage, selected 1 GB disk export, per-phase desktop RSS and real export fault/cleanup host evidence VERIFIED; Windows native probe/ABI/collector verified; actual Hello and iPhone G1 remain open |
| P02 | NOT STARTED | Depends on P00/P01 findings; qualified review remains external |
| P03 | NOT STARTED | Tooling may begin after P00; final contracts follow P02 |
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
