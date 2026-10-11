# Test evidence

Date: 2026-10-10. Host: Debian 13.6 x86_64, Python 3.12.14, Git 2.52.0.
Only synthetic/documentation work has been performed. This file never treats
an unexecuted command, a compiled scaffold or an AI review as feature acceptance.

| Check | Command / method | Outcome |
| --- | --- | --- |
| Repository inspection | `git status`, `git symbolic-ref HEAD`, `git ls-files` | PASS: initially empty unborn `work`, no existing files |
| Remote read | `git ls-remote origin` | PASS: exit 0, zero refs |
| Requested branch | `git ls-remote --exit-code origin refs/heads/main` | Exit 2: main absent before bootstrap; not a credential failure |
| Archive CRC | Python `zipfile.ZipFile(...).testzip()` | PASS: no corrupt member |
| Version research | HTTPS metadata and official source mirrors; receipts in SOURCE_EVIDENCE.json | PASS for selected metadata; some direct hosts BLOCKED (proxy 403) |
| Docker availability | `docker info --format '{{.ServerVersion}}'` | PASS: daemon 28.4.0; no app containers started |
| GitHub CLI auth | `gh auth status` | FAIL: supplied GH_TOKEN reported invalid; no value displayed |
| Baseline check | `python3 scripts/check_baseline.py` | PASS: executed locally, exit 0 |
| Negative integrity checks | Temporary copies: changed spec, missing handoff, broken link, reduced file limit | PASS: all four rejected with exit 1; restored copy passed |
| GitHub Actions | `.github/workflows/baseline.yml` | NOT RUN: workflow prepared; API status retrieval blocked (proxy Forbidden) |
| App build / service / feature tests | No implementation exists | NOT RUN: P03 onward |
| Physical Windows / iPhone | No target attached | BLOCKED: P01 requires genuine targets |
| Independent review | No qualified reviewer engaged | NOT RUN: P02/P17 gates |

GitHub CI status remains separate from local test status. No application tests
were skipped or replaced with baseline documentation checks.

## Baseline validation details

Ran `python3 scripts/check_baseline.py`: 21 SHA-256 entries matched; UTF-8,
local file links, fence closure, phase records and scope checks passed. Exact
maximum-file framing is 120 chunks, last plaintext part 1,755,648 bytes, total
data ciphertext 1,000,001,920 bytes excluding the separately encrypted manifest.
Both cache/reservation budgets accommodate data-chunk framing; complete manifest
and object overhead accounting remains P12 work. This is arithmetic, not a transfer.

Negative validation used disposable `/tmp` copies via the checker
`--root` argument, then restored originals. It detected modified specification
bytes, a missing handoff file, a nonexistent local-link target, and a silently
reduced file limit. The restored copy passed. No tracked input was damaged.

`gh api repos/kurasis/AnyNote --jq .default_branch` failed with proxy Forbidden.
The earlier CLI token status therefore does not establish that the injected
credential itself is expired; API network access must be resolved first.

## Publication and clean-clone evidence

Initial commit `0967778a02bcd3beaee3e2e1695d435e3bb31c4a` was pushed to
`origin/main`; `git ls-remote origin refs/heads/main` returned the identical SHA.
This bootstrapped the empty repository directly, so there was no PR to merge.

A separate remote `git clone --depth 1 --branch main` into a disposable `/tmp`
directory ran `python3 scripts/check_baseline.py` successfully; the clone stayed
clean. Baseline fresh-clone reproducibility is verified, not application setup.

The Actions workflow was included in that push. Querying Actions runs still
returned proxy Forbidden, so CI execution/result is UNVERIFIED. Only
`api.github.com` was added to custom allowed domains in a confirmed saved cloud
configuration draft; existing package-manager presets were preserved. The save
requires environment-settings review/save and publication; it did not apply
network changes to this instance. No setup/start script or secret field was
changed: P00 needs no dependency installation or live service.

## P01-CRYPTO-INTEROP — initial local run

Pinned Rust/Cargo 1.99.0, Node 24.21.0/npm 11.19.0 and libsodium 1.0.22.
`cargo test --locked --release`: 3 passed, 0 failed/ignored.
`cargo clippy --locked --release -- -D warnings` passed after using Rust
1.99 is_multiple_of instead of the earlier modulo-style lint violation.
`node run.mjs --native-only --large --write-fixtures`: PASS_NATIVE_BROWSER_NOT_RUN;
156 primitive positive/negative checks across Rust/Node. Real files at 0, 1,
8 MiB−1, 8 MiB, 8 MiB+1 and 1,000,000,000 bytes round-tripped; oversize rejected
before directory creation. Maximum file used 120 chunks and 1,000,001,920 data
ciphertext bytes; native SHA-256 and output length agreed, peak RSS 26,128 KiB.

Browser startup with sandbox enabled failed before page load: the cloud helper
is owned by nobody and /proc user namespace mapping is read-only. This is a
confirmed runtime capability blocker. No --no-sandbox workaround was used.
At this initial local run, hosted Ubuntu browser evidence was pending. No physical Windows/Hello/iPhone
checks or qualified review have run.

### Hosted initial Chromium fixture run

[Run 38052534170](https://github.com/kurasis/AnyNote/actions/runs/38052534170)
passed at `f48dc074407ef63ee8346bc5d06dee1de577795c`: real Chrome
154.0.8037.97, sandbox enabled, 312 live cross-runtime primitive checks and
small native/browser file boundaries. Public browser-worker fixture was obtained
from this run and consumed successfully by local Rust/Node. Raw sanitized
report: [p01-bootstrap-small.json](evidence/p01-bootstrap-small.json). It is
explicitly a **small** run, not the full decimal 1 GB browser acceptance.

Initial cancelled larger runs were investigated rather than called passed:
38052136292 and 38052390745. Phase timing isolated a bulk synthetic-source
CSPRNG bottleneck: Node 8 MiB randombytes_buf took approximately 24–25 s while
AEAD encryption took approximately 0.14 s. Browser old-source timing similarly
spent about 12 s generating one chunk. Native Web Crypto CSPRNG now fills test
source buffers in requests of at most 64 KiB; libsodium still creates keys and
performs encryption. The harness also avoids CDP interception of binary uploads
to avoid artificial copies. No forced garbage collection or weaker randomness.

A fresh local frozen reinstall, Cargo release build and baseline checker passed.
Local committed-fixture checks: 390 Rust/Node positive/negative checks; browser
NOT RUN in this cloud invocation. The later full hosted run is recorded below.

Reusable cloud install_script and start_skill were saved successfully. They
activate pinned tools, use frozen installs, retain checksum/signature/TLS
verification and document the cloud browser blocker. Saving a draft did not
publish an environment snapshot; review/save and publish through settings is
still needed to retain the prepared configuration for future tasks.

### Full hosted 1 GB and frozen-corpus run

[Run 38052778078](https://github.com/kurasis/AnyNote/actions/runs/38052778078)
completed **PASS** at `8bbebb4e80f919a7660c97c9a09d1630f44274e7`.
Ubuntu 24.04 x64, Node 24.21.0, Rust 1.99.0, native/WASM sodium 1.0.22,
actual Chrome 154.0.8037.97 with sandbox enabled. Sanitized machine report and
source/run provenance: [p01-large.json](evidence/p01-large.json).

- 663 primitive positive/negative checks: eight live producer/consumer paths
  (312), plus three frozen producer fixtures consumed by all three runtimes (351).
- Six corrupt/version fixture rejections and two 1 GB+1 input rejections;
  three native Rust tests passed. Formatting and strict release clippy passed.
- Native real disk file: 1,000,000,000 bytes, 120 chunks, authenticated decrypt
  and exact output length/SHA-256 match; 30,733 ms, peak RSS 27,212 KiB.
- Browser worker: independent generated 1 GB CSPRNG stream, ciphertext-only
  loopback upload/download, exact SHA-256/length match; 100,422 ms, uploaded
  and downloaded 1,000,001,920 bytes each; no external requests or page errors.
- Browser WASM heap stayed at 16,908,288 bytes after warmup. Sampled aggregate
  Chrome process RSS rose by 421,376 KiB to 1,377,956 KiB. Shared pages can be
  counted twice and transient peaks missed; this is a desktop approximation.
  The 64 MiB iPhone budget is **not verified**, despite bounded JS chunk sizes.

These are two host feasibility pipelines, not a single Windows/iPhone product
transfer, source-picker/recipient protocol, interruption/resume or iOS Files
export. Physical tests remain NOT RUN. Two earlier P00 baseline Actions runs
were also confirmed successful: 38050530611 and 38050457441; this resolves the
historical API-unavailable observations above.

### Owner-supplied targets and Windows source reference

Owner reports iPhone 17 Pro / iOS 26.7.1 and Windows 11 Pro 25H2; Windows Hello
will be available. These reported strings are preserved without claiming an
inspected build, configured provider, API/PRF support or physical trial.

The requested upstream handoff and selected source snapshots were saved under
[docs/reference/passkeylocal](reference/passkeylocal/README.md), with archive and
per-file SHA-256 receipts. Retrieved current source `15f54f00...` and installer
source `c18894e...` through authenticated Git, preserving license/header notices.
Upstream owner confirmation applies to its password-vault Hello flow, not AnyNote
or the newer File Safe flow. The PRF/TPM mechanism is mapped to a random local
vault key in ADR-003 and the next probe task. No upstream installer/source build
or Windows hardware operation was executed in this cloud capture.

## P01-LOCAL-UNLOCK host evidence

[Run 38056304802](https://github.com/kurasis/AnyNote/actions/runs/38056304802)
completed **PASS** at `066fdd0a6838c3dfaa1dc9831b6fe8b527820c2c`.
Raw sanitized reports and provenance are retained in
[p01-local-unlock-large.json](evidence/p01-local-unlock-large.json) and
[p01-windows-capabilities.json](evidence/p01-windows-capabilities.json).
This is host feasibility evidence, not physical G1 acceptance.

- All 663 prior live/frozen primitive checks passed. Native Rust tests: 4;
  portable Windows policy/lifecycle tests: 70. Formatting and strict clippy pass.
- Three frozen Argon2id13 vectors match Rust, Node and a real Chromium worker;
  14 invalid profiles per consumer (42), three wrong-phrase wrapper rejections
  and concurrent KDF admission rejection pass. Browser times: 174/161/163 ms;
  WASM heap: 67,371,008 bytes at the 64 MiB / opslimit 3 public profile. These
  figures do not establish a total-process 64 MiB iPhone budget.
- IndexedDB and OPFS contain only synthetic opaque ciphertext. Exact bytes/hash
  reopen across worker restart, actual read-only transaction rejection and
  bounded quota fault rejection pass. CDP quota injection produces real
  QuotaExceededError; it is not physical disk exhaustion. Persistence was denied.
- A real selected disk File of 1,000,000,000 bytes is encrypted, uploaded,
  downloaded, authenticated and explicitly written to an OPFS test export;
  reread saved-file length/hash match independent Node SHA-256
  `55cdb814804366d2ba8e2915b88c513df1ed0cc77a7e8af131a9af140d49cbbe`.
  Upload and download are each 1,000,001,920 ciphertext bytes. The runner uses an
  isolated disk-backed Chrome profile with the sandbox enabled. This selected
  file pipeline has no separate process-memory result yet.
- Oversize-before-read, source-reselection mismatch and locked export rejection
  pass. A verified empty disk File share candidate is prepared, but Chrome
  reports share capability false: actual sharing **NOT RUN**, iOS Files
  **NOT VERIFIED**. No whole-file buffer/Blob fallback was introduced.
- Windows 2025 / MSVC: 98 routine tests pass; one independent official-header
  ABI case is ignored in the routine run and then explicitly executed: 1 pass,
  zero ignored. Release build passes. The preserved Microsoft header retains
  exact SHA-256 `da82d5be6b90a2706185ae44ad93649bcefc0f89c97ab930ec4e6f0abb7b2283`.
  The unsigned probe artifact hash is recorded with source provenance. Hosted
  OS build 26100 reports WebAuthn API 7: **BLOCKED** by the required API 9 gate,
  no native objects created, no enroll/unlock or physical acceptance claimed.

Earlier [run 38055718166](https://github.com/kurasis/AnyNote/actions/runs/38055718166)
failed: Windows strict clippy found needless_question_mark; Linux completed
primitive/KDF/storage checks but the selected 1 GB OPFS export produced
QuotaExceededError in an incognito context after quota fault injection. The
successful run isolated that fault in another context and used a fresh disk
profile; both changed, so the isolated cause is not proven. The unchanged 1 GB
size and all assertions were retained. The initial compile/lint run
38055457400 also failed, and its superseded Linux job was cancelled. Failures
are not counted as successful complete runs.

Local pinned runtime checks also passed: native-only interoperability/KDF,
both Rust test suites, formatting, strict clippy, baseline and clean diff
whitespace. Local sandboxed browser startup remains BLOCKED by the cloud
sandbox helper; full browser evidence comes from Actions without disabling it.
An optional GNU cross-target attempt could not build sodium without MinGW;
the successful MSVC build above supplies Windows build evidence.

The installer steps were repeated successfully, including frozen npm install
and both Rust builds. A temporary loopback trusted-HTTPS server was exercised
with normal certificate verification: PWA assets/CSP, 32-byte bounded ciphertext
PUT/GET and rejection of part 120. Its own server was stopped and temporary
payload state cleaned. No public/private-device origin was deployed.

The updated tested cloud install/start draft was saved as
`06e641e5-588c-4150-8c32-487c9910c0b2~cecfgdraft_6aca3db0b514819fbc2465187459c698`.
It still requires publication in environment settings for future tasks.
Actual Windows Hello prompts/cancellation/lock and installed-iPhone
KDF/storage/memory/Files trials remain **NOT RUN**. See NEXT_TASK.md for the
next bounded physical/fault evidence slice.

## P01 export memory, fault and owner-trial preparation

[Run 38060083515](https://github.com/kurasis/AnyNote/actions/runs/38060083515)
completed **PASS** at `1664d0dcdc4db560d1c342a70c8f7dead73f3c4b`, together
with baseline run 38060083516. Sanitized reports/provenance:
[p01-export-faults-large.json](evidence/p01-export-faults-large.json) and
[p01-hosted-collector.json](evidence/p01-hosted-collector.json).

- All 663 live/frozen primitive checks, KDF/storage/quota checks and the exact
  native/generated-stream/selected-file 1 GB pipelines pass. Existing Rust
  suites and strict fmt/clippy gates also pass: 4 native, 70 portable, 98 Windows
  routine plus 1 explicitly executed independent ABI test.
- Real selected File: saved 1,000,000,000 bytes; upload/download each
  1,000,001,920 ciphertext bytes; independent SHA-256
  `e2127a52742b8c47998ad53e5558d0092b058c0f9ce9f489045a94a317e8fdba`.
  Browser sandbox remains enabled; there are no external requests/page errors.
- Separate selected-file desktop RSS measurements:

| 1 GB phase | Baseline KiB | Sampled peak KiB | Increment KiB | Samples | Duration ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Encrypt/upload | 1,064,008 | 1,480,700 | 416,692 | 140 | 62,461 |
| Decrypt/export/saved-file readback | 1,323,872 | 1,428,848 | 104,976 | 986 | 25,157 |

These are aggregate desktop process samples, not mobile memory or hard peaks.
Shared pages may be counted twice. The requested 25 ms timer is serialized
behind CDP/proc reads and can have much longer gaps; sample count/duration are
reported, not a claim of an achieved fixed interval. The final sampler adds
longest observed gap tracking. iPhone memory remains **NOT MEASURED**.

- Corrupt and truncated HTTP second parts after one verified first-part write
  are rejected. Actual OPFS writer abort preserves the previous committed file.
  An unchanged-ciphertext retry fully authenticates and rereads the correct file.
- Holding the second real GET until lock acknowledgement then releasing it is
  rejected as PAUSED_LOCKED, with only the first part processed and old output
  preserved. This is a host lifecycle fault, not a physical interruption pass.
- Real gzip response: encoded Content-Length 32,784, decoded bytes 32,785.
  Fixed-buffer reader rejects expansion before any plaintext write; old output
  remains unchanged. Actual exclusive OPFS writable ownership denies a competing
  export. No mocked crypto/sink replaces these checks.
- Failed share preparation removes its owned temporary directory. Reload loses
  live keys; marked orphan cleanup removes one verified export while preserving
  no-marker, different-marker and unrelated test controls. Second cleanup removes
  zero. No secure-erasure or arbitrary-OS-sink claim.
- Windows collector executes capabilities on actual hosted Windows Server 2025
  build 26100/24H2, checks source/EXE hash and writes content-free metadata.
  Embedded source matches the run, SHA-256
  `c0105e5ac6301fbd509629d53a66b2cd1579c89aff215344b4f64db8b3b96aea`.
  API 7 is BLOCKED by the required API 9 gate, native objects false, physical
  acceptance false, environment explicitly hosted. Hardware is a VM.

Local actual fixture-tool checks pass at 0/32,768/8,388,609 bytes: create/inspect
agree with independent Python SHA-256, overwrite is refused without changing
existing data, 1,000,000,002 is rejected before creation. Native-only small
interop/KDF passes; browser is explicitly NOT RUN in that mode. A separate full
local invocation failed at sandbox startup after the native slice: cloud helper
ownership remains the environment blocker. No sandbox/verification bypass used.

Owner reports the private HTTPS host is not ready. Prepared owner/Windows HTTPS
runbooks are procedures, not executed certificate/firewall/device tests. The
template is explicitly UNFILLED. Actual Windows prompts, installed-iPhone
storage/KDF/Files/process memory, physical low space and the second older phone
remain **NOT RUN/BLOCKED**. G1 is open; next independent work is P03 tooling.

## P01-DEVICE-KIT local preparation

72 portable native tests PASS: prior 70 plus frozen AEAD/three public Argon2id
corpora and actual 8 MiB+1 disk output / pre-write 1 GB+1 refusal. Strict clippy
and formatting PASS. Static kit build PASS with bundled pinned sodium; ZIP
contains 14 root-level assets with CRC and SHA-256 receipts verified. Original
21 specification checksums and baseline checks PASS. No dependency resolutions
changed. Actual hosted nested-path one-button/exact 1 GB/mock-share workflow,
MSVC build/ABI/single-EXE 1 GB report and publication are pending in this initial
source snapshot. Physical iPhone/Hello and production release gates stay open.

### Hosted device-kit evidence

At `4629afe9a22ddf37ac28a6de8a52771274371481`,
[run 38067929130](https://github.com/kurasis/AnyNote/actions/runs/38067929130)
passed all three feasibility jobs, including the existing full 1 GB
Rust/Node/browser network/export/fault suite. Chrome
154.0.8037.97 with sandbox enabled exercised the actual button/worker at
`/nested/anynote-p01/`: three frozen crypto corpora, public KDF vectors/invalid
profiles, ciphertext storage, local bounded pipelines and real second-part
corruption/truncation/overflow preservation, exact 1 GB/120 parts, selected saved
output, downloaded JSON and zero remaining owned export directories.
Share was an explicit test-only mock with a real bounded disk copy, not an OS
Files pass. The full SHA-256 was
`bac21eb6053ff6e85c13c06149afb0c8ef217fb7a5f86601947b52b0562184e7`.
[Raw browser report](evidence/p01-device-kit-hosted-browser.json).

MSVC: 100 routine native tests passed, one independent official C-header ABI
test explicitly passed. Single-EXE hosted report included 51 frozen AEAD/KDF
checks, a real exact 1 GB/120-part disk round-trip and cleanup PASS. Its source
and executable hash were validated by CI. Actual hosted WebAuthn API 7/build
26100 remained BLOCKED and no native objects were created; there was no fallback
or physical Hello claim. [Raw Windows report](evidence/p01-device-kit-hosted-windows.json).
Final dependency-import inspection and latest-source CI remain pending here.

The first static job in
[run 38067761595](https://github.com/kurasis/AnyNote/actions/runs/38067761595)
failed during saved-file verification: the next action was enabled while
share cleanup still held the worker request. The overall run was subsequently
cancelled by the next push, not counted as a full pass. The corrected UI keeps
the action disabled until cleanup finishes; the repeat at 4629afe passed.
No assertion was weakened and no browser sandbox was disabled.

### Final kit verification and publication transport

Final source `5a09852b15f863de297a1ac4965c417d580df80d` passed all three
feasibility jobs in
[run 38068299281](https://github.com/kurasis/AnyNote/actions/runs/38068299281)
and baseline
[run 38068299240](https://github.com/kurasis/AnyNote/actions/runs/38068299240).
PR #4 merged to `4dd38864787ecf30c3758de0b300a0b8967c7c75`; its source tree
was compared equal to the tested head. Final downloaded Windows EXE SHA-256:
`6e4902fdcee70ae55808b85afc3e96330f5c5a8a87f286bc915b9f6c5d462975`;
iPhone ZIP:
`e0d35cd1111bd9a6f1995bc47e2e6be367bbdbfc4ba68e6b0f1f227e84942d7a`.
Runtime source/hash, ZIP CRC and all asset receipts matched after download.
Microsoft dumpbin observed only system DLLs, no VC runtime or sodium DLL.

The cloud release-upload attempt failed with HTTP 401 at uploads.github.com;
subsequent API listing confirmed no retained release or tag. This was not a
CI/build/physical failure. A guarded Actions publisher now uses its own job
token and verifies actual published bytes/tag. Its execution is pending in
this initial source snapshot; no upload success is inferred from preparation.

## Owner-supplied 0.1.0 trial and 0.1.1 regressions

[Raw Windows report](evidence/p01-owner-windows-v0.1.0.json) is the owner's
chat-supplied JSON, semantically preserved, not a cloud/hosted capture. Its source
5a09852 and EXE hash 6e4902fd... match the published 0.1.0 artifact. Timestamp
1791651566384 is reported by that device, not independently verified. Owner
reports Windows 11 Pro 25H2; observed report is build 26200/API 9, available
platform, one unlocked display-name candidate. Crypto/KDF 51, exact 1 GB/120
chunks and local cleanup PASS. No native operations ran; no per-key or Hello
authorization acceptance is inferred. The unresolved `eligible=false` flag was
incorrectly used as trial admission. Portable regressions exercise this exact
record and reject old/missing APIs, malformed reports, failed checks, locked or
missing providers; all 74 native portable tests and strict Clippy PASS.

The owner separately reported installed iPhone PWA resetting to its initial page
after saving to Files. No phone JSON, hash, process-memory or precise termination
cause was available. New regression uses a real sandboxed browser page reload
while an activated mocked Share is pending after its bounded 1 GB OS-copy stand-in.
It restores the same diagnostic files/digests, marks handoff UNKNOWN, independently
reselects/hashes saved bytes, downloads the retained report, preserves success and
failure across reopen, and rejects malformed/denied storage. Actual hosted result
and new release evidence will be attached after CI; this is not physical iOS proof.

Hosted browser regression PASS at source
`f92dcb4eda58c6ce164728a378699f93adef572b`, feasibility run 38071301931,
static job 114269092773 (sandboxed Chromium 154.0.8037.97). Actual raw report:
[p01-device-kit-recovery-hosted-browser.json](evidence/p01-device-kit-recovery-hosted-browser.json).
The exact selected output has SHA-256
`5dc9473978377eb7d3454963eee3354bc4c512d615ad2850fbbb403596f19697`;
checkpoint restored after actual page destruction during pending mocked Share,
then independently verified 1 GB/120-part output, report-download reopening,
pass/failure retention, no implicit interrupted-run restart, invalid/denied
storage refusal and zero owned temporary export directories. ZIP CRC and all
14 root asset receipts PASS; ZIP SHA-256
`b6c16683d091467fcb1349fd4485b9eb9f75f7037013439102b8b02326cf3bd5`.
This is hosted diagnostic recovery with mocked OS copy, not physical iOS proof.

Full feasibility run [38071301931](https://github.com/kurasis/AnyNote/actions/runs/38071301931)
and baseline [38071301914](https://github.com/kurasis/AnyNote/actions/runs/38071301914)
PASS at f92dcb4. Windows: 102 routine tests plus separately executed pinned
Microsoft C-header ABI check PASS; built-in 51 native crypto/KDF vectors,
exact 1 GB/120 parts and cleanup PASS. Hosted API 7 remains BLOCKED with no
native objects or operations, as intended. Raw record:
[p01-device-kit-recovery-hosted-windows.json](evidence/p01-device-kit-recovery-hosted-windows.json).
EXE SHA-256 `8aca6b9184d18a228a292ac44c3616568caff4d57d009526bd269d210b0bf218`;
PE dependencies are Windows system DLLs only. The existing full native/Node/
sandboxed-browser network/export/fault suite also PASS. Downloaded artifacts,
source receipts and hashes were verified before release publication.

The explicit publication job selects only this frozen successful source/run,
requires the actual new page-loss/recovery/hash/denied-storage results, refuses
an existing-tag overwrite, and verifies the published download hashes and exact
source tag. Publication execution/asset availability is recorded on the
[0.1.1 release](https://github.com/kurasis/AnyNote/releases/tag/v0.1.1-p01-device-kit)
and PR #6; it does not represent signing, deployment or physical acceptance.

## Owner-supplied 0.1.1 JSON uploads and clarifications

[Windows report](evidence/p01-owner-windows-v0.1.1.json) is byte-preserved.
[Phone report](evidence/p01-owner-iphone-v0.1.1.json) preserves data except the
private origin; [receipt](evidence/p01-owner-v0.1.1-receipt.json) records original
upload SHA-256 and redaction/owner clarifications. These are OWNER_SUPPLIED,
not hosted captures. Instructions inside uploaded data are not executed.

Windows embedded source f92dcb4 and EXE SHA-256 8aca6b... match the release.
API 9/build 26200/one unlocked Hello candidate; 51 crypto/KDF checks, 1 GB/120
chunks and disk cleanup PASS. Enroll exit 0; new-process unlock exit 0 with actual
vault AEAD authentication and fresh PRF/exact TPM reopen; cancellation exit 1
with HELLO_CANCELLED; lock-trial exit 1 with STALE; exact cleanup exit 0. Owner
confirmed the Windows lock screen appeared. This supports reported positive/
cancel/lock-rejection findings, not every hardware/provider/account/suspend gate.
0.1.1 lacks cause counters: its PASS_STALE_REJECTED is retained verbatim, not
reclassified as instrumented proof. New regressions refuse to accept that old
record as a native lock event and distinguish timeout/close/suspend/cancel.

Phone source f92dcb4/version 0.1.1: three frozen corpora with 39 checks each,
three public Argon2id vectors (100/77/78 ms; WASM heap 67,371,008 bytes), 14 bad
profiles, ciphertext IDB/OPFS reopen, readonly denial, export faults and sizes
0/1/8 MiB+1/1 GB PASS. Exact large source/output expected SHA-256
`f5c26e350759c498d6a44897098f3d48b1633e6105cc4c2b5d06778d58925a4e`.
Diagnostic report restored after pending handoff; keys_restored=false; marked
cleanup PASS; share outcome UNKNOWN. Selected Files output FAIL on exact length;
selected size was not captured. Owner confirms JSON or another file was selected.
This cannot establish Files byte/hash failure of the actual .bin, or a successful
save. installed_pwa=false: physical Safari, not Home Screen evidence. The user
agent does not independently verify the reported iPhone model/iOS release.
WASM heap is not process memory; network/resume and remaining G1 matrix OPEN.

Portable native tests 76 PASS and strict Clippy PASS after the instrumentation
and retry changes. Hosted regression uses an activated picker to select a tiny
JSON, records 5 versus 1,000,000,000 bytes, retains the failure across reload,
then selects/hashes the existing 1 GB without another automatic trial. It also
checks legacy report-stage recovery from the one documented previous key.
Hosted results and exact 0.1.2 publication receipts are recorded separately.

### Hosted 0.1.2 build and publication selection

All three feasibility jobs [38074016248](https://github.com/kurasis/AnyNote/actions/runs/38074016248)
and baseline [38074016234](https://github.com/kurasis/AnyNote/actions/runs/38074016234)
PASS at a225e3f099551b95aa1893f941de522f543e8f44. Windows: 105 routine native
tests plus separately executed pinned Microsoft C-header ABI PASS; 51 crypto/
KDF checks and exact 1 GB/120 chunks/cleanup PASS; hosted API 7 stays BLOCKED
with no native objects. Event-mapping tests use Windows message constants,
not a physical lock; portable classification rejects missing-event legacy STALE,
timeout/close/suspend/cancel and successful-authentication mismatches.

Raw hosted records: [browser](evidence/p01-selection-retry-hosted-browser.json),
[Windows](evidence/p01-selection-retry-hosted-windows.json). Browser selected
5-byte JSON through the activated picker, retained its FAIL across reopen, then
selected and independently hashed the same saved 1 GB without another automatic
trial. Large selected digest `efeac2a321293d568de43140742c05a579a8b8974f747154f49e2d7d4648bc18`.
Legacy failed report-stage recovery from the one documented sibling key PASS;
original key preserved. Prior page-loss/denied-storage/fault/cleanup regressions
and the existing full native/Node/browser network/export/fault suite PASS.

Downloaded EXE SHA-256 `434878b19f7b0816c07ddf283d5156b652ac68650a4ad03df4718eda45550cb1`; system-only PE dependencies.
ZIP SHA-256 `02a6b5b1f46db4fe1eb85a6706e5d177906a38f0d865489392cec0d29a7c6f96`;
CRC/source/14 asset receipts verified. The explicit publisher freezes these
successful bytes, additionally requires actual wrong-JSON size/retry and legacy
recovery results, and verifies published downloads and the exact source tag.
Publication execution is recorded in [PR #7](https://github.com/kurasis/AnyNote/pull/7)
and the [0.1.2 release](https://github.com/kurasis/AnyNote/releases/tag/v0.1.2-p01-device-kit).
Hosted sharing remains mocked; no production deployment/signing or complete
physical acceptance is inferred.

## Owner 0.1.2 feedback and 0.1.3 candidate

Raw [Windows report](evidence/p01-owner-windows-v0.1.2.json) preserved byte for
byte; [receipt](evidence/p01-owner-v0.1.2-receipt.json) records upload checksum,
source/EXE and owner clarification. Source a225e3f and EXE 434878... match the
0.1.2 release. Positive enrollment/fresh-process authentication, cancellation,
cleanup and local checks PASS. Guided lock: HELLO_CANCELLED, all event counters
zero, NOT PROVEN. No new phone JSON; reported Share restart is an owner
observation, not host-derived cause or Files acceptance.

Local 77 portable tests PASS, including actual owner cancelled/zero-event
regression and refusal to classify OS-request acceptance as lock proof. Strict
Clippy PASS. Static kit builds; hosted real attachment/replay/recovery/picker/hash,
Windows compilation/ABI and release publication are pending.

Hosted candidate 2cc346e: static kit and Windows jobs PASS in [run
38076184680](https://github.com/kurasis/AnyNote/actions/runs/38076184680).
[Raw browser](evidence/p01-stream-download-hosted-browser.json) and
[raw Windows](evidence/p01-stream-download-hosted-windows.json) are archived.
Chrome 154.0.8037.97 uses its actual sandbox and download stack: exact 1 GB
streaming attachment, independent Node disk SHA-256 and activated picker match;
partial stream cancellation releases the lock, replay/unknown token/arbitrary
path/wrong-purpose marker are rejected. Retained synthetic output reopens and
rehashes after page destruction/reload; wrong JSON retry and previous diagnostic
migration pass. Owned export directories remaining: zero. Optional OS Share
alone remains explicitly mocked. The initial fcee8b3 candidate failed when a
download attribute cancelled the new attachment; navigating to the scoped SW
attachment fixes that route. No failed run is counted as acceptance.

Windows: 106 routine tests PASS; one ABI test initially ignored is explicitly
run separately and PASS against the Microsoft C-header measurements. Strict
Clippy, 51 native crypto/KDF, exact 1 GB/120 chunks, cleanup and system-only PE
imports PASS; hosted API 7 creates no Hello objects and requests no system lock.

Frozen candidate asset SHA-256:

- EXE: `1a3dbdd9b62965a00d2a36a46ddc63a849ba8205c411e1f8c7a94ad3603db85e`
- ZIP: `01670435db6fa4f08078cc41ec7ffa009aa3787640cb90032cb7e6325e995e50`

ZIP CRC, exact source/version and all static asset receipts PASS locally.
Source baseline [38076184710](https://github.com/kurasis/AnyNote/actions/runs/38076184710)
PASS. Full Linux native/Node/network/browser job also PASS: 663 primitive checks,
public Argon2id vectors, real storage, exact 1 GB selected upload/download/export,
corrupt/truncated/expanded response, late-lock/exclusive-sink/orphan cleanup.
All three source feasibility jobs PASS; publication execution remains pending
and is recorded on PR #8/release after it runs. Physical iOS stream/Files/memory and selected Windows lock
remain OPEN; these reports do not close G1.

0.1.3 publication run 38076628838 PASS; independently downloaded EXE/ZIP
match recorded hashes, ZIP source/version/receipts and exact source tag.
0.1.4 adds durable single-use synthetic ticket metadata and a real CDP worker
stop before attachment request; new source run pending. The earlier test
release remains unchanged, not overwritten with unverified bytes.

0.1.4 source 566ec84: all three [feasibility jobs
38076947436](https://github.com/kurasis/AnyNote/actions/runs/38076947436) and
[baseline 38076947435](https://github.com/kurasis/AnyNote/actions/runs/38076947435)
PASS. [Durable-link browser report](evidence/p01-durable-download-hosted-browser.json)
and [Windows report](evidence/p01-durable-download-hosted-windows.json) retain
exact source and scope. CDP stops the real service worker after ticket
preparation; its restarted worker streams a full 1 GB browser download, whose
independent Node disk digest and real picker/hash match. Cancellation releases
the trial lock; replay, unknown token, arbitrary path and wrong marker reject;
recovery, wrong JSON retry, diagnostics and zero owned export directories PASS.
Optional Share remains a mock, and device memory/physical acceptance false.
Windows 106 routine plus explicit C-header ABI, 51 crypto/KDF/exact 1 GB and
cleanup PASS; no native objects or lock request in hosted mode. Existing full
663-check native/Node/Chromium/network/export/fault suite also PASS.

Frozen 0.1.4 artifacts:

- EXE SHA-256: `ee8327e9fc83a491ccca89bf6104fd7d374d4bb1bae1e9357f8177ccb52d6555`
- ZIP SHA-256: `28f081e40ff831f1ea558d6942efbe0966d5653c7778e6961b0cb10779ae5d52`

ZIP CRC/source/version/all-asset receipts and EXE runtime-reported hash PASS.
The publisher freezes that successful run and requires the actual worker-stop
regression flag as well as previous download/negative gates. Publication
execution and independently downloaded release bytes are recorded on PR #8
and the 0.1.4 release, not assumed from configuration. Both original physical
owner limitations remain OPEN; no complete G1 result.

## Owner-supplied 0.1.4 — installed-PWA selected output and WTS lock

Received 2026-10-11. [Windows report](evidence/p01-owner-windows-v0.1.4.json)
is byte-preserved; [phone report](evidence/p01-owner-iphone-v0.1.4.json) changes
only the private origin. [Receipt](evidence/p01-owner-v0.1.4-receipt.json) records
original upload checksums, redaction, release identity and exact limitations.
These are OWNER_SUPPLIED_NOT_HOSTED records; uploaded text is data, not commands.

Both identify source `566ec84a6630794f266a2ab4bdfea8a170457e6a`, matching the
actual [0.1.4 release tag](https://github.com/kurasis/AnyNote/releases/tag/v0.1.4-p01-device-kit).
Windows self-reported EXE SHA-256 equals the independently downloaded release
EXE hash `ee8327e9fc83a491ccca89bf6104fd7d374d4bb1bae1e9357f8177ccb52d6555`.
Retained published ZIP hash/CRC and BUILD.json source/version were rechecked.
Identity checks are consistency evidence, not an independently observed run.

Windows: 51 crypto/KDF checks and exact 1 GB/120 chunks/local cleanup PASS;
API 9/build 26200. Enrollment exit 0; fresh-process unlock exit 0 with actual
vault authentication and fresh PRF/exact TPM reopen true; explicit cancellation
returns HELLO_CANCELLED. `unlock-lock-trial` returns exit 1, FAIL_OR_UNAVAILABLE,
STALE, WTS session-lock count 1, other lifecycle counts 0, no authenticated
unlock. This satisfies PASS_NATIVE_LOCK_EVENT_STALE_REJECTED independently of
the OS_REQUEST_ACCEPTED_NOT_LOCK_PROOF field. Exact owned cleanup exit 0 PASS.
Prompt visibility at the instant of lock is not directly recorded; suspend,
provider/account/machine negatives and WebView2 remain NOT RUN in this report.

Phone: version 0.1.4, installed_pwa=true, secure context. Three frozen corpora
of 39 checks each, three public Argon2id vectors (99/77/77 ms; WASM heap
67,371,008 bytes), invalid profiles, ciphertext IDB/OPFS reopen, readonly denial,
export corruption/truncation/overflow and sizes 0/1/8 MiB+1/1 GB PASS. The scoped
SW sent 1,000,000,000 bytes. Independently selecting the output produced
PASS_SELECTED_OUTPUT_HASH, exact selected length and digest
`7408855a02fe65cc1ace7e0742c2e3129a2d7d4dbd5569607ab53d3dd5b83764`,
matching the local 1 GB expected digest. The stream-sent status alone is not
saved-output proof; the selection digest is the narrower successful evidence.

After reopening at verify stage, recovery reports RESTORED_DIAGNOSTICS_ONLY,
keys_restored=false, retained_export=REOPENED_AND_HASH_VERIFIED; temporary
export cleanup PASS. This establishes reported diagnostic/export recovery,
not the cause of the page restart, background stream survival or resumed keys.
Destination folder provenance and process memory are unmeasured. UA does not
independently verify the owner-reported iPhone model/iOS version. Remaining
network/resume, older-phone, low-space, passkeys and PWA update gates stay open.

Local review assertions PASS for release/source/hash identity, strict lock
classification, selected length/digest, recovery/cleanup and archival fidelity;
phone JSON equals its original after the single origin replacement. Repository
baseline/checks are recorded on the evidence PR. No application code, dependency,
original specification byte, kit asset or release changes in this slice. P01/G1
remains IN PROGRESS; no repeat of these specific successful whole trials needed.

## P03 development foundation — real local service evidence

[Primary-source receipt](evidence/p03-primary-sources.json) records current
upstream metadata and verified official image pulls.
[Local report](evidence/p03-foundation-local.json) is an actual cloud-host
synthetic integration report, not physical-device or production acceptance.
It records the then-current commit plus dirty=true and exact foundation source
SHA-256 receipts; uncommitted development is not misrepresented as that commit.
Hosted clean-checkout evidence and exact tested head are recorded on the PR.

Local commands: scripts/dev-stack.py install/up/test, then stop/up/check;
strict Composer validation/platform/native extensions, audit (zero advisories
at execution), 20-file Pint, PHPUnit 3 tests/7 assertions PASS. Actual MariaDB
11.8.9 InnoDB temporary commit/rollback/drop leaves no product tables. Real
Nginx 1.30.5 -> FPM/PHP 8.4.26 -> Laravel 13.35.0 -> MariaDB request PASS.
Composer runtime 2.10.3; 99 exact dependency/license/source records PASS.

Actual container inspection confirms loopback-only Nginx and no DB/FPM host
ports; FPM/Nginx run non-root. Static app host cannot serve API/PHP; unknown
hosts and private/arbitrary-PHP/traversal paths fail with 400/403/404. Response
cache-control includes no-store across duplicate headers, no X-Powered-By.
Stopping only the owned DB yields generic 503; restart restores readiness.
Production environment refuses the tooling route/command. Native extension
loading is checked explicitly, not inferred from Composer polyfill satisfaction.

Gitleaks 8.30.1 official archive SHA-256 verified. Complete Git-visible source
scan PASS; three disposable random fake PAT negatives reject normally and in
both allowlisted receipt paths. Twelve existing reference hashes and three
generated source-input hashes were reviewed false positives. A global allowlist
failed the inventory-path negative case and was replaced with a rule-scoped AND
file/checksum-shape allowlist. Ignored state/vendor and all Git history are outside
this scan; no complete secret-absence/security audit claim. Scanner values redact.

Initial Docker build failed on read-only builder state, then on missing egress
proxy/CA trust; final build uses owned writable config, injected proxy and the
provided public trust anchor with TLS and signed Debian checks still enabled.
Initial FPM config was root-readable only; explicit COPY chmod fixes non-root
startup. The static root initially missed directory/index routing; direct HTTP
now verifies it. Laravel CLI tests use actual Artisan/DB execution rather than
requiring Mockery; missing .env warnings are resolved by preserving-or-creating
the nonsecret example. No failed attempt is counted as a passed gate.

The complete saved install script preserves existing P01 tooling and appends
frozen P03 install/start/readiness; executed locally with required activation.
install_script/start_skill draft-save result is recorded on the PR/final report.
Draft save, publication and future-task restoration remain distinct. P03 tooling
is verified; final contracts/types/errors/logging depend on P02. P01/G1 and
qualified review stay open. No public deployment, owner device action, native
reference/license change, production format/schema migration or real secret.

### Hosted fresh-checkout P03 source and existing regression checks

[Raw foundation report](evidence/p03-foundation-hosted.json) and
[receipt](evidence/p03-hosted-receipt.json) preserve the actual hosted results.
Foundation [38119399644](https://github.com/kurasis/AnyNote/actions/runs/38119399644),
baseline [38119399647](https://github.com/kurasis/AnyNote/actions/runs/38119399647)
and all three P01 [38119399652](https://github.com/kurasis/AnyNote/actions/runs/38119399652)
jobs PASS for workflow head 76860c8. Actions checkout tested merge ref 1405c76,
whose parents are main 7656fc2 and head 76860c8; its entire tree equals that head.
The raw report keeps the actual checkout commit, not a substituted PR-head stamp.

Actual foundation versions match pins; native extensions, InnoDB commit/rollback/
cleanup, HTTP readiness, DB outage/recovery, static/API/path/host isolation, actual
loopback bindings/users, production denial and 3 tests/7 assertions PASS. Hosted
source tree stays clean; generated PHPUnit cache is excluded from Git and input
receipts. The earlier dirty local capture retains that transient cache's fingerprint
as historical data, not a committed source assertion. All 43 hosted source-input
SHA-256 receipts independently match current foundation bytes. Existing native/
Node/sandboxed-browser/network/1 GB/export/fault and Windows gates also PASS.
Cancelled initial 6c79236 runs are not counted; they were superseded by the cache
tracking correction. The publication-only job is intentionally skipped.

[Environment receipt](evidence/p03-environment-setup.json) confirms complete
install execution, repeated frozen install, full owned stop/start/readiness and
actual saved install_script/start_skill. Tool returned requires_publish=true:
review/save/publish in environment settings remains product-owned; no future
restoration or production deployment is claimed.

## P02-KEY-AND-FILE-CONTRACT — candidate bytes, not application crypto

Local Node 24.21.0/npm 11.19.0/Python 3.12.14, 2026-10-11:
[raw input-hash/result receipt](evidence/p02-local.json),
[primary sources](evidence/p02-primary-sources.json),
[environment save/execution receipt](evidence/p02-environment-setup.json).
The local source commit is the previous clean main plus precisely hashed dirty
candidate inputs; do not substitute a later committed SHA into this capture.

| Check | Actual command / result | Outcome |
| --- | --- | --- |
| Frozen installation/repetition | Full saved script; repeated npm ci --ignore-scripts for packages/protocol; no source/lock mutation | PASS |
| Strict parser/schema/context/history bytes | npm --prefix packages/protocol test | PASS: 69 executed, 69 passed, 0 fail/skip |
| RFC 8785 independent expected cases | Exact numeric/string sample and UTF-16 property-order vector, no Unicode normalization | PASS |
| Candidate boundary fixture drift | npm --prefix packages/protocol run fixtures:check | PASS: six sizes, 0 through 1,000,000,000 bytes |
| Independent restricted fixture reference | python3 scripts/check-p02-fixtures.py | PASS: six cases /125 nonce-AAD pairs and two deliberately bad outputs rejected |
| File/history adversarial framing | Wrong contexts, wrap bytes, inventory/order/length/zero-file, parent digests/cycles, predecessor and greedy byte-capped pages | PASS for candidate consistency, not authority |
| Dependency/license/integrity drift | inventory:check; seven locked packages, no lifecycle scripts | PASS |
| npm advisory audit | npm --prefix packages/protocol audit --audit-level=low | PASS: zero reported vulnerabilities at execution; not a security audit |
| Git-visible source secrets and negatives | scripts/check-secrets.py | PASS: current source plus four PAT path negatives and two changed fixture key/digest values rejected |
| Original spec / P01 preservation | check_baseline.py; git diff against pre-task main for docs/spec and experiments/p01 | PASS: all 21 checksums/source unchanged |
| Existing developer service request | python3 scripts/dev-stack.py check | PASS: real Nginx/FPM/Laravel/MariaDB |
| Saved setup/start configuration | complete install script exit 0, readback exact fields/revision 6 | PASS save only; requires_publish=true |
| Candidate cryptography / authority / full R01/R14/R19 | No production implementation exposed | NOT RUN |
| Rust/browser/PHP candidate interoperability / new physical trials / qualified review | Outside this byte-contract slice | NOT RUN |

An initial RFC-order test accidentally supplied a literal control character in
JSON and correctly failed; fixing the test's escaped input produced its exact
external expected bytes. Initial source-scan failures were known public fixture
key/digest bytes, including scanner-decoded expected bytes. Final allowlist is
rule/path/exact-secret-value scoped to two known values; no partial-value/whole
path suppression. Six negative sentinels prove changed credentials still fail.
Self-review found count-only checkpoint packing excluded legal large-ancestry
records under the byte cap; final greedy count/byte packing and rejection tests
resolve it. No failed attempt counts as a PASS or qualified independent review.

Complete environment install/start instructions preserve all earlier toolchain/
service steps and add frozen candidate installation/drift/reference commands.
Readback confirms saved fields. Publication and future-task restoration NOT RUN;
review/save/publish in environment settings remains product-owned. No new secret,
network, live-data, owner Hello or phone-kit action is required for this slice.
Hosted fresh-checkout/exact-head results are recorded on the PR before merge.

Initial hosted candidate run 38121442916 failed before installing dependencies:
the workflow used the cloud default /workspace toolchain path, unavailable to a
hosted runner user. Corrected only that workflow to explicit owned /tmp toolchain
and npm-cache paths as existing P01 jobs do. No permission, checksum, TLS, test
or sandbox bypass. That failed run is not counted; final-head CI must pass.

### Hosted candidate source receipt

[PR 11](https://github.com/kurasis/AnyNote/pull/11) and
[hosted receipt](evidence/p02-hosted-receipt.json) record actual successful
candidate run [38121514437](https://github.com/kurasis/AnyNote/actions/runs/38121514437),
baseline 38121514433 and foundation 38121514438 at corrected source 0e19c86.
Candidate log confirms Node 24.21.0, 69 tests/zero fail/skip, six fixtures/125
nonce-AAD pairs, independent rejection mutations, seven-package inventory,
zero advisories, unchanged working tree and baseline PASS. Actual Actions checkout
6813b0b is a merge of main 29102ae and that head; its entire tree equals the head,
verified independently from Git. Keep the actual checkout stamp, not a replacement
PR-head claim. The prior dirty local receipt differs only in the documented
hosted path correction; all core/schema/fixture/document hashes still match.

P01 Windows job on that attempt failed in unchanged libsodium dependency download
with OS error 11002 / DNS resolution, before native tests. Other P01 jobs were
still running at this capture. This is not passed regression or physical-device
evidence. A fresh final-head run must pass every applicable candidate/foundation/
baseline/P01 check before automatic merge. Final exact-head outcomes are recorded
on PR 11; this receipt documents its earlier functional source, not a fabricated
future outcome. Production/full P02/G1/qualified review gates remain open.

## P02-IDENTITY-CERTIFICATE-RECIPIENT — larger candidate crypto batch

2026-10-11, Linux cloud Node 24.21.0/npm 11.19.0 and owned pinned PHP 8.4.26.
[Local source/result receipt](evidence/p02-identity-local.json),
[primary metadata/standards/notices](evidence/p02-identity-primary-sources.json),
[actual setup/save receipt](evidence/p02-identity-environment-setup.json).
Local source stamp is existing main 30cc8b2 plus hashed dirty candidate inputs,
not a substituted future PR commit. No product keys, routes or acceptance.

| Check | Command / actual outcome | Status |
| --- | --- | --- |
| Strict identity/kit/cert/recipient/crypto negatives + old tests | npm --prefix packages/protocol test: 145 executed/passed, zero failure/skip | PASS |
| External primitive/encoding expectations | RFC 5869 case 1 exact OKM; BIP 350 checksum and wrong variant | PASS |
| Fixed public root/kit/cert/file vectors | crypto:check reproduces derivation/keys/signatures/context/file; sealed boxes frozen as inputs, no RNG patch | PASS |
| Fresh synthetic recipient paths | Both device and recovery key -> G -> manifest DEK -> manifest/file-data key -> exact 79 public bytes; no uploader DEK receiver input | PASS |
| Independent PHP native reference | check-p02-crypto.py: PHP 8.4.26/sodium 1.0.18 HKDF/seed keys/signatures/JCS fixture subset/sealed/AEAD plus wrong signature/tag/AAD negatives | PASS |
| Known context/pin/recipient changes | Root substitution, checksum/Unicode/bounds, cert issuer/context/capability, unexpected sender, inner/outer mismatch, missing/duplicate/extra/changed roster/epoch recipients, wrong key and file corruption | PASS for evaluation scope |
| Existing serialization/reference drift | fixtures:check + check-p02-fixtures.py: six cases/125 nonce-AAD pairs/two bad outputs; original p02-file-c1 schema/vector bytes unchanged | PASS |
| Exact dependency inventory/advisories | inventory:check ten locked packages; npm audit --audit-level=low reports zero at execution | PASS |
| Source scanner + negative policy | Current Git-visible source, five fake PAT paths and five changed key/digest negatives; ten complete public values narrowly excepted | PASS |
| Complete setup and repeat | Saved complete install executed twice, both exit 0; repeated run preserves every Git-visible source/fixture/lock byte | PASS |
| Original/P01 preservation | Baseline all 21 checksums; no original spec/P01 source change | PASS |
| Saved setup/start readback | Draft revision 7 exact fields, same network/repository membership, requires_publish=true | PASS save only |
| Pairing, current roster/policy/roles/reset/session authority, full R01 application | Explicit NOT_EVALUATED; no production endpoints | NOT RUN |
| Full native Rust/browser/general PHP strict contract, new physical/memory, qualified review | No reviewer booked or audit performed | NOT RUN |

PHP assertion count includes serializer ASCII-field preconditions; do not present
it as thousands of independent crypto tests. The fixture-only serializer is not
a production RFC 8785/parser/schema implementation. Native PHP sodium 1.0.18 is
the existing image's OS dependency, not a changed production baseline. Both
signature proof tokens and exact coverage explicitly retain NOT_EVALUATED
current authority; decryptability never grants writer permission.

Initial readiness failed after snapshot because services were stopped; explicit
owned up recovered actual Nginx/FPM/Laravel/MariaDB. First npm metadata query
without writable cache failed, then explicit owned cache succeeded. GitBook
libsodium docs returned proxy tunnel 502; verified the same official primary
source repository over TLS instead. None of these failures is relabelled PASS.
Sixteen scanner findings were exactly ten complete known public fixture values;
a later receipt path containing check-secrets was misread as a key assignment.
Use explicit path/hash records (independently recomputed), no new scanner exemption;
changed-key/PAT negatives still reject. No arbitrary hash/whole-path/partial
encoded-value exemption, TLS/signature/checksum or browser sandbox bypass.

Full frozen setup/start instructions are saved and exact readback confirmed.
Review/save/publish in environment settings remains product-owned; save is not
publication or future-task acceptance. No new secret/network/owner physical
action is required by this candidate. Final fresh hosted checks and exact tested
head/source-tree proof are recorded on the review PR before automatic merge.

## P02-ROSTER-AND-RECOVERY-STATE — larger candidate batch

Date: 2026-10-11. Public synthetic inputs only. This supersedes prior device-state
NOT RUN items for isolated evaluation only; product/physical/audit gates stay open.
Receipts: [local](evidence/p02-state-local.json),
[primary source](evidence/p02-state-primary-sources.json),
[saved environment](evidence/p02-state-environment-setup.json).

| Check | Actual result / boundary | Outcome |
| --- | --- | --- |
| Node tests | 189 PASS (145 prior + 44 state tests); dual-key activation, both QR modes, cap/CAS/retry/cancel, descendant revoke, concurrent reset, forged handles, session/challenge expiry, stale recipient denial and raw parser/resource failures | PASS |
| Frozen state/channel input replay | Five signed events/heads, two QR modes, seven real secretstream frames; random inputs frozen without RNG replacement | PASS |
| Independent PHP/native sodium | PHP 8.4.26/sodium 1.0.18; five event signatures/possession/head/snapshot checks and seven secretstream frames with signature/tag/AAD/wrong-key negatives; 4,812 assertions include serializer preconditions | PASS public ASCII subset only |
| Current device recipient gating | Provisional/revoked/stale device contexts rejected; current exact certified issuer/recipient heads checked; group authorization NOT_EVALUATED | PASS candidate device layer only |
| Frozen dependency/advisory checks | Ten-package exact inventory, no new dependencies/lock changes, npm audit reports zero advisories | PASS |
| Source scan / negatives | Full Git-visible source; six fake PAT paths/eight changed fixture keys rejected; 28 new findings reviewed as 12 exact full PUBLIC state/QR key values | PASS |
| Existing bytes / baseline | Previous file/identity schemas/vectors and npm lock exact unchanged; all 21 original checksums PASS; no P01/release/reference change | PASS |
| Full saved install and repeat | Both complete final scripts reach final PHP state step; all Git-visible source/fixture/lock bytes preserved across installation and repetition; owned HTTP/DB readiness checked | PASS |
| Draft readback | Revision 8 exact setup/start, network and repository membership preserved; requires_publish=true | PASS save only |
| Real account authentication / QR intent/camera / persistent transactions / group policy/history authority / qualified review | Simulated or explicitly absent; no product endpoints, deployment or new owner physical trial | NOT RUN |

Earlier full setup failed because a random all-letter changed-key sentinel was
suppressed by Gitleaks' upstream generic-key alphabet heuristic; no source leak
was exposed. Replaced only negative sample generation with a fixed public
high-entropy mutation, preserving scanner rules and narrow exceptions. Complete
final installs and all negatives then passed. Cancellation validation was also
strengthened to forbid recycled keys/session bindings; the old expected error
was updated to the earlier key-reuse rejection, and the full 189-test suite passed.

Local source stamps intentionally name the base commit with dirty candidate input
hashes. Final hosted source checks and exact tested/merge tree evidence are added
to the review PR before automatic merge; do not relabel the dirty local stamp as
hosted/physical evidence. Save does not publish the environment or establish
future-task restoration: review/save/publish remains required in its settings.

## P02-GROUP-POLICY-EPOCH-HISTORY-CONTRACT — larger candidate batch

Date: 2026-10-11. Public synthetic data; product/physical/qualified audit gates open.
Receipts: [local](evidence/p02-group-local.json),
[saved environment](evidence/p02-group-environment-setup.json).
Exact bytes/trust/resource boundaries: [group contract](P02_GROUP_CONTRACT.md).

| Check | Actual result / boundary | Outcome |
| --- | --- | --- |
| Node | 249 tests (189 prior + 60 group); policy/role/reader denial, provisional admission, complete derived grants, revoke/reset/rekey/CAS/retry/expiry/cancel, wrong-key repair, independent history/pin/old-writer ambiguity and parser bounds | PASS |
| Frozen group replay | Eight policies, six epochs, 105 sealed grants, five checkpoints; three accounts, enrollment/transfer/archive/reset and real 50-byte historical file through G/manifest/file key path | PASS candidate only |
| Independent PHP | PHP 8.4.26/sodium 1.0.18; all 105 unwraps, signatures/context/page commitment/history/file bytes and tag/AAD negatives; 61,792 assertions include serializer preconditions | PASS public ASCII subset |
| Multi-page | 501 cloned serialization records in two count-bounded pages; invalid packing/order/duplicates fail; records do not claim signature/coverage validity | PASS serialization only |
| Source scan | Seven fake PAT paths, twelve changed fixture field negatives and changed full-fixture fingerprint rejection | PASS |
| Prior bytes | 125 protected spec/P01/reference/previous schemas/vectors/locks unchanged; all 21 original specification checksums | PASS |
| Dependencies | Same frozen ten-package inventory, zero npm advisories; no new runtime dependency or lock update | PASS |
| Full setup twice | Both complete final install scripts reach PHP group; all 282 Git-visible files present at setup preserved byte-for-byte; actual owned service readiness | PASS |
| Foundation integration | Three PHPUnit tests/seven assertions, actual Laravel/MariaDB transactions, HTTP/origin/path/production-denial and owned DB outage/restart | PASS development foundation |
| Draft | Revision 9 exact install/start readback, network/repository membership preserved, requires_publish=true | PASS save only |
| Product account/session/recent-auth/SQL, general PHP group verifier, full physical/Rust/browser group interoperability, qualified independent review | Unimplemented or NOT RUN; no deployment/release/new owner trial | OPEN |

New byte-limit test initially exceeded 1 MiB before reaching 500 records; bounded
serialization placeholders then exercised two pages without pretending authority.
Adding unknown-history write quarantine initially made the first frozen expected
snapshot and PHP observer state inconsistent. Only expected metadata/observer
state were corrected; signed crypto inputs were not regenerated. Final full Node,
PHP and both complete installs passed; earlier failed setup is not relabelled PASS.

Scanner review: 228 findings in PUBLIC group fixture. Exceptions require 31
complete exact public values, one exact complete sealed-ciphertext field line,
and one complete exact 28,672-byte PUBLIC scanner fragment. Pinned Gitleaks'
chunk-boundary location returned a truncated fingerprint inside that fragment;
matching the full literal fragment avoids exempting an arbitrary partial key or
path. Any changed full fixture field loses that exemption; actual mutation rejects.
No detector disablement, arbitrary digest/path exemption, verification bypass,
secret or token was added. Previous rules/negative cases remain active.

Local stamps name the base commit with dirty candidate input hashes. All code is
isolated evaluation; public inputs are not physical/audit evidence. Final hosted
runs, actual checkout SHA and exact full tested/merge tree proof are recorded on
the review PR before automatic merge. Environment settings must review/save and
publish the saved draft; persistence is not publication/future-task validation.

## P02 complete design freeze

See [complete contract](P02_COMPLETE_CONTRACT.md), [review tracking/findings](P02_REVIEW.md),
[actual local receipt](evidence/p02-complete-local.json),
[controlled setup](evidence/p02-complete-environment-setup.json) and
[inspected upstream/license sources](evidence/p02-complete-primary-sources.json).
These local commands ran on base cdd6c84 with the completed **dirty** implementation;
source-input hashes disambiguate it. They are not a claim that the old clean base
already contained these changes. Final hosted exact-head/tested-tree evidence
is recorded in the completion PR before normal merge.

- PASS: 306 Node tests, including existing 249, all new contexts/errors/crypto,
  2 MiB note boundary, tombstone/restore/ancestor closure, writer/reader/metadata
  decisions, local profile/credential/native descriptor binding, KDF admission,
  lock generation, immutable unknown-send reconciliation after receipt expiry
  and role loss, current removal denial, observed ciphertext commitment before
  commit, sync gaps/generation, snapshot completeness/revocation and restore fence.
- PASS: real signed admission for twenty accounts/twenty epochs, exact 800 grants,
  multiple authenticated greedy pages within 500 records/1 MiB; old c1 remains
  independently capped at ten and cannot parse/reuse c2 signatures.
- PASS: 55 complete schema byte vectors / 160 frozen inputs; all old file,
  identity, state, group and dependency inventory checks. 131 existing original
  specification/schema/vector/lock/P01/reference files compared byte-for-byte
  with base, unchanged. npm advisory check: zero vulnerabilities.
- PASS: independent Python 210 restricted JCS/USTAR/actual two-age-engine checks;
  native PHP 8.4.26/sodium 1.0.18/OpenSSL 9,648 serialization/Argon/HKDF/XChaCha/
  Ed25519/AES-GCM checks; independent c2 signed-chain/author subset 3,856 checks /
  nine decisions. These subsets do not establish a general arbitrary parser.
- PASS: actual Rust rage 0.12.1 ↔ Go age 1.3.2 recovery of the same authenticated
  USTAR bytes, original cross-account note and selected-DEK small file using only
  archive/independent kit. Empty/compact/paginated-evidence cases, wrong identity,
  changed/truncated/trailing age streams, hostile tar paths/types/padding/counts,
  missing footer/changed inventory/forged identity/missing independent pins reject.
  No filesystem extraction or live destination mutation. Reference collection/file
  limits are 16 MiB / 64 KiB; full 1 GB/100 GB product utility remains P13.
- PASS: actual owned Laravel/MariaDB/FPM/Nginx integration, 3 PHPUnit tests /
  7 assertions plus HTTP/outage/origin/path/production-denial checks. No product
  authorization/storage/schema or production deployment was exercised.
- PASS: Git-visible source scan with nine fake-token paths, fifteen changed
  key/digest/encoded negatives, exact legacy fragment mutation and a different
  synthetic age private identity. Exceptions bind only complete exact PUBLIC
  values. No new partial-field/arbitrary-hash/path suppression.
- PASS: complete final saved install script executed twice after the final model
  correction, exits 0, all 449 then-visible source paths byte-identical before/
  after. Earlier two successful refreshes were preparatory, not substituted for
  the final two. Install/start draft saved once and exact readback verified;
  repository/network/secret/runtime metadata preserved. Publication and actual
  future-task restoration remain NOT PERFORMED / NOT RUN.

Initial failures are recorded as failures, including the real twenty-account
page boundary and inherited JCS cap; corrected code, not weakened limits or
changed legacy inputs, passed. Development writers created new PUBLIC inputs
before freeze and were never executed by setup/CI. No actual platform/native
custody, product SQL/import/large-archive/memory acceptance or independent audit
is claimed. Qualified review is TRACKED_NOT_BOOKED / NOT_RUN, G2/G3 still open;
this is completion of original P02 chapter 14 §5 design/fixture deliverables.
