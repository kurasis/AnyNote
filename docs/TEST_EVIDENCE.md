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

## P03 completion — actual local foundation checks

Source base e034859168c47bfacfcc6c33425522fc02d77724 with uncommitted implementation
changes, explicitly source_tree_dirty=true; input hashes are in
[evidence](evidence/p03-complete-local.json). This is not an exact clean hosted-head
claim. The final PR records hosted job URLs, actual checkout/full tree and merge
receipt after checks complete.

- Read-only generator PASS: 79 initial operations, 157 schema-derived TS/PHP types;
  all 157 strict Ajv schemas compile, generated local OpenAPI refs resolve.
- Strict TypeScript PASS with five expected-error cases; Node client tests 5/5.
  Nine changed input/output/client-predicate negatives fail in isolated temp copies;
  repository source is never rewritten to exercise drift.
- Actual native PHP 8.4.26 / PHPUnit 12.5.38: 11 tests / 215 assertions PASS, Pint and
  generated PHP syntax PASS. Composer locked/platform/advisory checks PASS.
- Owned Nginx/FPM/Laravel/MariaDB transaction/rollback/cleanup, DB stop/restart,
  HTTP/origin/private-path/binding/unprivileged-user checks PASS. No product tables.
- Actual HTTP client: 16 checks PASS, including exact five-component negotiation,
  canonical service/request IDs, false features, hostile CORS/profile/header/body,
  duplicate/UTF-8 JSON, ordinary and chunked 4 MiB overflow with canonical 413,
  identical unavailable-resource errors, trusted FastCGI marker nonforgeability,
  persisted safe-log poison inspection. Raw logs are never uploaded.
- Full saved setup ran twice: exit 0 in 111.53s / 111.22s, 483 Git-visible files,
  zero changed paths each run. Script hashes/results are in
  [setup evidence](evidence/p03-complete-environment-setup.json); install_script and
  start_skill were saved and read back exactly. Publication NOT_PERFORMED and new
  task restoration NOT_RUN. Live processes require owned up/check after restoration.
- Existing P02 checks PASS: 306 Node tests, 55 structures/160 frozen inputs,
  9,648 PHP crypto and 3,856 PHP author-decision checks, 210 Python/age checks.
  Original specification/P01/P02/schema/vector/lock bytes remain unchanged.
- Git-visible source scan and all existing scanner negatives PASS; no exceptions
  added. npm client audit 0 vulnerabilities at run time. New compiler lock/source/
  integrity/license inventory retains 26 records including optional platforms.

During development positive tests correctly rejected initial UUID/hex service/
request IDs, GET test-helper array bodies and duplicate response headers; canonical
P02 IDs and Nginx header handling corrected the implementation. Scanner initially
flagged two public API-key-shaped hash-map keys; path/hash records preserve exact
hashes without suppressions. Drift helper initially lacked temporary inputs/list
mutation handling, fixed before claiming negative PASS. Generator syntax and
finite/depth cases were corrected and required checks rerun. Initial failures are
not passes. Local Chromium/hardware/production TLS/SQL authorization/general PHP
crypto validation/independent qualified review are not certified by P03.

Final generator cleanup removed an extra generated-PHP EOF blank line after the
local evidence snapshot. Generated drift negatives, native PHP syntax, strict TS
and git diff whitespace checks were rerun and passed; the unchanged install/start
scripts retain their two-run evidence. Hosted CI validates the final complete tree.

The first P03 hosted foundation run 38142798498 stopped before Node installation
because the cloud-default /workspace toolchain directory is not writable on a
GitHub runner. Use the existing installer's supported ANYNOTE_TOOLCHAINS override
pointing to /tmp/anynote-p03-toolchains. This is a CI configuration correction,
not a source test PASS or a signature/checksum/TLS bypass. All final checks must
pass again on the updated head; prior-head successes do not approve the new tree.

Alternate-port robustness: actual owned Compose project moved temporarily to port
55629; native PHPUnit and all 16 HTTP checks PASS. Exact original synthetic
configuration/credentials and port were restored in finally. The HTTP wrapper
reads only the marked project's persisted port before invoking the fixed-loopback
client; PHP CORS tests use the configured Origin. Updated target command repeated
strict generation/drift/types, 11 PHP tests / 215 assertions and 16 HTTP checks PASS.
These are actual development checks, not production network/TLS acceptance.

## P04 actual backend and public-signature slice (2026-10-11)

Local source base e22bbee with an explicitly dirty P04 implementation; exact source
hashes and scopes are in evidence/p04-complete-local.json. No clean/merged or
hosted/browser result is inferred from this dirty local run. `p04-checks.py`:
21 PHPUnit tests / 321 assertions PASS; three-account current authorization,
signed Node encrypted-object/PHP acceptance, strict errors, CAS/immutable IDs,
quota/retry/conversion, wrong-scope/reader/admin/device and final SQL failure
rollback. Separate real SQL harness: 575 checks (including column/engine
inspection), 46 tables/164 constraints, eight PHP child processes, actual same-body
retry/CAS/cross-group quota race and counter commit/rollback visibility PASS.
Actual scheduled/queued heartbeats and restart after killing their own PHP
processes inside the non-root owned containers PASS. No power-loss/PITR claim.

P03 regression: 11 tests / 215 assertions, five Node groups, 13 changed-input/
output drift negatives, 16 actual Nginx/FPM HTTP/log checks PASS. Composer audit/
platform/Pint, frozen native 70-record inventory/fmt/Clippy, original specification,
all 160 frozen design inputs and prior 306 Node reference tests PASS. Four exact
P04 compatibility negatives reject lock tampering, including recomputed new hash;
all 99 prior package records remain identical and four named versions are added.
Primary source/license receipt exists; no scanner exception or verification bypass.

Rust public signing/verification: four checks PASS, exact Node/PHP header/signature
bytes. Cloud real-browser launch BLOCKED by the unusable SUID sandbox helper;
no --no-sandbox or mock substitute. Mandatory hosted real worker is pending and
P04 remains IMPLEMENTED / UNVERIFIED until it passes. Fixture checksum binds the
SQL acceptance and native/browser corpus. P05 general codecs/AEAD/custody remain
open; the PHP canonicalizer is public-only, not general float JCS.

Full saved P04 setup executed successfully with 521 Git-visible files unchanged.
Its first attempt correctly failed the P02 frozen Composer checksum; explicit
baseline preservation/compatibility fixed this without editing the frozen registry.
Setup never writes tracked vectors/contracts or migrates product data. Install/
startup scripts saved and exact readback verified; repository/network/credential
bindings preserved. Draft saving is not publication or fresh-task restoration.
Current owned API/DB readiness verified; no owner trial/deployment/release/reviewer
outreach performed. CI and final tested-tree evidence will be recorded in the PR.


### P04 complete clean-source and hosted acceptance

Candidate dc41686cff5c65eb55a8f7d6501ebab68362dca3 was tested at actual PR checkout
83a1af58d366cee9ab860582574804e67cd8488c. Both full trees are
c0456d70e62f8513c7d9ce5799a4b691eb925a23. This supersedes the initial pending
P04 result above; the dirty historical local record remains unchanged.

[Actual backend report](evidence/p04-backend-hosted.json): 21 PHPUnit tests / 322
assertions and 578 real SQL checks PASS. The added checks refuse unknown group
permissions and internal counter/quota calls without a transaction. Eight-process
CAS/retry/cross-group quota races, commit-order/rollback visibility, SQL fault
recovery, 46 inspected tables/164 constraints and supervised non-root maintenance
crash restart PASS. Actual hosted source is clean; all 82 recorded backend input
hashes match the candidate tree.

[Actual public-signature report](evidence/p04-public-signature-hosted.json): native
Rust four checks and real Chromium 154.0.8037.97 worker seven checks PASS with
sandbox enabled. Node-generated signing bytes/signatures match native/browser and
PHP SQL acceptance over the same PUBLIC fixture hash
1a375941e08eecd4c14420db4696086a3b7d54efb725cb8931203bd9e0057acd. All eight recorded
public-adapter input hashes match. No sandbox bypass, mocked-browser result or
physical acceptance is claimed. The first hosted new-step run failed because the
fixture was sent before module/crypto initialization installed its message
listener; an explicit READY handshake fixes it. The passing rerun verifies this
actual worker behavior.

All six source jobs PASS: [foundation 38149194986](https://github.com/kurasis/AnyNote/actions/runs/38149194986),
[contracts 38149194968](https://github.com/kurasis/AnyNote/actions/runs/38149194968),
[baseline 38149194983](https://github.com/kurasis/AnyNote/actions/runs/38149194983),
and [three platform jobs 38149195000](https://github.com/kurasis/AnyNote/actions/runs/38149195000).
Publication was SKIPPED as intended. [Hosted receipt](evidence/p04-hosted-receipt.json)
binds actual check/job URLs, checkout and full tree; final tracking-only changes
receive fresh CI and exact-tree merge verification recorded in PR #17.

[Complete saved setup rerun](evidence/p04-complete-setup.json) PASS on clean
dc41686, preserving all 522 Git-visible files. Install/start draft revision 12
readback matches exactly; unrelated environment settings are preserved. Saving
is not publication or a fresh-task restore; the environment UI still requires
Review/Save -> Publish. Local Chromium remains BLOCKED and is separate from the
mandatory successful hosted gate. P04 is VERIFIED within its specified backend
scope; general P05 crypto, P01 physical matrix, qualified review and production
rollout remain open. No action on an owner device is required for this phase.

## P05 full core local acceptance (2026-10-11)

[Actual dirty local core report](evidence/p05-core-local.json) records the P04
base commit plus exact implementation input hashes at execution. It is not clean
or hosted evidence. Native Rust -> Node and Node -> Rust: 146 frozen positive
frames across five profiles, 21 public signature types, 28 independently expected
RFC8785 numeric/UTF16 cases and 14 malformed raw byte cases; complete-object,
local/Argon/PRF/native-AES, root/recovery/device/recipient, file and pinned-history
round trips/negatives PASS. Native with peer and 1 GB: 504 checks; Node with
native peer: 525 checks. Actual release native 1,000,000,000-byte ciphertext-only
disk round trip: 120 chunks, maximum plaintext chunk 8,388,608 bytes, 10,549 ms,
peak process RSS 89,356 KiB. CSPRNG source and full authenticated plaintext digest
are checked; only the newly owned temporary directory is removed.

Native unit suite: three meaningful tests PASS, including four real simultaneous
Argon2id jobs (one correct result, three KDF_BUSY), wrong AEAD AAD/key/nonce/tag,
preallocation KDF bounds and correctly signed/digested frames with damaged AEAD
or authenticated invalid decrypted JSON/context. Full native fmt/Clippy and
156-record inventory, five portable frozen-predicate drift checks PASS. New core
inputs include deterministic closed-frame unknown-property/version mutations.
Factories reject repeated completed file index/source retry and choose fresh
keys/nonces. Immutable durable restart/source-version coordination is P12.

[PHP public-only report](evidence/p05-php-local.json): 227 checks PASS over all
21 public signable types from Rust and Node, exact canonical bytes, changed/wrong
signatures/keys, closed unknown fields and all 14 malformed byte cases; secret
schemas refused. This process receives no group/local/root/private keys or
payload plaintext. P04 regression: 21 tests/322 assertions plus 578 actual SQL
checks, eight-process transaction/concurrency and supervised restart PASS. All
306 old Node reference tests, 160 frozen design inputs, unchanged prior locks,
read-only contract generation and existing real scanner negatives PASS.

Cloud sandboxed Chromium launch is BLOCKED and no bypass/mock is used. Mandatory
hosted actual Worker two-way ciphertext/signature acceptance, single-job RPC,
UI/memory and OPFS files (0, 1, 8,388,607, 8,388,608, 8,388,609, 1,000,000,000),
plus actual Windows/MSVC core, remain pending before P05 VERIFIED/merge. C04/C16
use independently supplied authorized issuer/checkpoint pins; complete account/
policy state authority is P08/P10. G1 physical/mobile memory, G2/G3 qualified
review and release/deployment gates remain open. No owner-device action is needed.

### P05 complete clean-source and hosted acceptance

This successful result supersedes the initial pending hosted gate above; the
historical dirty local reports remain unchanged. Candidate
1ac93efa0cf7bee9b5a3b8be5f22c54a3a28e80e and actual clean hosted checkout
38c5e3766b0837d0437213c4bffb75b0e1a67b95 share complete tree
78785f7ff5ad46e19000c91c87c3c34483108c9b. The checkout parents are the unchanged
P04 main and this candidate. [Hosted receipt](evidence/p05-hosted-receipt.json)
binds all eight successful job URLs and the metadata-only raw reports.

[Core report](evidence/p05-core-hosted.json): native 506, Node 527 and actual
Chromium Worker 527 checks PASS; Worker -> native 505 checks PASS. The same 146
frozen frames, 173 closed-frame mutations, 28 independently expected general
RFC8785 cases and 14 malformed byte inputs run in each client. Fresh bidirectional
note/local/phrase/PRF/AES/recipient/file bytes are accepted across runtimes.
Native concurrent KDF, typed AEAD/schema failures, unauthorized issuer/stale epoch,
new backdated versus independently anchored historical note/file, nonce/index
reuse and raw closed export framing tests PASS. Phrase FEFF/NEL word semantics
now agree across Rust/JavaScript without altering the raw phrase KDF bytes.
Dedicated product Worker/RPC admits one operation, refuses concurrent/unknown
requests, and has bounded startup and pending-operation deadlines.

Actual release native 1,000,000,000-byte ciphertext-only disk round trip: 120
chunks, 6,015 ms, peak process RSS 90,616 KiB. Actual sandboxed Chromium
154.0.8037.97 Worker independently completes 0, 1, 8,388,607, 8,388,608,
8,388,609 and 1,000,000,000-byte owned OPFS ciphertext round trips, exact lengths
and authenticated full plaintext hashes. The 1 GB run has 120 chunks, takes
20,727 ms and uses bounded sync OPFS handles without Blob/File accumulation.
The maximum plaintext chunk is 8,388,608 bytes and reported Wasm heap is
67,371,008 bytes. UI heartbeat: 451 ticks, maximum timer lag 5 ms.

Sampled aggregate Chromium process RSS across the full suite is 1,312,508 KiB.
It includes both workers and the corpus/KDF/file sequence; shared pages may be
counted twice and 250 ms sampling may miss peaks. It is neither file-only
incremental RSS nor a hard memory ceiling. Native/browser chunk processing is
bounded, but this desktop total does not pass physical iPhone/WebView2 memory
acceptance. Direct sync OPFS improved time relative to the earlier 31,252 ms
run but did not materially reduce aggregate RSS (earlier 1,308,020 KiB).
P01 physical memory and its remaining network/provider matrix stay OPEN.

The first full hosted 1 GB attempt timed out: generating the public test source
with sodium's browser per-byte random bridge dominated the experiment (an 8 MiB
file took 12 seconds). P01 had already measured this path. The helper now fills
only PUBLIC incompressible source bytes through maintained WebCrypto CSPRNG in
at most 64 KiB calls. Cryptographic keys/nonces still use maintained sodium.
The unchanged 1 GB limit, checks, worker deadline and browser sandbox passed;
no fixed-zero source, mock browser, weakened gate or sandbox bypass was used.

[Actual PHP report](evidence/p05-php-hosted.json): PHP 8.4.26, 377 public-only
checks PASS over 24 frames from each actual Rust/Node/Worker source: 21 frozen
signable types plus fresh note/file/grant signatures. Exact canonical/signing
bytes, wrong key/signature, unknown fields, malformed raw JSON and refusal of
private/local schemas PASS. The input projection supplies public frames only,
never root/group/local/private keys or decrypted payloads. Its SHA-256 is
cf0decf84c57eb52e64445c2d64559a9fffb648896d6c841d995e7ba0749338d.
[Actual Windows report](evidence/p05-windows-hosted.json): real MSVC native 505
and Node 527 checks PASS, plus native fmt/Clippy/unit tests; this is not a
physical Hello/TPM/WebView2 acceptance result.

All 63 core source-input and seven Linux fixture hashes match candidate Git
bytes. All seven Windows raw fixture hashes match those same Git bytes after
ordinary LF-to-CRLF checkout conversion; expected protocol hex bytes are
unchanged and fixtures were not regenerated. Previous frozen locks/corpora and
160 P02 design inputs remain unchanged. All eight jobs PASS:
[P05 Linux/browser/PHP and Windows 38157941999](https://github.com/kurasis/AnyNote/actions/runs/38157941999),
[foundation 38157942002](https://github.com/kurasis/AnyNote/actions/runs/38157942002),
[baseline 38157941991](https://github.com/kurasis/AnyNote/actions/runs/38157941991),
[contracts 38157942000](https://github.com/kurasis/AnyNote/actions/runs/38157942000),
and [three prior platform jobs 38157942001](https://github.com/kurasis/AnyNote/actions/runs/38157942001).
Test-release publication is SKIPPED as intended. Tracking-only final changes
receive fresh CI; exact final-head/tree merge verification is recorded in PR #18.

[Full saved setup](evidence/p05-complete-setup.json) passed with 568 Git-visible
files unchanged; another complete execution passed on clean 24b0707.
[Latest extension recheck](evidence/p05-setup-extension-recheck.json) on clean
1ac93ef passed native build/tests/inventory, portable drift, Node/native 527
checks, PHP 257 two-source public checks and owned service readiness, preserving
all 570 Git-visible files. Local Chromium remains explicitly BLOCKED; the
mandatory hosted result is separate. Exact install/start draft revision 13 was
saved/read back and unrelated bindings preserved. Publication and fresh-task
restore are NOT_RUN; environment settings still require Review/Save -> Publish.

P05 is VERIFIED within the specified cryptographic-core scope. C01–C04/C07/C08/
C10/C16 mapping is in P05_CRYPTO_CORE.md. Current authority, persistent custody,
durable file source/resume and maximum-scale history indexes remain P08/P10,
P07, P12 and P11 respectively. Qualified G2/G3 review remains unassigned/unbooked/
NOT_RUN; production release/deployment are not complete. No new owner-device
action is required for P05. The next full batch is P06 authentication/sessions.

## P06 local implementation checks (hosted acceptance pending)

Local actual TLS Nginx -> Laravel -> owned MariaDB authentication passes 215
checks. Both eight-request registration and refresh races have one winner and
seven denials; refresh reuse revokes the family. Rate admission: 64 requests
in eight concurrent waves, exactly 60 admitted/four typed denials; expired
window reset PASS. Expired-cookie login, CSRF regeneration after logout,
cross-account isolation, admin invite/disable, all-session revocation and
bounded expiry cleanup preserving roots/devices/rosters PASS. The real Rust oauth2 adapter
uses the PHP League server over verified HTTPS, real TCP callback, state/PKCE
and refresh/reuse, with metadata-only output. Four native tests execute IPv4/
IPv6 callbacks, attacker substitutions, one-use/deadline and maintained PKCE.
P04 regression: 21 tests/322 assertions and actual SQL/rollback/concurrency PASS.
The auth compatibility gate preserves 103 old records plus 23 reviewed additions
and rejects four real tampered-lock cases even with recomputed current checksum.
P06 static/API/session readiness is repeatable on the current restored instance.
The local sandboxed browser attempt is BLOCKED; hosted strict-CSP UI/WebAuthn
and Windows/MSVC jobs remain mandatory. These local outputs describe a dirty
development tree based on 129cd63, not a clean hosted acceptance commit.

P05 saved setup publication and a fresh-task restoration are now observed: the
owner published the prior draft and this P06 task restored exact tools/packages
and owned service readiness. This does not publish a later P06 configuration.

The first parallel local P03/P06 attempt was invalidated by P03's deliberate
shared database outage; sequential P03 rerun passed. Real concurrent admission
then exposed MariaDB ER_CHECKREAD (1020) after a nonlocking rate-bucket snapshot.
The corrected implementation locks the current bucket first and retries bounded
first-insertion deadlocks. All 215 checks, strict one-winner races and the exact
64-request rate bound passed after that correction. No error assertion or
verification control was weakened; temporary metadata-only diagnostics were
removed from application source before commit.

The initial P06 Windows workflow stopped during setup before running Rust:
CPython 3.12.14 has no Windows x64 build in the maintained Actions manifest.
The Windows-only helper runtime is pinned to maintained CPython 3.14.8, verified
against the primary actions/python-versions manifest. Linux/cloud remain at
3.12.14. This does not alter any cryptographic dependency or weaken an assertion.
The source receipt records the actual helper Python version and platform.

The second Windows job completed Rust fmt/clippy but rejected the raw-lock
inventory: checkout converted the new Cargo.lock to CRLF. Its Git attribute now
preserves exact frozen bytes (`-text`) on every platform. The checksum and
package/license records are unchanged; the checker does not normalize away drift.
No native test pass is claimed for either failed initial Windows job.

The initial hosted TLS/SQL attack suite passed; the real browser reached the
strict-CSP static app but account-service bootstrap failed, so WebAuthn acceptance
was not claimed. The harness now waits for completed SDK bootstrap and retains
bounded public pre-credential network/runtime diagnostics instead of timing out
on a generic status. Subsequent hosted acceptance remains required.

Hosted Windows/MSVC acceptance passed at 28a5581: actual IPv4/IPv6 callback,
one-use/deadline, attack matrix and maintained PKCE tests all executed. The
hosted browser's completed bootstrap returned a TypeError without a network
failure; the SDK default fetch must retain its Window/Worker receiver. Its
default is now bound to globalThis. Node's fetch ignores that receiver, so the
previous Node-only transport result did not expose the browser-specific issue.
The real sandboxed browser gate remains mandatory after the correction.

The browser fetch correction passed real bootstrap, attestation, offline kit
export, root/device registration and cookie checks. The next failure was a test
provider choice: adding a passkey on the same authenticator correctly rejects
its already enrolled credential through excludeCredentials. The harness now
uses two independent resident UV providers and keeps production exclusion
checks unchanged. It then logs in with the second provider.

The HTTP matrix also includes eight parallel code redemptions (one grant and
one access/refresh row), and eight assertions with the same nonzero counter
(one grant). Current-row locking avoids old REPEATABLE READ snapshots for OAuth
revocation, account status, admission caps and all-session revocation. The
maintained verifier's existing current credential counter read remains intact.

## P06 completed hosted software acceptance

[Authentication run 38170283444](https://github.com/kurasis/AnyNote/actions/runs/38170283444)
passes both actual Linux/TLS/SQL/browser and Windows/MSVC jobs. All ten source jobs
at branch head `d8198af2746a55e46239ee9b4ea1b27e20c5d654` completed successfully.
Actual checkout `8b12e0d20e409c9c1bf0f5dae1bb5cc622c14d19` and the branch head have
identical complete clean Git trees: `363f1761bcd5c28775ecb7928623a6806a6df2c5`.

- HTTP/SQL: **215** actual checks, real Rust oauth2 -> verified HTTPS -> PHP
  League, real loopback TCP, PKCE/issuer/state and refresh/reuse.
- Four eight-request races (registration, code, refresh, same nonzero assertion
  counter) each produce one winner and seven denials. Code redemption creates
  exactly one access/refresh row. Refresh reuse revokes the whole family.
- Admission: 64 requests in eight parallel waves admit 60 and return four typed
  rate denials; expired-window reset and bounded cleanup preserve roots/rosters.
- Browser: **18** real checks through the shipped UI, Chromium sandbox enabled,
  NSS trusted disposable CA and hostname validation, strict CSP with no JS eval/
  inline exception, genuine resident UV credentials from two independent CDP
  providers, excluded-provider rejection, offline kit, cookie/CSRF and restricted
  login with no content authority or storage tokens.
- Native: **four** actual tests per Linux and Windows/MSVC platform. This is
  software callback evidence, not physical Windows Hello/TPM/iPhone acceptance.

Public raw reports: [HTTP](evidence/p06/http-report.json),
[browser](evidence/p06/browser-report.json),
[Linux source](evidence/p06/linux-source-report.json),
[Windows source](evidence/p06/windows-source-report.json),
[gate/tree/artifact acceptance](evidence/p06/acceptance.json). Linux's 131 raw
input hashes match the checkout exactly. Windows's receipt retains its 131 actual
working-file hashes: 130 normal text inputs are CRLF, while the native lock is
byte-identical LF through `-text`. Both Git tree IDs are identical; inventory
hashes were not normalized to bypass a mismatch. These artifacts contain no
credential, cookie, token, R or private key values.

The final read-only setup extension passed at d8198af and preserved all 625
then-visible source files; install/start fields were saved/read back as revision
14 with unrelated configuration preserved. P06 Review/Save -> Publish and a
fresh-task restore remain NOT_RUN; earlier P05 publication/restore are observed.
Final source tracking/receipt changes require all ten jobs on the final head
before ordinary merge. Physical P01 and qualified G2/G3 remain open/unbooked/
NOT_RUN. No production migration/deployment, release, owner trial or outreach.

## P07 initial local checks (before clean source commit)

Restored published P06 environment and restarted only its owned services with
actual TLS/SQL readiness. Five Node custody suites PASS; fifteen native SQLite/IPC
custody tests PASS plus inherited provider/portable container tests. Actual P07
HTTPS/SQL/native proof/credential storage and maintained rotation: 28 PASS. Local
Chromium remains sandbox BLOCKED; hosted acceptance is recorded below. Local
reports describe the dirty pre-commit source, not a clean hosted tree. Independent
review, new physical trials, production migration/deploy/release/outreach NOT_RUN.


## P07 full hosted local custody acceptance

P07 encrypted local persistence and lock boundary are software VERIFIED. All
twelve mandatory source jobs passed at branch head
`28cb562eee03733baa312a9e8629ed5b572a9b6c`. Actual hosted checkout
`1caaa234ef9326664aabe6a92b5be2a78fb4ca07` and that branch head share complete clean
Git tree `407021f7f9216c9826b6b087a88e2e07696a4d51`.

- Five actually executed Node custody attack suites cover atomic draft/outbox,
  immutable attempts, leases/generations, tamper/pins/known rollback, fresh nonce,
  PRF context/salt/credential binding, fallback and L rotation. Their transactional
  fault model is distinct from actual persistent storage checks below.
- Actual HTTPS/SQL: **28** checks use Laravel/MariaDB and maintained Rust OAuth2,
  native SQLite device proof, server replay rejection, encrypted credential
  adoption/rotation and refresh-reuse family revocation. No mock verifier or
  general test token issuer is used.
- Actual sandboxed Chromium: **28** checks use persistent IndexedDB and shipped
  Worker/UI, verified TLS/NSS trust and strict CSP. Registration/public manifest,
  encrypted inspector, abort/preserve, two windows/lease fences, page destruction,
  stale replies, relogin/fresh proof, actual CDP PRF extension, static-only service
  worker, L rotation, lost-store recovery and non-destructive unknown-schema refusal
  pass. CDP is a synthetic platform authenticator, not owner hardware evidence.
- Native custody: **15** tests on each Linux/Windows platform exercise actual
  SQLite/WAL faults, restart, capabilities, strict typed IPC, tamper, leases,
  encrypted credentials and atomic rotation. Preserved provider/container tests:
  Linux **71**, Windows **99** routine. The default ignored official-header ABI
  case is separately executed: **1 PASS**, after independent MSVC/C-header
  reference generation. WTS registration is real; lock/suspend messages are
  injected software events. No Hello/TPM objects or physical trial were created.

Public raw reports: [HTTP](evidence/p07/http-report.json),
[browser](evidence/p07/browser-report.json),
[Linux source](evidence/p07/linux-source-report.json),
[Windows source](evidence/p07/windows-source-report.json),
[gate/tree/artifact acceptance](evidence/p07/acceptance.json). All 111 Linux raw
input hashes match source bytes. Windows preserves 111 actual working-file hashes:
107 text inputs are CRLF, both native Cargo locks and both preserved vendor headers
are byte-identical. Full Git trees match; hashes were not normalized to bypass a
mismatch. Reports contain public source/check metadata, no bearer/private keys.

Earlier failed gates were corrected before acceptance: Worker result/input alias
wiping, Windows constant/module visibility, legacy Rust-2021 style lint under
2024, UTF-8 report capture, complete DPAPI-wrapper comparison and official-header
ABI reference preparation. No assertion, verifier, cryptographic policy, sandbox,
TLS or physical eligibility was weakened. Clean passing intermediate versions
3baf162 and 69bc46e preceded the accepted lost-store/unknown-version checks.

Published P06 environment was actually restored in this task. Read-only P07 setup
preserved 670 then-visible source files and passed again with all 675 files after
archiving public reports. Complete install/start
fields were saved/read back as revision 15; unrelated network/credential/repository
settings were retained. P07 publication/fresh-task restore remain NOT_RUN. Local
cloud browser sandbox BLOCKED remains separate from hosted PASS. Physical P01,
qualified G2/G3 review, production migration/deploy/release/owner trial/outreach
remain open or NOT_RUN. Final source tracking changes require all twelve jobs on
the final head before ordinary authorized merge.

## P08 full trusted-device software acceptance

All fourteen required hosted jobs PASS at clean branch/actual checkout
`bb41c0cbfb67bdcaab1b08785fc221bd8f5fe6cc`, Git tree
`eccb040a0c584f7d808c5a9be986d4381b0bbdc8`. Exact public reports:
[HTTP](evidence/p08/http-report.json), [browser](evidence/p08/browser-report.json),
[Linux source](evidence/p08/linux-source-report.json),
[Windows source](evidence/p08/windows-source-report.json),
[checks/tree/artifact acceptance](evidence/p08/acceptance.json).

Seven Node attack/custody suites and sixteen randomized dense maintained QR codec
round trips pass. Real HTTPS/MariaDB/native-process interop: **153 checks**,
including two QR directions, immutable confirmation races, actual SQL-trigger abort/
retry, recipient substitution, security-reserve limits, cap/expiry, independent
siblings/transitive descendants, derived native session/code revocation and distinct
concurrent root resets with exactly one winner. Native/Node secretstream and JCS
ID/AAD agree; a fresh native process reopens encrypted SQLite without key export.
A populated legacy-schema upgrade preserves all original counts under normal
owner-validated additive migration. The original P06 215-check race suite also passes.

Actual persistent sandboxed Chromium UI: **33 checks**, with verified TLS/strict
CSP, CDP synthetic resident UV providers, downloaded PNG encoding/decoding, mutual
approval/confirmation, G distribution, descendant revoke and fresh kit recovery.
Network abort after the atomic bootstrap journal, real ten-second lease expiry
and page restart resolve the original signed request without R persistence.
Provider counters, writer guards and QR payload validation remain enforced.
Native: **nine** new tests on each Linux/Windows, plus prior **15** custody tests,
provider/container **71 Linux / 99 Windows**, and **one** explicitly prepared/run
official-header ABI case. Native SQL abort/two connections, lock/restart, closed
IPC/capability/epoch, tamper, rotation and fresh-root recovery pass. Physical
Hello/TPM objects are not created; OS event injections are software evidence.

All 283 Linux raw source hashes match Git blobs. Windows retains 283 actual raw
working-file hashes: 280 CRLF text inputs and three byte-identical inputs. Complete
Git trees agree. Downloaded artifact ZIP SHA256 equals GitHub artifact digests;
archived reports exclude private fixtures, R, QR values and credentials.
Prior spec/corpora/locks remain unchanged. No failed assertion, verifier, CSP,
TLS, sandbox, ABI or eligibility guard is bypassed. QR detector reliability was
fixed using the maintained pure-image path for dense exported grids, with exact
text self-verification; camera uses the ordinary perspective detector.

Published P07 environment was restored. Full P08 install ran twice and preserved
all 712 tracked source files on its final complete run; current read-only readiness
runs separately and passed while preserving all 713 then-tracked files, including
the new QR codec test. Saving/publishing/fresh restoration remain distinct. No production
migration/deployment/release, new owner trial or outreach. Physical P01 and qualified
G2/G3 remain open/unbooked/NOT_RUN. Final tracking/evidence changes require fourteen
fresh successful jobs before ordinary authorized merge.

## P09 complete private-note vertical slice — software VERIFIED

All sixteen mandatory jobs PASS at
`a1520167e634c173c5cc56d942417b1faf3648fa`, clean full tree
`3223224565ec319752b2acb088d9dd35a4473401`. The prior-phase jobs' actual virtual
merge checkout has the identical complete tree; the P09 workflow checked out the
exact PR head. [Acceptance](evidence/p09/acceptance.json) retains check/run/job IDs,
public artifact ZIP hashes and raw report hashes. Final tracking/evidence requires
fresh full CI before ordinary automatic SHA-guard merge.

| Execution | Actual outcome |
| --- | --- |
| Portable protected workflow and closed transport | Eight suites PASS; real maintained crypto, atomic failures, unknown/newer edits, lock/restart, peer ciphertext/tamper, revoked/backdated history and valid signed route substitution |
| Verified HTTPS/Nginx/Laravel/MariaDB and native SQLite | 131 checks PASS; real maintained WebAuthn/root bootstrap, full private genesis, commit ordering, exact retries, eight-identical and eight-distinct edit races, rollback/quota/isolation, explicit delete/restore, large note and edge bounds, two-way actual native/PWA adapter bytes and SQL/log inspection |
| Actual shipped PWA UI | 49 checks PASS with Chromium sandbox, trusted CA/hostname TLS and strict CSP; safe Markdown/checklists, encrypted favorites/order/read markers, scoped summary, static-only offline cache, actual commit with lost response, durable offline restart, versions/trash/restore, independent mutual QR enrollment/key delivery, preserved peer conflict/resolution and SQL/IndexedDB/log/ordinary-storage inspection |
| Native Linux and Windows/MSVC | Six note tests per platform PASS over actual SQLite/WAL, restart, receipt-trigger rollback, immutable/newer drafts, rotation/reserved IDs, closed main-window IPC and independent signed-revoke blocking with false server flags |
| Native/PWA adapter interoperability | Sixteen checks per platform PASS; independent native device keys generated inside the vault, actual enrollment/roster/genesis, native-to-PWA and reverse verified ciphertext, protected persistence and no general key export |
| Preserved acceptance | All fourteen prior jobs PASS; nine native device tests and fifteen custody tests/platform, provider/container Linux71/Windows99 plus the explicitly executed official-header ABI test |
| Exact raw source receipts | 307 inputs/platform verified against Git blobs; Windows304 CRLF working-file inputs and three byte-identical inputs verified without normalizing the reports |
| Complete frozen installation | PASS: all 747 then-visible source files and marked private-note database state preserved |
| Complete startup and readiness | PASS: owned services, trusted TLS/API/session, eight-suite P09 target, native inventory and read-only contract comparison; source stays unchanged |

Raw reports: [HTTP](evidence/p09/http-report.json),
[browser](evidence/p09/browser-report.json),
[Linux source](evidence/p09/linux-source-report.json),
[Windows source](evidence/p09/windows-source-report.json),
[Linux interop](evidence/p09/linux-native-interop-report.json), and
[Windows interop](evidence/p09/windows-native-interop-report.json).
Node custody models and native/PWA adapter interop are not substitutes for the
separately executed persistent PWA UI or actual native SQLite tests. Local cloud
sandbox remains BLOCKED; no sandbox/TLS/CSP/verification bypass was used. Manual
browser diagnosis is optional and does not replace any required job. Initial failed
cases were diagnosed and corrected; they are not acceptance evidence.

P09 leaves original specification, frozen P02 corpora and prior locks unchanged;
Markdown uses its own seven-record frozen inventory. No new Hello/TPM objects,
owner-device trial, production migration/deployment, release or reviewer outreach
occurred. Full physical G1/Hello/iPhone and qualified G2/G3 stay open/unbooked/NOT_RUN.
Perfect memory erasure and universal hostile-server freshness are not claimed.
Published P08 restoration was observed; P09 draft persistence, publication and
independently demonstrated fresh P09 restoration remain distinct. Next full batch
is P10; scale/convergence, files, complete export/retention and packaging retain
P11–P15 ownership. No owner action is required for independent P09 software CI.

## P10 complete shared-group slice — software VERIFIED

All eighteen mandatory jobs PASS at `fddd9fde0e5158ef7fdefa5396fde51d53865b56`, clean full tree `b3d7c465f8c4b6c4e0ed2c13b51e02fa387df284`.
[Acceptance](evidence/p10/acceptance.json) retains exact check/run/job references,
GitHub artifact ZIP digests and raw public report hashes. Final tracking/evidence
requires fresh full CI before ordinary automatic SHA-guard merge.

| Execution | Actual outcome |
| --- | --- |
| Maintained-crypto portable protected workflow/transport | Five suites PASS, including actual engine restart, atomic state, pinned invitation scope, exact acknowledgement, signed route substitution and wiped Worker input preserving live membership/candidate G |
| Verified HTTPS/Nginx/Laravel/MariaDB plus native peer | 407 checks PASS: four real account bootstraps, full retained history/trash, reader-with-G forgery denial, offline role-loss drafts, immediate removal, fresh epoch exclusion, audience/fresh-encryption copy, old-author history, dual recent owner consent, archive, independently enrolled native device grants, narrow reader maintenance, partial page coverage, cancelled commitment burn, actual recipient revoke after complete staging, receipt fault rollback, eight distinct policy CAS writers/eight identical retries and account-closure orphan prevention |
| Actual shipped PWA | 40 checks PASS, three independent persistent account processes, sandboxed Chromium, verified trusted CA/hostname TLS and strict CSP; create/invite/accept/all-history key delivery, independent new-member card refresh, editor write, reader retained draft/denial, removal clears plaintext DOM and restores the retained unsent local draft, new-epoch write, EN/RU and actual SQL/IndexedDB/log/ordinary-storage inspection |
| Native Linux and Windows/MSVC | Three shared tests/platform PASS over real SQLite/WAL, restart, atomic receipt-fault rollback, protected candidate keys, closed main-window commands and lock fences; prior six note/nine device/fifteen custody tests preserved |
| Actual native/portable multi-account adapters | 89 checks/platform PASS using protected native custody, independently enrolled devices and actual signature/ciphertext compatibility; transition/content receipt responses here are modeled and never replace the separately executed actual HTTP/SQL/browser gate |
| Inherited platform gates | All sixteen prior jobs PASS, including provider/container Linux71/Windows99 and the explicitly executed official-header ABI case; no physical Hello/TPM objects created |
| Raw source receipts | 323 Linux and 323 Windows inputs verified against Git blobs; 320 Windows CRLF hashes verified without normalizing raw reports |
| Complete frozen installation | PASS, all 775 then-visible source files and marked private/shared content counts/quota/counter preserved |
| Complete startup/readiness | PASS, owned services, trusted TLS/API/session, five-suite P10 check, native inventory and read-only contracts; source remains unchanged |

Raw reports: [HTTP](evidence/p10/http-report.json), [browser](evidence/p10/browser-report.json),
[Linux source](evidence/p10/linux-source-report.json), [Windows source](evidence/p10/windows-source-report.json),
[Linux interop](evidence/p10/linux-native-interop-report.json), [Windows interop](evidence/p10/windows-native-interop-report.json).
Initial diagnostic failures are corrected, rather than acceptance evidence. No
assertion/verifier/crypto/TLS/CSP/sandbox/eligibility bypass was used. Local cloud
Chromium remains BLOCKED; optional hosted browser diagnosis does not replace the
mandatory three-account run. Ordinary proof reads are paced below unchanged service
limits; eight-way mutation races remain genuinely concurrent and no API responses
are mocked by the hosted browser harness. Original spec, frozen P02 corpora and prior locks
are unchanged. Current bounded-proof limits are documented in P10_SHARED_GROUPS;
P11 owns scale/convergence, P12 files and P13 retention/purge.

Published P09 restoration was observed. P10 configuration saving, publication and
fresh-task restoration remain separate. No production migration/deployment/release,
new owner hardware trial or reviewer outreach occurred. Full physical G1 and
qualified G2/G3 remain open/unbooked/NOT_RUN. No new owner action is required for
this software phase. Continue the complete P11 handoff in NEXT_TASK.


## P11 development checks — not final acceptance

On 2026-10-13 the restored P10 checkout, owned dev-stack/P06 TLS/SQL readiness,
frozen baseline, P10 portable checks and native inventory passed. Additive P11
staged snapshot/paged-local work passed four portable suites and seven actual
native SQLite note suites (six inherited and one synchronization suite), strict
Clippy and the maintained standalone-validator/CSP static build. A real TLS/SQL
three-object snapshot plus following content delta passed protected application.

The cloud browser failed to start its required Chromium sandbox. No sandbox/TLS/
CSP checks were disabled. The broader HTTP suite and final exact-source hosted
acceptance remain pending; local development receipts have a dirty source flag
and cannot establish final phase acceptance. See P11_SYNC.md and NEXT_TASK.md.

P11 follow-up: the actual HTTPS/SQL transport suite passed 104 checks locally,
including three separate authenticated accounts, immutable snapshot/write overlap,
hidden ranges, malformed query rejection, exact retry, expiry/cancel, acknowledgement
and materialization rollback. Six portable suites now include bounded header-only
cache compaction and host-bound browser timer/backoff behavior. Seven native SQLite
note suites passed with compaction/delta/re-download and SQL fault rollback added
to the synchronization suite. Strict Clippy and the CSP build passed.

First hosted runs found an obsolete P03 phase/operation assertion and a browser
Window timer receiver error. These are fixed, not bypassed. Native Windows/MSVC
P09/P10 jobs passed at the development head; this is still not final P11 acceptance.
The diagnostic local source receipt produced while files changed during execution
is discarded. Future P11 receipts compare the source head/tree/raw hashes and clean
state before and after native execution. No invalid development receipt is archived.

P11 secret/history scale checks: seven portable suites passed, including 661-key
secret-root restart, aborted migration, complete identity preservation, refusal
of the older frozen decoder and ciphertext inspection. The complete Linux native
run passed 106 actual tests (72 unit, 9 devices, 7 notes, 3 shared, 15 custody);
the new 661-key test uses actual SQLite/WAL and strong-phrase restart. Nine real
native/portable interop checks validated 1,001 signed events and rejected a missing
event, signature corruption and known rollback. Inherited seven P08 workflow
suites and five P10 suites passed after updating their owned-secret readers for
the explicit new profile; original assertions remain.

At development head 0e4d728 the genuine sandboxed P09/P10/P11 Linux browser jobs
passed. One P11 Windows build encountered an upstream DNS resolution failure while
building unchanged libsodium; other Windows native jobs passed. Latest source and
final Windows/Linux acceptance still require complete final runs.

P11 follow-up transport/ancestry/recovery: the actual TLS/SQL suite passed 112
checks including 2,001 console-owned unsigned hidden hints and two full 1,000-row
scanned ranges. The three-role/independently enrolled second-device HTTP suite
passed 418 checks with existing leased pages reauthorized across role downgrade,
removal and device revoke. Ten portable suites now cover missing signed ancestry,
owned local recovery/source-attempt preservation and precise cancelled-stage cache
cleanup. Native note tests cover owned recovery and immutable attempt preservation.

The P08 quota saturation test originally left its owned global ledger artificially
full; a console-only cleanup restores actual account charge totals without deleting
content. HTTP suites must run sequentially: overlapping local P08/P10 executions
invalidated a global-counter race assertion and were repeated sequentially.

Windows source inputs now use explicit Git LF text checkout, with supplied spec and
Microsoft header bytes preserved. A core.autocrlf=true prospective index checkout
passed the unchanged P03 generation hashes and all original specification checksums.
Raw platform bytes remain recorded in source receipts. This fixes checkout drift
without relaxing lock/artifact/source assertions. Foreground UI work can yield a
background sync at the next protected command; interrupted stages remain durable.

P11 software restore fence: cancellation, later staged finish and quarantine
reclassification cannot clear RESTORE_QUARANTINE. Content/group/security publication
is blocked while local draft work and exact receipt reconciliation remain available.
The portable regression test exercises the closed-command downgrade attempts.
Operational restore attestation and production generation fencing remain P16.

## P11 complete synchronization slice — software VERIFIED

All twenty mandatory jobs PASS at `fae5e306181c05a9542449e8219706859f4b87a2`, clean tree `630436bcfdfb2e7c3dbc4a52f80aba7f6b6a805a`.
[Acceptance](evidence/p11/initial/acceptance.json) retains exact head/check/run/job references,
GitHub ZIP digests and raw public report hashes. Final documentation/evidence needs
fresh twenty-job success before ordinary automatic SHA-guard merge.

| Execution | Actual result |
| --- | --- |
| Maintained-crypto portable workflow | Ten suites PASS: partial encrypted stage/restart, atomic cursor/abort, hidden scanned ranges, malformed scope/body/root, signed ancestry omission, compaction and exact historical payload recovery, part integrity/L rotation/private G, visible polling/backoff and bounded 101-page catch-up, 661-key migration/older reader denial, source-preserving owned recovery and lease-before-local cancellation |
| Verified HTTPS/Nginx/Laravel/MariaDB sync | 112 checks PASS: three authenticated accounts, immutable snapshot/write overlap, 2,001 real hidden namespace hints/two bounded scanned ranges, closed raw duplicate query handling, expiry/cancel, exact retry, acknowledgement and SQL rollback |
| Membership plus leased transport | 418 checks PASS, inherited three-role workflow and independently enrolled native peer; existing lease page authorization across downgrade/removal/device revoke |
| Actual shipped PWA | 45 checks PASS, three independent persistent accounts, genuine WebAuthn, sandboxed Chromium, trusted CA/hostname TLS, strict CSP, encrypted draft preservation after removal/local reopening, EN/RU sync and reload; actual SQL/IndexedDB/log/ordinary-storage inspection |
| Actual native Linux and Windows/MSVC | 106 actual all-feature Linux tests; seven SQLite notes suites/platform, 661-key inventory restart, staged cursor/rollback/compaction/recovery and inherited 9 device/3 shared/15 custody suites; OS/ABI gates retained |
| New native/portable interoperability | Nine checks/platform PASS over actual protected native storage, 1,001 signed roster events, missing/corrupt event/known rollback rejection |
| Raw source and artifact verification | 494 Linux and 494 Windows input hashes match exact Git blobs byte-for-byte (zero checkout transformations needed); raw receipts preserved; GitHub ZIP digests match actual downloaded bytes |
| Complete install/start | PASS; 800 tracked files and marked snapshot/pin state preserved, real owned TLS/API/SQL services ready; generators compare source read-only |

Public reports: [sync HTTP](evidence/p11/initial/http-report.json),
[membership/leases](evidence/p11/initial/membership-report.json),
[browser](evidence/p11/initial/browser-report.json),
[Linux source](evidence/p11/initial/linux-source-report.json),
[Windows source](evidence/p11/initial/windows-source-report.json),
[Linux interop](evidence/p11/initial/linux-native-interop-report.json),
[Windows interop](evidence/p11/initial/windows-native-interop-report.json).
Source receipts verify clean head/tree/raw inputs before and after native execution.
Diagnostic failures are corrected rather than archived as acceptance. Browser removal
checks accept the two real poll/foreground timings while retaining mask/DOM/draft
assertions. Frozen P02 frames, original spec bytes and prior dependency locks remain
unchanged; no auth issuer/verifier/crypto/TLS/CSP/sandbox/eligibility bypass occurred.
No credentials/authenticated diagnostic logs or private candidate keys are archived.

Published P10 restoration was independently observed. Saving P11 configuration,
Publish and independently observed fresh P11 restoration are distinct. Full physical
G1/Hello/iPhone/memory/network and qualified G2/G3 remain open/unbooked/NOT_RUN.
No production migration/deployment/release, new owner trial or reviewer outreach.
Continue the full P12 handoff in NEXT_TASK.

## P11 final follow-up — regression gate remains open

Initial fae5e30 twenty-job code acceptance and archived raw reports remain factual.
At 5116fad the P10 browser and all other eighteen jobs passed, but P11 browser
failed with VAULT_LOCKED on the reader local save. No failing job is bypassed and
no merge occurred. Content-free Worker error/operation/visibility diagnostics are
being added to determine the originating custody lock. A closed lock-reason marker
also lets the client immediately mask and terminate when Worker custody closes.
Ten local P11 suites (including isolated host failure masking) and all five P07
maintained-crypto suites passed. Final source/platform CI remains mandatory.

P11 background/idle follow-up: visible polling now runs in a host background scope
which does not extend the five-minute UI lock timer. Trusted visible user input
still extends it. The isolated host test checks an unchanged timer after background
RPC failure, rejection of untrusted activity, trusted activity renewal and actual
idle callback masking. The original ten P11 and five P07 crypto suites, read-only
contracts, strict-CSP build and owned service readiness passed locally. Native and
hosted final acceptance remains pending; this does not explain the older singleton
VAULT_LOCKED result, whose original reason was not recorded.

## P11 lifecycle follow-up — exact-source code acceptance PASS

All twenty jobs passed at `08ca97c7f9b1caff1ffc55b284a2afa7a8f0bb65`, tree `e4c7e51a27d386314b792310d115fe3e3c7f62c9`. [Latest acceptance](evidence/p11/acceptance.json)
retains exact check/run/job/ZIP references and raw report digests. Original fae5e30
reports remain [separately archived](evidence/p11/initial/acceptance.json), with their
raw bytes unchanged. The later 5563bc0 diagnostic run passed all twenty; no failing
job was bypassed. The original 5116fad isolated lock cause was not recorded and is
not fabricated after the fact.

Latest execution: ten portable suites, 112 actual sync HTTPS/SQL checks, 418 actual
membership/lease checks, 45 genuine sandboxed shipped-PWA checks, seven native
SQLite note suites/platform, nine new native/portable interop checks/platform and
all inherited jobs PASS. 494 raw input hashes/platform matched exact Git blobs.
The hosted browser includes only closed error/operation/reason/visibility diagnostics;
no private RPC values are observed. Five local P07 maintained-crypto suites also
passed. Worker closure immediately masks the host; explicit tests preserve ciphertext
and typed error codes across five-minute expiry and backwards-clock closure, and
verify that background RPCs leave the idle timer unchanged while trusted activity
renews it. Full physical G1 and qualified G2/G3 remain open/NOT_RUN.

Latest [browser](evidence/p11/browser-report.json), [HTTP](evidence/p11/http-report.json),
[leases](evidence/p11/membership-report.json), [Linux source](evidence/p11/linux-source-report.json)
and [Windows source](evidence/p11/windows-source-report.json) are public metadata only.
Final documentation/source-byte revalidation, ordinary guarded merge and complete
configuration persistence still require their actual recorded outcomes.

Complete latest installation passed at `08ca97c7f9b1caff1ffc55b284a2afa7a8f0bb65` with all
810 then-visible tracked files and marked private/shared quota/counter
and snapshot/pin state unchanged. Full startup/static/API readiness passed again.

## Initial P12 exact-source software acceptance before the resync follow-up

PASS at `4d6f3c93f54919987f64f669b27e5c1eb0907ec1`, complete clean tree `e5d5f22f3ce758dceb76244bb03fb4284bd1a511`: all twenty-two mandatory jobs,
twelve portable file tests, 368 actual verified HTTPS/SQL/blob checks with a 1 GB
round trip, 452 real file authority/full-quota security checks and 60 actual
sandboxed shipped-PWA checks. Both native source receipts execute the real 1 GB
SQLite/source/resume/export test and report actual all-feature counts:
Linux 109, Windows 137.
Raw implementation inputs/platform: 522/522;
each was independently matched to the accepted Git blob (raw Windows line endings
verified), and GitHub ZIP digests matched downloaded bytes. Frozen corpora and
prior dependency locks were preserved.

The desktop PWA actually locks a pending upload, reselects/resumes identical bytes,
exports 1 GB through its single-use service-worker channel, verifies ciphertext
OPFS/pin state, exports the same hash with file network requests disabled, attaches
and publishes the note, and checks masked DOM/ordinary stores. Native tests reject
source changes, preserve immutable attempts, verify cached bytes, refuse corrupt
exports and atomically finalize only a complete selected output. Public memory
samples retain baseline/peak/growth and process scope; they are not iPhone or
packaged WebView2 physical acceptance or a hard RSS ceiling.

Actual socket/receipt loss, quota/commit rollback, concurrent reservations,
collector/commit and snapshot pin races do not charge twice or expose partial files.
Pruning drops encrypted payload/key-wrap metadata but retains signed proof and the
exact request digest for receipt reconciliation. Qualified G2/G3 and physical
G1/U11/U12 remain OPEN/NOT_RUN; no production operation, release or new owner trial.

Public [all-gate receipt](evidence/p12/initial/acceptance.json), [HTTP](evidence/p12/initial/http-report.json),
[authority](evidence/p12/initial/membership-report.json), [browser](evidence/p12/initial/browser-report.json),
[Linux](evidence/p12/initial/linux-source-report.json) and [Windows](evidence/p12/initial/windows-source-report.json)
preserve raw execution bytes. Final documentation-head source-byte comparison,
ordinary guarded merge and tested configuration persistence are separately checked.

The complete frozen installer actually passed at `4d6f3c93f54919987f64f669b27e5c1eb0907ec1`, preserving all 849 then-tracked files, 26 independently hashed persistent tables and TLS/OAuth files. Startup/static/API and read-only contracts passed. Draft persistence, Publish and independent fresh restoration remain separate outcomes.

## P12 exact-source software acceptance

PASS at `d53b90f1ee3398ea0c784becdd1557e2eac78bd2`, complete clean tree `e6fb1363c2398e5dd4c5182a6709a95720602e14`: all twenty-two mandatory jobs,
twelve portable file tests, eleven protected sync tests, 368 actual verified HTTPS/SQL/blob checks with a 1 GB
round trip, 452 real file authority/full-quota security checks and 60 actual
sandboxed shipped-PWA checks. Both native source receipts execute the real 1 GB
SQLite/source/resume/export test and report actual all-feature counts:
Linux 109, Windows 137.
Raw implementation inputs/platform: 522/522;
each was independently matched to the accepted Git blob (raw Windows line endings
verified), and GitHub ZIP digests matched downloaded bytes. Frozen corpora and
prior dependency locks were preserved.

The desktop PWA actually locks a pending upload, reselects/resumes identical bytes,
exports 1 GB through its single-use service-worker channel, verifies ciphertext
OPFS/pin state, exports the same hash with file network requests disabled, attaches
and publishes the note, and checks masked DOM/ordinary stores. Native tests reject
source changes, preserve immutable attempts, verify cached bytes, refuse corrupt
exports and atomically finalize only a complete selected output. Public memory
samples retain baseline/peak/growth and process scope; they are not iPhone or
packaged WebView2 physical acceptance or a hard RSS ceiling.

Actual socket/receipt loss, quota/commit rollback, concurrent reservations,
collector/commit and snapshot pin races do not charge twice or expose partial files.
Pruning drops encrypted payload/key-wrap metadata but retains signed proof and the
exact request digest for receipt reconciliation. Qualified G2/G3 and physical
G1/U11/U12 remain OPEN/NOT_RUN; no production operation, release or new owner trial.

Public [all-gate receipt](evidence/p12/acceptance.json), [HTTP](evidence/p12/http-report.json),
[authority](evidence/p12/membership-report.json), [browser](evidence/p12/browser-report.json),
[Linux](evidence/p12/linux-source-report.json) and [Windows](evidence/p12/windows-source-report.json)
preserve raw execution bytes. Final documentation-head source-byte comparison,
ordinary guarded merge and tested configuration persistence are separately checked.

The complete frozen installer actually passed at `afc6bbd88130372f0a013073e12f55a5853c2099`, preserving all 860 then-tracked files, 26 independently hashed persistent tables and TLS/OAuth files. Startup/static/API and read-only contracts passed. Draft persistence, Publish and independent fresh restoration remain separate outcomes.

## P13 exact-source software acceptance

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

## P15 development observations

Executed locally on the P15 working tree: six real service-worker policy tests
pass, install assets/build pass, all 179 frozen baseline files compare unchanged,
and generated contracts compare read-only (325 structures/111 operations).
Cloud Chromium failed before startup due to its sandbox-helper ownership; no
browser/physical acceptance is claimed. The new CI gigabyte/update/V8-memory
case and source-receipt collector are prepared and NOT_RUN at this source.

P15 local follow-up: seven executable tests pass (six worker policy tests plus
translation isolation for runtime/recovery text and prototype-shaped strings).
The first remote P07 browser run failed NO_AUTH_API_KIT_OR_DYNAMIC_CACHE because
its exact allowlist did not yet include the new manifest and two icons. The test
is updated to exactly 14 static resources and explicitly rejects query strings;
no API/cache security assertion or prior lifecycle test is disabled. New Chromium
gigabyte/update and hosted WebKit checks remain pending for the updated source.

The initial P15 browser run stopped after actual 1GB protected upload/reselection
at P12_UNATTACHED_RECOVERY_VISIBLE: the UI now intentionally displays a localized
human label instead of the raw UNATTACHED enum. The exact workflow state/version
is retained in DOM data attributes; the regression now requires an UNATTACHED row
with an available Attach action. No upload, cryptographic, full-hash, receipt or
size assertion is removed. This initial run does not establish the later download,
portable export/import, update or memory results.

The final P14 head b30dc74bd2e97b3c46a6cacd51ee02ffc9568e70 was independently
checked through GitHub: all 25 mandatory jobs succeed. Downloaded artifact
11996283176 has SHA-256
793dc5dca37591b1f65dcdf9666981e5228ffddeb3c246af25a3e17e9349a9ec.
Its clean source receipt binds tree49e97603ea2bfd3d83a7976dddbf19dd18f9ad73;
all 869 input hashes were compared with actual Git blobs, all seven declared raw
report hashes/statuses and the installer digest verified. This read-only audit
neither reran physical tests nor closed the retained signing/memory limits.

At a3706f4 the P12 browser subcase completed all 14 assertions, actual protected
1GB upload/reselection, service-worker full-hash download and OPFS/offline export.
The following P15 case timed out on a hidden mobile tab because P12 intentionally
ends locked. Its precondition now uses the real unlock/proof/group flow and actual
writer readiness before proceeding; lock and timeout boundaries are unchanged.
The full cohort remains failed until the corrected P15 scenario executes.

A direct trusted-TLS request found manifest delivered as text/plain. Nginx now
sets application/manifest+json explicitly, delivery policy participates in the
static revision, and both browser gates assert the actual response media type.
P15 revision also clears decrypted destination titles and stale preference
references at lock, keeps the save state visible at a keyboard-sized viewport,
and records source/recovered/imported full digests and per-process memory counters.

The a3706f4 inherited Windows host job116677705874 stopped with exit1 during
signed-test-upgrade, after two logged writer-readiness waits. No sanitized error
or final WebView PASS receipt was produced; the cause is NOT_ESTABLISHED. Its
installer/report ZIP12009129806 digest is
ce9fa74f963b89958d1eb8bee8e6b44b4c97982f4f63fd677dc4b43ede6ae693.
Pairing/sharing/preflight receipts pass, but they do not establish the unfinished
host acceptance. The earlier 6d47151 Windows host job passed. The final P15 head
still requires its own complete passing mandatory cohort; no retry or timeout
weakening is used to relabel this observation.

At d68be7e, actual hosted WebKit27.2 passes16 shell checks including the delivered
manifest media type. ZIP12009034586 SHA256
8afe19697e0343960e5237209f14a3f0721670e542985fb9ca68026b4abb0175 and all885
Git input blobs independently verify. The focused PWA run is separate from full
27-job merge acceptance and physical iPhone tests.

The cloud's full owned development foundation check now passes, including actual
Composer locked advisory audit (no known vulnerabilities),102 formatted PHP files,
11 PHPUnit tests/217 assertions, transactional SQL and database-outage recovery.
Trusted P06 HTTPS/session/CSRF/origin readiness passes afterwards. Local protocol
306 tests and4 hostile-preview tests pass. These observations supersede the
earlier cloud Packagist access blocker; they are not production deployment.

The focused d68be7e Chromium run completed inherited P12 but stopped before P15
portable export while selecting the reopened entry by title. The UI cleared its
title map on lock, then listed entries without decrypting their verified titles;
the list remained Untitled until opening an entry. P15 now opens authenticated
payloads for the current list page (or retained offline references), checks the
current generation and renders only their verified titles. The existing title
selector is retained and the opened editor title is asserted explicitly. No API
response, cryptographic check or actual gigabyte is replaced. ZIP12010332975
digest6fea55c44372f9367482110b420efb57aca44712a8bde5aa7e61b8116b0c0f5b
was independently checked; it is a failed development receipt, not acceptance.

The final prepared P15 update scenario also stages a real API-accepted immutable
attempt with only its response lost, edits a newer local version, and compares
all encrypted outbox record hashes before/after actual activation while still
locked. Fresh unlock must reconcile that exact old operation receipt, retain the
newer local text and leave it locally saved. Only ciphertext record hashes and
opaque identifiers enter the report. This expanded scenario remains pending
until its exact-source browser receipt passes.

The af01b02 focused browser run passes the reopened-title, mobile/keyboard,
manifest/cache and actual1GB archive EOF/kit-release assertions, then its
independent reader rejects UNANCHORED_HISTORY. ZIP12011298739 SHA256
a0b7aa25425c199787225353f9c15f8f0d50626586e4ef32ec93e68fc3591518 verifies.
The exported shared journal lacked inclusion of newer live records. Production
export now checks its portable journal before creating an outer stream; the
browser regression requires denial before any download, then uses the existing
owner history-confirmation API/UI and repeats the complete genuine1GB recovery
and import. This is not reader relaxation or a smaller substitute. Full P15
acceptance remains pending at the corrected source.

A focused state regression reproduced a second import issue before the full
large-file resume: after new-private group creation, begin returned a fresh
audience token but retained the initial token. The pre-fix test failed because
the old token was still accepted. Resume now persists its freshly displayed
token; two tests with the real frozen authenticated archive prove that the old
token is rejected, the new one works, and a later destination change still
cannot publish or replace the retained job. The read-only P13 suite now passes
19 tests, and the seven PWA tests/build/frozen179 checks pass. This small state
regression supplements the unchanged genuine1GB browser/API scenario.

P15 final storage-fault acceptance is prepared in the same full1GB Chromium job:
CDP sets the actual origin quota to zero, the shipped Worker attempts an encrypted
IndexedDB transaction, typed storage failure must prevent a new-save acknowledgement,
and ciphertext records/last acknowledged text must survive lock/reload/fresh
authorization. The quota override is restored in finally, without deleting data.
This prepared check is NOT_RUN locally because the cloud browser sandbox is
unavailable; its exact-source hosted result is required. It does not assert
physical iPhone storage, disk filling or immunity from OS eviction.

The cf1c631 ordinary PWA job (38822277539 / 116721420311) completed the
full genuine gigabyte export, independent offline hash, protected import resume
and imported-destination full hash, then failed
`P15_NEW_WORKER_WAITS_FOR_CONTROLLED_WINDOW`. Artifact 12015111858 ZIP SHA-256 is
`67941f76955dd2613112bf5f0c1f56d7e27a9d6d978c4b3ce36886dd1491285f`.
Its receipt did not capture the individual registration states; the cause is
not established. The follow-up requires an actually controlled active window
before update and waits for all active/waiting/controller conditions together
within the unchanged 30-second bound, recording closed lifecycle states if it
fails. A non-null waiting slot is no longer used as the transition barrier.
No early activation, runtime cache policy or timeout is changed. This diagnostic
follow-up is not a passing update or quota result until actually exercised.
