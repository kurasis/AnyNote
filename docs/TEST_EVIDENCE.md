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
