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
