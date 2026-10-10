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
Hosted Ubuntu browser evidence is pending. No physical Windows/Hello/iPhone
checks or qualified review have run.
