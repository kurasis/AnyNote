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
