# P18 review candidates and final software handoff

The advertised scope is synthetic software evaluation. Production publication is
blocked. P18 does not deploy a service, publish a GitHub Release, collect signing
keys, book an auditor or claim physical-device/security acceptance.

## Versioned deliverables

`AnyNote-0.18.0-review-{windows,pwa,api}-<commit>.tar.gz` contains a canonical
`candidate.json` with exact source commit/tree, SHA-256/length of every file and
explicit release blockers. The Windows binary retains its tested application
version **0.14.0**; 0.18.0-review identifies this handoff set, not a fabricated
binary upgrade. The corresponding source is the actual `git archive` of that
commit, including immutable historical test profiles. Those old standalone
auth/vault locks are source history, not supported executable release profiles.
Only the maintained Windows application/helper graph is a native distribution
target; it uses rustls0.23.46 and excludes the tracked GTK closure.

| Package | Exact executable/static input | Contents and evidence |
| --- | --- | --- |
| Windows x64 | NSIS executable hashed by the actual installed Windows/WebView2 job | Single installer, GPL text, source identifier, conservative712-component inventory, SBOM and upstream notices including embedded PDF font/CMap terms; test updater signatures remain synthetic |
| PWA | The actual restored original static directory used by sandboxed Chromium's full1GB/lifecycle/update journey | All20 static files, frozen dependency metadata, installed notices, SBOM; no session/auth response, private key or profile |
| API | The immutable Docker image ID recorded inside the actual signed backup and tested during clean-host restore | Exact saved image, hardened deployment templates, operator script, Composer production inventory/notices/SBOM; no environment values, DB dump, blob store, TLS/OAuth or backup identity |
| Recovery and protocol | Corresponding source in every package | Frozen OpenAPI/schemas/fixtures, P13 portable export/import/offline reader, P16 private-genesis root-kit reader, frozen installation locks and instructions |

The source archives and dependency inventories deliberately include build/test/
optional package metadata. They are not an exact linked-code census, an OS-image
advisory census or an independent license/security review. Windows derivative
license is GPL-3.0-only. Repository-wide release-license selection is still open;
the review set does not grant a new repository-wide redistribution license.

## Reproduce and inspect

Use Python3.12.14, Node24.21.0/npm11.19.0 and Rust1.99.0, with frozen `npm ci`,
Composer install and `cargo --locked`. See [development setup](DEVELOPMENT.md),
[Windows](P14_WINDOWS.md), [PWA](P15_IPHONE.md) and
[operations](P16_OPERATIONS.md). Do not execute extracted archives from an
unverified sender. Do not install the synthetic CA or enable fixture controls in
an owner deployment.

The existing ordinary jobs package artifacts only after their actual runtime
checks and exact-source receipts. Commands, in the same clean job checkout:

```bash
python3 scripts/p18-candidate.py build windows
python3 scripts/p18-candidate.py build pwa
python3 scripts/p18-candidate.py build api
python3 scripts/p18-candidate.py verify PATH_TO_CANDIDATE.tar.gz
python3 scripts/check-p18.py
```

Each build role needs its corresponding executed reports and prepared inputs;
there is no skip-tests switch. Verification streams bounded regular members,
rejects duplicate/traversal/link/sparse/missing/modified files and does not extract
anything. SHA-256 manifests authenticate consistency with observed CI bytes, not
the publisher's identity. Verify the exact source/job/ZIP digest through a trusted
GitHub session independently. Do not treat a checksum downloaded from an attacker
beside the file as an independent trust anchor.

For a completed ordinary cohort, obtain all30 named job receipts and all28
original artifact ZIPs/metadata from the GitHub API using the existing trusted
connection. Keep `cohort.json`, `download-receipt.json`, `<artifact-id>.json` and
`<artifact-id>.zip` together. The assembler rechecks actual Git blobs, ZIP hashes,
all inherited P15/P16/P17 assertions and all three package manifests:

```bash
python3 scripts/p18-acceptance.py --cohort cohort.json \
  --downloads ORIGINAL_DOWNLOAD_DIRECTORY --output NEW_OFFLINE_REVIEW_DIRECTORY
```

The result includes three versioned archives, three manifests, `SHA256SUMS`,
`acceptance.json`, the95-case F/C/S/U/X/O/R plus7-gate `matrix.json`, original
cohort/raw-report index and inherited verification receipts. Copy the original
ZIP/metadata directory alongside it for independent re-verification. Actions
attachments expire after14 days: retain the complete offline set before expiry.
No candidate binary is committed as source or silently published as a release.

## Final linked journey and acceptance boundary

`operations-linux-drill` creates a new hardened API installation, registers one
synthetic owner and enrolls a second independent device. That owner admits a
separate reader with a signed invitation, acceptance and complete epoch grants,
uploads a multilingual file, verifies the reader's complete hash, removes the
reader, checks group/manifest denial, excludes it from a fresh epoch and publishes
again. The same owner then runs the real1,000,000,000-byte private-file backup,
root reset, independent checkpoint comparison, clean-host quarantined restore,
offline root-kit recovery and explicit fresh-identity/file copy. It verifies the
source/recovered/fresh-download hashes and keeps old credentials quarantined.
This does not claim the root kit recovers rotated/shared history. P13 portable
archives and separate export kits cover those selections in their existing jobs.

All30 existing ordinary jobs remain mandatory, including native Windows/SQLite,
installed WebView2/update, actual1GB, Chromium sandbox, WebKit, operations/capacity
and live advisory/adversarial evaluation. Package tests supplement these gates.
PR and merged-main cohorts are observed separately; exact checked source, base,
merge parents and equal checked/merged tree must be verified before completion.

The matrix preserves every frozen criterion and identifies related original
executed report members/hashes/job URLs/dates. It does not infer every complete
criterion PASS from a whole-suite count. `NOT_RUN` records absent case-level or
external acceptance, while related engineering execution remains visible.
Known measured failures remain FAIL. G5/G6 PASS is bounded to the synthetic
recovery/honest-handoff scope; no production gate is declared passed.

## Release eligibility and remaining owners

`python3 scripts/p18-candidate.py eligibility` returns JSON `BLOCKED` and exit2.
No manifest field, caller boolean, ephemeral test signature or command-line flag
can authorize production through this tool. Production requires a separately
authorized, reviewed ceremony and exact-artifact evidence for every blocker:

| Owner | Missing evidence/action |
| --- | --- |
| Qualified independent reviewer, appointed by owner | Protocol/crypto/auth/recovery/update review, actual findings, remediation/retest and a documented scoped risk decision; AI review is not independent |
| Physical validation owner | iPhone17Pro/iOS26.7.1 and a declared lower-memory supported target or explicitly narrowed accepted scope; real1GB Files output, lock/background/force-close/storage, passkeys/PRF and device memory |
| Windows/memory maintainer | Real Windows11Pro25H2 Hello/TPM/suspend/session evidence; repair or explicitly narrow the128MiB native budget after the observed339361792-byte growth |
| Capacity operator | Real100GB ciphertext inventory on a sized isolated host plus backup/work/reserve space; never sparse files or fabricated quota counters |
| Release signer/security custodian | Real Authenticode, final installer digest, production updater claims/payload signatures and independent verification; separate offline recovery/backup/static deployment custody |
| Service owner/operator | Trusted HTTPS hosting, repository-wide license decision, named operational acceptance and separately authorized production publication |

Do not repeat hardware/host questions or request secrets in chat. No reviewer
outreach, owner physical trial, signing ceremony or production rollout is started
by P18. See [known limits](KNOWN_LIMITATIONS.md), [user guide](USER_GUIDE.md),
[operator handoff](OPERATOR_HANDOFF.md), [security review](P17_SECURITY_REVIEW.md)
and [evidence index](evidence/p18/README.md).
