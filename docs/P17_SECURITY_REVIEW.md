# P17 adversarial evaluation and independent-review package

This is an AI-assisted engineering evaluation of the implemented synthetic
candidate. It is not an independent cryptographic audit, an ASVS certification,
a production penetration test or authorization to deploy. Qualified design and
implementation review remain `TRACKED_NOT_BOOKED / NOT_RUN`; G2/G3 production
security release is not satisfied. Only synthetic evaluation is permitted.

The frozen specification remains unchanged. The [R01–R24 traceability](security/P17_TRACEABILITY.md)
binds actual authority and maintained tests; its machine check rejects stale
anchors. Static bindings are not runtime evidence. Final acceptance requires
all29 inherited ordinary jobs plus `adversarial-linux`, on the exact source.
Original clean-source reports, Git-input hashes and ZIP digests are indexed in
[P17 evidence](evidence/p17/README.md). Candidate/development results with dirty
source never substitute for the final cohort.

## Scope and reproducible execution

Read AGENTS, the frozen threat/acceptance/state-transition chapters, protocol ADRs,
P02 contracts, P13 portable recovery, P16 operations and the limitations first.
Use pinned tools and frozen locks. In an already prepared cloud checkout:

```sh
source scripts/runtime-env.sh
python3 scripts/p17-check.py
python3 scripts/p17-run.py
node --expose-gc packages/protocol/security/response-regression.mjs
node packages/protocol/security/fuzz.mjs
python3 scripts/p17-stack.py up
node packages/protocol/security/http.mjs
python3 scripts/p17-supply-chain.py
# Only a clean actual Git source is eligible:
python3 scripts/p17-evidence.py
python3 scripts/p17-stack.py stop
```

The normal [workflow](../.github/workflows/security-review.yml) installs the
maintained prerequisites and uses ordinary PR/main triggers. The existing
Windows/WebView2, full1GB, native, sandboxed Chromium, WebKit, operations and
capacity jobs are mandatory independently. No manual-dispatch substitute,
signature/TLS bypass, reduced gigabyte, relaxed storage reserve or browser
sandbox bypass is allowed.

`p17-check.py` is read-only except its generated public receipts. Do not run reset,
fault or maintenance commands against retained P06. The P17 target uses a distinct
owner-marked `anynote_p17_security` database, Compose project, loopback20443 and
private runtime logs. It reuses the established synthetic TLS/OAuth files read-only,
never resets existing databases and preserves its data on stop. Existing P03/P06
SQL/TLS/OAuth/profile/key/pin/draft/outbox state stays protected. Repeated local
runs may append marked synthetic rows; they are not described as fresh installs.
The ordinary hosted P17 job creates a new target on its clean runner.

## Executed campaign and observable limits

The portable runner executes69 maintained client tests with genuine libsodium,
Argon2, signatures, encrypted records and transactional store fixtures. It records
the actual process exit, every test name, counts, stdout/stderr hashes and elapsed
time. It requires zero failures, skipped/cancelled/todo cases. This local store is
an in-memory transactional model; actual SQL, OPFS, SQLite, native IPC and installed
Windows behavior remain separately executed inherited gates.

The reproducible `AnyNote/P17/bounded-mutation/v1` campaign performs:

- 4352 mutations across file, identity, roster/channel, group and object/local/export
  schemas, comparing the frozen Node predicates and portable adapters;
- 2376 raw control cases compared against the actual PHP parser, including escaped
  duplicate keys, invalid UTF8/Unicode, excessive depth/size and nonfinite numbers;
- 512 authenticated signature/context/ciphertext/key-wrap/epoch/parent/author/thread
  substitutions, each refused before trusted content;
- five excessive/invalid KDF profiles refused before expensive allocation;
- one positive streamed tar with arbitrary chunk boundaries and512 one-bit header
  corruptions refused before any entry visitor is called.

Seed, PRNG, corpus digest, actual accepted/rejected counts and Node process RSS
high-water mark are in the raw report. This is bounded deterministic mutation,
not coverage-guided fuzzing, exhaustive proof, independent implementation diversity
or an iPhone/aggregate process-memory acceptance. PHP comparison covers raw syntax;
the separate maintained PHP/public-signature and native/browser gates cover their
own schemas and crypto. Positive seeds prevent a reject-everything implementation
from passing.

The separate HTTP evaluation registers three actual accounts through maintained
WebAuthn verification and root/device possession. It tests known foreign object,
revision, snapshot and file IDs, malformed raw controls, hostile Origin/CSRF,
unsupported push and ciphertext download. Twenty-four new publications run with
up to eight requests in flight. A response is destroyed after real committed
response bytes begin; eight immutable retries resolve to one receipt. Actual SQL
inspection requires exactly one revision for each of25 operations. Typed503
responses are counted, respect bounded Retry-After and retry identical bytes;
none is relabelled an acknowledged commit. Local contention produced transient
refusals, whose underlying database cause was not captured and is not asserted.
Latencies include the measured HTTP scope, not a production SLA.

The additional file is genuinely random1MiB+1 with exact full download hash.
It supplements the unchanged actual1GB workflows. An actual listening loopback
canary receives zero requests for unsupported push registrations; this does not
claim implemented enabled-provider DNS/redirect defenses. Push stays disabled.

Only owned P17 SQL values, blob bytes, actual runtime logs and the protected local
fixture are scanned for independent random plaintext title/body/name, private
device keys, group keys and root recovery material. Both raw and encoded key
representations are checked. The same scanner must detect a positive canary first.
Reports retain counts/byte scopes, never the canaries, SQL dump, keys or kits.
This targeted inspection cannot prove absence of every secret, arbitrary encodings,
OS swap/crash remnants, malicious-origin exfiltration or undiscovered logging paths.

R03 now publishes real counter before/blocked/after observations for both commit
and rollback, with an independent PDO observer and another connected process.
R10/R11/R22 retain their actual snapshot/response-loss/restore assertion boundaries;
see traceability for exact injection and remaining OS/power-loss limitations.

## Remediation register

Engineering severity is contextual triage, not an independent severity verdict.

| ID | Observation | Result / evidence |
| --- | --- | --- |
| P17-01 | Moderate resource amplification: bounded response bytes still retained one allocation per received chunk until EOF | FIXED: one bounded destination; actual GC observation frees consumed chunks before EOF. Exact old Git function fails the same observable control. No measured physical-memory pass is inferred. |
| P17-02 | Low resource cleanup: cancelling an already errored stream rejects before releasing its reader lock | FIXED: nested finally always releases the lock; exact old/new real Web Streams comparison records the difference. |
| P17-03 | Low error-boundary inconsistency: portable strict base64 padding errors escape AJV as untyped exceptions | FIXED: portable AJV format adapter returns false on decoder failure; same frozen schema/semantic predicates and positive byte acceptance remain checked by generation and differential mutation. |
| P17-04 | Live advisory matches in cross-target/old frozen dependencies | TRACKED, qualified by actual target: see exact advisory triage below. No blanket ignored-advisory list or production waiver. |
| P17-05 | Missing qualified independent design and implementation review | OPEN release gate: review inputs/questions below, reviewer unbooked and review NOT_RUN. Passing engineering tests never closes it. |

No content key, cipher, signature domain, byte schema, production migration or
frozen lock is changed. R01–R24 and all179 frozen specification/P02/prior-lock
files remain protected. Revert the reviewed implementation/test/doc commit to
roll back; preserve local evidence and synthetic target data independently.

## Dependency and release-chain review

The live OSV query covers1075 unique package versions from every tracked product
and experiment npm/Cargo/Composer lock. npm integrity/source, Cargo registry and
checksums, Composer HTTPS/dist commit references, immutable action refs and local
same-commit workflow hashes are checked. A conservative lock closure includes
dev/build/optional/other-target dependencies; it is not an exact linked binary list.
OSV responses have timestamps and byte digests. A newly observed advisory fails
the gate unless its exact package/version/advisory and actual scope are reviewed.
Network failure is a failed check, never an empty vulnerability result.

Actual locked all-feature Windows metadata is walked from the root, including
build dependencies. It excludes `glib` and `proc-macro-error` and contains only
`rustls0.23.46` with ring/std/tls12. The exact [triage](security/p17-advisory-triage.json)
retains every observed advisory:

- `glib0.18.5`: RUSTSEC-2024-0429 / GHSA-wrw7-89jp-8q8g are one upstream unsound
  iterator issue. Present in Linux GTK lock closure, absent from Windows resolve.
  Any Linux desktop product needs a maintained GTK update and new review first.
- `proc-macro-error1.0.4`: RUSTSEC-2024-0370 is an unmaintained notice in that
  excluded closure; it remains a build supply-chain concern.
- `rustls0.23.45`: RUSTSEC-2026-0346–0349 remain in the old standalone auth/vault
  frozen synthetic test profiles. They cover conditional session-value Debug
  disclosure, ECH rejection leakage, Brotli allocation and key-share prediction
  downgrade. Product Windows/helper/content locks already contain fixed0.23.46.
  The old profiles remain synthetic-only and cannot become release inputs.

P18 must enforce the actual supported root/helper locks. A future standalone
distribution requires a new reviewed maintained profile while retaining historical
fixture locks. Composer's frozen dist references lack archive hashes, so TLS and
upstream-provider trust remain. Container OS packages, WebView2/browser/OS/driver
updates, genuine signature key custody and independent static/backup deployment
credentials still need actual owner-host review. Existing synthetic signing keys
never become production credentials. Source checks and installer/update tamper
gates cannot certify an uncompromised CI provider or a malicious authorized signer.

## Qualified independent-review handoff

Review baseline: OWASP ASVS5.0.0 Level2 as an engineering reference, with extra
attention to cryptography and trust transitions. This is a category-level review
map, not a complete ASVS control-by-control assessment or certification:

| Area | Concrete implementation / evidence | Qualified review still required |
| --- | --- | --- |
| Encoding, validation, API and file handling | Raw parsers, five schemas, signed contexts, streamed archives, limits, hostile imports and preview isolation | Parser composition, decoded bounds, schema evolution and malicious decrypted inputs |
| Authentication, sessions, authorization and OAuth | WebAuthn, root/device possession, descendant revocation, role/current-head checks, literal loopback PKCE | Root-reset/login distinction, atomic approval/revoke, callback/browser/token boundaries |
| Cryptography and secure communication | Maintained libraries, native/browser/PHP fixtures, key delivery, authenticated contexts, signatures and TLS | Pairing/OOB proof, root/roster/epoch/history composition, retired writer closure and trust assumptions |
| Configuration, data protection and logging | Minimal native capabilities, encrypted local/outbox/search, canary inspection, signed encrypted backups, restore fence | Key lifecycle, physical caches/memory/export remnants, operator separation and current-security recovery |
| Architecture, build/update and delivery | Frozen sources/locks, checked actions, signed update tamper/downgrade tests, separate app/API/static boundaries | Production key provenance/custody, source-to-release correspondence, compromised PWA origin/build/provider |

Provide reviewers the frozen specification, P02 registry/fixtures/ADRs, actual
source/tree IDs, complete report archive, this remediation register, dependency
triage, P13 recovery formats and P16 runbook. No real secret or production SQL
backup is needed. Do not contact or book reviewers without separate authorization.
Reviewer identity, organization, scope agreement, conflicts, dates, report, finding
severity and independent remediation retest are all `NOT_RUN / NOT_BOOKED`.

Ask the reviewers specifically to challenge:

1. QR/OOB trust bootstrapping, channel replay/reflection and session/device/root
   possession; missing physical ceremony evidence remains distinct.
2. Root-reset authority versus authentication and another group's ownership;
   descendants, pending approvals and stale/isolated rosters.
3. Role/epoch/history composition, independently witnessed inventory/parents,
   backdated signatures, incomplete grants and wrong unwrap repair.
4. Immutable attempts across lost responses, conflict/rekey/removal, snapshot
   leases/GC/reference retention and local encrypted draft recovery.
5. Fresh-client rollback/fork limits, independent pins and malicious server
   withholding; no universal transparency guarantee exists.
6. Streaming nonce/AAD/source-change framing, full authenticated export import,
   plaintext sinks/OS remnants and native/PWA lifecycle generations.
7. Restored security fencing and independent backup/root/export-kit custody;
   private epoch-zero root-kit reader is bounded, not automatic general recovery.
8. Delivery/build/OS trust, dependency advisory scope and production signing/
   deployment separation; a compromised PWA origin can replace its verifier.

## Release-risk decision

### Post-merge native writer regressions

The first P17 main cohort at `626e25e` failed the positive 1001-event
native-history scenario in `files-windows-native`, at snapshot adoption. Its
ordinary PR cohort had passed 30/30; that does not make the main failure PASS.
An isolated local process with controlled CPU pauses reproduced `STALE_WRITER`
after 38.7 seconds of otherwise valid snapshot processing. The implementation
claimed its 10-second writer lease before replaying the signed history.

Snapshot adoption now verifies the complete history first, then claims the
unchanged short lease. It requires the resulting revision to equal the original
revision plus exactly the lease's own increment before publishing. Intervening
writes, foreign owners, stale capabilities, lifecycle generations, rollback
anchors and the transaction's existing fence checks still reject adoption.
This does not extend the lease, omit events, retry an assertion, or weaken any
signature check. The existing full-history positive/corrupt/omitted/rollback
interop checks and native concurrency/lifecycle suite remain mandatory. The
interop assertion now exposes only the typed native error for diagnosis.

The same initial main cohort also failed `host-windows-build` after uploading
the full 1 GB: progress polling called `file_transfers`, which claimed a new
lease/revision even though it only read transfer metadata. That could invalidate
the protected content comparison while the uploaded file was being attached.
The existing readiness/CAS regression now interleaves actual transfer-list reads;
it reproduced `STALE_WRITER` before this correction. Transfer listing now only
authorizes and authenticates the read, preserving the in-flight revision. The
regression also retains rejection of a real intervening commit and a locked
capability. Mutations still acquire and check their normal writer fences.

Production release remains blocked. P17 software acceptance authorizes only the
existing synthetic evaluation scope. The bounded campaign and fixes do not prove
absence of critical/high exploitable defects. No independent reviewer has issued
such a conclusion, and no implicit owner acceptance of undiscovered risks is
recorded. External G2/G3, physical G1/U11/U12/Hello/TPM/PRF, actual100GB, device
memory, real signing/custody and deployment gates remain open. The existing native
helper sampled growth339361792bytes already exceeds128MiB; CI samples cannot
overrule it. Proceed to P18 packaging/handoff software with explicit gates and no
production release or new physical trial by implication.
