# Decisions

## ADR-001 — Scope, stack and initial version matrix

Date: 2026-10-10. Status: ACCEPTED for development baseline; platform support
remains a candidate until P01 evidence. Wire contracts are not frozen by this ADR.

### Context and options

The repository is empty. Specification 1.1.0 requires Tauri/Rust/React/WebView2,
an iOS PWA, and Laravel/MariaDB/Nginx/PHP-FPM. Preserve this stack instead of
substituting a Node backend, Electron or native iOS. Use npm initially to avoid
an additional package-manager bootstrap; PHP and Rust retain Composer/Cargo.

### Selected exact development versions

| Component | Selected version | Source / support evidence | Runtime state |
| --- | --- | --- | --- |
| Python baseline checker | 3.12.14 | Installed runtime; CI pins same version | Executed |
| Git | 2.52.0 observed | Installed runtime; no special Git feature required | Executed |
| Node | 24.21.0 LTS | Official release index and Release schedule; 24.x security support to 2028-04-30 | Host has 24.19.0; install target at P03 |
| npm | 11.9.0 baseline candidate | Installed with current Node; confirm/pin chosen Node distribution's npm at P03 | Available, no dependency install yet |
| Rust | 1.99.0 | Official stable channel dated 2026-10-01 | Not installed |
| Tauri Rust / JS API | 2.12.2 | crates.io and official npm package metadata | Not installed |
| React | 19.3.0 | Official npm package latest metadata | Not installed |
| TypeScript | 7.0.2 | Official npm package latest metadata; verify build-tool integration at P03 | Not installed |
| Laravel framework | 13.35.0 | Packagist plus official Git tag; Laravel 13 supports PHP 8.3–8.5, security through 2028-03-17 | Not installed |
| PHP CLI / FPM | 8.4.24-1~deb13u1 | Debian trixie package baseline; PHP 8.4 active support to 2026-11-21, security to 2028-11-21 | Not installed |
| Composer | 2.8.8-1+deb13u3 | Debian trixie package baseline; Composer 2 runtime API | Not installed |
| MariaDB | 11.8.6 (Debian 1:11.8.6-0+deb13u1) | Debian trixie maintained package; upstream release tag verified | Not installed |
| Nginx | 1.26.3-3+deb13u7 | Debian maintained security revision; upstream tag verified | Not installed |
| Browser sodium candidate | libsodium-wrappers-sumo 0.8.4 | Official npm metadata; binding must pass P01 before acceptance | Not installed |

Versions are assessment pins, not an application lockfile or claim of tested
integration. Before P03 installation resolve current security fixes, pin the
actual binaries/packages and transitive dependencies, and record justified
changes here. Debian package revisions use distribution maintenance rather than
an assumption that an older upstream Nginx minor is supported upstream. Native
sodium binding, canonicalization, WebAuthn and OAuth libraries await P01/P02;
do not choose them implicitly or write custom primitives.

### Supported OS candidates

| Platform | Candidate | Acceptance still needed |
| --- | --- | --- |
| Windows | Windows 11 24H2 or later, x64, current Evergreen WebView2 | Physical target/version capture; actual Hello/CNG key gating, DPAPI limits, file lifecycle |
| iPhone | iOS 18.x minimum candidate and current shipping iOS; installed PWA | Physical device/provider exact versions, 1 GB export/resume, PRF, OPFS, eviction, lifecycle |
| Server development | Debian 13 x64 | P03 actual Laravel/MariaDB/Nginx/PHP-FPM startup and integration |

These are test targets, not advertised supported platforms. Record exact OS,
WebView2/Safari, SDK/compiler/provider versions in P01 measured evidence.

### Scope and consequences

Freeze invite-only independent accounts, private/shared groups, threads,
versioned entries/checklists/attachments, owner/editor/reader, E2EE for titles,
bodies, filenames, tags, drafts, previews and retained versions. Keep routing,
authorization, length and accounting metadata visible. Limits are decimal
1,000,000,000 bytes/file and 100,000,000,000 committed encrypted bytes globally.

No universal server recovery key. Authentication, trusted devices and local
unlock are separate. Recovery requires an offline user-held kit. Concurrent
edits and revocation preserve unsynced work. Static app and API origins are
separate, with exact CORS, host-only API cookies and synchronizer CSRF.

No continuous iOS background-transfer guarantee, universal rollback/fork
detection, remote erasure, forward secrecy or immunity to a malicious PWA origin.
English/Russian interface localization is required; repository artifacts use
English. OCR, AI, federation, public signup and server previews remain deferred.

Security effects: preserve the specified endpoint/server trust boundaries and
all independent-review gates. Migration effects: none; no data or schema exists.
Tests: baseline artifact verification only at P00; native/browser/backend
interoperation and physical platform compatibility are assigned to later phases.

### Primary sources checked

- [Laravel release policy source](https://raw.githubusercontent.com/laravel/docs/13.x/releases.md)
- [Laravel framework package metadata](https://repo.packagist.org/p2/laravel/framework.json)
- [Node release index](https://nodejs.org/dist/index.json) and [support schedule](https://raw.githubusercontent.com/nodejs/Release/main/schedule.json)
- [Rust stable channel](https://static.rust-lang.org/dist/channel-rust-stable.toml)
- [Tauri crate](https://crates.io/api/v1/crates/tauri) and [official prerequisites source](https://raw.githubusercontent.com/tauri-apps/tauri-docs/v2/src/content/docs/start/prerequisites.mdx)
- [Tauri API](https://registry.npmjs.org/@tauri-apps/api/latest), [React](https://registry.npmjs.org/react/latest), [TypeScript](https://registry.npmjs.org/typescript/latest), [sodium JS](https://registry.npmjs.org/libsodium-wrappers-sumo/latest)
- [PHP support policy source](https://raw.githubusercontent.com/php/web-php/master/include/branches.inc)
- [Debian trixie package index](https://deb.debian.org/debian/dists/trixie/main/binary-amd64/Packages.xz)
- [MariaDB official source](https://github.com/MariaDB/server), [Nginx official source](https://github.com/nginx/nginx)

See `SOURCE_EVIDENCE.json` for fetched metadata hashes, selected observations and
Git tag SHAs. Direct documentation hosts were blocked; official source mirrors
were used. This is source research, not a dependency security audit.

## ADR-002 — P01 experimental bindings and runner

Date: 2026-10-10. Status: ACCEPTED for synthetic feasibility only.

Select maintained `libsodium-rs` 0.2.5 (official jedisct1 repository, Rust MSRV
1.88) with locked `libsodium-sys-stable` 1.24.0 and native libsodium 1.0.22.
Keep the default bundled signed sources; do not enable `fetch-latest` or replace
the upstream signature key. Select browser wrappers/core 0.8.4, which reports
libsodium 1.0.22, bundled with esbuild 0.28.2. Avoid the older sodiumoxide
binding and custom primitives. Cross-runtime tests are required before app use.

Rust 1.99.0 and Node 24.21.0 were installed with official artifact checksums.
The Node distribution includes npm **11.19.0**; this replaces ADR-001 npm 11.9.0
candidate. JS dependencies use exact versions, a core override, npm lockfile
and an explicit allowlist for the esbuild 0.28.2 install script.

Playwright Core 1.64.0 drives an actual host browser. Chromium keeps its sandbox
enabled. The cloud helper owner/user-namespace restrictions prevent startup;
hosted Ubuntu supplies a supported sandbox. Do not disable it or weaken the
container to fabricate browser success. Tests use local bundled sources only,
CSP with narrow WASM allowance and a loopback ciphertext-only test transport.

This selects no application canonicalization, authenticated pairing, key
wrapper or sender authorization. Sealed-box decryptability is not permission.
Physical Windows/iPhone and independent-review gates remain open. Migration:
none; this isolated experiment has only public fixtures and temporary data.

Primary metadata checked on this date: crates.io `libsodium-rs` /
`libsodium-sys-stable`, npm `libsodium-wrappers-sumo`, `playwright-core`, `esbuild`,
and the fetched official crate build source (Minisign verification retained).
Actual positive/negative results are tracked in TEST_EVIDENCE.md.

## ADR-003 — Reuse the measured Windows PRF/TPM design as a P01 reference

Date: 2026-10-10. Status: ACCEPTED as the next probe design; AnyNote adapter and
physical acceptance remain unimplemented/unverified.

The owner requested preservation and use of the passkeylocal Windows Hello
handoff. Exact working installer source `c18894e210a07546ba66cf178b8048ae5c40ac61`
and current handoff/source `15f54f00ab0e6de3016f3ad3c83ead53fdc93f9b` are retained
with licenses and integrity receipts in [the reference](reference/passkeylocal/README.md).
Upstream reports a working delivered password-vault flow; preserve that scope.
Its File Safe extension is useful for random-key mapping but is not physically
accepted by that observation. Embedded upstream briefs are reference content,
not new instructions or AnyNote evidence.

Choose the next isolated Windows probe around native WebAuthn PRF with fresh
UV, creation-time PRF evaluation and API 9+ routing, plus a separate verified
Platform KSP nonmigratable TPM RSA key. The TPM wraps synthetic local key L;
PRF-derived HKDF-SHA256/AES-256-GCM wraps that ciphertext. Windows/KSP/TBS and
the running native application are trusted. This is not remote attestation or
proof against an administrator/kernel attacker. Do not substitute DPAPI alone,
consent booleans, cached plaintext, signature hashes or silent software fallback.
DPAPI may be assessed separately and labeled with its lower user-context limits.

Use new AnyNote namespaces, bounded fixed IPC, real HWND, strict independent ABI
and authenticator-data fixtures, exact credential/key ownership, pre/post native
lock generations and durable cleanup. Recover random L rather than the upstream
password-only KDBX credential component. Preserve independent recovery and verify
the actual local encrypted vault before publishing an unlocked session. AnyNote's
production envelope/context and cross-platform policy still await P01/P02;
the upstream envelope is not its wire format.

No migration or production key-custody change occurs in this task. Reference
copies retain GPL-3.0-only and MIT-header notices; compatible source import and
release license choices must precede packaging. No Hello/TPM reset, policy changes
or repeated unchanged upstream owner diagnostics are required.

## ADR-004 — Bounded local-unlock and export feasibility adapters

Date: 2026-10-10. Status: ACCEPTED for isolated synthetic probes only.

Freeze the measured fallback vector profile as libsodium Argon2id13, 32-byte
output, 16-byte salt, opslimit 3, memlimit 67,108,864. Profile v1 rejects costs
outside opslimit 3–10 / 64–256 MiB before hashing. Use exact UTF-8 bytes including
NUL, with no hidden normalization or cheaper retry. A sole worker serializes
KDF work. Other application worker/process concurrency awaits production design.
Desktop latency is not a slow-iPhone cost selection or proof of phrase strength.

Port selected source from the preserved c18894e... installer into the separately
GPL-3.0-only Windows probe, retaining licenses and exact original/adapted source
hashes. Protect random L, use independent RP/domain/key/journal namespaces, and
remove serialization from the secret-bearing native reply. Reuse atomic/ACL/link
protections, native generated FFI and independently measured Microsoft-header
ABI. Portable doubles check lifecycle policy; hosted capability-only results
create no objects and cannot establish physical user verification/TPM evidence.
The rest of AnyNote's license and production release remain undecided.

Browser storage tests use ciphertext-only normal records. Origin quota failure
is injected in a separate context. Large selected-file export uses a fresh
disk-backed persistent profile; initial incognito/post-injection quota failure
is retained as failure evidence, not attributed to an iPhone. Never enlarge the
physical product limit or claim an estimate guarantees available space.

Explicit exports are the sole test plaintext-disk exception: stream one bounded
part into a writable sink, verify the full output, and remove owned test output
afterward. Prepare an existing verified OPFS disk File for a separate user-click
Web Share candidate; no concatenated full-file Blob or plaintext server. Shares
may background/lock crypto while finishing an already authorized explicit export.
A resolved share/canShare is not Files acceptance or a mobile memory measurement.
Marked orphan test exports have explicit cleanup; no secure-erasure claim.

P01/G1 remains open for physical Windows and at least two iPhones, tested Files
output and low-space/lifecycle/resume. The prepared harness has no production
auth, sender/recipient trust, signed manifest, durable key/transfer recovery or
remote deployment. Application key custody/contracts still await P02/P07.

## ADR-005 — Bound decoded responses and preserve explicit export evidence

Date: 2026-10-10. Status: ACCEPTED for the isolated P01 harness.

Content-Length may describe encoded bytes while fetch returns a decoded body.
Read selected-file ciphertext into a fixed expected-part buffer through the
response reader, enforce the decoded bound before copying, reject truncation,
then validate digest/tag. Never allocate an entire response before enforcing
its limit. A real padded gzip fixture tests correct encoded length with excess
decoded data; it must fail before plaintext writing.

Use actual Chromium OPFS transactional writers to test second-part corruption,
network truncation and lifecycle invalidation after a verified first write.
Abort must preserve the old committed test output for those pre-close failures.
Do not generalize to all OS sinks or rollback once an OS close/commit occurred.
Cleanup encloses marker creation and failed preparation; unsupported sharing
also removes its authorized temporary record. Reload tests prove loss of live
keys and selective removal of only correctly marked directories. No test
fault switch is exposed over HTTP/IPC; no production retry/resume is inferred.

Separate selected-file upload from export/readback memory sampling. Record
baseline, observed aggregate peak/increment, duration, sample count and actual
cadence limitations. The timer interval is only requested; final samplers also
report longest observed gap. Shared-page double counting, irregular samples,
retained browser processes and missed peaks prevent an iPhone budget claim.

Prepare content-free Windows capture only after verifying the exact native EXE
hash and embedded source. Hosted execution remains labeled hosted. Physical
trials require the owner's devices and a ready private trusted HTTPS origin;
manual CA trust provisioning is an optional owner action, not a TLS bypass or
cloud deployment. Retain the existing device strings without repeatedly asking.
No protocol, release scope, migration or key-custody change occurs here.

## ADR-006 — one EXE and a static ZIP for owner trials

Date: 2026-10-10. Status: ACCEPTED for isolated P01 test tooling.

Owner instruction replaces multi-command physical setup with a self-contained
Windows EXE and a ready-to-upload iPhone ZIP. Reuse the native Hello adapter
without changing reference imports; statically link the MSVC CRT and compute
executable hash at runtime. Capabilities gate actual native operations; fresh
processes, explicit cancel/lock instructions, original native codes and durable
exact cleanup remain intact. One report replaces separate collector records.

The iPhone ZIP works under any HTTPS subdirectory using relative bundled
assets, scoped manifest/static-only service-worker cache and worker synchronous
OPFS access. An exclusive Web Lock protects marked orphan cleanup. Its
transport is a bounded local ciphertext adapter, deliberately labeled in all
reports; this avoids introducing unauthenticated upload endpoints or requiring
a Node/PHP server for the requested simple kit. It does not certify network
transfers, account/session/recipient protocols or production resume.

One button starts all automatic checks and then advances through Files and
report steps. Separate taps and OS choices are required by transient user
activation and actual Files output selection; no hidden permission bypass or
1 GB plaintext Blob fallback is added. Disk staging publishes a verified
in-memory file alias, not a claim about atomic production path replacement.
Physical acceptance stays false; host mocks, public KDF heap measurements and
selected-output hashes retain their exact scope. Test artifacts may be
published as an unsigned GitHub prerelease with exact corresponding source,
asset receipts and scoped licenses; this is not production release/deployment.

ADR-006 publication transport addendum: the cloud's injected GitHub credential
received HTTP 401 at uploads.github.com after successful repository API/merge
actions. Use a workflow_dispatch-only publication job with contents:write and
actions:read instead of requesting an owner's secret or retrying unchanged
credentials. Publish only frozen already successful synthetic artifacts;
revalidate source/runtime/hash/ZIP receipts and downloaded release bytes.
Refuse existing-release overwrite and preserve the exact build-source tag.

ADR-006 owner-feedback addendum (0.1.1): native capability route availability
is admission to an experiment, not security eligibility. Keep the upstream
`eligible=false` and all per-key checks; validate the complete content-free
capability observation before starting owned native enrollment. Persist only
small synthetic diagnostic JSON in path-scoped browser storage, with synchronous
write/readback before Share to retain real transient user activation. Restore
diagnostics and expected synthetic output digests, never live crypto keys or
file handles. Interrupted system handoff stays UNKNOWN; actual selected bytes
must independently match. Bounded verified storage failure blocks handoff/new
trials. Recovery cleanup requires an exclusive Web Lock and exact purpose marker.
Use a new static subdirectory when replacing an old installed kit to avoid its
service-worker cache without clearing retained site evidence. No production
unlocked/transfer resume or physical durability guarantee follows.

ADR-006 second owner-feedback addendum (0.1.2): distinguish Windows OS sign-in
from the cancelled old test authorization. STALE can also mean timeout/close/
suspend and alone is insufficient evidence for a session-lock PASS. Record
content-free WTS and owned-window events in each fresh subprocess; require an
observed WTS lock plus failed STALE unlock. Keep owner-confirmed earlier results
separate from new instrumentation. Native cancellation/security imports stay
unchanged; no automatic system locking, policy changes or Hello reset is added.

Treat wrong selected Files bytes as a retryable diagnostic failure. Show .bin
sample versus .json log explicitly and retain source checks/digest. Record sizes,
not selected personal names. Permit recovery from the single documented sibling
0.1.1 diagnostic key on the same origin/storage; preserve that original key,
never enumerate arbitrary application storage or restore keys/handles. Safari
and installed-PWA results remain distinct; private origin is redacted before
archiving an owner-supplied report. No protocol/dependency/version-resolution
change or broader physical acceptance follows.

ADR-006 third owner-feedback addendum (0.1.3): avoid the reported physical
1 GB Share restart by default. Stream only a marked exact-size synthetic output
via a single-use five-minute random capability in this kit's SW scope. Validate
client/owner/name/marker/size, reject ranges/replay/arbitrary paths, never cache
exports, and hold the exclusive kit lock through stream completion/cancellation.
No vault keys, generic filesystem or production plaintext route. Retain only
nonsecret generated metadata; recovery rechecks the disk hash without keys
and preserves other site data. Real WebKit/Files/memory acceptance stays OPEN.

Replace the failed keyboard trial with an explicitly selected, disclosed
one-shot OS lock request. Arm only unlock-lock-trial while unlock is pending;
remove its timer on completion/close, never retry automatically. Record OS
accepted/denied/not-requested separately. Only WTS lock plus STALE is a lock
PASS; prompt timing still needs owner observation. No Hello/TPM reset or
policy change, production deployment or crypto change.

ADR-006 0.1.4 lifecycle correction: an in-memory SW ticket registry cannot
guarantee that a prepared attachment remains available after the browser stops
that worker. Persist only generated synthetic ticket metadata in a dedicated
path-scoped IndexedDB table. Issue prunes expired/same-client records and caps
retained tickets at 64; consume atomically removes before use. Keep five-minute
expiry, strict synthetic owner/name/marker checks and no runtime export cache.
Test actual SW termination before consuming the prepared URL, not a JS mock.
This does not resume an interrupted stream or guarantee background survival.

ADR-006 owner 0.1.4 evidence addendum (2026-10-11): archive the new owner
Windows report byte for byte and redact only the phone's private origin, with
original upload SHA-256 values and source/release verification in a receipt.
Classify the actual WTS lock plus failed STALE operation as the instrumented
lock result, and the installed-PWA selected 1 GB SHA-256 match as saved-output
byte evidence. Recovery records confirm diagnostics and key-free synthetic
export reopening, not resumed unlocked state. Do not infer a restart cause,
Files folder provenance, prompt visibility at lock, memory bound or complete
G1 acceptance. Preserve earlier failed/limited runs; successful narrow owner
results do not require another whole trial or an application change. P03 tooling
can proceed independently while remaining platform and review gates stay open.

## ADR-007 — containerized P03 foundation without provisional product contracts

Date: 2026-10-11. Status: ACCEPTED for synthetic developer tooling only.

Use the available Docker daemon rather than installing host/system services.
Primary upstream sources supersede P00 candidates with PHP 8.4.26 security
release, Composer 2.10.3, MariaDB 11.8.9 LTS and stable Nginx 1.30.5. Preserve
verified official image manifest digests and exact Composer lock; Laravel stays
13.35.0. Pin selected signed Debian compiler libraries, retain HTTPS/package
verification and document that indirect OS packages are repository-resolved.
Cloud builds reuse the provided proxy/trust anchor in an ignored local image
copy; do not disable verification or change host trust. Docker builder state
uses a writable owned path; no existing credentials are copied or replaced.

Create only the needed apps/api and infra/dev areas. Omit default users/auth/
password recovery/migrations/UI/Tinker and product OpenAPI/generated types until
P02 authoritative contracts exist. A local/testing-only readiness route reads
MariaDB; a CLI temporary InnoDB table proves commit/rollback/cleanup. Both refuse
production environment. APP_KEY is a generated framework key, never content
encryption. Composer proprietary describes absent redistribution permission,
not an owner decision on the future release license; upstream notices remain.

Expose only a loopback Nginx port; DB/FPM have no host port. Static and API hosts
route separately; FPM cannot mount/write the static source. Use non-root FPM/
Nginx, dropped capabilities, owned marked runtime state and generated disposable
credentials excluded from Git/evidence. Stop only this checkout's project and
preserve its volume; no global prune or automatic product migration. Disable
content logging; actual production logging/request-ID/error contracts remain
pending. No public exposure, production deployment or physical gate change.

Use the checksum-verified upstream Gitleaks CLI against all Git-visible current
source. Review the 12 generic-key false positives as upstream file SHA-256 entries;
allow only that rule/file/checksum shape; the three new source-receipt checksum
false positives use the same bounded policy in the generated evidence files.
A global path allowlist was rejected
when its negative case skipped the file; the final rule-scoped AND allowlist
must reject fake PATs normally and at both allowlisted receipt paths. No all-history
scan/audit claim follows. Frozen-lock inventory drift and meaningful real DB/
HTTP/outage/production-denial tests run locally and in a fresh hosted checkout.
P03 tooling can be verified while contracts remain incomplete; P02 key/file
contract is the next bounded task, with qualified review and P01/G1 still open.

## ADR-008 — bounded candidate file/checkpoint byte contract before product use

Date: 2026-10-11. Status: ACCEPTED for candidate synthetic evaluation only.

Use the explicit p02-file-c1 marker, closed JSON Schema 2020-12 definitions and
additional codec predicates. Primary metadata/source/license checks select
canonicalize 5.1.0 Apache-2.0, Microsoft jsonc-parser 3.3.1 MIT and Ajv 8.20.0
MIT in an isolated private Node reference package. Preserve exact lock/integrity/
license inventory; no GPL native adapter import. Do not hand-write JCS or crypto.
Raw bytes/visitor rejection precede JSON.parse/JCS: duplicates, bad syntax/UTF-8/
Unicode/nonfinite values fail; schema counters are bounded decimal strings.
Do not normalize Unicode or accept unsigned routing/key-wrap overrides.

Follow specification manifest-only file-data-key delivery: independent manifest
and file-data keys, group epoch wraps manifest key, data key stays encrypted.
Context binds pinned author/root/generation/roster, policy/epoch, previous history
checkpoint and parent envelope digests. AAD precedes its own ciphertext hashes;
manifest AAD can include already-produced chunk inventory; sign header last.
Wrap digest includes full canonical nonce/context/ciphertext, not a mutable ID.
Domain strings end in byte 00; candidate nonce uses 16-byte random prefix and
uint64 little-endian bounded chunk index. Changed source/context/epoch creates
new version/keys; no rewrap-as-revocation claim.

Choose complete sorted paginated checkpoint inventory, not unspecified Merkle
proofs. Fixed binary domain/count/index/byte-length/page-digest framing provides
noncircular commitment. Full parent closure includes compact evidence after
payload pruning; reject missing/wrong/cyclic ancestry. Descriptor references
predecessor only. Future transition intent/commit binds immutable descriptor and
distribution digests. Signer role, witness completeness, trusted predecessor and
policy/roster/recipient authentication remain required unimplemented layers; a
reader cannot certify unanchored history. No server-only freshness/time guarantee.
Candidate caps need mobile measurement/review before production freeze.

Known fixture key/signature/ciphertext bytes are serialization placeholders, not
valid cryptographic vectors. Independent restricted Python fixture comparison
and RFC expected bytes distinguish drift checks from actual interoperability.
Gitleaks also decodes expected-byte encodings; allow only two exact known public
values under that one fixture path/generic rule. Whole paths, partial keys and
blanket hash/entropy rules are not allowed; fake PAT and changed field negatives
must fail. Source/schema/lock bytes are untouched by frozen setup.

This bounded candidate changes no production trust/key custody, migration or
endpoint. Other protocol schemas, root HKDF/kit/pairing/recipient constructions
and qualified review remain open. Full G2/R01/R14/R19 acceptance is not claimed.
See protocol-v1.md and evidence/p02-primary-sources.json for checked references.

## ADR-009 — larger candidate root/certificate/recipient crypto batch

Date: 2026-10-11. Status: ACCEPTED for public synthetic evaluation only.

The owner requests larger batches. Combine root HKDF/kit/identity, provisional
certificate signatures, signed sealed recipient contexts/coverage and a linked
small-file cryptographic path, preserving p02-file-c1 and original specification
bytes. Separate new p02-identity-c1 marker/schema/registry from earlier file
candidate. Node maintained HKDF-SHA256 uses exact SHA256 domain/context salt and
distinct info labels; sodium seed-keypair APIs keep signing/recovery keys separate.
New device identities use independent random keypair calls, not root derivation.
Select @scure/base 2.4.0 MIT Bech32m HRP anr/version byte 01 + random 32-byte R;
strict lowercase bounded encoding, no phrase/PIN or error correction. Sodium
wrappers/core 0.8.4 ISC are locked/overridden, existing primitive WASM 1.0.22.

Root fingerprint covers unsigned exact identity body; root signature has its
own purpose domain. Independent service/account/root pins are required, not
kit/server self-assertion. Certificates bind both device keys, generation,
predecessor, exact issuer-certificate digest, capabilities and transcript digest.
Private proof handles attest signature verification only and explicitly retain
NOT_EVALUATED authorization. No certificate, root signature, valid AEAD or
coverage result upgrades a session or proves current membership/roster authority.
Authenticated pairing, activation/possession, delegate revocation/descendant
closure, reset/CAS and group policy/epoch transactions remain subsequent gates.
Do not expose candidate references as a product enrollment/recovery API.

Sealed inner context binds exact sender and device/account-recovery recipient,
key fingerprint, membership/roster/epoch/operation; outer signature authenticates
whole context/ciphertext. Require matching trusted expected contexts and exact
coverage with unique recipient IDs and one transition base. Derive expected
recipients from authenticated current state in later product work; no SQL array,
administrator recipient, reader writer privilege or global freshness assertion.
Random sealed boxes are frozen as public inputs; never seed/patch global RNG.
Deterministic derivation/signatures/file bytes and real random creation checks
are distinct. The file evaluator is 64 KiB-capped; 79-byte fixture follows full
manifest-only key path for separate device/recovery recipients without uploader
DEK input. It is not a 1 GB product, mobile-memory or complete R01 verdict.

Independent pinned PHP 8.4.26/native sodium 1.0.18 reproduces public HKDF/keys/
signatures/sealed/AEAD and restricted ASCII-key/string fixture serialization.
Its handwritten fixture serializer is not a production JCS/parser/schema API;
Rust/browser/general PHP contract interoperability remains pending. Package
metadata/license/SRI and upstream docs are checked; library review at old
versions/self-review does not establish review of 2.4.0 or this protocol. No
qualified reviewer booked/performed. JS/WASM/GC secret erasure remains best
effort, ephemeral root/kit material never belongs on the server/everyday clients.

Review 16 scanner false positives as ten complete known PUBLIC TEST fixture
fields, allowing only exact rule/path/value (including scanner-decoded full
expected fields). No arbitrary hashes, partial-value or whole-path suppression.
Five PAT-path and five changed-key/digest negatives must fail. Saved setup uses
frozen locks and crypto checks without fixture/source writes; owned P03 services
restart after snapshot. Normal revert has no production data/format migration,
site deployment, kit replacement or repeated owner action.

## ADR-010 — authenticated QR pairing and pinned device-state evaluation

Select existing locked libsodium secretstream with a fresh high-entropy one-use
32-byte authenticated QR/OOB key; no invented short-code cryptography or new
dependency. Single-message streams require TAG_FINAL and typed direction/anchor
AAD. Signed offer/response/invitation/approval/confirmation bind the full transcript.
Two QR modes let either new Windows or existing Windows display a code scanned
by a phone, avoiding a mandatory PC camera. Root/head import and actual owner
intent are explicit future ceremonies, not trust derived from the server. Primary
API receipt is evidence/p02-state-primary-sources.json; qualified composition
review remains NOT RUN. No forward secrecy or physical QR claim.

Separate pinned client history from live synthetic authority. Historical replay
checks signatures/head/capability ancestry, not today's expiry; live authority
checks monotonic trusted time, exact pending/session/challenge/receipt and CAS.
Only confirmed dual-key possession activates a device. Root-signed active cap
(default 5, bounded candidate 1–32) has no silent eviction/change on reset. Revoke
requires exact descendant closure by a surviving delegate; reset preserves root,
advances generation, revokes old sessions/pending, then upgrades the new device.
Same-root reset cannot recover a compromised root identity. No server receives R.

Ledger login/challenges/sessions/atomic mutations are SIMULATED in memory, never
P03 durable authentication or transaction evidence. New private state handles
attest current device authority from the supplied independent pins; group policy,
roles, epochs, full-history grants and historical writer acceptance remain
NOT_EVALUATED. Do not reinterpret old signature-only proofs or group-key knowledge
as writer access. Previous candidate bytes/locks remain unchanged. PHP only
reproduces public ASCII fixture signatures/possession/events/secretstream inputs,
not general strict schema/JCS/auth verification. Exact PUBLIC values alone are
scanner-excepted; six fake PAT path/eight changed key negatives must still reject.

## ADR-011 — pinned group policy, complete epochs and witnessed history

Add isolated p02-group-c1 without changing earlier schemas/vectors/locks. Signed
policy states distinguish owner/editor/reader and exact independently pinned
member roots/rosters. Full-history invitation acceptance stays pending until all
retained epoch/device/recovery grants finalize at exact heads. Removal/role loss
blocks access/writes immediately; mandatory reader roster maintenance cannot
change membership or certify history. Shared transfer co-signs the same body;
recent account authentication remains a required unimplemented product gate.

Select standard SHA-256 equality commitment over typed group scope and a CSPRNG
32-byte G to detect reuse across cancelled/excluded-recipient operations. Signed
intent precedes grants, descriptor and final commit; new grants reference intent
digest, not a recursive final digest. Greedy bounded pages have exact binary
ordered commitment/counts. Finalize checks all-head CAS/coverage before synchronous
mutation. This is client evaluation, not a durable SQL/session endpoint. Server
cannot verify encrypted key contents; recipient wrong-G unwrap requires repair.
No new dependency, entropy proof, forward secrecy or qualified-review claim.

Historical acceptance uses independently observed exact envelope/parent closure,
qualified current writer endorsement and sequence/head/operation-bound checkpoints.
An independent OOB pin may import a complete boundary for a new client; server
flags/timestamps alone cannot. Reader cannot endorse unknown history; new/recovered
clients without an independent boundary remain UNANCHORED_HISTORY for writes.
Old authorized signatures outside that known index remain quarantined. Simulation
is not an actual server commit or proof of global freshness. Full byte/key formulas,
limits, native PHP subset and remaining review questions are in P02_GROUP_CONTRACT.

Source scanner preserves upstream detection and uses only 31 complete known PUBLIC
fixture values plus one complete field and one complete exact PUBLIC scanner fragment
(random substring/chunk location heuristics); no arbitrary hashes/partial ciphertext/path exemption. Seven fake
PAT paths and twelve changed key/digest negatives and a full-fixture mutation must reject. Rollback: ordinary
revert, no production migrations/data. P02/G2 and physical/audit/product gates stay open.

## ADR-012 — complete P02 design profile and honest phase boundary

Freeze p02-v1 over unchanged file/identity/state c1 components and separate group
c2. c2 resolves the original default of twenty members, related-account proof
budget 200 and theoretical full retained-epoch coverage 660,000 grants, while
keeping aggregate reference bounds; it never silently upgrades c1 signatures.
Shared profile factories preserve legacy vectors and private WeakMap proofs.
Actual authenticated twenty-account / twenty-epoch / 800-grant pagination tests
exercise the greedy-byte-limit correction rather than only placeholder schemas.

Use locked libsodium XChaCha/Ed25519, Node maintained HKDF/AES-GCM and existing
native PHP sodium/OpenSSL for the new bounded references. Freeze exact note,
metadata/trash/local/outbox/sync/snapshot/restore/error/negotiation schemas,
contexts and typed domains. Native wrapper bytes explicitly require future
verified real provider/TPM/lock-generation admission; no platform boolean or
renderer's PRF bytes constitute a trusted unlock. Everyday records exclude R.

Select maintained Rust age 0.12.1/rage 0.12.1 and independent Go age 1.3.2, pinned
official release SHA-256 and inspected tagged licenses. Standard age v1 wraps
strict USTAR, selected DEKs, original ciphertext, complete source pages and all
cross-account public author/history evidence. Independently preserved kit and
signed footer/EOF/inventory precede live import. Generated opaque paths and
117,179,869,184 observed archive-byte cap permit 100 GB plus explicit bounded
framing; full product throughput/space/staging utility remains P13. No new
product npm/Composer/Cargo dependency or lock, invented crypto or GPL import.

Original P02 §5 requires review scheduled/tracked; production adapters, custody,
full utility and release review belong to P05/P07/P13/P17. Finish P02 design and
track qualified review as unassigned/unbooked/NOT_RUN rather than falsely
performing it or repeatedly deferring design completion behind later phases.
G2/G3 and security-sensitive production use remain blocked pending real review
and remediation. Reproducible subsets do not claim general cross-platform parser
or actual SQL/session/hardware acceptance. No reviewer outreach was performed.

Source scanner exceptions are only complete exact known PUBLIC fixture values,
including the intentionally published test age identity; encoded byte blocks
keep whole JSON values below decoded scanner chunk boundaries. Existing frozen
fragment exceptions stay unchanged; no new partial-field/hash/path suppression.
Changed-key/encoded-field, fake-token and alternate-age-key negatives still fail.
Rollback is a normal revert without production data/format migration. Frozen
setup reads/rechecks; deliberate writers never run in setup or Actions.

## ADR-013 — generated P03 foundation and a content-free request boundary

Generate initial OpenAPI 3.1 and shared TS/PHP transport types from unchanged P02
and a closed supplemental P03 schema. Explicitly mark future phase-owned paths
unimplemented and transport wrappers unavailable, rather than introducing dummy
authentication or generic payload acceptance. Input/output receipts bind schema,
predicate, registry, documentation and dependency changes; setup never generates.
Use a separate pinned TS 7.0.2/Ajv development lock without changing old locks.
PHP generated readonly primitives are not full nested/auth/crypto validation.

Use canonical P02 16-byte IDs for service/request correlation, never UUID/hex.
Common errors derive fixed mappings from generated authoritative metadata, conceal
unauthorized resources and strip framework exception diagnostics. Raw duplicate/
UTF-8/depth/size controls precede future DTO-specific acceptance. Nginx overflow
passes a trusted server-only marker and no request body to the PHP boundary so
ordinary and chunked 413s have valid IDs/errors. Exact CORS is not CSRF/auth.

One Monolog formatter discards arbitrary message/context/exception/extra fields
and retains only fixed public request metadata. Seven-day mode-0600 daily logs
are inspected after hostile body/query/cookie/token inputs; volume monitoring is
P16. No source-scanner exception is added; hash provenance uses path/hash records.
Production HTTPS rejects untrusted forwarded headers; real deployment/session
trust remains phase-owned. P03 exit concerns reproducible tooling, not product
login/SQL/crypto/hardware or qualified review. Roll back with a normal revert.

## ADR-014 — durable P04 authority and atomic publication

Use explicit query-builder writes/read-only domain DTOs rather than mass assignment.
Model threads/entries in a single typed routing table with immutable revisions,
FK scope constraints and SQL immutability triggers. MariaDB projections are the
honest-service current authority; they are never independent client crypto trust.
P08/P10 must verify signed transitions before updating them. Trusted sessions
have no public/test issuer in this phase, and bearer hashes/ownership are rechecked
under locks. Root/certificate public signatures and current state are distinct.

Serialize account/group/object/quota locks before acquiring the transactional
sync counter LAST; use no AUTO_INCREMENT transport watermark or external I/O
under product locks. Fixed global/group/stable-account accounting and the separate
inaccessible security reserve protect content limits. P12 adds physical-space/
durable-byte admission, P11 conflict/snapshot flows and P13 safe compaction.

Add maintained Opis 2.6.0 and Kanon 1.0.1 with frozen Composer records, preserving
all 99 existing records. Kanon is suitable only for the closed public ASCII/
short-integer subset here; its general ECMAScript float serialization is incomplete
and cannot become the P05 arbitrary-payload canonicalizer. Reuse locked native
sodium and browser Ajv/JCS/sodium for the P04-required P05 public-signature slice;
caller-validated native canonical bytes are not a full native JSON adapter.
Record the actual real-browser CI separately from the blocked cloud sandbox.

Disposable SQL tests own a separately marked database and may reset only that DB.
Install/setup never migrate a product DB, regenerate tracked bytes or resolve
locks. Actual maintenance services run non-root with no published ports and a
restart policy; fixed jobs and null failed-job storage preserve content-free logs.
Admin bootstrap promotes an existing identity through console coordination,
never creates content ownership; invitations persist one-way token hashes only.
No production rollout/reviewer booking or new physical trial is implied.

ADR-014 compatibility addendum: P02 freezes the original Composer lock checksum.
Preserve its entire bytes in docs/reference/p02/composer-p02.lock and keep the
registry unchanged. The explicit P04 compatibility receipt replaces only that
physical current-lock lookup, still requiring the original checksum, all 99
identical package records and precisely four named/versioned additions. Four
real tamper negatives (including recomputing the new current hash) reject an
altered baseline, changed existing record, new version or extra package. This
is an explicit backend dependency evolution, not relaxed general drift checking.

## ADR-015 — maintained P05 client core and independently supplied authority

Add a separate unpublished Rust core with its own exact Cargo lock/inventory;
preserve all old frozen inputs/locks. Maintain portable browser versions of the
frozen codec predicates with a read-only source-equivalence gate. Use existing
locked browser JCS/Ajv/sodium and native maintained RFC8785/JSON-schema/sodium/
RustCrypto libraries rather than invent primitives or extend PHP to plaintext.
RFC8785 independent IEEE754/Unicode expected bytes and frozen P02 frames are the
oracles, with actual two-way fresh ciphertexts and relevant PHP public signatures.

Require trusted context/issuer/recipient/checkpoint pins at crypto entry points.
Crypto-valid data does not become an evaluation handle, current SQL permission,
active roster or universally fresh history. Full inventory inclusion/ancestry
rejects freshly backdated signatures without independent witnessed evidence;
metadata timestamps alone do not. Maximum-size persisted history indexing is P11.

Make nonce/key ownership explicit: random fresh object/file keys, random local/
wrapper nonces and sequential owned file preparations. No exposed reencryption
index or caller-chosen encryption nonce. Changed-source durable version/resume
coordination remains P12; no plaintext or hardware/software eligibility fallback.
Enforce KDF bounds before allocation and one active native/worker job, then
measure actual desktop Worker/1 GB behavior. RAM/GC erasure, P07 generation
fencing and the P01 physical/mobile matrix retain their explicit limits. Ordinary
CI creates only synthetic owned resources and metadata artifacts, not a release,
production rollout, device trial or qualified review.
