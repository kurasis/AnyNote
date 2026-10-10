# Specification Review Findings and Change Log

Reviewed revision: **1.1.0**, 2026-10-10. Baseline: specification 1.0.0, 19 Markdown documents. Updated package: 21 Markdown documents plus checksum manifest. No application implementation is included.

## 1. Scope and interpretation

This review examined the full supplied specification for internal contradictions, incomplete key/data paths, authorization and recovery transitions, concurrency/durability errors, platform assumptions, quota/retention interactions and development handoff quality. Relevant component behavior was checked against primary references in file 16.

The issues below are **specification defects or gaps**, not demonstrated vulnerabilities in deployed software. Severity describes their potential impact if implemented literally. Corrections are incorporated into the authoritative chapters, not merely listed here. R01–R24 are required future regression tests; they have not been executed against an application.

## 2. Findings and corrections

| ID | Impact | Baseline weakness | Applied correction | Chapters / tests |
| --- | --- | --- | --- | --- |
| REV-01 | High: recovery failure | File chunks used a separate DEK without an explicit recipient delivery path | Encrypted manifest contains file-data DEK; independent manifest DEK wrapped by epoch; complete chain specified | 04, 10, 20 / R01 |
| REV-02 | High: recovery deadlock | New recovery device could need envelopes while untrusted API access denied them | Root challenge/reset activates new device atomically before authorized recovery-envelope fetch | 05, 08, 20 / R02 |
| REV-03 | High: silent sync loss | Monotonic event IDs did not define commit ordering | Transactional counter row locked last through commit; delayed earlier transaction cannot be skipped | 07, 09 / R03 |
| REV-04 | High: delivery boundary | Static/API isolation was inconsistent with a same-origin proxy and cookie examples | Separate controlled app/API origins, host-only session, synchronizer CSRF, exact CORS, API excluded from script sources | 02, 05, 11 / R04 |
| REV-05 | High: device impersonation | Login plus a declared device ID lacked explicit session-bound possession verification | One-use signed challenge required for trust upgrade and re-login | 05, 08, 20 / R05 |
| REV-06 | High: premature trust | Approval, active roster and new-device confirmation ordering were ambiguous | Provisional certificate; final possession confirmation commits activation; no keys before active state | 05, 20 / R06 |
| REV-07 | High: attacker persistence | Revoking a compromised delegator did not explicitly invalidate its descendants | Cascading descendant/session/pending-approval revocation; safe hardware gets new keys | 03–05, 20 / R07 |
| REV-08 | Medium: availability | Reader could lose its only device while required rekey depended on owner/editor availability | Narrow mandatory roster-only rekey permission for readers, with no write/membership privilege | 01, 04, 06, 20 / R08 |
| REV-09 | High: duplication/loss | Stable operation IDs conflicted with changed ciphertext after rekey or conflict | Separate draft ID and immutable attempt ID; reconcile ambiguous receipt before new attempt | 09, 20 / R09 |
| REV-10 | High: incomplete sync/export | Stable snapshot claim lacked materialization, pinning and cleanup-race semantics | Consistent inventory/watermark, scoped leases, coordinated GC pins, current authorization | 07–09, 17, 20 / R10 |
| REV-11 | High: orphaned user files | File commit and entry publication were treated as effectively one workflow | Explicit two-step journal, committed unattached recovery view, quota/retention and retry rules | 07, 08, 10, 20 / R11 |
| REV-12 | High: broken history | Three-file-version cap conflicted with retained note revisions referencing older files | Soft target; every retained strong reference protects bytes; visible retention reason | 07, 16, 20 / R12 |
| REV-13 | Medium: boundary failures | Exact-decimal cache/reservation defaults ignored encryption overhead | 1 GiB mobile cache, 2 GiB/account pending budget, exact tag arithmetic and physical-space checks | 07, 10, 16 / R13 |
| REV-14 | High: revoked-author forgery | Historical signatures lacked a sufficiently explicit closure contract | Bounded signed inventory, independent known-history checks, unanchored-history quarantine; readers cannot certify history | 04, 06, 20 / R14 |
| REV-15 | Medium: resource exhaustion | Byte quota alone left empty metadata, snapshots and transitions insufficiently bounded | Count/depth/page/concurrency caps and separate abuse budgets | 03, 08, 16 / R15 |
| REV-16 | High: local key risk | Local nonce lifecycle and KDF parameter semantics were underspecified | Fresh random local AEAD nonce; bound AAD; exact libsodium Argon2 profile and allocation bounds | 04, 16 / R16 |
| REV-17 | High: unsafe import | Streaming export authenticity completed late, but import staging rules were incomplete | Full footer/container/inventory verification before live import; encrypted staging and safe bounded archive parsing | 17 / R17 |
| REV-18 | High: auth handoff | Native code/refresh mechanism and browser-origin integration were too open-ended | Maintained OAuth code+PKCE flow, exact loopback policy, short single-use code, shared WebAuthn RP, no client secret | 05, 08 / R18 |
| REV-19 | High: context substitution | Some routing/attachment and mutable key-wrap references could escape explicit signature scope | Bind thread/context/attachment versions and immutable key-wrap digests; noncircular serialization order | 04, 08, 20 / R19 |
| REV-20 | Medium: platform races | Multi-window leadership and background during system sheets were missing | Transactional fencing, lock-generation checks, recoverable auth/file-sheet lifecycle | 09, 11 / R20 |
| REV-21 | Medium: unusable membership | Invite target acceptance and large grant activation had no complete pending lifecycle | Accepted pending grants, bounded staging, expected-head checks, atomic membership activation and unwrap repair | 06, 08, 20 / R21 |
| REV-22 | High: restored revoked access | New sync generation did not prevent old backups reviving revoked members/devices/passkeys | All restored sessions disabled; recovery-only quarantine and security-state reconciliation before release | 12, 20 / R22 |
| REV-23 | Medium: false guarantees | Maintenance reserve sounded sufficient even on physical disk failure | Finite bounded reserve, operational headroom, fail-closed writes and no false revocation success | 12, 16 / R23 |
| REV-24 | High: server exposure | Optional push registration did not explicitly prevent outbound SSRF | Provider/host allowlist, safe address resolution/revalidation, no unsafe redirects | 03, 16 / R24 |

Additional corrections: exact original file size is acknowledged as inferable from fixed unpadded chunks; an unfinished upload must restart with fresh keys after an epoch change; revocation does not authorize deleting unsynced drafts; archive permits security maintenance; private ownership migration remains explicit; encrypted payload truth cannot be checked by the server; API contracts include recovery challenges, invitation acceptance, staged grants, snapshots, receipts and unattached files. Sources, phase dependencies, C16/U17 coverage and the P16 capacity-test reference were synchronized.

## 3. Development plan changes

File 14 remains the standalone 19-phase P00–P18 plan. Tooling may start early, but schemas follow P02. P04 backend public-signature acceptance depends on P05 fixtures without making P05 depend on P04. P16 recovery testing requires recovery/export features. Review-derived slices and R01–R24 evidence are assigned to their owning phases. Design review is scheduled at P02; implementation review remains at P17.

File 20 centralizes transitions across chapters. It does not replace the byte-level schema/fixture work in P02. An implementation assistant must not invent incompatible shortcuts to close those gates, rename mocked behavior “verified”, or treat this document review as an independent cryptographic audit.

## 4. Remaining explicit engineering gates

- Real iPhone 1 GB download/decrypt/save and interrupted transfer behavior need physical-device evidence. Browser storage/background execution cannot be guaranteed by design prose.
- Pairing construction, checkpoint encoding, root/roster/epoch composition and exact library bindings require frozen fixtures and qualified independent review.
- A compromised PWA delivery origin can send malicious client code. The independently packaged Windows client reduces that specific delivery exposure but is not immune to endpoint/build compromise.
- Recovery history preserves old decryption capability; v1 is not a forward-secret messenger. Revocation cannot erase already received keys/copies.
- Malicious-server freshness/fork detection is bounded by available trusted checkpoints; no independent global transparency service is promised.
- Very slow whole-corpus exports may exceed bounded snapshot leases; smaller exports or a measured future extension are needed.
- Server recovery must reconcile newer security state. Where trustworthy state is unavailable, explicit quarantined recovery is required instead of silently restoring old access.

These are documented acceptance gates or inherent limitations, not hidden claims of completed work. No product code, physical-device benchmark, penetration test or professional cryptographic audit was run in this review.

## 5. Packaging validation

Before delivery, validate UTF-8 Markdown, internal links, source IDs, phase/test references, code-fence closure, uniqueness of numbered documents, exact 1 GB/chunk/tag arithmetic, SHA-256 manifest entries and ZIP CRC. These checks establish document/package consistency only. The final archive and manifest are the reviewed deliverable; development evidence remains to be produced through file 14.
