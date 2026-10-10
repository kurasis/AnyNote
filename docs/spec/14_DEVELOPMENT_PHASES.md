# Development Phases — Execution Plan for a Coding Chatbot

## 1. How to execute this plan

Implement one bounded task or phase at a time. Do not attempt the entire application in one uncontrolled change. This document is a standalone implementation roadmap; the other Markdown files define the requirements. A phase is complete only when its deliverables and exit criteria are evidenced. UI mockups, scaffolded endpoints, TODO comments, and mocked cryptography do not satisfy feature acceptance.

Use the status vocabulary NOT STARTED, IN PROGRESS, IMPLEMENTED / UNVERIFIED, BLOCKED, VERIFIED. Track phase status and test evidence in docs/PROGRESS.md. Maintain docs/DECISIONS.md, docs/KNOWN_LIMITATIONS.md, docs/TEST_EVIDENCE.md, and docs/NEXT_TASK.md. No application or test execution has been performed by the specification author.

Read files 00–06, 19 and 20 before coding, then the referenced detailed files for the current task. Inspect the existing repository and applicable instructions before making changes. Preserve existing work. Make small reviewable commits where a repository is available; do not publish/deploy or overwrite live data merely because a phase describes deployment.

## 2. Critical-path overview

| Phase | Goal | Depends on | Primary gate |
| --- | --- | --- | --- |
| P00 | Repository assessment, scope, supported versions | None | G0 foundation |
| P01 | Windows/iPhone feasibility experiments | P00 | G1 platform feasibility |
| P02 | Threat model and protocol freeze | P00; P01 findings | G2 design prerequisites |
| P03 | Monorepo, contracts, CI, synthetic environment | P00; final contracts require P02 | Reproducible tooling |
| P04 | Backend schema and authorization foundation | P02, P03; signature acceptance requires P05 fixtures | Isolation and transactions |
| P05 | Cross-platform cryptographic core | P01, P02, P03 | Interoperability |
| P06 | Account login and native session handoff | P04 | Auth correctness |
| P07 | Local encrypted vault and lock lifecycle | P05, P06 | No persistent plaintext |
| P08 | Device enrollment and account recovery | P05–P07 | Trust and recovery |
| P09 | Private groups and encrypted notes | P04, P07, P08 | First E2EE vertical slice |
| P10 | Shared groups, roles, signed membership | P09 | Collaboration integrity |
| P11 | Incremental sync, conflicts, offline behavior | P09, P10 | Durability/convergence |
| P12 | Large-file protocol and quota accounting | P04, P05, P10, P11 | Correct 1 GB transfers |
| P13 | Search, previews, history, retention, exports | P11, P12 | Safe complete content UX |
| P14 | Windows application completion | P07–P13 | Native platform acceptance |
| P15 | iOS PWA completion | P01, P07–P13 | Physical iPhone acceptance |
| P16 | Production deployment and backup/restore | P04, P08, P11–P13 | G5 recoverability |
| P17 | Adversarial testing and independent review | P02, P08–P16 | G2/G3 security release |
| P18 | Release packaging, acceptance, handoff | P14–P17 | G4/G6 release |

P03 tooling may begin after P00; contract completion follows P02. P04 schema/transaction work and P05 crypto adapters may progress together: P05 has no P04 dependency, and P04 signature-verification acceptance is completed against P05 fixtures. The numbering is a roadmap, not permission to bypass this dependency. P16 restore testing also requires the P08 recovery flow and P13 offline export tools.

Independent work can proceed when a physical device or external credential is unavailable, but dependent gates stay explicitly unverified. For example, backend isolation tests can progress while iPhone export testing is blocked; the product cannot be declared iOS-complete.

## 3. P00 — Assessment and locked scope

**Read:** 00, 01, 02, 16.

**Tasks:** Inspect repository structure and existing instructions. Record what already exists, languages, package managers, lockfiles, build/test commands, and any uncommitted work. Freeze accepted scope: invite-only, personal/shared groups, 1,000,000,000-byte files, 100,000,000,000-byte global committed quota, WebView2 Windows client, iOS PWA, Laravel/MariaDB/Nginx/PHP-FPM. Select maintained exact versions and supported OS candidates from current primary sources. Create compatibility and dependency/license inventories.

**Deliverables:** Repository assessment, ADR-001 stack/version matrix, requirements checklist, initial risk register, and progress files.

**Exit:** A fresh developer can identify required tools and reproduce the documented baseline. No silent stack substitution or optional-feature expansion.

**Next task prompt:** “Implement P00 only. Inspect before editing, record exact environment facts, and create the implementation tracking documents. Do not build the application yet.”

## 4. P01 — Feasibility experiments before UI investment

**Read:** 04, 05, 10, 11, 13.

**Tasks:** Build isolated synthetic experiments for native/browser libsodium interoperability, bounded chunk processing, Windows key wrapping/Hello, passkey login/PRF capability, and iPhone PWA storage/export. Test a real 1 GB incompressible file end-to-end through encryption, upload, download, decryption, and save to Files. Force backgrounding, termination, low space, network interruption, and source reselect. Measure memory and report actual device/OS/provider versions.

**Deliverables:** Reproducible experiments, measured platform report, proposed minimum platform matrix, and ADRs for crypto bindings/local wrappers/mobile export pipeline.

**Exit:** No major unsupported assumption remains hidden. If physical testing is unavailable, mark it BLOCKED and isolate the uncertainty; do not replace it with desktop WebKit results. If iOS cannot meet the agreed path, prepare concrete options for owner decision before claiming that scope supported.

**Next task prompt:** “Execute P01 using synthetic files only. Prioritize the complete iPhone 1 GB export path and actual Windows key gating. Report evidence and unresolved platform restrictions; do not hide a failed gate behind a lower limit.”

## 5. P02 — Protocol specification and reviewable security design

**Read:** 03–06, 08–10, 19, 20.

**Tasks:** Freeze key hierarchy, account-root/recovery derivation, roster/delegation rules, authenticated pairing construction, group policy/epoch transitions, recipient-envelope authorization, file nonce profile, and signature canonicalization. Define exact JSON/binary schemas, domain separation, bounds, version negotiation, and error cases. Specify state transitions including concurrent revoke/enroll/rekey and restored-server checkpoints. Select an established pairing/channel construction; do not improvise a six-digit-password protocol.

**Deliverables:** docs/protocol-v1.md, schema registry, transcript diagrams where useful, public known-answer vectors, review checklist, and candidate-review findings.

**Exit:** An independent implementer can produce byte-identical outputs and validate authorization decisions. Qualified review is scheduled/tracked; security-sensitive production use remains gated until review/remediation, even if synthetic implementation proceeds.

**Next task prompt:** “Complete P02 as a precise protocol contract. Resolve each ambiguous signed field and trust transition, create deterministic fixtures, and list assumptions requiring external review. Do not claim an audit.”

## 6. P03 — Repository and development foundation

**Read:** 02, 08, 13, 15.

**Tasks:** Create/adapt the monorepo, shared types, lint/typecheck configuration, formatting, dependency lockfiles, reproducible local MariaDB/API environment, synthetic fixtures, and CI jobs. Produce an initial OpenAPI contract and generated types from authoritative schemas. Establish secret scanning and prevent production values in fixtures. Add common structured errors, request IDs, and content-free logging.

**Deliverables:** Fresh-clone setup, one-command targeted checks where appropriate, CI definition, schema validation, and contract-drift tests.

**Exit:** A clean environment runs the relevant checks. No insecure dummy auth/crypto is reachable in a production build. Keep experiments separated from production code.

## 7. P04 — Backend model, policy, and transactional foundation

**Read:** 06–08, 12.

**Tasks:** Implement migrations/entities/indexes, account/group scoped repositories, strict request validation, public-signature verification, immutable revisions, quota ledgers, mutation receipts, and sync-event transactions. Build admin bootstrap/invite scaffolding without implicit content ownership. Test authorization with at least three accounts and cross-group IDs. Add protected health/readiness endpoints and supervised queue/scheduler setup.

**Deliverables:** Migrations, policy tests, concurrency tests, object/ledger service contracts, and OpenAPI updates.

**Exit:** Backend rejects forged/wrong-scope operations and recovers transactionally from failed mutations. Database inspection finds no content-title/body/filename columns intended for plaintext storage.

## 8. P05 — Cryptographic core and interoperation

**Read:** 04, P02 frozen contract, 13.

**Tasks:** Implement library adapters, canonicalization, signing/verification, AEAD, key envelopes, local wrappers, manifest handling, and strict decoders. Use deterministic public vectors for tests; CSPRNG in real operation. Add negative fixtures for incorrect AAD, sender, epoch, length, JSON ambiguity, invalid keys, and nonce-reuse attempts. Exercise Rust->browser and browser->Rust with PHP verifying relevant public signatures.

**Deliverables:** Native/browser crypto modules, shared fixture corpus, versioned codecs, typed errors, and performance measurements.

**Exit:** C01–C04/C07/C08/C10/C16 pass. No hand-written primitive, base64-as-encryption placeholder, fallback plaintext, or catch-and-ignore integrity failure. Memory/worker behavior meets measured feasibility decisions.

## 9. P06 — Account authentication and session lifecycle

**Read:** 05, 08, 11.

**Tasks:** Implement invite consumption, WebAuthn registration/assertion, multiple passkeys, PWA session+CSRF, native browser handoff with state/PKCE, refresh rotation/reuse detection, logout/session list, and authentication recovery codes. Keep content decryption unavailable to authenticated-but-untrusted devices. Add recent-auth checks and rate limits.

**Deliverables:** Login/account security UI, auth API, native-session adapter, and attack tests.

**Exit:** Forged origin, reused challenge, invalid callback, CSRF, stolen old refresh, expired invitation, and enumeration tests behave correctly. Passkey login is not falsely described as content-key recovery.

## 10. P07 — Encrypted local persistence and lock boundary

**Read:** 04, 05, 07, 09, 11.

**Tasks:** Implement L, encrypted device vault, local durable outbox, cache transactions, unlock wrappers, lock generation/capabilities, and suspend/background transitions. Build a minimal locked/unlocked shell. Persist drafts before lifecycle transitions; limit plaintext lifetimes without promising perfect erasure. Validate Windows wrappers and PWA fallback/PRF behavior against P01 choices.

**Deliverables:** Local schema/migrations, storage adapters, encrypted-state inspector tests, and lock/unlock integration tests.

**Exit:** Restart recovers ciphertext safely; IPC cannot bypass native lock; no plaintext index/outbox/WAL fields or logged keys. A lost browser origin triggers enrollment/recovery, not an unrecoverable exception loop.

## 11. P08 — Trusted devices and recovery

**Read:** 04–06, 08, 13.

**Tasks:** Implement root bootstrap, recovery kit generation/verification, account roster chain, both QR directions, authenticated manual fallback if included, single-use approval, independent device keys, same-account key distribution, device revoke, root-signed recovery reset, and security notifications. Use a hostile relay harness to mutate messages/keys.

**Deliverables:** Enrollment/recovery UI, signed lifecycle records, recovery instructions, and fresh-client recovery traces.

**Exit:** C05/C06/C11/C13 pass. New device root trust is not sourced solely from the API. Recovery requires separate server access plus offline secret. Administrator reset cannot decrypt content. Old-generation device sessions/authorizations are rejected.

## 12. P09 — First complete private-note vertical slice

**Read:** 01, 04, 07–09.

**Tasks:** Create private groups, encrypted group/thread titles, entries, basic Markdown/checklists, encrypted account preferences, and local-save/server-save states. Publish only real E2EE payloads. Render through safe components. Validate a note created on Windows can be read by an enrolled PWA client and vice versa.

**Deliverables:** Usable private vault with a small real UI, server persistence, cross-device flow, and leakage inspection.

**Exit:** End-to-end note path works with API unable to decrypt. Private account isolation and no-title/body/log leakage tests pass. No file-transfer complexity is needed to demonstrate this vertical slice.

## 13. P10 — Shared groups and membership integrity

**Read:** 01, 03–06, 08.

**Tasks:** Implement owner/editor/reader, verified account invitation, full-history/key delivery, owner transfer, signed role changes, membership removal, same-account device distribution, and rekey-required state. Enforce historical-author vs current-writer distinctions. Provide private->shared copy with audience preview and fresh encryption.

**Deliverables:** Membership UI, signed policy/epoch services, multi-account traces, and malicious-reader tests.

**Exit:** F03–F10/C09/C12 pass. Removed recipients receive no future epoch grants. A reader with group keys cannot forge a permitted write. Rekey races fail safely and show actionable read-only state.

## 14. P11 — Synchronization, offline edits, and conflicts

**Read:** 07–09, 13.

**Tasks:** Implement cursor feed, stable full snapshots, pagination, encrypted outbox retry, idempotency, concurrency controls, conflict branches/resolution, tombstones, reconnect/backoff, stale-policy refresh, and safe revoked-draft preservation. Integrate checkpoint regression detection and restored-server transport generation.

**Deliverables:** Sync engine, conflict UI, lifecycle state diagrams, fault-injection harness, and large-list fixtures.

**Exit:** S01–S12 pass for supported platforms. No lost edits, silent cursor skipping, silent resurrection, or last-write-wins note-body data loss. Full resync preserves unsent work.

## 15. P12 — Encrypted large files and quota correctness

**Read:** 04, 07, 08, 10, 13.

**Tasks:** Implement source/sink adapters, immutable upload sessions, ciphertext chunking, manifests, reservations, bounded streaming, commit/cleanup state machine, server-side authorized ciphertext download, resume/reselect verification, and actual-byte accounting. Integrate pending attachments with note revisions and current policy/epoch checks. Test 1 GB and all chunk boundaries with incompressible data.

**Deliverables:** Transfer manager, quota/storage UI, private blob store adapter, cleanup jobs, and crash/concurrency evidence.

**Exit:** U01–U10/U13–U17 pass; physical iPhone U11/U12 are exercised here and finalized in P15. No giant plaintext buffer, nonce reuse, cross-group file reference, partial-visible file, or double-counted quota.

## 16. P13 — Search, safe previews, history, and exports

**Read:** 01, 07, 09, 10, 13, 17.

**Tasks:** Implement encrypted local search, corpus coverage UI, safe Markdown/PDF/image/text previews, encrypted thumbnails, version compare/restore, trash, retention with reference safety, favorites/read markers, encrypted portable export/import, and explicit plaintext export. Portable export must include documented manifest/key envelopes/history needed to recover selected data independently; import validates formats and generates appropriate destination IDs/keys.

**Deliverables:** Complete content UX, retention jobs, export format documentation and clean-import tests.

**Exit:** Search/index leakage, unsafe content, dangling retained-file references, export/import, and deletion tests pass. Whole-vault export runs on Windows as a streaming job; do not require iPhone to export the entire 100 GB archive.

## 17. P14 — Windows release-quality client

**Read:** 11, 13.

**Tasks:** Complete three-pane UX, keyboard accessibility, local storage migration, system-browser auth, native file dialogs/transfers, lock/suspend, device management, content-free diagnostics, signed updater integration, and installer behavior. Minimize Tauri permissions/window scopes and harden navigation/IPC. Test on actual Windows with supported WebView2.

**Deliverables:** Windows release candidate, capability audit, installer/update test report, and exact signing requirements.

**Exit:** Native platform tests, 1 GB workflows, update tampering, and encrypted local state survive install/update/restart. Missing production signing credentials are recorded; no fabricated signed artifact claim.

## 18. P15 — iPhone PWA release-quality client

**Read:** 10, 11, 13.

**Tasks:** Complete responsive UI, install guidance, worker pipeline, storage estimates/persistence, lock/background behavior, neutral push, safe service-worker update, and full 1 GB export path proven in P01. Re-run with all production data flows and crypto, not just the initial isolated experiment. Test selected minimum and current real-device targets.

**Deliverables:** PWA release candidate, physical-device evidence, compatibility matrix, and user-facing limitation text.

**Exit:** U11/U12 plus storage/PRF/update tests pass. Any failure is a release blocker for the advertised feature, not an excuse to add server decryption. If platform constraints require a scope decision, present tested options to the owner and continue independent work.

## 19. P16 — Deployment, backup, and recovery operations

**Read:** 12, 13.

**Tasks:** Prepare production templates, runtime permissions, static/API separation, protected admin path, Nginx/PHP limits, scheduler/queue supervision, monitoring, secret injection, and consistent backup. Perform clean-host restore with a clean client and offline recovery kit using synthetic accounts. Validate DB/blob consistency, revoked sessions, sync-generation reset, and physical capacity reserves.

**Deliverables:** Operator runbook, reproducible staging deployment, measured RPO/RTO, backup inventory, restore evidence, and incident checklists.

**Exit:** O01–O06 as applicable pass; no public private-storage path, runtime-writeable static bundle, or untested restore claim. Actual production deployment requires the owner's environment and authorization; preparing reviewable templates does not require repeated permission.

## 20. P17 — Adversarial review and remediation

**Read:** 03, 13 and all protocol ADRs.

**Tasks:** Run complete multi-account security tests, fuzz parsers/envelopes, inspect stores/logs, test malicious relay/server responses, review dependencies and release chain, and perform qualified independent cryptographic/security review. Resolve findings with regression tests. Measure concurrency and fault recovery under realistic storage/network conditions.

**Deliverables:** Threat-to-test traceability, independent review report/status, remediation log, known limitations, and release-risk decision record.

**Exit:** No unresolved critical/high exploitable finding; G2/G3 satisfied or release explicitly limited to synthetic evaluation. An AI self-review is useful but cannot be renamed independent professional audit.

## 21. P18 — Final release and handoff

**Read:** All files, especially 13 and 16.

**Tasks:** Assemble signed Windows artifacts where credentials exist, PWA/API releases, dependency manifests, final OpenAPI/protocol docs, user recovery guide, admin runbook, migration/update plan, and acceptance matrix. Run the required targeted release checks on exact artifacts. Verify install->enroll->share->upload->revoke->recover->restore as a final synthetic end-to-end journey.

**Deliverables:** Versioned release package, checksum manifest, known limitations, all evidence references, and clear operational ownership.

**Exit:** G0–G6 complete for the advertised scope. No leftover mock auth/crypto, plaintext fallback, debug secret, disabled certificate check, or falsely passed test. Owner receives exact instructions for secure setup and recovery.

## 22. Rules for splitting each phase across chat sessions

Prefer task slices of one schema/migration family, one protocol operation, one native adapter, one UI workflow, or one acceptance scenario. Each slice must include its contracts and meaningful tests. Do not split a security transition so a partially implemented insecure state becomes a usable production feature.

At the end of each session, record: current commit/files; task outcome; tests actually run; failures/blockers; decisions made; remaining gate; exact next task. Start the next chat with file 15's continuation prompt and the repository state, not an unverified summary alone.

If a task is blocked, finish all independent authorized preparation first. Ask only for the specific missing credential/device/access or product choice. Never request confirmation for every reversible code edit. Never bypass sandbox/access restrictions or falsify physical-device results to keep the roadmap green.

## 23. Review-driven task slices and gate updates

Use file 19 for the reason behind each correction and file 20 for transition invariants. Do not append a later hardening phase while leaving these defects in earlier usable features.

| Phase | Required additional slice | Evidence from file 13 |
| --- | --- | --- |
| P02 | Freeze file key path, signed context, checkpoint pages and no circular digests; review design before relying on it | R01, R14, R19 |
| P03/P04 | Origin contract, commit-order counter, bounded snapshots, transactional metadata caps | R03, R04, R10, R15 |
| P05/P07 | Local nonce lifecycle, exact Argon2 binding, lock-generation and multi-window fencing | R16, R20 |
| P06 | Synchronizer CSRF, exact native callback, session-bound device proof | R04, R05, R18 |
| P08 | Provisional enrollment, cascading compromise revoke, recovery reset before envelope fetch | R02, R06, R07 |
| P10 | Pending invitation acceptance/grants, narrow reader maintenance, immediate revoke then history closure | R08, R14, R21 |
| P11 | Stable draft vs immutable attempt IDs, ambiguous receipt recovery, authorized snapshot bootstrap | R09, R10 |
| P12 | Explicit manifest-to-file-key chain, recoverable unattached files, epoch restart, framing-aware quota | R01, R11, R12, R13 |
| P13 | Strong retention references and full archive validation before import | R12, R17 |
| P14/P15 | Cross-window lock tests, system-sheet lifecycle, genuine large-file budget and streaming | R13, R20 |
| P16 | Security-state rollback quarantine, reference-safe backup/GC, finite operational reserve | R22, R23 |
| P17 | Exercise every R01–R24 regression; review protocol composition and unresolved assumptions | R01–R24 |

Arrange a qualified protocol design review once P02 is concrete, early enough to avoid baking flawed key/trust transitions into P08–P12. P17 verifies the implemented result and remediation; it must not be the first time anyone reviews the protocol. An unavailable external reviewer does not block documentation or synthetic experiments, but the independent-review production gate remains unmet.
