# Encrypted Notes and Files — Development Specification

Version: 1.1.0 (reviewed revision; supersedes 1.0.0)  
Prepared: 2026-10-10  
Language: English  
Status: approved product direction; implementation specification with explicit feasibility and security gates. No application code is included.

## 1. Assignment

Build a private, invite-only notes and file service for a small circle of trusted people. Provide separate accounts, private and shared groups, threads, notes, checklists, and attachments. Support Windows through a packaged WebView2 application and iPhone through an installed PWA. The backend MUST use PHP/Laravel, MariaDB, Nginx, and PHP-FPM. Sensitive user content MUST be end-to-end encrypted (E2EE) before it reaches the backend.

The reference Windows stack is Tauri 2 + Rust + React + TypeScript. The PWA reuses the React/TypeScript interface and protocol contracts. Do not replace the required backend or Windows WebView2 platform without an explicit architectural decision accepted by the owner.

## 2. Read order

| File | Purpose |
| --- | --- |
| [01_PRODUCT_AND_UX.md](01_PRODUCT_AND_UX.md) | Scope, workflows, roles, defaults, and interface requirements |
| [02_ARCHITECTURE.md](02_ARCHITECTURE.md) | Components, trust boundaries, repository structure, and platform adapters |
| [03_THREAT_MODEL_AND_SECURITY.md](03_THREAT_MODEL_AND_SECURITY.md) | Threats, guarantees, residual risks, and security controls |
| [04_CRYPTOGRAPHY_AND_FORMATS.md](04_CRYPTOGRAPHY_AND_FORMATS.md) | Key hierarchy, encrypted formats, signatures, and cryptographic gates |
| [05_ACCOUNTS_DEVICES_AND_RECOVERY.md](05_ACCOUNTS_DEVICES_AND_RECOVERY.md) | Login, QR enrollment, device trust, local unlock, and recovery |
| [06_GROUPS_SHARING_AND_REVOCATION.md](06_GROUPS_SHARING_AND_REVOCATION.md) | Group permissions, signed membership, history access, and rekeying |
| [07_DATA_MODEL_AND_STORAGE.md](07_DATA_MODEL_AND_STORAGE.md) | MariaDB entities, local persistence, metadata, and storage accounting |
| [08_API_CONTRACT.md](08_API_CONTRACT.md) | REST operations, authorization, errors, idempotency, and protocol contracts |
| [09_SYNC_OFFLINE_AND_CONFLICTS.md](09_SYNC_OFFLINE_AND_CONFLICTS.md) | Durable local writes, incremental synchronization, conflicts, and deletion |
| [10_FILES_UPLOADS_AND_PREVIEWS.md](10_FILES_UPLOADS_AND_PREVIEWS.md) | 1 GB files, chunking, resumability, manifests, and safe previews |
| [11_WINDOWS_AND_IOS_PWA.md](11_WINDOWS_AND_IOS_PWA.md) | Native integration, PWA restrictions, updates, and device acceptance gates |
| [12_DEPLOYMENT_BACKUPS_AND_OPERATIONS.md](12_DEPLOYMENT_BACKUPS_AND_OPERATIONS.md) | Hosting, hardening, backup/restore, maintenance, and incident handling |
| [13_TESTING_AND_ACCEPTANCE.md](13_TESTING_AND_ACCEPTANCE.md) | Acceptance matrix, platform tests, security tests, and release criteria |
| [14_DEVELOPMENT_PHASES.md](14_DEVELOPMENT_PHASES.md) | Separate step-by-step implementation plan for a development chatbot |
| [15_DEVELOPMENT_AGENT_HANDOFF.md](15_DEVELOPMENT_AGENT_HANDOFF.md) | Execution rules, task prompts, progress reporting, and handoff templates |
| [16_DECISIONS_LIMITS_AND_SOURCES.md](16_DECISIONS_LIMITS_AND_SOURCES.md) | Decision register, exact limits, source links, and unresolved engineering gates |
| [17_PORTABLE_EXPORT_AND_MIGRATION.md](17_PORTABLE_EXPORT_AND_MIGRATION.md) | Streaming encrypted export, offline reading, and independent recovery |
| [18_REQUIREMENTS_TRACEABILITY.md](18_REQUIREMENTS_TRACEABILITY.md) | User requirements mapped to documents, phases, tests, and final deliverables |
| [19_REVIEW_FINDINGS_AND_CHANGELOG.md](19_REVIEW_FINDINGS_AND_CHANGELOG.md) | Findings, corrections, residual gates, and verification scope |
| [20_PROTOCOL_STATE_TRANSITIONS.md](20_PROTOCOL_STATE_TRANSITIONS.md) | Recovery, enrollment, rekey, snapshot, and commit transition contracts |

Read this file, files 01–06, and files 14, 19, and 20 before implementing any feature. Read the relevant detailed document before each phase. File 16 owns numerical defaults; domain documents own behavior, with file 20 defining cross-component state transitions. File 19 explains the corrections and does not replace the corrected requirements. If a contradiction is discovered, record and resolve it explicitly rather than silently selecting the easier implementation.

## 3. Normative language

MUST / MUST NOT indicate release requirements. SHOULD indicates a preferred approach; deviations need a recorded rationale and equivalent acceptance evidence. MAY indicates optional work. A gate is a condition that must be evidenced before dependent functionality is represented as production-ready.

This specification is not a cryptographic audit. It selects established primitives and states a candidate application protocol. The exact binary encodings, authorization transcripts, and interoperation fixtures must be frozen and reviewed before real secrets are entrusted to the application. Passing AI-generated tests does not constitute independent cryptographic review.

## 4. Immutable requirements

- Invite-only service, initially sized for approximately 2–10 accounts and up to 5 active devices per account; limits are configurable, not licensing restrictions.
- Both private and shared groups are first-release functionality.
- Groups contain threads; threads contain versioned entries and file attachments.
- Maximum plaintext file size: 1,000,000,000 bytes (decimal 1 GB).
- Global committed storage quota: 100,000,000,000 bytes (decimal 100 GB), including retained versions and trash; actual encrypted byte accounting is authoritative.
- E2EE includes titles, body text, filenames, tags, drafts, previews, and retained content versions.
- Necessary routing, authorization, synchronization, and accounting metadata remain visible to the service. Do not claim that every database column is encrypted.
- No administrator recovery key that decrypts all users' data.
- Login credentials, server sessions, content keys, and local unlock mechanisms are separate concepts.
- Device enrollment through an existing trusted device plus offline recovery as a fallback.
- No silent data loss on concurrent edits, network interruption, device revocation, or local schema migration.
- No continuous background-transfer guarantee for iOS PWA.

## 5. Explicit security boundaries

E2EE protects content confidentiality from database/object-store disclosure when endpoint keys remain secret. Signatures and authenticated encryption support detection of tampering by a malicious service. They do not provide availability or unconditional detection of every rollback or split view.

A compromised PWA delivery origin can serve malicious application code that steals plaintext when the user unlocks. A separately controlled static origin reduces coupling with API compromise, but does not eliminate this browser delivery risk. A compromised unlocked endpoint or an authorized recipient can copy readable content. Revocation cannot erase previous knowledge.

The product MUST explain these boundaries without presenting the system as unhackable, zero-metadata, remotely erasable, or a DRM solution.

## 6. Delivery expectations

The developer must deliver source, reproducible setup instructions, migrations, OpenAPI, protocol schemas and fixtures, signed Windows release artifacts when signing credentials are available, the PWA build, operational runbooks, backup/restore tooling, and honest test evidence. Production secrets and signing keys must not appear in source, chat logs, CI artifacts, or this documentation.

Implement the phases in file 14. Complete the current phase and its evidence before claiming completion. If physical iPhone testing, signing credentials, hosting access, or independent review are unavailable, continue all independent authorized work and record the blocked gate precisely. Never replace an unavailable test with an invented success.
