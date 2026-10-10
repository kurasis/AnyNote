# Development Agent Handoff and Working Rules

## 1. Initial prompt

Use this prompt when giving the archive to a coding assistant:

> Build the application specified in this documentation package. First read 00_README.md, the product/architecture/security/cryptography/account/group documents, 14_DEVELOPMENT_PHASES.md, 19_REVIEW_FINDINGS_AND_CHANGELOG.md, and 20_PROTOCOL_STATE_TRANSITIONS.md. Inspect the existing repository and its applicable instructions before changing anything. Preserve existing work. Begin with P00 and proceed in bounded tasks through the roadmap. The accepted stack is Tauri 2 + Rust + React/TypeScript + WebView2 on Windows, an iOS PWA, and Laravel + MariaDB + Nginx + PHP-FPM on the server. Private and shared groups are required. The maximum file is 1,000,000,000 bytes; the global committed encrypted-storage quota is 100,000,000,000 bytes. End-to-end encryption, recovery, role integrity, and data durability are mandatory. Do not implement a server plaintext fallback. Keep progress, decisions, limitations, and test evidence in the repository. Distinguish implemented from tested and tested from independently reviewed. Do not claim real iPhone/Windows checks without those environments. Work autonomously on authorized reversible tasks, and raise only concrete blockers or decisions that change scope/security. Start by reporting repository facts and the first bounded task.

## 2. Continuation prompt

> Continue from the actual repository state. Read docs/PROGRESS.md, docs/NEXT_TASK.md, docs/DECISIONS.md, docs/KNOWN_LIMITATIONS.md, and the relevant specification files. Verify that the recorded state matches the files/commit. Complete the next bounded task and its meaningful tests. Do not restart completed phases, silently change protocol decisions, overwrite unrelated work, or treat an unverified prior claim as a passed gate. Update handoff documents with exact evidence and the next task.

## 3. Task card

Every task should have:

| Field | Required content |
| --- | --- |
| Task ID | Phase plus stable task identifier |
| Objective | User-visible or security outcome |
| Prerequisites | Verified contracts, modules, and gates |
| Inputs | Exact specification sections and existing code |
| Scope | Files/components to change and intended behavior |
| Exclusions | Adjacent features intentionally deferred |
| Invariants | Security/durability rules this task must preserve |
| Acceptance | Observable tests/results, not only a completion assertion |
| Evidence | Commands/procedures, environment, output/artifacts |
| Rollback/recovery | How to preserve data if the change fails |
| Handoff | Remaining issue and exact next task |

## 4. Progress report template

Use concise factual sections in the implementation repository:

- Phase/task and status.
- What changed and why.
- Contracts/schema versions affected.
- Checks actually executed and outcomes.
- Checks not executed and the exact reason.
- Security and data-compatibility implications.
- Remaining blocker or next task.

Use PASS/FAIL/BLOCKED/NOT RUN consistently. Do not mark a test PASS because a library is widely used, because the code compiles, or because another platform has a similar API.

## 5. Non-negotiable development rules

1. No application content encryption with Laravel APP_KEY as the E2EE layer.
2. No server-held universal recovery key or automatic administrator access to private groups.
3. No mock encryption, secret-in-URL shortcuts, or plaintext fallback in production paths.
4. No copying one device's private identity keys to another installation.
5. No unsigned recipient-key substitution or group membership trusted solely from SQL.
6. No 1 GB in-memory read/concatenation as the only transfer implementation.
7. No global plaintext hash/deduplication service or server-side plaintext previews.
8. No silent overwrite of conflicting note edits or unacknowledged local data loss.
9. No remote HTML/scripts in the privileged Windows window.
10. No repeated nonce/key pair for changed bytes; no ignoring failed integrity verification.
11. No insecure test mode enabled by default or reachable through production config drift.
12. No real user secrets in chat, source, logs, test snapshots, or CI artifacts.
13. No automatic deployment, destructive migration, or deletion of production content beyond actual authorization.
14. Do not misrepresent an application security review as a formal cryptographic proof or professional audit.

## 6. Design changes

Routine implementation choices may be resolved using this specification and engineering judgment. Record an ADR when changing a trust boundary, primitive/binding, canonical format, account recovery behavior, supported platform, quota interpretation, storage lifetime, auth-session protocol, or an accepted user workflow.

An ADR contains context, considered options, selected option, security effects, migration effects, tests, and source links checked on that date. A change requiring server decryption, weakening isolation, silently reducing the 1 GB iOS requirement, removing shared groups, or replacing the backend stack requires an explicit owner decision.

## 7. Test-data policy

Use synthetic notes, randomly generated incompressible files, fabricated account identities, and test-only passkeys/providers. Public deterministic crypto vectors must be labeled nonsecret. Production signing credentials, private keys, recovery kits, and user databases are not ordinary development inputs. If a required external service is unavailable, use a clearly isolated mock and keep the corresponding real integration test unverified.

## 8. Portable encrypted export requirement

Before release, document a versioned self-describing export format containing selected ciphertext data, manifests, required key envelopes, identity/policy evidence, and the independently user-held age export identity specified in file 17. Include an offline-verification/import tool or documented client flow so the user is not permanently dependent on a running original API. Do not include an unencrypted recovery secret inside an encrypted archive's public header.

Export imports into a new destination must preserve provenance while issuing new destination IDs/keys where group/security context changes. Importers enforce size/path/format bounds and never execute embedded scripts. A successful encrypted ZIP creation without a tested recovery path is not a complete export feature.

## 9. Completion definition

The project is complete when the specified workflows work on the declared real platforms, release gates are evidenced, recovery and clean-host restore succeed, artifacts are deliverable, and the owner receives operational instructions and truthful limitations. A beautiful UI over placeholder APIs, or a secure backend without usable iPhone file export, is incomplete.
