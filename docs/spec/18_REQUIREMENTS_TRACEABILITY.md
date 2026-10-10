# Requirements Traceability and Delivery Checklist

## 1. User requirement mapping

| Requirement | Authoritative documents | Implementation phases | Main acceptance evidence |
| --- | --- | --- | --- |
| Notes and file storage | 01, 07, 10 | P09, P12, P13 | F01–F03, U01–U17, R01/R11–R13 |
| Groups and threads | 01, 06, 07 | P09, P10 | Private isolation and shared role tests |
| Windows application using WebView2 | 02, 11 | P01, P14 | Actual Windows/WebView2 runtime and IPC tests |
| iOS PWA | 10, 11 | P01, P15 | Physical iPhone install/lifecycle/storage/export evidence |
| Laravel + MariaDB + Nginx + PHP-FPM | 02, 07, 08, 12 | P00, P03, P04, P16 | Clean deployment and backend integration |
| E2EE before server storage | 03, 04 | P02, P05, P09, P12 | Interoperability, store/log inspection, no server key |
| Strong security and protection against compromise | 03–06, 11–13 | All; P17 review | Threat-to-test coverage and honest residual risks |
| Simple multi-device operation | 05, 09 | P07, P08, P11 | QR enrollment, independent devices, convergence |
| Several independent accounts | 01, 05–08 | P04, P06, P08 | Account isolation and no admin master key |
| Personal and shared groups | 01, 06 | P09, P10 | Role signatures, full-history invitations, rekey |
| Files up to 1 GB | 10, 11, 16 | P01, P12, P14, P15 | Exact 1,000,000,000-byte round trips |
| Total storage up to 100 GB | 07, 12, 16 | P04, P12, P16 | Concurrent reservation/ledger/capacity tests |
| Recoverable data without a running original service | 05, 12, 17 | P08, P13, P16 | Offline kit, portable export, clean-host restore |
| Proper staged chatbot development | 14, 15 | P00–P18 | Per-task handoff and evidenced gates |

## 2. Critical invariants to trace in code review

- Every content write has authenticated encryption, a verified authorized signature, explicit immutable context, and an idempotent commit path.
- Every key recipient is derived from verified account/group state; no raw SQL recipient list is trusted blindly.
- Every new revision/file version has fresh key material and a nonce-safe immutable lifecycle.
- Every credential-handling boundary distinguishes server authentication from local unlock and device authorization.
- Every quota change is concurrency-safe and tied to a durable object lifecycle.
- Every “saved” state corresponds to the documented durability level.
- Every file reference belongs to the correct group and points to committed or explicitly pending content.
- Every destructive retention operation preserves current references, conflicts, required ancestry, and recoverability promises.
- Every browser/native API exposure is limited to its intended trust domain.
- Every “tested” statement references an actual environment and result.

## 3. Production deliverables checklist

- [ ] Source tree with lockfiles, licenses, SBOM, and reproducible build/setup instructions.
- [ ] Versioned protocol specification, strict schemas, derivation/signature/encryption fixtures.
- [ ] OpenAPI and generated client contract types, including bounded error responses.
- [ ] Laravel migrations, policies, transaction services, cleanup jobs, and private blob adapter.
- [ ] Windows installer and signed updater artifacts or precise missing-signing limitation.
- [ ] PWA assets/manifest/service worker with physical-device compatibility report.
- [ ] Account enrollment, recovery, device revoke, and group membership/rekey flows.
- [ ] Durable sync/outbox, conflict handling, deletion/retention, and local encrypted search.
- [ ] 1 GB transfer/export evidence and exact quota accounting.
- [ ] Portable encrypted export with offline recovery/import guide and successful clean-machine test.
- [ ] Deployment templates, secrets inventory without values, hardened networking/permissions.
- [ ] Consistent backup, clean-host restore evidence, measured RPO/RTO.
- [ ] Security review/remediation log, threat model, known limitations, and acceptance matrix.
- [ ] User guide for installation, recovery-kit storage, sharing, removal, offline use, and plaintext export.
- [ ] Operator runbook for updates, incidents, disk full, lost owner/device, and recovery.
- [ ] Final status that distinguishes verified, unverified, and intentionally deferred work.

## 4. Specification authoring validation

This package was prepared as documentation only. Internal file links, numbered phase references, file-size arithmetic, UTF-8 encoding, and ZIP integrity are checked when packaging. Those checks do not validate application code, physical iPhone behavior, cryptographic composition, or production hosting; those are development and review gates in file 13.

The archive contains no production keys, application implementation, installer, or claim of completed development. The included development phases are instructions for the implementation assistant.

## 5. Reviewed revision

Specification version 1.1.0 adds the finding register in [19_REVIEW_FINDINGS_AND_CHANGELOG.md](19_REVIEW_FINDINGS_AND_CHANGELOG.md) and the transition contract in [20_PROTOCOL_STATE_TRANSITIONS.md](20_PROTOCOL_STATE_TRANSITIONS.md). The R01–R24 cases in file 13 and task slices in file 14 trace the fixes into implementation. “Corrected in specification” is distinct from “implemented”, “tested” or “independently audited”.

Packaging validation checks all local document links, unique document names, phase/test references, source IDs, exact file framing arithmetic, the checksum manifest and ZIP CRC. The review does not remove the P01 physical-platform or P02/P17 independent-security gates.
