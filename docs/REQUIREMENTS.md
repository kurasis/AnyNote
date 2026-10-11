# Locked scope and implementation checklist

P00 scope is recorded; unchecked boxes mean implementation/acceptance outstanding,
not optional scope. Specification chapter 16 owns numeric defaults, domain
chapters own behavior, chapter 20 owns transitions. Resolve contradictions in
an ADR. Full traceability: [specification chapter 18](spec/18_REQUIREMENTS_TRACEABILITY.md).

| Required outcome | Owner phases | Acceptance references | State |
| --- | --- | --- | --- |
| Invite-only accounts; passkeys separate from decryption/device trust | P04/P06/P08 | Auth isolation, C05/C06, R02/R05/R06 | NOT STARTED |
| Private and shared groups; threads/entries/checklists | P09/P10 | F01–F10, C09/C12 | NOT STARTED |
| Encrypted titles, text, filenames, tags, drafts, previews/history | P05/P07/P09/P12/P13 | C01–C04, storage/log leakage inspection | NOT STARTED |
| Signed roles, recipient authorization and fresh epochs | P02/P05/P10 | C07–C10, R08/R14/R19/R21 | NOT STARTED |
| Independent devices, QR approval, offline recovery, no admin master key | P08 | C05/C06/C11/C13, R02/R06/R07 | NOT STARTED |
| Durable offline drafts/sync, conflict preservation | P07/P11 | S01–S12, R03/R09/R10/R20 | NOT STARTED |
| Exact 1,000,000,000-byte files; bounded resumable transfer/export | P01/P12/P14/P15 | U01–U17, physical U11/U12 | NOT STARTED |
| Global 100,000,000,000-byte committed ciphertext quota | P04/P12/P16 | Reservation concurrency, R11–R13/R23 | NOT STARTED |
| Native Windows Tauri/Rust/WebView2; English/Russian UI | P01/P14 | Actual key gating, IPC, installer and update tests | NOT STARTED |
| Installed iPhone PWA; honest background/storage limitations | P01/P15 | Physical export, lifecycle, PRF and storage tests | NOT STARTED |
| Laravel/MariaDB/Nginx/PHP-FPM; private blob storage | P03/P04/P16 | Development service startup/isolation implemented; product storage/deployment pending | IN PROGRESS |
| Encrypted portable export and recovery without original API | P13/P16 | R17, clean-machine offline import/recovery | NOT STARTED |
| Hardened deployment and consistent backup/restore | P16 | O01–O06, R22/R23 | NOT STARTED |
| Qualified independent design/security review | P02/P17 | G2/G3, R01–R24 | NOT STARTED |
| Signed Windows artifacts, PWA, contracts, runbooks and handoff | P18 | G0–G6 on exact release artifacts | NOT STARTED |

- [x] Preserve accepted stack and scope without substitutions.
- [x] Record original repository and cloud runtime facts.
- [x] Record exact version candidates, source observations and license inventory.
- [x] Preserve the original 21 specification files and checksums.
- [x] Document baseline reproduction and a meaningful integrity check.
- [ ] Validate production features, physical platforms and independent review.

P02-KEY-AND-FILE-CONTRACT: specification 04/10/20 and R01/R14/R19 now map to
protocol-v1.md, packages/contracts/p02-file-c1.schema.json, strict candidate
codecs/tests and fixtures/protocol/p02. Status is candidate byte/framing/design
evidence only; no complete R01 fresh-recipient crypto, R14 author/reader trust
state or R19 application thread/signature substitution acceptance.
