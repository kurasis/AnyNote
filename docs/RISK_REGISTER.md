# Initial risk register

No risk is resolved by this document alone. Only evidence closes a gate.

| ID | Risk / effect | Mitigation and owner phase | Current status |
| --- | --- | --- | --- |
| RK01 | iPhone 1 GB decrypt/save path may exceed platform memory/storage or be interrupted | Synthetic physical-device trials, bounded sink/source pipeline, measured options; P01/P15 | BLOCKED: no physical iPhone attached |
| RK02 | UI-only Hello prompt may leave actual private keys accessible | CNG/Hello operation gating and negative tests; document DPAPI user-context limits; P01/P07 | OPEN: scoped random-L native PRF/TPM probe, policy tests and official API 9 header ABI pass; physical execution pending; hosted API 7 is BLOCKED |
| RK03 | Candidate protocol composition may fail authorization/recovery or canonicalization | Frozen transcripts/schemas/vectors plus qualified design review at P02, implementation review at P17 | NOT STARTED |
| RK04 | Stale rosters/revocation and recovery reset races leak future epochs | Chapters 19/20 invariants, expected-head transitions and R02/R06–R08/R14; P08/P10 | NOT STARTED |
| RK05 | Ambiguous publication receipts or snapshots lose/duplicate drafts | Immutable attempt IDs, receipt reconciliation, pinned snapshot inventories; P11 | NOT STARTED |
| RK06 | Commit without attachment publication or retention cleanup loses files | Publication journal and strong-reference-aware collector; P12/P13 | NOT STARTED |
| RK07 | Full disk/quota concurrency breaks maintenance or framing | Exact ciphertext accounting, finite headroom, transaction tests; P04/P12/P16 | NOT STARTED |
| RK08 | PWA delivery origin/dependency compromise steals unlocked plaintext | Separate static origin, restrictive CSP, pinned audited dependencies and release permissions; P03/P15/P17 | Inherent boundary; controls NOT STARTED |
| RK09 | Backup restores revoked credentials/members or inconsistent blobs | Recovery quarantine/security-state reconciliation and clean-host drill; P16 | NOT STARTED |
| RK10 | Moving metadata/version sources cause unrepeatable builds | P00 source receipts; P03 exact lockfiles, binary/image integrity pins and repeatable clean setup | P00 baseline recorded; app setup NOT STARTED |
| RK11 | API/primary-source network access blocks CI evidence/research | Preserve presets; add only required hostnames in environment settings; use official source mirrors where valid | API access restored and CI verified; some direct documentation hosts remain unavailable |
| RK12 | Signing/hosting/reviewer unavailable delays production gate | Continue synthetic work; enumerate required secure bindings and exact outside evidence | No credentials/reviewer claimed; later gates |
| RK13 | Workspace cannot hold representative 100 GB production corpus | Separate measured synthetic host; do not equate small fixtures with capacity acceptance | Approximately 30 GiB available locally |
