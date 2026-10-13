# P11 implementation and verification status

P11 remains **IN PROGRESS**. This document describes implemented paths, not phase
acceptance. Frozen P02 records, signatures, independent pins, provider eligibility,
TLS and CSP remain authoritative. See ADR-021.

The additive closed `p11-sync` transport exposes account/group-scoped sparse hints
over commit-ordered global positions. A page binds its input cursor, captured
watermark, actual scanned count and next position. Hidden rows count as scanned;
unscanned rows cannot be skipped. Query parsing uses the original query string to
reject duplicate, unknown and malformed parameters.

Resync materializes immutable group catalog and revision inventory under one SQL
read view and the GC coordination lock. Pins and pages commit before the descriptor
is returned. The frozen inventory commitment, exact operation retry, fixed thirty
minute lease and current account/device/session/group authorization apply to each
page/reference. Cancellation or expiry cleanup releases pins and ephemeral inventory;
it never purges encrypted content or signed ancestry. Export/collector are P13.

Protected portable and native control now reads legacy local frames and writes the
additive `p11-local-v1` profile. A root manifest references encrypted 256 KiB parts,
with exact index, byte count, digest, root pin and installation binding. The logical
cap is 32 MiB. A prepared private candidate group key stays in the encrypted root.
Committed secret inventory now uses the same encrypted part profile with a closed
10,000-key logical type. Account roster replay retains all signed events up to
10,000 / 32 MiB, while child frozen frames/signatures stay unchanged.

Old clients must refuse the new profile: this is an additive reader migration, not
a safe downgrade of an active installation. Existing signatures, private candidate
keys, independent pins, immutable outbox bytes and exact acknowledgement rules remain.

Snapshots and content deltas stage independently from the visible projection. They
reuse the existing content authority/decryption verifier. The durable cursor and
projection publish only in the final fenced local transaction. Partial application
survives restart, while missing pages, unverified content and storage abort prevent
advancement. A lower cursor or changed transport generation enters persistent
`RESTORE_QUARANTINE`; a newer unsigned server response cannot clear it.

Bounded cache compaction retains every signed header and witnessed ancestry. It
protects current heads and pending draft/outbox bases, works under the same atomic
lease fence, and permits exact historical payload download later. SQL/transaction
abort preserves the previous payload. It does not purge server content.

The notes UI has English/Russian sync controls and visible/online polling with five
second base interval, bounded jitter, fifteen-to-sixty-second failure backoff and
immediate reconnect/resume scheduling. Cooperative removal hides accessible views
after saving the dirty editor locally. Security hints request fresh signed authority
and a consistent snapshot; they never authorize a local mutation by themselves.
No continuous iOS background service is promised.

Current local verification: ten maintained-crypto portable suites, seven actual
native SQLite note suites including staged snapshot restart/rollback, unchanged five
P10 portable suites, strict native Clippy and the strict-CSP static build passed.
The small actual HTTPS/SQL staged snapshot smoke passed. The broader actual TLS/SQL suite passed 112 checks in development; all hosted
gates still require completed execution at the final exact source.
Cloud Chromium cannot start its required sandbox; hosted browser acceptance is
mandatory and is not replaced by disabling it.

Outstanding before full P11 acceptance: complete multi-device/three-role convergence
and independent browser/fault evidence; complete migration/lease race evidence; final conflict/convergence and platform coverage; lease/authorization/restore races; final exact-source Linux/MSVC
reports, all twenty CI jobs, tracking and P12 handoff. Physical G1 and qualified
G2/G3 remain open/NOT_RUN. No production deployment or restore is authorized here.
