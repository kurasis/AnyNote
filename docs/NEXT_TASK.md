# Next implementation batch

## Finish P06 hosted acceptance, then complete P07 local vault

P06 implementation and local real HTTPS/SQL/Rust checks are present. Complete
mandatory hosted strict-CSP UI/resident UV WebAuthn and Windows/MSVC gates, retain
metadata-only exact-source evidence, save/test reusable read-only setup and merge
only after every required job passes. Do not label local sandbox BLOCKED a pass.

After P06 acceptance, read AGENTS.md, tracking, original 05/06/11/13/14/20,
P05_CRYPTO_CORE.md and P06_AUTHENTICATION.md. Russian chat, English repository;
existing checkout; ordinary passing PR and automatically authorized push/merge.
No production deployment, release, owner-device trial or reviewer outreach.

Complete P07 persistent local vault in one full batch: encrypted IndexedDB/native
SQLite state and migration policy; existing strict C01/C08/C10 frames and P05
maintained crypto; device/local secret custody; protected Windows Hello adapter
using the saved proven handoff and passphrase fallback only when explicitly
permitted by frozen eligibility policy; local lock/idle/suspend/logout generation
fencing; Worker/native key isolation; multi-window arbitration; interrupted
unlock/crash/rollback/replay/tamper and stale-completion tests; bounded memory and
secure best-effort wiping. Keep auth sessions, device trust and local unlock
separate. A trusted server session cannot substitute for private key custody.
Persist no raw reusable bearer/device/R secret in ordinary storage or logs.
Integrate P06 session-bound both-key proof after local unlock/re-login without
inventing a roster. Preserve all original spec/locks/fixtures.

Run appropriate actual SQL/HTTP/native/sandboxed browser/Windows regression;
update progress/decisions/limits/evidence and exact next task. Broader pairing/
root reset and current roster materialization stay P08, group authority P10,
large history indexing P11, durable file-source/resume P12. Physical P01 matrix
and qualified G2/G3 review remain open, unassigned/unbooked/NOT_RUN.
