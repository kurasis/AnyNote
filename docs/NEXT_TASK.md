# Next implementation batch

## Complete P10 shared groups and membership integrity

First confirm the final P09 evidence, tracking and passing mandatory CI. Read
AGENTS.md, PROGRESS.md, TEST_EVIDENCE.md, DECISIONS.md, KNOWN_LIMITATIONS.md,
P04_BACKEND.md, P05_CRYPTO_CORE.md, P07_LOCAL_VAULT.md, P08_TRUSTED_DEVICES.md,
P09_PRIVATE_NOTES.md and original spec 00 then 01, 03–06, 08, 09, 13, 14 and
relevant 20 criteria. Work in the existing checkout, Russian chat and English
source/docs/commits/PRs. Ordinary passing push/merge is authorized. No worktrees
or subagents unless expressly requested; no production migration/deployment,
release, new owner-device trial or reviewer outreach.

Restore with runtime-env.sh, dev-stack.py up/check and p06-stack.py up/check.
The published P08 snapshot was actually restored. P09 saved setup is distinct
from publication and independently observed fresh P09 restoration. Preserve
marked credentials/TLS/OAuth state, DB volumes, encrypted drafts/outbox and
pending cleanup journals. Install the frozen QR and Markdown projects before
the shared UI build. Default setup/generators compare source read-only. Never
regenerate original spec/corpora/old locks to make checks pass. Run P03 outage
checks sequentially with P06/P07/P08/P09 HTTP because MariaDB is shared.

Implement the entire shared-group vertical slice: owner/editor/reader, independently
verified target account/root invitation and explicit acceptance, full-history/key
delivery, owner transfer, signed role changes, membership removal, same-account
active-device distribution and rekey-required maintenance. Bind every recipient
to current independently replayed group policy/account roster and authenticated
public keys. Signature validity alone authorizes neither current writers nor key
recipients. Invitation is pending admission, not active access. A nonmember/admin
must not gain plaintext or a key. Preserve private namespace isolation.

Reuse frozen group-c2 signed pages, transition staging, commit coverage and P04
transaction/CAS/quota/receipt/event semantics. Complete general public policy/
epoch/history proof transports as closed additive contracts; preserve P02 frames.
Distinguish historical authors from current writers. Current P09 known local
witnesses allow already verified old content, but a fresh client with no independent
historical anchor must not accept an arbitrary backdated revoked signature. Build
actual signed history closure and current recipient/epoch coverage rather than
clearing flags or suppressing UNANCHORED_HISTORY. P11 owns scaled snapshot/delta
convergence, not permission to bypass P10 transition correctness.

Removal/revoke must stop new publication and rotate future access with honest
limits: exposed old keys/plaintext/backups cannot be erased. Preserve unsent work
under local L and explain access-lost/rekey/history-required states. Every signing
or recipient mutation rechecks fresh session/device/current policy. Freeze signed
attempt bytes and reconcile unknown operation receipts. Account roster and group
maintenance races must have explicit deterministic winners and durable recovery.

Implement private-to-shared copy with an audience preview and explicit confirmation,
fresh objects/DEKs/epoch encryption, no old private ciphertext/key reuse. No silent
sharing of private account preferences or unrelated attachment references. Make
membership, role, owner transfer, removal and maintenance usable in EN/RU through
safe UI and closed protected native commands; no general key/token/SQL/path IPC.

Retain P07 random-L custody, strong phrase/eligible Hello+TPM/optional PRF/current-user
DPAPI, worker termination, writer/epoch/generation fencing and lock masking. Retain
P08 independent root pins, both QR directions, mutual one-use approval, independent
device keys and root-signed recovery. Root/R remain transient. Retain P09 safe DOM,
strict page and static-worker CSP, ciphertext-only SQLite/IndexedDB/WAL, immutable
note attempts, conflict preservation and exact explicit restore ancestry.

Use actual maintained crypto, real HTTP/SQL and persistent protected native/browser
storage. Exercise at least three accounts/roles, target-root substitution, unauthorized
recipient/signer, stale policy/epoch, concurrent enroll/revoke/role/rekey/owner transfer,
unknown result/retry, interrupted staging, historical read/current-write distinctions,
private-copy audience and leakage. Windows/MSVC plus sandboxed verified-TLS/CSP PWA
acceptance are mandatory alongside all sixteen inherited gates at the exact final
head/full tree. Never weaken verifier/assertions/crypto/TLS/CSP/sandbox/eligibility.
Archive only exact-source public reports; update tracking, limitations, decisions,
dependencies, complete read-only install/start configuration and full P11 handoff.
Ordinary merge requires all checks passing and a SHA guard, then clean local/remote
main and the tested tree. Draft saving is not publication or fresh restoration.

Full physical G1/Hello/iPhone and qualified G2/G3 remain open/unbooked/NOT_RUN.
Software acceptance is not a production security release. P12 owns large-file
source/resume/quota, P13 full search/export/retention, P14/P15 host packaging,
P16 operations and P17 qualified adversarial review. Do not start unrelated phases
or request new physical hardware actions merely to validate P10 software.
