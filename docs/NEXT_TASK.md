# Next implementation batch

## Complete P08 trusted devices and recovery

P07 is software verified: five Node custody suites, 28 actual HTTPS/SQL checks,
28 sandboxed verified-TLS/strict-CSP browser checks, fifteen native custody tests
per Linux/Windows platform plus preserved provider/official-header ABI gates.
All twelve hosted jobs pass at the exact clean tree recorded in evidence/p07.
Confirm final tracking and CI before making changes. Published P06 setup was
actually restored; P07 complete install/start draft revision 15 is saved, with
publication/new-task restoration separately NOT_RUN. Start owned services using
the saved read-only instructions; do not reset ordinary user data.

Read AGENTS.md, tracking, original 04–06, 08, 13, 14 and relevant 20 criteria,
P05_CRYPTO_CORE.md, P06_AUTHENTICATION.md and P07_LOCAL_VAULT.md. Russian chat,
English repository; existing checkout; normal passing PR and automatically
authorized push/merge. No production deployment, release, new owner-device trial,
real user-data mutation or reviewer outreach.

Complete the whole P08 batch: root bootstrap/kit generation and verification;
current signed account-roster chain and independent identity pins; both QR pairing
directions with bounded hostile-relay transport, TTL, rate limits, human intent
and single-use approval; independent device signing/encryption keys; authenticated
manual fallback only if allowed by the chosen original contract; same-account key
distribution; enrollment/activation/revoke and root-signed recovery reset with
CAS/receipts and security notifications. Implement enrollment/recovery UI, signed
lifecycle records, clear offline recovery instructions and fresh-client traces.

Integrate P07 encrypted custody and lifecycle cancellation. Generate new private
device keys on the new installation; keep them under random L with the current
hardware/explicit-phrase policy. R/root secrets are transient recovery/bootstrap
inputs, never everyday state. Bind pairing to independently verified account/root/
service/device identities; never trust a new root solely because the API supplied
it. Recovery requires separate server access plus the offline secret. Root reset
must reject old-generation device sessions/authorizations and cannot give an
administrator plaintext. Fresh P06 both-key proof upgrades only current session
trust, not local unlock or group authority. Do not equate passkey login with key
recovery or silently invent current roster/group state.

Materialize a complete current account roster and private preference-group genesis
before preference writes, preserving original ownership/signature/key-distribution
rules. Group membership authority stays P10 and usable note flows P09; no fake
roster/group placeholder satisfies P08. Keep bounded durable transitions, precise
pending/crash/retry behavior, cancellation/stale-result fences, revoked-device
exclusion and content-free diagnostics. Preserve original spec, frozen corpora
and prior locks; any additive dependency/format is explicit and inventoried.

Run hostile relay mutation/key-swap/replay/expiry and independent-pin tests, fresh
client recovery, SQL concurrency/rollback, actual HTTPS and persistent Worker/
native custody integration, sandboxed browser and Windows regressions. Close
original C05/C06/C11/C13 for this scope; retain real physical/audit limits. Update
progress/decisions/limits/evidence and exact next task; require all final source
jobs before ordinary automatic merge. P11 owns sync/history, P12 file-source/resume,
P14/P15 full native/PWA product packaging, P16 operations and P17 qualified review.
The full P01 physical matrix and qualified G2/G3 remain open/unbooked/NOT_RUN.
