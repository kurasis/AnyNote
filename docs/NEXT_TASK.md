# Next implementation batch

## P06 complete account authentication and session lifecycle

Read AGENTS.md, current tracking, original 05/08/13/14/20, P04_BACKEND.md and
P05_CRYPTO_CORE.md. Russian chat, English repository; existing checkout; normal
passing PR and automatically authorized push/merge. No production deployment,
release, owner-device trial or independent reviewer outreach is implied.

1. Implement P06 account/invitation/bootstrap/login/session/logout and recovery
   transport workflows against the frozen contracts and durable P04 authority.
   Use maintained password hashing/auth tools, exact trusted origins/issuers,
   host-only secure cookies/CSRF and supported native bearer/session routing.
2. Distinguish unauthenticated, restricted and trusted-device sessions. Do not
   invent an active roster from a valid certificate or claim P08 enrollment/root
   reset is complete. No generic test-token issuer or verification bypass.
3. Implement fixed errors, concealed resource responses, throttling, revocation,
   concurrent/replayed/expired session/invitation tests and actual HTTP/SQL flows.
   Keep quota/immutable revision/counter-last ordering and server opaque E2EE bytes.
4. Run frozen core/reference regression and Linux/browser/Windows/PHP CI as
   relevant. Update progress/decisions/limits/evidence and tested read-only setup.

P05 implementation is complete; its mandatory hosted interoperation/resource gate
must pass before merge. Check current PROGRESS/TEST_EVIDENCE for verified status.
C04/C16 use independently trusted issuer/checkpoint inputs; P08/P10 will establish
those authorities. P07 owns persistent local custody/lock/multi-window fencing;
P12 owns durable file source/resume/reservation state. Full physical P01 matrix
and G2/G3 qualified review remain open, unassigned/unbooked/NOT_RUN. No new action
on an owner device is required for this independent phase.
