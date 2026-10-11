# Next implementation batch

## P06 complete account authentication and session lifecycle

Read AGENTS.md, current tracking, original 05/08/13/14/20, P04_BACKEND.md and
P05_CRYPTO_CORE.md. Russian chat, English repository; existing checkout; normal
passing PR and automatically authorized push/merge. No production deployment,
release, owner-device trial or independent reviewer outreach is implied.

1. Implement single-use invite consumption, maintained WebAuthn registration/
   assertion and multiple passkeys against the frozen contracts and durable P04
   authority. Bind exact trusted origins/RP IDs and one-use challenges; do not
   substitute a password/test-token login for the specified passkey flows.
2. Distinguish unauthenticated, restricted and trusted-device sessions. Do not
   invent an active roster from a valid certificate or claim P08 enrollment/root
   reset is complete. No generic test-token issuer or verification bypass.
3. Implement PWA host-only secure sessions/CSRF, native browser handoff with
   state/PKCE, refresh rotation/reuse detection, logout/session list,
   authentication recovery codes, recent-auth and rate limiting. Test actual
   HTTP/SQL flows, concurrent/replayed/expired challenges, invitations and
   refresh sessions, origin/RP/substitution failures and concealed errors.
   Keep quota/immutable revision/counter-last ordering and server opaque E2EE bytes.
4. Run frozen core/reference regression and Linux/browser/Windows/PHP CI as
   relevant. Update progress/decisions/limits/evidence and tested read-only setup.

P05 is VERIFIED: mandatory hosted two-way Worker/Rust, Windows/MSVC, PHP and
measured desktop 1 GB gates passed. Exact clean-source/tree and raw metadata
reports are retained in TEST_EVIDENCE.md and docs/evidence/p05-*-hosted.json.
C04/C16 use independently trusted issuer/checkpoint inputs; P08/P10 will establish
those authorities. P07 owns persistent local custody/lock/multi-window fencing;
P12 owns durable file source/resume/reservation state. Full physical P01 matrix
and G2/G3 qualified review remain open, unassigned/unbooked/NOT_RUN. No new action
on an owner device is required for this independent phase.
