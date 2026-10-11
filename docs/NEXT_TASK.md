# Next implementation batch

## P04 backend model, authorization and transactions

Read AGENTS.md/current tracking, original chapters 06–08/12/14/20, the frozen P02
contracts/review package, and P03_DEVELOPMENT.md. Use the existing checkout;
Russian chat, English repository; automatically push/merge passing normal PRs.

1. Implement bounded product migrations/entities/indexes and account/group-scoped
   repositories, invite/admin bootstrap scaffolding, no implicit content ownership.
2. Finalize P04-owned OpenAPI DTOs before serving endpoints. Implement strict
   request/current actor authorization and immutable revision/receipt/quota/sync
   transaction boundaries; no in-memory evaluation handle is product authority.
3. Prove isolation with three accounts, cross-group IDs and current device state;
   exercise CAS/idempotency/concurrency/faults against actual MariaDB. Verify no
   plaintext title/body/filename columns. Signature acceptance requires P05 native/
   browser/public PHP adapters and fixtures; coordinate P05 work without marking
   that dependent gate passed prematurely. P05 has no P04 dependency.
4. Add protected readiness/queue/scheduler foundation with safe errors/logging;
   preserve frozen prior bytes, update generated contracts explicitly, fail drift.
5. Update handoff/evidence and tested read-only environment setup; actual CI and
   exact tested tree before automatic merge. No production deployment/migration,
   account credentials, test-kit release or external outreach is authorized here.

P03 tooling VERIFIED; product behavior remains P04 onward. P01 full physical
matrix and G2/G3 independent review remain open. Qualified reviewer unassigned/
unbooked/NOT_RUN; owner/external booking is needed before security release.
No new owner device trial is needed for the independent P04 batch.
