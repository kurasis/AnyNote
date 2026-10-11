# Next implementation batch

## Finish P03 contracts, generated types, errors and safe logging

Read AGENTS.md, progress/decisions/limitations and original chapters 08/14/15/16/20.
Read protocol-v1.md, P02_COMPLETE_CONTRACT.md, P02_REVIEW.md and active
packages/contracts/p02-v1.registry.json. Chat Russian, repository English. Use
the current checkout; automatically push/merge passing normal PRs as authorized.

1. Complete P03 against the frozen five-component protocol: API/OpenAPI DTOs and
   generated client/backend types, exact transport error mapping and version
   negotiation. Fail CI on generated/schema/predicate/fixture drift; generation
   is an explicit development command, never an install/setup mutation.
2. Add bounded safe structured request errors/logging/redaction/request IDs to
   the existing Laravel foundation; validate unauthorized existence concealment,
   no ciphertext/plaintext/credential/key/SQL/path/stack logs and content limits.
3. Verify owned MariaDB/FPM/Nginx/Laravel integration, strict generated-client
   parsing and source/dependency checks. Preserve all original specification,
   prior schema/vector/lock/P01/reference/release bytes and exact PUBLIC exceptions.
4. Update evidence/handoff and saved read-only setup; run relevant CI, push/merge
   with all required checks and exact tested tree evidence. Do not deploy/release
   or declare product P04/P05/P07/P13 or independent review complete.

P02 design deliverables VERIFIED; qualified review TRACKED_NOT_BOOKED / NOT_RUN,
G2/G3 production release remains blocked. An actual qualified reviewer booking
and report/remediation is an owner/external action, not a self-review or CI pass.
P01 full physical/memory/network/provider matrix stays independently open. No
new owner device trial is needed for this P03 batch.
