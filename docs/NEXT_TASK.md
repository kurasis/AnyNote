# Next bounded task

## P02-KEY-AND-FILE-CONTRACT — key hierarchy and signed file context

Prerequisites: P00 VERIFIED; P01 host/owner findings recorded. P03 development
foundation is implemented and verified separately; the phase remains IN PROGRESS
until authoritative contracts/types and their integration exist. P01/G1 remains
OPEN: owner 0.1.4 positive Hello/lock and installed-PWA selected 1 GB hash/recovery
PASS, but memory/network/older-phone/provider/account/lifecycle matrix incomplete.
Do not repeat successful whole owner trials or infer broader platform acceptance.

Read AGENTS.md, progress/decisions/limitations/evidence and original specification
00–06, 08–11, 13–15, 17, 19 and 20. Preserve original specification bytes, existing
experiments, reference licenses, release assets and unrelated work. Reuse the
checkout and saved tool activation; no Git worktree. Start foundation through
scripts/dev-stack.py up/check when needed; stop only owned synthetic services.

1. Map the specification's account-root/recovery/device/vault/group/file key
   purposes and custody. Identify unresolved P01 assumptions explicitly,
   including per-credential PWA PRF; no plaintext server or universal recovery key.
2. Write a bounded reviewable protocol contract for the file-key path, wrap/AAD
   domains, exact versioned field types/bounds and signed context. Resolve
   checkpoint ancestry, epoch/role/recipient binding and circular digest hazards
   from review findings R01/R14/R19. Do not improvise cryptographic primitives
   or a six-digit pairing construction. Keep other protocol operations pending.
3. Define authoritative candidate schemas and deterministic public serialization/
   context fixtures for this slice only, using an established canonicalization
   implementation after primary-source/license/version checks. Reject duplicate
   keys, ambiguous Unicode/nonfinite numbers, missing/extra fields and wrong
   contexts with meaningful parser/fixture checks. Do not call candidate schemas
   globally frozen or expose incomplete security transitions as product endpoints.
4. Record security assumptions, decisions, trust boundaries and review questions.
   Qualified independent review remains external/unmet; self-review is not audit.
   No production security claim, content key custody change or migration.
5. Integrate only relevant reusable schema/fixture validation and drift commands
   into the prepared P03 foundation. Leave account/session/product APIs and full
   generated contracts/types for subsequent approved protocol slices.
6. Run required checks, update tracking/evidence and exact next task, push and
   automatically merge tested reviewable work as authorized. Respect required
   checks; never force/admin-bypass or relabel unrun physical/audit results.

Exit: an independent implementer can reproduce this candidate key/file context
serialization and its rejection cases. P02 stays IN PROGRESS until the complete
protocol/review deliverables exist; P01/P03 and production gates retain their
precise outstanding scope. No owner actions are currently required for the
already-successful 0.1.4 device checks; request only specific new physical
observations when a concrete subsequent test requires them.
