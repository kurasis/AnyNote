# Next bounded task

## P02-ROOT-IDENTITY-CONTRACT — derivation, recovery kit and identity anchor

Prerequisites: P00 VERIFIED; P01 findings recorded; P03 developer foundation
verified with product contracts incomplete. P02 key/file/checkpoint candidate
p02-file-c1 implemented with serialization evidence only. P01/G1 and G2 OPEN.
Do not repeat completed owner 0.1.4 trials or relabel candidate codecs as product
security acceptance. Qualified independent review is not performed/booked.

Read AGENTS.md, progress/decisions/limitations/evidence, docs/protocol-v1.md,
packages/contracts registry/schema and original chapters 00–06, 13–15, 17, 19,
20. Preserve original spec bytes, P01/release/reference licenses and unrelated
work. Reuse checkout and saved activation; no Git worktree. No deployment,
plaintext server path, root custody change or content migration.

1. Define exact domain-separated HKDF-SHA-256 root-signing and recovery-encryption
   seed contexts bound to protocol/version/service/account/purpose. Select a
   maintained implementation and library seed-keypair APIs after primary-source/
   version/license review. No custom primitive or six-digit pairing scheme.
2. Specify bounded checksummed human-readable random 32-byte recovery-secret/kit
   encoding and strict public root identity/signature/fingerprint schema. Bind
   service/account/format explicitly; freeze noncircular identity fingerprint
   and detached root signature input, rejecting supplied replacement roots.
3. Add public deterministic derivation/identity/kit vectors and wrong-context,
   checksum/Unicode/length/unknown-field and purpose-separation negatives. Keep
   this synthetic reference separate from live account endpoints; do not retain
   R/root private keys on everyday devices or send them to the server.
4. Review consistency with candidate file/root/roster fingerprints and document
   assumptions, custody/loss/compromise limitations and qualified review questions.
   Keep unresolved certificate/roster/recipient/pairing/reset/epoch authorization
   schemas explicit for later slices. No production protocol freeze/audit claim.
5. Integrate meaningful targeted candidate checks/inventory/drift with P03/CI,
   verify frozen setup if dependencies change, update evidence/tracking and the
   exact next task, push and automatically merge the tested PR as authorized.
   Respect required checks; never force/admin-bypass or fabricate platform review.

Exit: independent implementer reproduces public recovery derivation, identity
fingerprint/signature-input and kit encoding/rejections. P02 remains IN PROGRESS
until all protocol/review deliverables, P03 remains incomplete until final shared
contracts/types/errors/logging. No new owner physical action currently required.
