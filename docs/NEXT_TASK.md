# Next bounded task

## P02-GROUP-POLICY-EPOCH-HISTORY-CONTRACT (larger batch)

Read tracking, original chapters 06/08/13/15/19/20, protocol-v1 and all three
candidate registries/contracts. Preserve original spec, previous schema/vector
bytes, P01 kits/reference/licenses, dependency locks and unrelated changes. Chat
Russian, repository English. Automatically push/merge the passing reviewable PR.

1. Freeze exact signed group genesis/policy/member/role/invitation/acceptance
   candidate bytes with independently pinned roots/policy heads and active device
   proofs. Distinguish owner/writer/reader/current membership from key possession.
   Invitations bind target root, role, explicit full-history disclosure and policy;
   acceptance remains pending until complete authorized grants finalize.
2. Implement synthetic trusted policy/epoch verifier and expected recipient
   derivation from current signed member and roster evidence. Device/recovery
   envelopes need exact coverage at pinned relevant heads; owner/policy/head or
   device changes invalidate staging. Validate current writer rights separately
   from signature and AEAD; reader receives keys but never writer permission.
3. Freeze staged transition/finalization/rekey contracts: bounded inventory/grant
   pages, digest-bound descriptor, all-head CAS, atomic complete epoch activation,
   no partial grant publication or excluded recipient reuse. Model compromise
   revoke/reset group maintenance and full-history admission/repair explicitly.
   Server cannot verify encrypted key contents; failed unwrap is repair, not PASS.
4. Connect existing checkpoint/file byte candidates to historical writer authority:
   independent witnessed history, signed descriptor/pages, exact inventory and
   parent closure, revocation boundaries and offline provenance ambiguity. No
   timestamp-alone acceptance or automatic reader-certified backdated writes.
5. Add frozen public vectors/adversarial tests and meaningful independent PHP
   subset checks, extend CI/saved setup with read-only frozen installs, update
   decisions/evidence/limitations/traceability. Explicitly distinguish synthetic
   synchronous ledger from P03 durable SQL/auth/product implementation.

Exit: independently reproducible policy/epoch/historical acceptance and recipient
coverage at pinned heads; reader denial, compromised delegation/roster changes,
partial/stale grants and ambiguous unanchored history fail safely. P02 remains
IN PROGRESS until all local/export/note formats and qualified review are complete.
Do not claim P04/P08/P09 product implementation. No new owner device action,
production deployment or kit release is needed for this synthetic batch.
