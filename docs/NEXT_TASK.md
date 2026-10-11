# Next larger task batch

## P02-ROSTER-AND-RECOVERY-STATE — authenticated state before product key release

Prerequisites: P00 verified, P03 owned developer foundation, P02 p02-file-c1 and
p02-identity-c1 public synthetic crypto. P01/G1 and P02/G2 remain open; qualified
review not performed/booked. The owner requests larger coherent batches and
authorizes automatic push/merge after checks. Chat Russian, repository English.
No repeated owner 0.1.4 trial is needed. No production endpoint/root custody,
content migration or live deployment; do not create a worktree.

Read AGENTS and tracking; original 00–06, 08–10, 13–15, 19/20; protocol-v1 and
P02_IDENTITY_CONTRACT, both registries, strict codecs and current public vectors.
Preserve original specification, all p02-file-c1 byte fixtures and P01/release/
reference licenses. Signature handles and recipient coverage prove no current
authority: authorization=NOT_EVALUATED is intentional, not a flag to remove.

1. Select an established authenticated pairing/channel construction through
   primary source/version/license review; define bounded authenticated OOB/full
   transcript binding and provisional approval/new-device possession confirmation.
   Do not invent a six-digit-password protocol or treat a transcript digest as
   authentication. Explicitly isolate unavailable channel/platform evidence.
2. Freeze candidate root registration + append-only signed roster events with
   exact parents/generation/issuer/certificate digest, enrollment approval and
   confirmation. Implement a synthetic trusted-state verifier: independently
   pinned root/head, monotonic CAS/no forks/regressions, active cap and device
   delegation ancestry. Only confirmed activation authorizes device recipients;
   reject provisional/replayed/cross-account/stale/revoked approvals.
3. Implement signed compromise revoke transitive descendant closure and root
   reset contexts: separate account-login prerequisite, one-use session/service/
   generation/head/new-key challenge, root signature against existing identity,
   advance generation, revoke old active/pending devices/sessions before key
   retrieval. Candidate state transitions must distinguish server transaction
   design from actual durable DB/session implementation. No server receives R.
4. Connect authenticated state to exact recipient contexts/coverage. Test active
   vs provisional certificates, parent compromise, stale head/recovery races,
   key substitution, max-device limit, denial after revoke/reset and controlled
   historical-key scope. Current group policy/member/reader/epoch authorization
   remains a separate mandatory layer until implemented; no writer privilege
   follows from group-key knowledge. Do not silently change old candidate bytes.
5. Add frozen public positive/negative state/transcript vectors and meaningful
   independent reference checks; extend hosted checks/setup with frozen installs.
   Update review questions/decisions/evidence/limitations/traceability and exact
   next batch. Push/merge the passing final PR automatically as authorized,
   respecting protection; no force/admin bypass or production deployment.

Exit: independent implementer can reproduce candidate pairing/state bytes and
known active/revoked/reset decisions from pinned evidence, without confusing
certificate signatures with activation. P02 remains IN PROGRESS until complete
policy/epoch/historical/local/export formats and qualified review. P03 final
contracts/types/errors follow authoritative P02. No new owner physical action
unless a concrete remaining test needs it; describe the simplest necessary steps.
