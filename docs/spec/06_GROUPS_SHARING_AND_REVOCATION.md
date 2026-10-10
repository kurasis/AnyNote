# Groups, Sharing, Authorization, and Revocation

## 1. Group boundary

Private group: one member account, possibly many devices. Shared group: explicitly admitted accounts with owner/editor/reader roles. Every group has independent epoch keys. Threads inherit group access; per-thread/per-entry custom ACLs are out of v1 scope.

Account identity and membership are separate. The service administrator has no implicit membership. A server account-disable prevents access to API but cannot decrypt or rewrite a group's signed policy. It can still cause loss of availability.

## 2. Signed group policy

Group genesis binds random group ID, owner root fingerprint, policy version, service ID, initial epoch, and initial owner device identity. It is signed by the verified owner device. Subsequent membership events bind predecessor digest/version, full resulting member identities/roles or an unambiguous delta, owner identity, and effect on key epochs.

Only an owner device can admit/remove accounts, change roles, transfer ownership, archive/unarchive the group, or authorize permanent group deletion. Ownership transfer is co-signed by the incoming owner after recent authentication; validate there is exactly one owner in the result.

Signed policy and key-epoch transition are related but distinct. Optional rekey without membership changes may be requested by owner/editor devices. Any current key-holding member, including a reader, may execute a mandatory roster-only rekey using the exact signed membership/current device set. Readers may also extend existing access to their own certified devices. These are key-maintenance permissions, not content or membership permissions. This distinction prevents a reader from writing content merely because they possess group encryption keys.

## 3. Invite with full history

v1 invitation grants all retained group history, including retained revisions and trash still present in the group. The owner must see and confirm this exact scope. Avoid misleading “current messages only” wording. If that scope is undesirable, create a new shared group and copy explicitly selected current content.

Invitation steps: verify target account fingerprint through QR or another independent channel; choose role; sign policy update; enumerate all retained required group epochs; create envelopes for target active devices and its recovery public key; atomically activate membership with complete grants or show a pending invitation until grants finish.

Never expose membership as fully usable when historical keys are absent. Very large key inventories are paginated/resumable. For the small expected group size, per-device envelopes are acceptable; avoid a group-wide shared private identity key.

## 4. New same-account devices

Once an account is a member, that account may enroll its own devices without asking every group owner again. Existing key-holding devices can package authorized group epochs to the new device only after verifying its current account certificate/roster. A recovered account can do the same with its recovery envelopes.

The server must not invent devices and must not mark a recipient verified based solely on its database record. Every client distributing keys validates the recipient chain and current known roster. A newly enrolled device receives historical checkpoints to improve rollback detection.

## 5. Removal and key epochs

Group member removal is a signed owner event and a transition to a fresh group epoch. Bind a verified retained-history checkpoint to the transition so post-removal backdated signatures cannot simply claim historical authorization. The exact bounded inventory/ancestry proof format is frozen in P02. Device revocation changes an account roster and marks each accessible group rekey-required even if membership accounts are unchanged.

For an honest service, removal/session revoke takes effect immediately for API access. New content commits are blocked while required rekey work is incomplete. An online authorized maintenance device computes the exact current recipient set, generates a fresh G[e+1], distributes envelopes, and signs the transition. For a roster-only required rekey this may be a reader; membership changes still require owner authority. In a private group the remaining owner device performs this work. If no authorized maintenance device is online, the group is temporarily read-only and states why.

Epoch transition atomically binds the group policy version and relevant account-roster checkpoints. Reject a race where a recipient is revoked between preparation and commit. The client refreshes and retries with a new transition. Never publish new ciphertext using old recipients merely to avoid a temporary read-only state.

Existing readable content remains available to current members under authorized historical keys. All new or edited object revisions use fresh DEKs under the new group epoch; all new file versions use fresh file keys. Re-encryption of every historical byte is not automatic and cannot erase copies already held by removed recipients.

## 6. Role change nuances

Editor -> reader immediately stops accepted new content signatures at the current policy version. Since a reader still knows decryption keys, encryption alone cannot enforce this; clients must validate device signature and writer role at the accepted event state. Rekey may be performed for consistency but is not what enforces write prohibition.

Reader -> editor requires owner-signed policy change; no need to rewrite historical content. Removing an account requires rekey, not merely changing an ACL row. Revoking an authentication session without revoking its device key is a narrower operation; the UI must distinguish “sign out” from “revoke device.”

## 7. Offline changes and malicious-server limits

Offline edits are encrypted drafts signed for local provenance. Before server commit, obtain current policy/roster checkpoints and key epoch. If permissions remain valid, re-encrypt under the current epoch and commit with an explicit parent. If permission is lost, preserve the draft privately and offer export/copy to an owned group; do not silently publish it to a revoked group.

A malicious server can withhold a revocation from isolated clients and present a stale but valid history. Local checkpoints, signed parent chains, pairing checkpoint exchange, and conflicts expose some attacks, not all. Full independent transparency/consensus is not a v1 guarantee. Document this in security claims.

## 8. Cross-group moves and copies

Moving a thread or file to another group changes its audience and encryption context. Require a preview of source/destination audience. Implement as a client-authorized decrypt/re-encrypt copy with new IDs/keys and then optional source deletion after successful destination commit. Copying ciphertext plus a database group_id update is prohibited.

Default copies include current selected content only. Copying history/trash requires explicit choice. Source retains its own version history until its retention rules delete it. Do not perform global cross-user plaintext deduplication.

## 9. Account deletion and orphan prevention

An account cannot self-delete while it owns shared groups without transferring or deliberately deleting them. Operator disable may leave groups unavailable for ownership administration; inform remaining members. Operators cannot appoint themselves a cryptographic owner. Account recovery is the preferred path for a lost owner.

Deleting an account revokes sessions/devices, schedules rekeys, and removes private content according to retention policy. Shared contributions remain subject to group policy and author attribution may retain an opaque identity tombstone. Explain that server backups may retain deleted ciphertext until backup expiry.

## 10. Membership activation and history closure

Group admission uses a pending invite bound to the target root and role. The target accepts through its trusted device. Key grants are staged in bounded batches under an invitation/transition ID; membership activates only when the signed complete historical-epoch inventory and intended recipient coverage commit. Expired, declined, or changed-identity invites never activate. At finalization recheck current policy and rosters; a recipient revoked during preparation is excluded and the affected grants are rebuilt.

Envelopes can be validated structurally and by signature on the server, but the server cannot prove that a sealed box contains the right group key. Recipient clients acknowledge successful unwrap after activation. Missing/incorrect keys cause an explicit repair state; no silent random key replacement is permitted. An authorized malicious key holder can deny key delivery, an availability boundary that E2EE cannot eliminate.

Revocation takes effect for server access immediately after the signed revocation event commits. It must not wait for uploading a large checkpoint or thousands of envelopes. New writes stay suspended until current key epoch and the required history closure are finalized. Signed history checkpoints are endorsed by an authorized owner/editor and verified against known ancestry. A reader performing roster-only maintenance cannot certify unknown backdated content or overwrite the writer's history checkpoint. It may complete key distribution, but historical records not covered by a verified checkpoint remain unanchored until an authorized writer closes history. This separates emergency access removal, key repair, and historical authorship.

## 11. State-machine limits

Cap concurrent pending membership/epoch transitions to one per group and serialize finalization by expected heads. Stage large inventories in pages, then sign their exact digest and count. Do not implement recursive signatures over each other's final hashes: policy intent is signed first, distribution/checkpoint descriptor next, then one transition commit binds their immutable digests. Server sequence/timestamps provide transport order only; they cannot prove a revoked author signed before removal.

Archive permits reads, member removal, key maintenance, ownership transfer and owner-controlled unarchive. Content edits/uploads remain forbidden. Routine private-group transfer is prohibited; migration to another account uses selected copy/portable export or a separately reviewed explicit identity migration, with capacity planned before starting.
