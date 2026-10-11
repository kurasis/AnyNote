# P02 pinned group policy, epochs and historical writer candidate

Status: `p02-group-c1`, isolated executable candidate. This completes the larger
P02-GROUP-POLICY-EPOCH-HISTORY-CONTRACT slice, not P02/G2 or a product endpoint.
Read the schema/registry, `group-codec.mjs`, `group-state.mjs`, public
`group-vectors.json`, and existing file/identity/state contracts together. Earlier
schema/vector/lock bytes remain unchanged. No new cryptographic dependency.

## Trust and authority

An independently pinned root plus verified roster establishes device authority;
an independently pinned group genesis establishes the initial owner. Private
WeakMap handles carry proofs; JSON flags cannot create trust. Replay verifies the
signed journal and caller-supplied independent final state pin. Live evaluation
also checks the pending operation, monotonic trusted clock and all relevant heads.
`replayGroupEpochForEvaluation` is client verification, never a live admission API.
These helpers do not implement account authentication, recent authentication,
server session gating, SQL durability or a real transaction.

One owner and at most ten members; owner/editor may write, reader may receive keys
and read. Only owner may invite/admit/remove/change roles/archive/unarchive. Shared
group ownership transfer requires both current active device signatures on the
same resulting policy; exactly one owner results. Private groups have one owner,
no sharing or routine transfer. Product transfer additionally requires recent
account authentication, which this candidate does not model. Administrators gain
no membership. Key possession and a valid signature alone never grant writer rights.

Policies sign exact predecessor/version, operation, signer, complete sorted
membership and action payload. Invites bind target independently pinned root,
role, current policy, nonce, expiry and explicit full retained history disclosure.
Target acceptance signs the exact invitation digest and target context. States:
INVITED -> ACCEPTED_PENDING_GRANTS -> STAGING -> ACTIVATED. Acceptance supplies no
immediate grants/access. One pending transition, cancellation/decline terminal;
48-hour invitation and ten-minute epoch staging maximums. Expired/stale staging
can be reconciled explicitly; fresh exposed key commitments are burned on retirement.

Removal denies access immediately. Downgrade denies new writes immediately.
Removal requires rekey and historical closure before new writes. Roster updates,
revocation and same-root recovery require all affected groups to refresh grants.
A reader may perform exact mandatory roster-only rekey with already held keys;
that grants no policy/content/history certification privilege. A current writer
must close independently known history. Optional rekey and removal rekey require
owner/editor. Archive blocks new content while allowing reads, revocation,
maintenance and unarchive. Already downloaded plaintext/old keys cannot be recalled.

## Exact bytes and noncircular commitments

Closed schemas use previous strict JSON/JCS rules: reject duplicate/unknown keys,
invalid UTF-8/surrogates, noncanonical binary encodings and out-of-range counters.
IDs/keys are unpadded base64url; bounded counters are canonical decimal strings;
protocol_version is integer 1. Lexical order is ASCII, never locale-dependent.

Signature input is UTF-8 `AnyNote/p02-group-c1/sign/{body.purpose}\0` followed by
JCS(body). Policy, invitation, acceptance, epoch-intent, descriptor, epoch-commit,
history, grant-page and epochs hashes use SHA-256 of UTF-8
`AnyNote/p02-group-c1/hash/{kind}\0` plus JCS(typed value). The registry lists
allowed purposes. Existing identity grant/file/checkpoint signature domains stay
unchanged. Transfer co-signs the policy body, not the first signature.

G is a fresh 32-byte CSPRNG client secret. Its equality commitment is SHA-256 of
UTF-8 `AnyNote/p02-group-c1/hash/group-epoch-key\0`, JCS of the typed
`{service_id,group_id}` scope, then the raw 32 bytes. Scope is fixed-format and the
secret has fixed length. This is an equality commitment, not a password KDF or
entropy proof; it intentionally exposes same-key reuse within one group. Epoch
number is excluded so canceled/excluded-recipient keys cannot be recycled under
another operation or epoch. Standard SHA-256/Ed25519/libsodium sealed boxes are
used; this composition still requires qualified independent review.

The signed epoch intent is created first: old policy/epoch heads, prospective
membership, next epoch, complete retained epoch inventory, key commitment,
current member roster anchors, history checkpoint, reason, operation and expiry.
Its digest is the fresh epoch_digest referenced by grants. Grants are then
created, followed by descriptor and signed final commit. No grant refers to a
final digest containing that grant; membership/epoch/history signatures have no
self-reference. The final epoch head hashes the final commit; next intent anchors
that head. File policy references the accepted intent digest and unchanged file
checkpoint descriptor digest.

## Full retained history and staged recipient coverage

Each transition redistributes every retained epoch to every resulting member's
currently active certified devices plus its account recovery recipient. Expected
contexts come from independently pinned member/roster proofs; the server's list
cannot define completeness. Context includes service/group, epoch identity,
prospective membership, operation, issuer and exact recipient generation/head.
No missing/extra/duplicate/revoked recipient is accepted. Admission becomes live
only after all coverage, signatures, heads and descriptor checks succeed.

Grant pages sort by zero-padded 19-digit epoch, account ID, recipient kind, device
ID. Greedily pack at most 500 records and 1 MiB per page. Pages have exact
0-based indexes and common scope/operation. Ordered inventory SHA-256 input:
domain `AnyNote/p02-group-c1/hash/grant-inventory\0`; big-endian uint32 page
count and uint64 total records; for each page big-endian uint32 index, uint32
record count, uint32 JCS byte length, then raw 32-byte domain-separated page
hash. Descriptor signs counts, inventory digest, retained epoch inventory digest,
intent digest, membership and signer. Immutable same-byte page retries and exact
final-commit retries are idempotent; changed data conflicts.

Finalize rechecks every relevant policy/epoch/roster head before any state mutation.
This is synchronous in-memory evaluation, not a durable SQL commit. Public retry
receipts are client-reference data, not an authenticated server endpoint. Server
cannot inspect sealed G, its entropy or ciphertext payload truth. The recipient
must unwrap the accepted record and verify G against the scoped commitment. A
signed structurally complete wrong G gives KEY_REPAIR_REQUIRED, never fabricated
success or an automatic replacement key. Current distribution replaces prior
records but retains epoch identities. No forward secrecy claim.

## Independently known history

An explicit fresh-genesis local observation simulation initializes empty known
history only at policy/epoch zero. It is not proof that arbitrary server history
is empty. Observed accepted files must have a current writer, exact policy/epoch,
active author roster/certificate and signature, plus known same-object parents.
The private index stores exact immutable envelope digests and parent closure.
No simulated observation proves an actual server commit, durability or global time.

History records wrap the unchanged signed file checkpoint descriptor with a
logical sequence, predecessor history head, operation and current signer. Format
version 1 remains a format version, not sequence. Descriptor pages must match
both the private independent witness snapshot and all known revisions exactly.
Owner/editor may endorse that history; reader cannot. Old checkpoint counts do
not close newly observed revisions before admission. Sequence/head/operation,
current roster/signer, old descriptor signature and ordered inventory are checked.

A new/recovered client can import a complete checkpoint only with an independent
OOB head pin, matching signatures and current closure policy/epoch/rosters. A pin
from the same untrusted server is insufficient. Import trusts the qualified
writer's endorsement of that boundary; no global newest-state claim follows.
New writes remain quarantined when no independent history is known.

Historical file acceptance requires exact envelope inclusion in the independently
known index, its historical policy granting writer role, verified historical
roster prefix/active certificate and signature. New backdated old-key signatures
absent from that index are UNANCHORED_HISTORY regardless of timestamps. Current
read access still requires current membership/device authority. Test decryption
uses G -> manifest DEK -> encrypted manifest/file DEK -> chunk, with no uploader
DEK input. No byte candidate proves encrypted payload semantic truth or availability.

## Resource limits and evidence scope

Default wire 64 KiB; epoch intent/commit 256 KiB; grant page 1 MiB; depth 32.
At most 20 related accounts, ten current members, 32 devices plus recovery per
member, 1,000 retained epochs, 330,000 logical grants, 1,000 grant pages. Staged
reference aggregate is additionally 16 MiB, so these maxima cannot all coexist.
Combined policy/epoch/history journal: 1,000 events and 16 MiB. Terminal operation
budget: 4,096. Existing history: 100,000 records/200 pages/500 records per page;
reference page aggregate and local observed envelope bytes additionally 16 MiB.
These are bounded candidate limits, not demonstrated production scalability.

Frozen public inputs replay eight policies, six epochs, 105 sealed grants, five
checkpoints, three accounts, enrollment/role loss/removal/transfer/archive/reset,
and a real 50-byte historical file. Seed bytes are explicitly PUBLIC TEST;
random sealed boxes are frozen inputs, never RNG substitutions. Two-page 501-record
serialization tests use cloned placeholder signatures and do not claim those
records satisfy authority/coverage. Adversarial tests distinguish key access from
writer privileges and exercise partial/stale/CAS/expiry/cancel/history ambiguity.

The independent PHP runner uses pinned PHP 8.4.26/native sodium 1.0.18 and its own
restricted ASCII fixture serializer. It reproduces root/device crypto, signatures,
page framing/commitments, all 105 unwraps, history/file bytes and tag/AAD negatives.
Its assertion count includes serializer preconditions; it is not a general PHP
parser/group verifier or production auth/SQL test. Rust/browser/physical group
interoperability, concurrent durable transactions, actual authenticated sessions,
recent-auth transfer and qualified security/composition review remain NOT RUN.

Rollback: ordinary revert of isolated additions; no production data or migrations.
No new owner device action, test-kit release or deployment is needed for this slice.
