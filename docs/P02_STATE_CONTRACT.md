# P02 pairing, device roster and recovery state candidate

Status: **CANDIDATE p02-state-c1**, isolated synthetic evaluation. This adds
current device authority to the unchanged [identity candidate](P02_IDENTITY_CONTRACT.md).
It does not implement product account authentication, persistent transactions,
group policy/history authorization, real QR UI or qualified protocol review.
Original specification 1.1.0 and previous candidate schema/vector bytes remain
unchanged. See [registry](../packages/contracts/p02-state-c1.registry.json),
[closed schema](../packages/contracts/p02-state-c1.schema.json),
[reference](../packages/protocol/src/roster.mjs) and
[public inputs](../fixtures/protocol/p02/state-vectors.json).

## Pairing construction and independent trust

Use the established libsodium `crypto_secretstream_xchacha20poly1305` API with
a freshly generated 32-byte random, one-use pairing key transferred in QR over
an authenticated user/OOB ceremony. This is separate from R, login credentials,
device keys and group keys. The untrusted relay receives ciphertext frames,
never the QR channel key. A random library header starts each single-message
stream; require authenticated `TAG_FINAL`. AAD binds message purpose, direction
and exact offer/invitation/transcript digest. Each role sends/receives a message
purpose once per channel handle; final transcript verification supplies protocol
ordering and enrollment dependencies. Role reflection, key/AAD/header/tag
substitution, replay and nonfinal authenticated streams fail closed. This is
not a short-code password protocol; it makes no forward-secrecy claim. Disclosure
of a QR key exposes its recorded channel. Delete/close channels after use or
cancel; do not send QR contents to telemetry or share QR screenshots.

The upstream secretstream primary source and package/license/API receipts are
in [source evidence](evidence/p02-state-primary-sources.json). Reuses locked
wrappers/core 0.8.4 (ISC), Node/WASM sodium 1.0.22; independent PHP uses existing
pinned sodium 1.0.18. This composition requires qualified review. A library's
security reputation or older audit does not review this protocol.

Two modes avoid requiring a camera on Windows:

| Mode | QR display / scan | Relay exchange |
| --- | --- | --- |
| `new-device-offer` | New Windows displays signed offer + random key; existing phone scans | Existing device signs response/approval; new device confirms |
| `existing-device-invitation` | Existing Windows displays signed invitation + random key; new phone scans | New device sends signed offer, existing replies/approves, new confirms |

Both sides must compare service/account/root pin, current head, device identity
and requested capabilities in an explicit owner ceremony before approving.
An existing device already knows the independently pinned identity and current
roster. A new device receives the root fingerprint/head through authenticated
OOB, fetches complete signed history and verifies replay against that head; it
must not accept identity/head from the same untrusted relay as its sole pin.
The invitation includes approver certificate digest; the offer includes both
new keys and restricted-session binding. Full transcript includes signed
invitation or explicit null, signed offer and signed response; digests cover
entire signed records. All records bind operation/account/service/root,
generation/head/nonces/expiry as defined in the schema.

The evaluator is passed an already pinned roster; QR scanning, root/head import,
user intent/confirmation, camera accessibility and relay transport are
**SIMULATED/NOT IMPLEMENTED**. No visual short-code comparison is supplied. The
secretstream helper alone never authenticates user intent or a new root.

## Exact bytes and resource limits

Strict UTF-8 JSON parsing occurs before schema validation: duplicate names,
escaped-name duplicates, BOM, invalid Unicode, nonfinite numbers and trailing
content are rejected. JCS uses the existing maintained serializer. All structures
are closed; unknown properties fail. Counters/timestamps are canonical decimal
strings in unsigned 63-bit range. IDs are canonical unpadded base64url 16 bytes,
keys/digests/nonces/bindings 32, signatures 64, secretstream headers 24. Binary
fields require canonical re-encoding and decoded-byte bounds. Device capabilities
and revoke target/closure arrays are sorted unique; signing/encryption device
keys are distinct and cannot reuse historical device IDs/keys.

- Raw state structure: 65,536 bytes, depth 32; QR: 8,192 bytes.
- Sealed challenge: at most 4,096 bytes; frame ciphertext: at most 16,384 bytes,
  plaintext at most 16,367 bytes including authenticated final-tag overhead.
- Replay: at most 1,000 events and 16 MiB aggregate; provisional operations: 32;
  terminal pending IDs: bounded staging budget 4,096; evaluation sessions and
  challenges: 256 each. Resource exhaustion denies further evaluation; persistent
  compaction/retention and production quotas remain unimplemented.
- Active-device cap is root-signed at registration, default 5, candidate range
  1–32. Reset cannot change it; no silent eviction. Policy changes need another
  reviewed contract. Historical records are retained independently of active cap.

Signature bytes: UTF-8 `AnyNote/p02-state-c1/sign/{body.purpose}` + byte `00` +
JCS body. Hash: SHA-256 of UTF-8 `AnyNote/p02-state-c1/hash/{kind}` + `00` + JCS
whole typed record. AAD: UTF-8 `AnyNote/p02-state-c1/aad/pairing-channel-frame` +
`00` + JCS channel-context. Certificate/root/recipient bytes and domains remain
`p02-identity-c1`; file/checkpoint bytes remain `p02-file-c1`.

## State transitions and activation

Every journal event binds scope, unique operation ID, exact predecessor head,
version increment and generation. Head digest covers full signed event. Root
registration starts version/generation 0 at null predecessor and activates the
first root-certified device only with signing and encryption possession.
Enrollment/revoke keep generation; reset increments it and never replaces root
identity. A trusted client replays from its independently pinned root and compares
result to an independently retained/OOB head. This detects known regression/fork
or truncation, not an unobserved global fork or dishonest server's global freshness.
Historical replay does not evaluate old timestamps against today's wall clock.

Enrollment has distinct stages:

1. New restricted session, signed offer and authenticated pairing transcript.
2. Active delegate signs provisional certificate and approval. Approval includes
   a fresh sealed encryption-possession secret with a typed digest commitment.
   Requested capabilities must be a subset of the approving certificate.
3. New device decrypts secret and signs confirmation binding exact transcript,
   certificate, approval, session and head. Its signed final event supplies both
   key proofs. A provisional certificate never enables key delivery/session trust.
4. Live authority rechecks current active delegate, pending exact approval,
   one-use operation, restricted session, expiry and head/cap before the sole
   append/session-upgrade mutation. A changed head invalidates all pending work.

Pairing lifetime is at most 10 minutes. Explicit cancel/expiry is terminal for
that pending operation. Retired pending IDs/keys/session bindings cannot be
recycled; a fresh enrollment needs fresh keys and a fresh restricted session.
Competing approvals can be staged but only a transition
against the current head can append. Exact receipt retry is idempotent only for
same event digest and original live session binding; changed bytes under same
operation or another session fail. Receipts never reactivate a revoked session.

Private WeakMap proof/session handles cannot be forged by passing booleans,
public JSON or `authorization` labels. `activeCertificateForEvaluation` and
roster-gated recipient APIs check active generation/capabilities/current exact
head. They return `device_roster_authorization=VERIFIED_FROM_PINNED_CHAIN` and
`group_authorization=NOT_EVALUATED`. Older signature-only APIs preserve their
`authorization=NOT_EVALUATED`; historical certificate retrieval does not approve
historical content or writers. Group key possession never implies write authority.

## Compromise revoke and reset

Revoke requires an active surviving delegate's signature over explicit targets
and their exact transitive active descendant closure. The signer cannot be in
that closure. Revoke invalidates affected devices and simulated sessions plus
all pending operations/challenges, and indicates groups require maintenance.
It cannot retract already disclosed plaintext or group keys; subsequent group
policy/rekey processing is mandatory and remains pending.

Root reset deliberately separates account login from offline recovery authority:

1. Independent recent account authentication supplies a restricted session.
2. Authority issues a one-use 60-second challenge binding service/account/root,
   session, current generation/head, new device ID/keys, nonce and reset intent.
3. New device proves signing and encryption possession; offline R-derived root
   signs certificate/event against the existing independently pinned identity.
4. Current-head transition increments generation, revokes all old active devices,
   sessions and pending work, then upgrades only this proved new session. Recovery
   recipient contexts become eligible for this generation, but product group-key
   retrieval still requires subsequent policy/history checks.

Normal device login also requires an issued one-use current-head dual-key proof.
Evaluation account login is an explicitly simulated helper, never an implemented
P03 authentication endpoint. Recent authentication: 5 minutes; simulated session:
15 minutes. Caller-supplied trusted BigInt clock must be monotonic; failed requests
can advance that clock but cannot append a roster event. No wall-clock source or
clock synchronization is implemented. Unissued/stale/replayed/cross-session
challenges, replaced root, old generation and reused historical keys fail closed.
Root compromise is not repaired by same-root reset: separate identity migration,
revocation dissemination and out-of-band verification must be designed.

The authority ledger is single-process memory. Mutation is atomic only within
this synchronous evaluation, not crash-safe SQL. Production must atomically lock
head/operation/challenge/session, verify account authentication and consume
challenge/invitation, append journal, invalidate old sessions/pending, and expose
idempotent receipts in one durable transaction. No migrations/routes or actual
account/session database are added here. Server never receives R/root private
key/recovery private key/group plaintext in this candidate design.

## Evidence and remaining review

189 Node tests include both QR modes, full signature/transcript substitution,
provisional denial, dual-key proof, cap/CAS/concurrent reset, terminal cancel,
exact retry, ancestor compromise closure, session/challenge denial, malformed raw
input and active recipient gating. Frozen random library inputs are replayed;
RNG is never seeded/patched. Five event heads and seven secretstream frames in
both modes also reproduce through independent PHP/native sodium; 4,812 reported
assertions include serialization preconditions, not 4,812 independent crypto tests.
PHP implements only this public ASCII fixture subset, not a general strict parser,
JCS/schema or production session/authorization reference. Existing primitive and
79-byte file vectors are unchanged. See [test evidence](TEST_EVIDENCE.md).

Required review: authenticated scan/user intent/root import and QR leakage;
channel composition and phase ordering; key possession/capability amplification;
head-pin retention/server equivocation; durable atomic retry/challenge expiry;
cap/retention bounds; root compromise; historical authority and group rekey after
revoke/reset. JS/WASM/string copies/GC erasure are best effort. Full Rust/browser,
physical pairing and qualified review are NOT RUN. P02/G2 remains IN PROGRESS;
P01/G1 and product P03 gates remain open. No owner device action or deployment
is needed for this synthetic slice. Rollback is a normal revert, no production
migration or existing ciphertext format change.
