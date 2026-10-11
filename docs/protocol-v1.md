# P02 protocol candidate: key custody and file context

Status: **CANDIDATE p02-file-c1**, synthetic evaluation only. This is the
reviewable P02-KEY-AND-FILE-CONTRACT slice, not the complete v1 protocol freeze.
Original specification 1.1.0 remains unchanged. The registry and schema are
[packages/contracts](../packages/contracts/registry.json); mandatory executable
predicates are in [the codec](../packages/protocol/src/codec.mjs).
Independent qualified design review is NOT RUN. No product endpoint consumes
this package and no migration, content encryption or key delivery is enabled.

## Key custody and recovery path

| Material | Creation / custody | Use and boundary |
| --- | --- | --- |
| R | Locally generated random 32 bytes; offline checksummed kit | Recovery authority; never server/login password or everyday stored secret |
| Root signing seed/key | HKDF-SHA-256 from R with distinct account/service/version/purpose context | Identity anchor and root recovery reset; clear practical memory after use; exact derivation/kit encoding pending next slice |
| Recovery encryption seed/keypair | Independent HKDF label from R; library seed-keypair API | Public key on server, private key only in deliberate recovery; separate from root signing |
| Device Ed25519 identity | Independently random on this device | Sign within certified current/historical authority; never clone to another device |
| Device X25519 encryption identity | Independently random, distinct from signing key | Recipient sealed boxes; certificate binds both public keys |
| G[e] | Random 32 bytes per group/epoch; encrypted under each local L | Wrap manifest/object DEKs; delivered only to exact certified device and account-recovery recipients |
| Manifest DEK | Fresh random 32 bytes per immutable file version | Encrypt manifest; wrapped under G[e] with fresh 24-byte nonce and bound context |
| File-data DEK | Separate fresh random 32 bytes per file version | Encrypt chunks; present only inside encrypted manifest/encrypted local state |
| L | Random 32 bytes per device/account profile | Encrypt identities, group keys, cache, search, drafts/outbox; never reused as an account/group identity |
| Unlock KEK/wrapper | OS-gated, credential-verified PRF/HKDF, or strong phrase/libsodium Argon2id | Alternate wrappers of L; weakest enabled path limits protection; no short-PIN-only defense |
| Export identity | Fresh independent age X25519 identity per export | Selected DEKs only inside encrypted age stream; exact archive profile pending |

The recipient path is device/recovery private key -> authenticated sealed G[e]
envelope -> G[e] -> manifest-key wrap -> manifest DEK -> encrypted manifest ->
file-data DEK -> chunks. A sealed box does not identify its sender. Require its
issuer signature, exact authorized recipient coverage and matching sealed inner
context before using G[e]. Those distribution/identity wire schemas are pending;
this slice takes a **previously verified** group epoch as a prerequisite, not
an unchecked SQL recipient array. No universal administrator recovery recipient.

Everyday clients keep R/root/recovery private keys out of ordinary vault storage.
Recovery requires account login plus root-authorized activation before fetching
recovery envelopes; it is not implemented by these codecs. Losing all keys and
R is unrecoverable; keys cannot recreate deleted ciphertext.

P01 Windows 0.1.4 supports only recorded synthetic fresh-process PRF/TPM/fresh
Hello/lock findings. A production wrapper still needs lifecycle/provider/account
and WebView2 evidence. iPhone selected-file success says nothing about passkey
PRF. Prove each PWA credential/provider wrapper before enabling it; otherwise
login remains possible but content requires the strong-phrase wrapper. Do not
interpret framework APP_KEY, a passkey login or a nonextractable browser key as
this content hierarchy.

## Encoding and version boundary

Every structure is selected by registry kind. Exact required fields and bounds
come from `p02-file-c1.schema.json`; unknown fields fail, including nested fields.
The JSON schema and codec predicates are both mandatory. The `p02-file-c1`
marker cannot be omitted or interpreted as a production-v1 default. Protocol,
file format and manifest schema each have explicit version fields; unsupported
versions fail closed. Candidate revisions require a new marker and reviewed
vectors before any product format is frozen.

Parse original UTF-8 bytes (maximum 1,048,576 bytes; depth <=32). Fatal UTF-8,
BOM, duplicate decoded property names (including escaped equivalents), comments,
trailing commas/data, nonfinite numbers and lone surrogates are rejected before
JSON.parse can erase ambiguity. Use jsonc-parser's visitor with explicit error
failure, not its fault-tolerant parsed value. Canonicalize validated structures
with maintained `canonicalize` RFC 8785 JCS, UTF-8, no trailing newline.
No Unicode normalization: composed/decomposed strings remain different bytes;
valid surrogate pairs are allowed. RFC property ordering uses UTF-16 code units.
The generic RFC comparison helper is not a substitute for typed schema decoding.

IDs are random opaque 16-byte values, digests 32 bytes, signatures 64 bytes,
XChaCha nonces 24 bytes; unpadded canonical base64url with exact decoded length
and a re-encoding equality check. Public fixture IDs/keys are sequential known
bytes only. Decimal strings use `0|[1-9][0-9]*`; counters <=2^63-1, file length
<=1,000,000,000, chunk count <=120, indices <=119. No numeric/exponent/leading-zero
counter substitution. The only JSON numbers are exact schema/version constants.
Roots/epoch/roster fingerprint derivations are not selected here: digest fields
are references whose authenticated producers must be specified in later slices.

## File fields, AAD and noncircular construction

`context` binds service/group/file/file-version/operation IDs; author account,
device, pinned root fingerprint, recovery generation and exact roster head;
exact membership head, epoch number and epoch digest; previous trusted history
checkpoint (or explicit genesis null); sorted unique previous file-version
references with full signed-envelope digests; file format and manifest schema.
Parents are limited to 32, ASCII base64url lexicographic order, no self-parent.
A file's previous versions remain in this file/group; the verifier checks their
resolved identities. A later entry publication binds attachment version IDs and
thread placement separately; this candidate is an unattached file commit, never
an unsigned way to insert an attachment into a different thread/group.

`framing` declares plaintext length, fixed chunk size `8388608`, derived count
and exact ordered `(index, ciphertext_bytes, ciphertext_digest)` parts. The
count is ceil(length/chunk size), zero for empty files. Every nonfinal chunk is
8,388,608 plaintext bytes; final length is the remainder. Ciphertext adds exactly
16 bytes per chunk. Empty files have no chunks but an authenticated manifest.
Maximum file: 120 parts, final plaintext 1,755,648 bytes and total data ciphertext
1,000,001,920 bytes. Manifest/wrap/control overhead is separately bounded and
counted by later reservation rules. No compression or padding in this candidate.

Construct in this order:

1. Create immutable context and fresh independent keys/nonces locally. Retain
   encrypted source commitments before using an index; nonce persistence alone
   cannot justify rereading changed bytes.
2. Chunk AAD is `(purpose=file-chunk, context, chunk_index,
   plaintext_chunk_bytes, chunk_count)`. Nonce is random 16-byte prefix followed
   by uint64 little-endian index. For candidate v1 only 0..119 are valid. Ciphertext
   hash is SHA-256 of exact ciphertext including tag; not plaintext. Chunk AAD
   cannot include its own digest or the final inventory.
3. After chunks, produce complete ordered framing. Manifest plaintext contains
   purpose, exact context/framing, 32-byte file-data key, 16-byte nonce prefix,
   original name (1..255 Unicode scalar values, no C0/DEL), client media type
   (0..127 printable ASCII), optional plaintext SHA-256 or explicit null. These
   private fields are never public headers/SQL/upload metadata/logs. Names are
   display metadata, never filesystem/archive paths. Serialize validated manifest
   with JCS, no compression; plaintext/ciphertext budgets must fit the 65,536-byte
   ciphertext cap including 16-byte tag.
4. Manifest AAD is `(purpose=file-manifest, context, framing)`. Encrypt with the
   independent manifest DEK and fresh 24-byte nonce. Its own ciphertext digest,
   key-wrap digest and signature are absent from AAD.
5. Wrap exactly the 32 manifest-key bytes under G[e]; XChaCha ciphertext is
   exactly 48 bytes including tag. Wrap AAD is `(purpose=file-manifest-key-wrap,
   context)`. Public wrap contains purpose/context/nonce/ciphertext. Its digest
   commits to the whole canonical wrap, including nonce/context/ciphertext.
6. Public header contains purpose/context/framing, manifest nonce, exact manifest
   ciphertext length (16..65,536), SHA-256 of its bytes and immutable wrap digest.
   Device Ed25519 signs header bytes under the fixed file-manifest signing domain.
   The final envelope is exactly `(header, signature)`, with no mutable outer
   routing overrides. Its digest covers the signature too, for parent/history
   references. Digests do not include themselves.

All AAD/signing/hash domains are UTF-8 literal bytes ending in a single NUL:
`AnyNote/p02-file-c1/{aad|sign|hash}/{purpose}\0`. This notation means byte 00,
not the two printed backslash/zero characters. Append **only JCS object bytes**;
never concatenate variable user strings. Registry lists signing/AAD purposes;
hash purposes are `key-wrap`, `file-envelope`, `history-page`,
`history-checkpoint`, `history-inventory`. SHA-256 raw ciphertext has no prefix.
AAD purposes and keys are separate; do not interchange wrapped manifest key and
file-data key. Actual signatures/AEAD are P05 work using selected sodium APIs,
not these serialization fixtures.

Changing context, source bytes or epoch requires a new version, fresh data and
manifest keys/nonces and publication attempt. Network retry resends byte-identical
prepared ciphertext. Rewrapping an old DEK cannot revoke prior knowledge. File
commit and entry attachment publication remain separate journaled transactions.

## Candidate history closure bytes and ancestry (R14)

An old membership number or timestamp cannot establish pre-revocation authorship.
A descriptor references its **previous** checkpoint digest, closed policy/epoch,
all relevant exact account roster/root/generation heads, record/page counts,
inventory digest and signer identity. Roster anchors are unique, sorted by
account ID, at most 10 (the selected small-circle sizing candidate). A descriptor
contains no signature or own digest. Sign its JCS bytes under history-checkpoint;
compute its reference digest under hash/history-checkpoint. Its detached
signature is authenticated separately. A predecessor's digest is never the
successor's digest. Closed policy's history reference must equal that predecessor.

Inventory records bind object kind (`group-metadata`, `thread`, `entry`,
`file-manifest`), exact object/revision IDs, full envelope digest, <=32 sorted
parent revision/digest references and payload status (`retained`, `pruned`,
`tombstone`). Payload pruning retains compact signed headers/signatures and
identity/policy evidence; a mere digest cannot manufacture missing evidence.
The candidate does not freeze encrypted schemas for the other object kinds.

Sort all records uniquely by ASCII revision ID. Pages have consecutive decimal
indices starting 0, same service/group, 1..500 records, <=1 MiB each,
<=200 pages /100,000 records total. Pack greedily in that order: add a record
only if count <=500 and canonical page bytes <=1 MiB; otherwise close the
page and start the next index. A nonfinal page with <500 records is valid only
if adding the next page's first record would exceed its byte cap. Counts alone
cannot determine page count for large ancestry records. Empty inventory uses zero
pages. Each page's digest is SHA-256(domain hash/history-page || JCS(page)).
Freeze the inventory commitment as SHA-256 of this byte sequence:

```
UTF8("AnyNote/p02-file-c1/hash/history-inventory") || 00
uint32_be(page_count) || uint64_be(record_count)
for page in index order:
    uint32_be(index) || uint32_be(page_record_count)
    uint32_be(JCS_page_byte_length) || raw_32_byte_page_digest
```

JCS length is UTF-8 bytes, not characters/base64 length. Decode/verify the complete
inventory before using its membership index. Reject missing/extra/reordered/
substituted pages, duplicate revisions, wrong context/count/digest, missing or
wrong parent digests/object kind/ID, self/cyclic ancestry. All required ancestors
are included, even after payload pruning. The selected record must match an
exact inventory record and its resolved signed envelope digest; knowing only
its object ID is insufficient. Full complete-inventory verification is the
baseline; no Merkle proof or single-page independent acceptance is claimed.
Caps and indexing need native/mobile measurement before production selection.

The **authorization predicates remain mandatory and unimplemented here**:
verify independently anchored account/device/policy/roster chains; the descriptor
signature and owner/editor authority at the actual closure boundary; its known
predecessor chain; inventory completeness against independently witnessed accepted
heads; and inclusion of the selected envelope with correct historic author
role/generation. A reader cannot sign unknown writer history even if it holds
G[e]. Its roster-only rekey never supplies writer authority. A fresh device must
receive authenticated checkpoints through pairing/recovery, not trust a server's
self-provided root/checkpoint. No surviving witness/closure means UNANCHORED;
quarantine or explicit fresh-provenance recovery, never automatic historical
acceptance. Known regressions/forks block publication; signatures cannot prove
universal newest state against an isolating malicious server.

Future membership/epoch wire transitions must sign intent first, stage closure
and distribution, then commit their immutable digests against expected policy
and roster heads. Removal denies access immediately and blocks writes without
waiting for this bounded inventory. The final transition does not go back into
its predecessor checkpoint or file AAD. This resolves byte-level cycles while
leaving the full concurrent transition schema for the next P02 slices.

## Receiver layering and review questions

1. Typed raw parse/canonicalization/bounds.
2. Independently pinned identity and authorized certified author/recipient.
3. Signature, exact expected context, policy/roster/epoch freshness and historical
   inclusion as appropriate; no outer-field override or reader-as-writer shortcut.
4. Wrap digest and exact bytes; authorized G[e] unwrap of manifest key.
5. Manifest ciphertext length/digest, AEAD tag, strict decrypted manifest schema,
   header/framing/context agreement, then chunk inventory/AAD/digests/tags.
6. Only fully verified output is complete; no plaintext fallback or partial render.

`checkFileBundle`, `checkManifestCiphertext`, `checkCheckpoint` return only
consistency success or safe error codes. They **do not authenticate**, accept
history, unwrap keys or authorize a write. Do not build a product acceptance path
from these checks alone. Exceptions never contain input values.

Review checklist (all independent-review answers outstanding):

- Are key isolation, recovery/public-recipient boundaries and eventual exact
  HKDF/kit/PRF contexts sufficient and compatible across sodium APIs?
- Are domain bytes, candidate versioning, payload limits and fixed framing
  unambiguous in Rust/TS/PHP and resistant to invalid Unicode/number handling?
- Does manifest-only key delivery cover fresh recipients without uploader cache,
  and do resume journals actually forbid key/nonce reuse on source/epoch change?
- Are checkpoint completeness, compact ancestry and predecessor/witness rules
  sufficient against backdated writers, reader closure, withheld revocation and
  forks; what availability/memory limits follow from the complete inventory?
- Do later transitions bind exact certified recipients/roles/generations and
  expected heads without recursive digests or a reader privilege escalation?

No reviewer is booked and no audit is claimed. Authenticated pairing, exact
root/recovery derivation, recipient sealed payload/distribution signatures,
roster/policy/epoch/reset/session operations, local wrappers, age archive,
production protocol freeze and Rust/browser/PHP crypto interoperability remain
subsequent tasks. R01/R14/R19 here have serialization/framing/design evidence
only, not the complete application regressions in original chapter 13.

## Reproduction, evidence and rollback

From the repository root, source scripts/runtime-env.sh, then:

```
npm --prefix packages/protocol ci --ignore-scripts --cache /workspace/.cache/npm --no-audit --no-fund
npm --prefix packages/protocol test
npm --prefix packages/protocol run fixtures:check
npm --prefix packages/protocol run inventory:check
python3 scripts/check-p02-fixtures.py
python3 scripts/check-secrets.py
python3 scripts/check_baseline.py
```

[Public fixtures](../fixtures/protocol/p02/vectors.json) carry exact canonical,
signature-input, AAD and nonce bytes as hex strings, digests as base64url. Known
key/signature/ciphertext fields are public framing-only placeholders, **not
valid encrypted/signed known-answer examples**. The restricted independent Python
reference reproduces these ASCII-key/schema-constant fixture bytes and standard
hash/nonce framing; it is not a hand-written production JCS implementation.
Node tests also check external RFC 8785 expected bytes and rejection mutations.
Fixture/inventory writes are intentional review commands, never setup actions.
No live keys, authority transition or product endpoint exists to roll back:
revert candidate additions as a normal commit, preserving original spec and P01.
