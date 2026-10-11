# P02 identity and recipient candidate

Status: **CANDIDATE p02-identity-c1**, public synthetic evaluation only. This
batch implements exact root derivation/kit/identity bytes, provisional device
certificate signatures, recipient sealed records/coverage and a linked small
file cryptographic path. It does not activate devices, authenticate pairing,
verify a roster/policy chain, implement reset or grant server access. Qualified
review NOT RUN/booked; no real-secret or production acceptance.

The closed [schema](../packages/contracts/p02-identity-c1.schema.json),
[registry](../packages/contracts/p02-identity-c1.registry.json),
[codec](../packages/protocol/src/identity-codec.mjs) and
[synthetic crypto reference](../packages/protocol/src/identity-crypto.mjs) are
all mandatory. Original specification and p02-file-c1 bytes remain unchanged.

## Bytes, derivation and offline kit

Use the existing strict raw UTF-8 parser and RFC 8785 library. This candidate
caps each raw structure at 16,384 bytes, nesting at 32; all fields are required
and closed. IDs are canonical unpadded base64url 16 bytes, fingerprints/keys
32, Ed25519 signatures 64. Decimal counters are strings in [0, 2^63-1].
Never normalize Unicode, discard duplicate properties, repair checksum errors,
coerce a phrase into R or silently fall back on an unsupported version.

Every prefix below is UTF-8, ends in exactly one byte 00, then is followed by
exact typed JCS bytes without newline. `D` is the validated derivation-context:

```
{"purpose":"account-root-derivation","contract":"p02-identity-c1",
 "protocol":"anynote","protocol_version":1,
 "service_id":"<16 bytes>","account_id":"<16 bytes>"}
```

R must be locally CSPRNG-generated 32 bytes, not a password/short PIN.
The reference generateRecoverySecret uses libsodium randombytes_buf(32). Compute:

```
salt = SHA256(UTF8("AnyNote/p02-identity-c1/hkdf/extract-salt\0") || JCS(D))
info_sign = UTF8("AnyNote/p02-identity-c1/hkdf/root-signing-seed\0") || JCS(D)
info_recovery = UTF8("AnyNote/p02-identity-c1/hkdf/recovery-encryption-seed\0") || JCS(D)
signing_seed = HKDF-SHA256(IKM=R, salt=salt, info=info_sign, L=32)
recovery_seed = HKDF-SHA256(IKM=R, salt=salt, info=info_recovery, L=32)
```

Use Node's maintained HKDF, libsodium `crypto_sign_seed_keypair` and
`crypto_box_seed_keypair` respectively. Never convert a signing key into the
recovery encryption key. PHP `hash_hkdf` and sodium independently reproduce the
public vectors. Service/account/candidate/protocol/purpose changes produce
other keys or reject unsupported input. No local-vault/wrapper/export/pairing
HKDF purpose is enabled by this API. Device signing/encryption keypairs use
independent libsodium CSPRNG calls, never derive from R or another device.

Human recovery secret: established Bech32m/BIP 350 through @scure/base 2.4.0,
HRP `anr`, payload `01 || R` (33 bytes), convert8to5 with standard padding and
six-character checksum. Canonical lowercase is exactly 63 ASCII characters,
standard 90-character bound; reject uppercase/mixed case, whitespace, wrong
HRP/version/length/checksum, nonzero leftover padding or normalization. Checksum
only detects mistakes; it does not authenticate an identity or make R safe to
share. It is an explicitly versioned random secret, not a cryptocurrency key.

The kit binds exact purpose/contract/protocol/version, service/account,
root_fingerprint, recovery_secret and full signed identity. It contains no
login credential, device private key, cached group key or network endpoint.
Recovery requires a separately pinned service/account/root fingerprint. Verify
kit identifiers, identity pin/signature, decode R, derive identity and require
byte-identical signed identity before returning ephemeral root/recovery keys.
A kit's own fingerprint is not independent evidence. Application login and
atomic root reset must precede envelope retrieval; neither is implemented here.
A future explicit export/print UI must explain that this offline kit is secret.

## Public identity and noncircular pins

Identity body includes account-root-identity purpose, candidate/protocol/version,
`derivation=hkdf-sha256-c1`, service/account, root_signing_key and
recovery_encryption_key. The signed record is `{body, signature}`:

```
sign_input = UTF8("AnyNote/p02-identity-c1/sign/account-root-identity\0") || JCS(body)
root_fingerprint = BASE64URL(SHA256(
  UTF8("AnyNote/p02-identity-c1/hash/account-root-identity\0") || JCS(body)))
```

Fingerprint excludes signature and itself. A signature change does not change
the pin but must still verify; either key/context change changes the pin.
Verify against an independently authenticated pin before accepting the public
key. The first trust ceremony and storage of pins are product work, not supplied
by the server or this fixture. A valid alternative self-signed identity fails
against the old pin. `verifyRootIdentity` produces a private WeakMap-backed
signature proof, never a caller JSON flag. Its result explicitly says
`authorization=NOT_EVALUATED`; returned public details are detached clones.

## Provisional certificates and delegated signatures

The certificate body binds protocol/purpose/candidate, service/account/root pin,
recovery_generation, predecessor_roster, issuer, device ID, separate signing/
encryption keys, sorted unique capabilities and pairing_transcript_digest.
Root issuer binds root fingerprint; device issuer binds device ID and exact
full certificate digest. Capabilities are a sorted subset of delegate-device,
distribute-group-key, receive-group-key, sign-content. They do not establish
membership or owner/editor/reader role. Equal public keys, self-delegation and
invalid bootstrap fail. Null predecessor is allowed only for root issuer at
generation 0. Root issuance at later generations requires a predecessor.

```
sign_input = UTF8("AnyNote/p02-identity-c1/sign/provisional-device-certificate\0") || JCS(body)
certificate_digest = BASE64URL(SHA256(
  UTF8("AnyNote/p02-identity-c1/hash/device-certificate\0") || JCS({body,signature})))
```

Verifier requires the identity proof and exact expected certificate body, plus
pinned issuer-certificate proof for delegation. A delegate must match service,
account/root/generation, exact certificate digest and delegate capability.
A valid root signature alone is not an approved registration/reset. A valid
delegate signature alone is not an active approving device: current roster,
transcript authentication, new-device possession confirmation, maximum device
count, session binding and atomic activation/CAS remain mandatory product gates.
`verifyCertificateSignature` deliberately proves signatures only. It cannot
reject an unknown revocation, certify a server roster, or release product keys.

## Signed recipient records and exact coverage

Grant context binds group-key-distribution purpose/candidate/protocol/version,
service/group/key_epoch/epoch_digest/membership_head/operation_id, issuer
(account/device/root/generation/current roster head/exact certificate digest)
and exact recipient. A device recipient adds device ID/certificate digest; an
account-recovery recipient has neither. Both bind account/root/generation/roster
head/encryption_key_fingerprint. No administrator recipient type exists.

```
encryption_key_fingerprint = BASE64URL(SHA256(
  UTF8("AnyNote/p02-identity-c1/hash/x25519-public-key\0") || raw32PublicKey))
inner = {purpose:"group-key-plaintext", context:grantContext, group_key:BASE64URL(G[e])}
sealed_ciphertext = crypto_box_seal(JCS(inner), exactRecipientPublicKey)
body = {context:grantContext, sealed_ciphertext:BASE64URL(sealed_ciphertext)}
sign_input = UTF8("AnyNote/p02-identity-c1/sign/group-key-distribution\0") || JCS(body)
```

Sealed ciphertext is 48..4096 bytes, canonical base64url; context/schema are
bounded before decryption. libsodium owns random ephemeral key generation.
Never seed, patch or replace its RNG for determinism. Public sealed boxes are
frozen as fixture **inputs**; recomputation checks deterministic keys, signatures
and file bytes, then independently verifies/decrypts those inputs. Creation
checks use actual random sealed boxes and verify different ciphertexts.

Before open: require exact expected context, certificate-bound sender and
signature, recipient key fingerprint plus public/private correspondence. After
open: strict inner purpose/schema and byte-identical context. A decryptable
sealed box from another signing key fails; a correctly signed box containing
wrong context fails; a correctly signed box containing wrong G fails file AEAD.
Authentication alone cannot prove an honest sender supplied the correct key.

Coverage: at most 60 recipients (candidate default 10 accounts * [5 devices +
1 recovery key]), all contexts share the exact operation/epoch/policy/sender;
each recipient account/type/device appears once. Every expected context must
have exactly one signed record, no extras/missing/duplicates/key replacement.
Trusted current policy/roster verification must build the expected list and
sender proof externally. Changed known roster/epoch invalidates old context;
this does not prove global freshness or authorize a rekey/write. Reader roster
maintenance, delegation descendant closure, revocation races and final atomic
epoch activation are the next state/authorization layer. Do not treat signature
proof tokens or coverage success as an activation/permission verdict.

## Linked file evaluation and evidence limits

The 79-byte public fixture links certified uploader signature and separate
recipient/recovery keys through G -> wrapped manifest DEK -> encrypted manifest
with independent file-data DEK -> exact original chunk bytes. No uploader DEK
or plaintext manifest is passed to receiver functions. Expected context and
sender public proof are explicit inputs. Digests, signatures, AEAD tags, strict
manifest fields and internal/public context agreement all verify. Altered keys,
rosters/epochs, sender/signatures, sealed inner context, wrap nonce, manifest
and chunk bytes fail without output. The reference file helper is capped at
64 KiB and materializes bytes; no mobile/1 GB/streaming memory claim follows.

Node 24.21.0 / libsodium WASM 1.0.22 and pinned PHP 8.4.26 / native sodium 1.0.18
reproduce these public key/signature/sealed/AEAD vectors. PHP canonicalization
is intentionally restricted to this fixture's ASCII property names, integer 1
and string values, with explicit preconditions. It is **not** a production
RFC 8785 implementation, duplicate-key parser or schema/authority verifier.
Full native Rust/browser/PHP production contract interoperability is NOT RUN;
P01 primitive results remain separately scoped. R01 gains a small synthetic key
path only, not full application/physical acceptance.

```
source scripts/runtime-env.sh
npm --prefix packages/protocol ci --ignore-scripts --cache /workspace/.cache/npm --no-audit --no-fund
npm --prefix packages/protocol test
npm --prefix packages/protocol run crypto:check
npm --prefix packages/protocol run fixtures:check
npm --prefix packages/protocol run inventory:check
python3 scripts/check-p02-fixtures.py
python3 scripts/dev-stack.py up
python3 scripts/check-p02-crypto.py
python3 scripts/check-secrets.py
python3 scripts/check_baseline.py
```

No fixture/inventory writes during setup. Preserve exact SRI/override for sodium
core 0.8.4 and notices; MIT scure, ISC sodium, Node's established HKDF. The primary
source receipt distinguishes old upstream library audits from review of this
candidate. Ten exact known public fields are rule/path/full-value scanner
exceptions; five PAT-path plus five changed key/digest negatives must fail.
No whole-file/path, arbitrary digest/key or partial decoded-value suppression.

## Open review and product gates

- Review exact HKDF seed API/profile, secret encoding/kit interoperability and
  independently authenticated first trust/pin recovery ceremony.
- Select established authenticated pairing/channel construction and exact
  transcript; provisional certificates cannot activate or release keys.
- Freeze append-only signed roster/enrollment confirmation/revoke/descendant/
  root-reset/session challenge/CAS schemas, checkpoints and transition verifier.
- Freeze signed group genesis/policy/roles/epoch intent/commit and historical
  authority/witness checks, exact recipients and revoke-during-stage invalidation.
- Freeze local wrappers and age archive; complete native/browser strict JCS and
  crypto interoperability, real key lifecycle/storage and platform memory tests.

R compromise permits future root signatures/resets; use new independently
verified identity/migration. Losing R and all working devices is unrecoverable;
no administrator path or ciphertext resurrection. Reference memory clearing is
best effort: JS strings, JCS/Buffer copies and GC/WASM cannot guarantee erasure.
Never retain these ephemeral root/recovery keys in everyday client state or
upload the kit. No production entrypoint is exposed. Normal revert removes the
candidate; no live content migration, deployment or owner trial is required.

Subsequent [pinned device-state candidate](P02_STATE_CONTRACT.md)
adds pairing/activation/revoke/reset verification in separate APIs. This does not
change these original signature-only bytes or grant group policy/history rights.
