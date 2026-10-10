# Cryptography, Key Hierarchy, and Wire Formats

## 1. Status and implementation rule

This document defines a candidate v1 protocol profile and mandatory invariants. It is not a claim that the composition has been audited. Before production use, phase P02 must freeze the complete schemas, canonical byte encoding, trust transitions, bounds, and deterministic interoperability fixtures. Subsequent changes require a protocol version and ADR. Use maintained libraries; never implement cryptographic primitives manually.

The backend validates public signatures/authorization but never receives plaintext content keys. A PHP sodium extension may verify public signatures; its presence is not a reason to perform content encryption on the backend.

## 2. Primitive profile

| Purpose | Candidate v1 choice | Constraint |
| --- | --- | --- |
| Content/key-wrap AEAD | libsodium XChaCha20-Poly1305-IETF | 32-byte key, 24-byte nonce, full authentication tag |
| Recipient key envelopes | libsodium crypto_box_seal | X25519-based sealed boxes; anonymity does not authenticate sender |
| Signatures | Ed25519 detached signatures | Separate signing keypairs; domain-separated messages |
| Public ciphertext digests | SHA-256 | Integrity addressing, not a substitute for signatures/AEAD |
| Secret derivation | HKDF-SHA-256 | Distinct versioned purpose labels and application/account context |
| Password-derived local KEK | Argon2id v1.3 | Salt and calibrated parameters persisted; bounds checked before allocation |
| Randomness | OS/browser CSPRNG via maintained library | Never timestamps, UUIDs, Math.random, or weak PRNG seeds |

Sealed boxes do not authenticate the sender. Each recipient envelope MUST be covered by a verified device signature and an authorized distribution record [SRC-08]. Do not treat algorithm names as a protocol specification.

## 3. Key hierarchy

| Key | Origin/storage | Purpose |
| --- | --- | --- |
| Recovery secret R | Random 32 bytes, generated locally; offline recovery kit | Root source for recovery authority, never ordinary login password |
| Account root signing key | Derived from R using a dedicated HKDF label | Bootstrap/recovery identity anchor; not retained on everyday devices |
| Account recovery encryption keypair | Derived from R under a separate label | Recover group keys from public-recipient recovery envelopes |
| Device signing keypair | Random on that device | Sign content and delegated account/device events |
| Device encryption keypair | Independently random on that device | Receive group-key envelopes |
| Group epoch key G[e] | Random per group/epoch | Wrap object DEKs and encrypt group-private key catalog data |
| Object/revision DEK | Random per new immutable encrypted revision | Encrypt one note payload, group metadata revision, or file version |
| Local vault key L | Random per device/account profile | Encrypt device secrets, cache records, local search, and outbox |
| Local unlock KEK | OS-protected mechanism, PRF-derived, or Argon2id-derived | Wrap L; never use a short PIN as the sole offline defense |

Private signing/encryption keys of one device are never copied to another. Distributing group keys to another authorized device is intentional; distributing another device's identity keys is not.

Recovery-secret derivation MUST bind the protocol name/version, purpose, account ID, and service installation ID with unambiguous encoding. The kit contains these nonsecret identifiers and encoding version. Root signing and recovery encryption seeds must differ. Use the library's seed-keypair APIs; freeze exact derivation in fixtures. R must have a checksummed human-readable encoding; a user-chosen phrase is not an equivalent substitute.

## 4. Public identity and delegation

An account's public identity record contains account ID, service installation ID, root signing public key, recovery encryption public key, protocol version, and root signature. Its fingerprint is derived from the canonical identity record. A mutable server account row is not the identity anchor.

Root authority enrolls the first device. Active authorized device certificates may delegate enrollment to new devices in the same account. The certificate binds both device public keys, device ID, account root fingerprint, account recovery generation, predecessor roster state, permitted device capabilities, and enrollment transcript digest. Normal devices can authorize same-account enrollment but cannot silently replace the root identity or recovery recipient.

The complete account roster is an append-only signed event chain with a root-signed recovery reset mechanism. Clients validate delegation against the roster state at the event, not merely whether a certificate exists. A removed device cannot enroll a new one using an old certificate after the client knows of its revocation.

## 5. Canonicalization and signatures

Use RFC 8785 JCS for structured signed headers, with a vetted identical interpretation on Rust, TypeScript, and PHP [SRC-09]. Reject duplicate JSON properties, invalid Unicode, nonfinite numbers, and unsupported fields in strict signed schemas. All large counters/byte lengths use canonical decimal strings. Use ASCII enumerations, base64url without padding for binary fields, and random opaque IDs that do not encode user names.

Define signing input as an unambiguous fixed application/purpose prefix followed by the canonical signed object. Different prefixes are required for identity, roster events, group membership, group epoch transition, object revision, key-envelope distribution, and recovery reset. Never concatenate arbitrary strings without a length or canonical container.

Object signature material includes: protocol/version, service ID, group ID, object kind and ID, revision ID, parent revision IDs, author account/device, membership version, relevant roster checkpoint, content encryption epoch, payload-schema version, nonce, ciphertext length and digest, and required key-envelope references. Do not accept an unsigned outer field overriding a signed inner value.

The exact field list for each operation must be frozen in schemas. Server envelope validation and client post-decryption validation are independent layers.

## 6. Object encryption

For every new immutable payload revision:

1. Generate a new random DEK and nonce.
2. Serialize the plaintext payload under its versioned schema. No compression in v1.
3. Build authenticated additional data (AAD) with immutable identity/context: service, group, object/revision, type, payload version, encryption epoch, and author identity as defined by the frozen schema.
4. Encrypt with AEAD; store nonce, ciphertext, and tag.
5. Wrap the DEK under the group epoch key with a fresh nonce and AAD binding DEK purpose, object/revision, group, and wrapping epoch.
6. Sign the envelope including ciphertext digest and key-wrap reference; commit as one logical operation.

AAD is authenticated but not encrypted, so it must not contain titles, filenames, tags, or body text. Changing immutable AAD requires a new ciphertext revision. Payload-size leakage is accepted in v1; padding can be a later versioned option.

Client verifies identity chain, operation authorization at the historical state, signature, AAD consistency, AEAD tag, and decrypted schema before display. A previously valid historical author remains valid for old records after being removed; new writes from that removed author are rejected. Distinguish historical verification from current permission.

A timestamp or reference to an old policy is not proof that a signature existed before revocation: a former writer may still possess its signing key and forge a backdated record. P02 must define signed history checkpoints bound into membership/epoch transitions, with an inventory commitment and inclusion/ancestry evidence for retained history. Locally witnessed pre-revocation revisions and revisions anchored in that history can retain historical validity. Unanchored purported old writes must not silently become trusted new content under a retired policy. No claim of universal trustworthy creation time or independent global freshness is made.

## 7. Group-key delivery

Each G[e] is wrapped independently for every active authorized device and each member account's recovery encryption public key. Recipient type, account/device ID, group ID, epoch, membership version, recipient-key fingerprint, issuer, and relevant roster checkpoints are authenticated by the distribution signature and verified after decrypting the sealed payload.

Recovery envelopes allow a recovered account to regain group keys it had received without storing R on everyday devices. Never include a global administrator recovery recipient. For shared groups, each admitted account gets its own recovery envelope; its recovery mechanism is part of that account's security boundary.

An account member may provide historical/current group envelopes to its own newly certified devices. It may not use that operation to admit another account or change roles. Group rekeying uses signed membership and current certified rosters, never unchecked server recipient arrays. An active reader can execute only a mandatory roster-change rekey with that exact fixed recipient set; this grants no content-writing or membership privilege. Owner/editor devices can additionally request optional rekey.

## 8. File encryption profile

Use immutable file versions with a fresh random file DEK. Candidate chunk profile: random 16-byte per-file nonce prefix followed by an unsigned 64-bit little-endian chunk index, producing a 24-byte XChaCha nonce. The prefix is selected once for a version and persists in encrypted manifest/state. This construction is subject to P02 review and exact test vectors; do not invent an alternative ad hoc.

Chunk AAD binds service, group, file ID, file version ID, encryption epoch, chunk index, actual plaintext chunk length, format version, and expected chunk count. Never reuse a file DEK/prefix/index for changed bytes. A reselected or changed source with unproven byte identity starts a new version/key; idempotent retry sends already-produced ciphertext.

The encrypted manifest MUST contain the fresh 32-byte file-data DEK, original name, client-detected type, total plaintext size, chunk size/count, nonce prefix, ordered ciphertext digests/lengths, and optional full plaintext digest. Encrypt it with a separate fresh 32-byte manifest DEK; wrap the manifest DEK under the group epoch using the ordinary object-key-wrap mechanism. The exact recipient path is device/recovery key -> group epoch key -> manifest DEK -> decrypted manifest -> file-data DEK -> chunks. Never put the file-data key in public headers, upload inventory, SQL metadata, or logs. The signed manifest envelope binds file version and ordered ciphertext inventory. All chunk AAD fields are reconstructible from authenticated manifest or immutable signed header and must agree with staging metadata.

The receiver validates the signed manifest envelope, decrypts it, then validates chunk count, order, digests, AAD, and tags. Reject missing, duplicate, trailing, substituted, or truncated chunks. Zero-byte files have zero data chunks and a valid authenticated manifest. Never present a partially verified file as complete.

Do not use secretstream as if it supported independent random-access chunk decryption. It remains a suitable alternative for a sequential export stream if separately specified [SRC-07].

## 9. Local unlock wrappers

All long-lived local content/identity secrets are encrypted under L. Wrap L using one or more independently revocable unlock methods. A valid wrapper is an alternate decryption path: the weakest enabled path limits security.

Argon2id fallback: freeze Argon2id v1.3 and the chosen binding's exact parameter semantics. For libsodium crypto_pwhash record alg, opslimit, memlimit and salt; do not equate another library's time_cost/parallelism parameters without byte-level vectors. Start measurement at memlimit=64 MiB and opslimit=3, targeting roughly 0.5–1.5 seconds on the slow supported device. v1 bounds for this profile: 64–256 MiB and opslimit 3–10, one KDF job at a time. A different profile/version is required beyond those bounds. Never silently reduce cost. Require a strong phrase and explain offline guessing risk; a short PIN is insufficient [SRC-06].

PRF: capability-test the actual passkey/provider/browser combination; use a separate HKDF context for local wrapping. PRF results, wrapper KEKs, and R must never be serialized to the server by a generic WebAuthn JSON helper. Login without PRF is valid but does not unlock content [SRC-10].

## 10. Revocation, rotation, and limitations

New group epochs use fresh random keys, and every new payload/file version uses a fresh DEK. Rewrapping a known DEK under a new group key does not revoke previously held knowledge. Old ciphertext and old key envelopes may remain for history and backups, with explicitly authorized current recipients.

The product is an archival vault, not a forward-secret messaging protocol. Recovery and retained history intentionally preserve historical decryption capability. Do not claim forward secrecy or post-compromise security comparable to a ratcheting messenger.

Root/recovery-secret compromise requires a new account identity or a reviewed root-rotation procedure, re-verification by group owners, revocation of old devices, new group epochs, and re-encryption where future confidentiality requires it. Merely changing the printable recovery kit cannot revoke a stolen root key.

## 11. Crypto release gate

Required evidence: exact schema registry; byte-level test vectors for every signed/encrypted structure; native/browser/PHP verification interoperability; known-answer library tests; wrong-key/tag/context tests; nonce-reuse prevention; sender-authentication checks; malformed JSON tests; key-rotation and recovery traces; threat analysis for pairing/roster equivocation; external qualified review with remediation tracking. Experimental builds may proceed with synthetic data before that review, but production-sensitive use remains gated.

## 12. Additional format invariants

A local-record AEAD envelope binds purpose, local account/profile/device, random record ID, schema version and nonce as AAD. Rewrites use fresh random nonces under L, not a counter that may roll back with SQLite/IndexedDB. Never persist private keys unwrapped under a claim of OS disk encryption.

Construct immutable content context/AAD first, encrypt next, hash ciphertext/key-wrap bytes next, and sign last. AAD cannot include the ciphertext's own digest or signature, avoiding a circular encoding. An object signature covers key-wrap ciphertext bytes through a digest, not merely a mutable database reference. File format/purpose identifies exactly which key is unwrapped.

Every enrollment records its delegating device. Compromise revocation invalidates transitive descendants; historical certificates remain verifiable at their historical state. No existing device may replace the root recovery recipient through a normal roster event. File 20 defines reset/fork and checkpoint behavior.
