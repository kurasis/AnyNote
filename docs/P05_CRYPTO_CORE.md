# P05 client cryptographic core

Implementation: `packages/crypto-core` (Rust) and
`packages/protocol/adapters/core.mjs` (Node/browser). Inputs are raw UTF-8 bytes,
not objects reconstructed from untrusted JSON.parse. All five frozen profiles
and the 55 complete-contract definitions are available. A codec validates closed
schemas plus the frozen semantic predicates; it establishes no policy authority.

Maintained libsodium handles Ed25519, XChaCha20-Poly1305, X25519 sealed boxes,
Argon2id13 and CSPRNG. Native RustCrypto/WebCrypto handle HKDF-SHA256 and
AES-256-GCM local native wrappers. JCS uses serde_json_canonicalizer/ryu-js and
canonicalize. Offline jsonschema/Ajv resolve only bundled schemas. Scure/bech32
handle the frozen versioned Bech32m recovery encoding. No handwritten primitive,
plaintext fallback, server master key or dependency-lock replacement is introduced.

## Supported operations and ownership

- Native `Codec::decode/encode/signing`, browser `decode/publicSigningBytes`:
  bounded raw JSON, fatal UTF-8, duplicate decoded names, lone surrogates, BOM,
  nonfinite numbers, comments, trailing values and depth over 32 are refused.
  General JCS follows IEEE754/UTF-16, including numeric rounding and key order.
- `objects` / browser `sealObject/openObject`: independently trusted context and
  author public key, wrapped fresh object DEK, signed public header, exact lengths/
  digests, AEAD, and closed decrypted payload/internal-reference validation.
  Cryptographic validity does not imply current read/write permission.
- Root derivation/identity/recovery kit: frozen service/account/purpose separation,
  pinned identity fingerprint/signature and derived-identity agreement. Device
  signing and encryption keys are independently random. Recovery APIs are explicit;
  normal vault key custody is P07/P08, not storage of R in everyday clients.
- `seal_grant/open_grant` / `sealGrant/openGrant`: signed outer distribution,
  independently authorized issuer key and exact epoch/recipient context, recipient
  public/private correspondence, then authenticated matching inner context. A
  decryptable box from another signer is refused. Roster/role transitions are P08/P10.
- Local phrase/PRF/native wrappers bind their entire descriptor/AAD and purpose.
  Native AES uses the frozen PRF profile, not a software eligibility fallback.
  This module does not verify hardware/provider authorization or create Hello/TPM
  objects. Descriptor inputs cannot include caller-selected nonce/ciphertext.
- `FileWriter`: fresh file/manifest DEKs and prefix owned by one sequential
  preparation, at most one 8 MiB plaintext chunk per call, exact last length and
  part count, no caller index/nonce/DEK and no resume-by-reencryption API. Finish
  encrypts the name/media/file key inside the manifest and signs its public frame.
  `FileReader` receives a raw closed export-file record, verifies framing, context,
  signature, wrap/manifest/chunk digests and tags, and only reports completion
  after all chunks and the optional full plaintext digest. Incomplete, extra,
  reordered or damaged data cannot complete. Decrypted chunks are staging bytes;
  the application must not advertise a complete file before finish succeeds.
- `HistoryAnchor`: separately pinned signed checkpoint, complete ordered inventory
  commitment, predecessor relation, parent closure and acyclicity; exact note and
  file envelope inclusion. Earlier-policy records may be included in a later
  closure. Timestamp/policy claims alone never establish historical trust.
  Callers independently verify the checkpoint signer/current state; this index
  is not the P08/P10 account/role state machine or a Merkle/freshness oracle.

Output JSON is newly constructed trusted data. Native signing of a constructed
Value is distinct from raw decoding at a trust boundary. Browser FileReader takes
raw bytes even for its outer frame so duplicate/unknown properties cannot be lost.
PHP `PublicProtocol::signedFrame` admits only closed public signable definitions;
never decrypted payloads, recovery kits, local/vault data or private keys. Its
public ASCII-property/small-integer JCS subset is tested against both clients;
Kanon's incomplete general float serialization is not used for client payload JCS.

## Resource and lifecycle decisions

Argon2id parameters/salt/phrase are validated before allocation: 64–256 MiB,
3–10 operations, 16-byte salt, 24–1024 UTF-8 phrase bytes and at least five words.
A native process mutex and a browser module/worker gate allow one KDF at a time;
actual concurrent jobs are tested. The dedicated Worker/RPC adapter waits for
READY, caps each request at 8 MiB/six arguments, allows one pending operation,
returns fixed typed errors and supports termination. Worker methods never persist
keys or log rejected input. App lock generation/multi-window fencing are P07.

Factories choose all encryption nonces with CSPRNG; object/file keys are fresh,
local nonces are random rather than rollbackable database counters. File chunk
nonces are the frozen random-prefix/u64LE-index construction. Repeating a completed
index or modifying a source for reencryption under that preparation is refused.
A restart/source change must use a new immutable version/operation and fresh
factory. Durable source identity, ciphertext retransmission, reservations and
crash reconciliation belong to P12; public revision uniqueness is separately
server-enforced. No API exports a writer's file DEK for reuse.

Native byte secrets use zeroizing owners, browser temporary key/plaintext byte
buffers are wiped on completion/failure where owned. Parsed JSON/immutable strings,
GC, registers and allocator copies cannot be guaranteed erased. This is not
complete P07 vault/lock custody, secure RAM erasure or a physical acceptance claim.
The checkpoint helper explicitly limits a collected verification batch to 200
pages/32 MiB; it refuses larger input before building its index. P11 must supply a
streaming/persistent index for maximum-scale inventories; this is a resource error,
never acceptance of a partially verified inventory or a smaller product limit.

The actual desktop 1 GB measurements are in test evidence. Native and real Worker
process one 8 MiB plaintext chunk at a time and persist only ciphertext in their
owned temporary directory/OPFS namespace. UI timer and sampled Chromium process
RSS are measured, not a hard/mobile memory guarantee. Physical iPhone/WebView2,
older-device memory, full P01 matrix and qualified G2/G3 review remain open.

## P05 acceptance mapping

| Gate | Executed core behavior | Authority/lifecycle boundary |
| --- | --- | --- |
| C01 | Fresh Rust -> Worker and Worker -> Rust note/local/AES/grant/file bytes; frozen KATs | Actual hosted Worker required, cloud BLOCKED is separate |
| C02 | 146 frames, 173 closed-frame negatives, 28 independent JCS cases, 14 malformed byte cases, 21 public signature types | PHP receives public-only frames; client JCS is general |
| C03 | Wrong key/tag/nonce/AAD/group/revision; correctly signed public frames still fail AEAD or invalid decrypted schema/context | No partial plaintext result/fallback from object operations |
| C04 | Decryptable envelope with rogue issuer signature refused | Independently verified issuer/context supplied; P08/P10 establish current authority |
| C07 | Exact root/recovery and local/Windows PRF-purpose vectors, changed service/account and random separate device keys | Everyday root custody/recovery UI is P07/P08 |
| C08 | Actual four concurrent native KDF jobs; Worker/RPC concurrency; low/high parameters and short PIN refused | Bounds checked before allocation; one active process/module job |
| C10 | Owned sequential writer refuses repeat completed index/changed-source retry; fresh keys/nonces and no caller nonce/index | Restart uses new immutable version; durable source/resume transactions are P12 |
| C16 | Pinned full checkpoint/inventory/ancestry; anchored note/file accepted, newly re-signed backdated revision refused | No timestamp/current-role/freshness inference; absent independent witness stays unanchored |

Browser callers use the dedicated worker for expensive crypto, rather than doing
Argon2id/file work on the UI thread. The direct module is also used by native/Node
integration tools. Startup waits for READY with a bounded timeout; closing a
pending initialization or operation rejects it and terminates the owned worker.

## Reproduce

After frozen environment installation and `source scripts/runtime-env.sh`:

```sh
cargo fmt --manifest-path packages/crypto-core/Cargo.toml --check
cargo clippy --manifest-path packages/crypto-core/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path packages/crypto-core/Cargo.toml --locked
python3 scripts/p05-native-inventory.py
python3 scripts/p05-port-codecs.py
cargo build --manifest-path packages/crypto-core/Cargo.toml --locked --release -j 4
P05_PROFILE=release node experiments/p01/p05-crypto.mjs --large
python3 scripts/check-p05-php.py
```

The owned P03 PHP stack must be running. Local cloud sandbox restrictions may
use `--allow-cloud-sandbox-block` to collect independent Rust/Node results; a
BLOCKED browser is never PASS. Mandatory CI runs without it on Ubuntu and also
executes the native/Node corpus on real Windows/MSVC. No sandbox disabling.
All upload reports are metadata-only. Ignored public corpora/peer ciphertexts are
not release assets or product credentials. Default drift checks never rewrite
tracked schemas, corpora or dependency inventories. Explicit development writers
are distinct from installation. Existing P01/P02/P04 locks stay byte-identical.
