# P07 encrypted local persistence and lock boundary

Software implementation follows original 04/05/07/09/11/13/14. Hosted acceptance
is pending at this initial implementation snapshot; source/evidence/tracking are
updated after the actual gates. P07 is not device enrollment, group authority,
file publication, a production release or independent review.

## Custody and formats

Each service/account/device/profile has independent random L and encrypted
device signing/encryption keys. R, root signing/recovery keys, plaintext indexes,
native bearer credentials, filenames and note bodies never enter ordinary storage
or diagnostic output. The frozen P02/P05 local contexts, envelopes, phrase/PRF
wrappers and native AES-GCM inner wrapper retain their exact bytes and maintained
cryptographic implementations. Every local edit uses a new random 192-bit nonce;
no database counter is a nonce. A full unknown old local backup cannot prove
freshness after restart, but editing it never repeats a counter-derived nonce.

An additive `p07-local-v1` public manifest binds scope, pinned service/account/root
and the unique encrypted secret-record ID. Ed25519 input is the literal
`AnyNote/P07/local-manifest\0` followed by RFC8785 JCS of the closed body. The
locally encrypted device key authenticates it at unlock and sensitive operations.
Metadata alone cannot replace the pinned root. The manifest is not disguised as
a frozen export-evidence/cache object and conveys no current group permission.

Windows Hello stores an additive native custody container: a fresh random T is
wrapped with the preserved actual TPM RSA-OAEP-SHA256 operation; maintained
XChaCha20-Poly1305 under T encrypts the unchanged frozen native AES-GCM wrapper.
Its AAD is `AnyNote/P07/windows-native-custody\0` plus JCS of every outer field
except nonce/ciphertext. Unlock requires exact TPM public/Name reopen, fresh native
credential PRF and the TPM private operation. PRF alone cannot recover the inner
wrapper from disk. Native handles/current HWND and lock generations are verified;
no UI-consent boolean, cached signature hash or software PRF fallback exists.
Provider journals precede object creation and use a separate P07 RP/key namespace.
Pending owned journals require explicit recovery/cleanup; no other objects reset.

The explicit Windows phrase mode additionally uses current-user DPAPI around the
unchanged Argon2id phrase wrapper, binding scope/context as optional entropy.
DPAPI is account/OS protection, not physical presence. Failure of Hello never
automatically enables phrase mode. PWA always keeps an explicit strong phrase
fallback; optional PRF uses the exact credential/salt/context and an actual
32-byte platform result. Ordinary WebAuthn login does not require PRF, and the
generic auth serializer never sends PRF results/KEKs to the API.

## Transactions, migration and fencing

Native SQLite schema 1 has only public JSON control metadata and `(opaque id,
encrypted frame)` rows. WAL uses FULL synchronization; temporary SQL data stays
in memory. IndexedDB schema 1 has the corresponding two transactional stores.
Upgrade/create transactions are atomic. Unknown database/schema versions are
preserved and refused; no destructive downgrade or erase-on-401 exists.

Draft/outbox/cache batches commit together before local-save acknowledgement.
Publication attempts retain immutable IDs/digests/signed bundle bytes; ambiguous
responses retain SENT_UNKNOWN rather than preparing a second publication.
Only replaceable cache rows may be evicted; drafts/outbox/pending work are retained.
The transactional writer lease has a random owner, increasing fence and ten-second
deadline. Old leaders cannot update after replacement. Lock generations and
capabilities are separate from leases, API sessions and device trust.

Removing PRF unlock methods rotates L and atomically streams every record into
fresh encryption under the new phrase-only path. A failed rotation preserves
the prior key/wrappers/records. Old wrappers cannot open new local ciphertext;
old backups may retain old data and device keys. Exposed device keys require
device revocation/new enrollment, not merely local-wrapper deletion.

Native refresh requests first persist an opaque nonsecret pending marker. One
request owns a rotation; unknown/crashed outcomes require fresh login, rather than
automatically replaying a consumed refresh. New credentials replace the encrypted
record and clear its marker in one transaction. No IPC route reads/adopts tokens.

## Lifecycle and shell

Main-window native IPC uses closed typed requests and a native-runtime window/
origin binding, with preview/remote windows denied. Unlock returns an opaque
capability. Native decryption/signing rechecks current generations, epoch, timeout
and signed manifest. WTS lock/suspend/close invalidate immediately; reachable keys
are wiped or deferred until a busy operation releases its mutex. An idle watchdog
scrubs after five minutes. Actual OS event classification is not a physical trial.

The static `/auth/vault.html` shell discovers only public installation identifiers,
starts locked, supports phrase/verified PRF unlock, fresh P06 both-key proof,
lock/logout, explicit wrapper removal and storage-persistence requests. P06 root
bootstrap happens in a dedicated worker; device keys are saved encrypted before
account registration completes. Interrupted pre-registration preparation may
restart with a new unregistered identity; no everyday R/root persistence is added.

Hide/pagehide masks synchronously, terminates the owned worker, rejects old
results, broadcasts per-profile locking and persists a new shared epoch. Other
profiles are independent. KDF admission is transactional across origin windows;
termination releases only that worker's admission lease. Cooperative save-and-lock
waits for encrypted durability; forced termination can lose an unacknowledged edit,
but never silently erases previously acknowledged work. Callers persist progress
before opening system sheets. PRF results received while locked need a fresh
visible continuation; no automatic prompt/unlock loop exists.

The optional service worker caches a closed set of app-origin static resources
only. API/auth/kit/plaintext/dynamic responses are excluded. Activation neither
upgrades nor deletes local data/outbox. Browser-wide eviction still requires
enrollment/recovery. JavaScript/GC/Wasm/OS copies and crash dumps prevent promises
of perfect erasure; device memory/OS/provider acceptance remains P01/P14/P15.

## Dependencies and phase boundary

The new GPL native crate has a frozen 313-record inventory, rusqlite 0.40.2 with
bundled SQLite, maintained P05 crypto and P06 auth. Old locks/corpora/spec remain
unchanged. Unified proc-macro syn 3.0.8 is already pinned in P06, replacing only
P05's separate 3.0.7 in this new crate. The provider sources are copied byte for
byte into build output, with conventional Rust module layout; its GPL license
and official-header/fixture copies are checked. The only legacy lint adaptation
is the shared provider/filesystem Rust-2021 `collapsible_if` style under Rust 2024;
verification/ABI/sandbox/TLS/crypto assertions remain enabled.

P08 owns actual enrollment/delegation/revocation/reset/private-group genesis;
P09 editing/current group payload flows; P10 group authority; P11 sync/history;
P12 encrypted OPFS/native file caches and durable file-source/resume. No fake
group/roster is created by the minimal P07 shell. Current device proof only upgrades
a current account session; it does not replace local custody or group permissions.

Reproduce with pinned tools and the owned P03/P06 stack. Read-only setup uses
`cargo ... --locked`, `p07-native-inventory.py`, `check-p07.py` and ordinary
`p06-stack.py up/check`. Coding acceptance may explicitly reset only its marked
disposable P06 DB, then run `p07-http.mjs` and `p07-browser.mjs` sequentially.
Hosted sandboxed Chromium/verified TLS and Windows/MSVC are mandatory; cloud
sandbox BLOCKED is separate. Physical Hello/iPhone and qualified G2/G3 remain
open/unbooked/NOT_RUN. No deployment, release, production migration or outreach.
