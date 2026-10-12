# Private groups and encrypted notes

P09 is being implemented; final hosted acceptance is pending. The development UI
is /auth/notes.html. Authentication, local unlock, active device proof and private
group authority remain distinct. Full Windows/PWA host packaging is P14/P15.

## Current implementation

Private group creation uses the same verified frozen group-c2 genesis as P08,
including every current device and the account recovery recipient. Group keys
stay under L; the server stores only signed public history and sealed grants.
Current private ownership, signed heads, roster, epoch and maintenance flags bind
actual P04 revision/CAS/quota/receipt/commit-order transactions. Titles, bodies,
checklists and preferences use real P05 fresh-DEK AEAD; PHP has no plaintext path.

The dedicated Worker and native main-window capability expose closed note
commands. Their protected local catalog binds encrypted evidence, frozen drafts,
immutable outbox attempts and known verified cache witnesses. An unknown outcome
retains the same operation and signed bytes. Newer local text remains recoverable.
Verified acknowledgement retires only the exact published draft; SQL/IndexedDB
failure rolls back retirement. Known history cannot be silently replaced.

p09-local-v1 is an explicit additive AEAD profile, separate from frozen P02
records: XChaCha20 under L, fresh nonce24 and JCS scope/root/record context with
AnyNote/P09/local-content NUL AAD. The control ID hashes JCS with the separate
AnyNote/P09/local-control NUL domain. Rotation covers old and new records.
The catalog is bounded to 100 groups and 512 drafts/attempts/witnesses; P11 owns
scale, indexing and journal compaction. R/root remain transient, not everyday
vault secrets. Old clients refuse unsupported operations instead of erasing data.

## UI and trust boundaries

The UI separates local durability, sending, unknown results, committed service
receipts and explicit conflicts. Offline work is encrypted locally. Markdown uses
maintained markdown-it15.0.2 with HTML disabled, a closed DOM renderer, safe
absolute HTTP/HTTPS links and no automatic remote-image fetch. It never inserts
user HTML or relaxes CSP. Checklists use stable IDs and revision conflicts.
Favorites/preferences use the hidden private settings group and its full grants.

Signed mathematical validity alone does not establish historical timing. A
currently revoked author cannot introduce unwitnessed backdated content. Locally
witnessed old ciphertext remains verifiable; a fresh client without independent
history receives an explicit UNANCHORED state. General policy/epoch/history
maintenance is P10/P11; P09 must retain blocked drafts, not clear those flags.
Group membership/sharing, full sync, file transfers and production deployment
retain their later phase ownership.

## Actual validation so far

Exploratory dirty-source runs passed six portable crypto/transaction-model suites,
five actual native SQLite/IPC/fault/rotation/restart tests, sixteen native-process
and maintained PWA-adapter interoperability checks, and 81 actual verified HTTPS/
MariaDB checks. These are not the final clean-source acceptance receipt.
Local Chromium sandbox is BLOCKED; required hosted browser/Windows acceptance
retains real sandbox, TLS, CSP and official-header ABI. No new owner hardware
objects/trial, qualified review, production migration/deployment or release.
