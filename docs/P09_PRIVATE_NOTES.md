# P09 private groups and encrypted notes

P09 implements the first private-note vertical slice. It uses the P04 transactional
backend, P05 frozen ciphertext formats, P07 local custody and P08 independently
pinned device authority. The original specification and prior locks/corpora are
unchanged. Hosted acceptance is recorded separately in TEST_EVIDENCE.md.

## Use the private vault

Open `/auth/notes.html` on the configured trusted app origin. Account setup and
device enrollment are on Account and Devices. Sign-in, local unlock and fresh
device proof remain separate. Choose a saved installation and its strong local
phrase. EN/RU controls cover private groups, encrypted titles, threads, Markdown,
stable-ID checklists, favorites, ordering, read markers and thread summaries.

Edits autosave after 500 ms to encrypted local drafts. Save on this device explicitly
acknowledges local durability; Save to service queues a signed immutable attempt.
Local save, syncing, synced, unknown, conflict and attention states are distinct.
Failures preserve acknowledged work. If a response is lost, Retry checks the exact
operation receipt before sending the same bytes again. An accepted older attempt
cannot erase newer local text. Only an unchanged acknowledged draft is retired,
atomically with protected cache/outbox state.

Concurrent edits keep both texts. Review the verified remote version, use it as
the base of a new revision, or keep your text as another entry. No automatic body
last-write-wins. Versions are immutable; trash uses signed tombstones. Restore
verifies the exact tombstone parent and publishes a fresh explicit restore revision.
Thread archive is a signed metadata change. Group membership/epoch maintenance is
P10 and group history/sync scale is P11.

For another trusted installation, enroll it through P08 mutual QR approval, then
deliver the selected private-group key. Only current active own-account devices
are eligible. Independent device keys remain under each installation's random L.
The key picker identifies opaque device IDs; it does not turn account login into
device trust. Revocation/key-maintenance flags block publication and retain drafts.

## Transport and server persistence

The closed additive `p09-notes` component brings generated contracts to 242
structures and 94 operations. Private group creation reuses full signed group-c2
genesis with all active-device and recovery grants, under account locking. Settings
genesis must exist first. General shared-group operations remain unavailable.

Current session/device/account/group authorization applies on every read/write.
Private groups cannot be read or mutated by another account. Lists are bounded
and scoped; entries use actual commit order, independent of opaque ID order.
Single immutable bundles fit the existing 4 MiB control limit; list pages fit
1 MiB. Public routing, roles, sizes and signed headers are visible, while titles,
Markdown, checklist text and account preferences are ciphertext.

Publication calls the actual P04 transaction: signed context, author, current
roster/policy/epoch, immutable parents, CAS, quota, revision, key wraps, receipt
and final transport counter/event commit together. Eight identical requests
have one durable effect; eight distinct same-base edits have one winner. SQL
receipt failure rolls everything back. Returning an already committed receipt
after deletion does not resurrect content.

Additive migrations store private genesis and object created/updated commit
sequences. Existing sequences are backfilled from committed sync events. Readiness
applies them only to the marked synthetic database after owner validation. No
production migration or data deletion is authorized by this development phase.

## Protected client custody and verification

`packages/protocol/notes` runs in the shipped Worker; native `notes.rs` implements
the equivalent closed main-window commands over actual SQLite. Neither interface
exports device/group keys, L, bearer tokens, arbitrary SQL or file paths. Root/R
remain transient. Current origin/window/capability/epoch/writer/generation checks
remain mandatory. Lock masks and clears plaintext UI state and terminates access.

The additive `p09-local-v1` profile encrypts control and genesis records under L
with fresh 24-byte nonces. AAD is `AnyNote/P09/local-content` plus NUL and RFC8785
JCS of scope, root, record ID and purpose. The control ID hashes the JCS scope
under `AnyNote/P09/local-control` plus NUL. Frozen draft/outbox/cache inner frames
are unchanged. Protected references, new G keys, ciphertext, witnesses and draft
retirement commit together. Generic save/eviction cannot alter their reserved IDs;
L rotation covers all old and additive records.

Clients independently replay the signed pinned roster, verify private genesis,
recipient and epoch context, ciphertext/signature/AAD and decrypted internal fields.
Summary pins require a verified same-group/same-thread entry; incoming summaries
are resolved and scoped before display. Historical writer authority differs from
current publication authority. Known protected witnesses retain verified old
content after author revocation. Unwitnessed backdated signatures cannot establish
history: missing independent evidence surfaces UNANCHORED_HISTORY. P10/P11 own
general history closure; universal hostile-server freshness is not claimed.

## Rendering and offline resources

Maintained markdown-it 15.0.2 has a separate frozen seven-package SRI/license
inventory. Tokens create safe DOM nodes: raw HTML is literal, script/unsafe URL
links are rejected, remote images are never fetched, and innerHTML is unused.
Preview rendering is bounded separately from the preserved editor text.

The page retains strict API-only connect-src, no unsafe-eval and no frames/objects.
The Service Worker has its own CSP enumerating only the nine static resources it
installs. It cannot connect to the API. Fetch routing caches exact static GET paths,
never dynamic responses, authentication, notes or keys. Encrypted IndexedDB remains
separate. Browser eviction, offline old backups and JS/RAM erasure limits remain.

## Reproduce development checks

Use the existing checkout, runtime-env.sh and workspace npm cache. Install both
QR and Markdown projects with frozen `npm ci --ignore-scripts` before building
the shared static bundle. Setup/default generators compare source read-only.

```sh
source scripts/runtime-env.sh
python3 scripts/dev-stack.py up
python3 scripts/dev-stack.py check
python3 scripts/p06-stack.py up
python3 scripts/p06-stack.py check
python3 scripts/check-p09.py
cargo test --manifest-path packages/vault-native/Cargo.toml --locked --all-features -j 4 -- --test-threads=1
node experiments/p01/p09-native-interop.mjs
```

Explicit attack checks reset only the marked disposable P06 DB, sequentially with
P03 outage tests: `p06-stack.py reset`, then `node packages/protocol/p09-http.mjs`;
reset again before `node experiments/p01/p09-browser.mjs`. Mandatory hosted jobs
retain verified TLS, strict CSP and Chromium sandbox. Local cloud sandbox is BLOCKED.
Windows runs actual MSVC/DPAPI/SQLite, official-header ABI and native/PWA adapter
interoperation. This is software acceptance, not a new owner Hello/iPhone trial or
complete native/PWA packaging. Public artifacts contain only checks/source hashes.

Bounds: 100 private groups per account, 512 local drafts/attempts/witnesses, 512 KiB
local control and 1,000 roster events. Pagination is transport discovery, not a
consistent complete snapshot or proof of deletion. P11 owns scale/compaction and
automatic convergence; P13 owns full search/retention/export. No production security
release or qualified audit acceptance is claimed. Rollback is an ordinary source
revert, preserving encrypted local work and requiring a separate data-preserving
plan before any deployed schema rollback.
