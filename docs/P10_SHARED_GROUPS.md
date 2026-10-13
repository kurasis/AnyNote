# P10 shared groups and membership integrity

P10 builds on the frozen group-c2 frames, P04 transactions, P05 crypto, P07 custody,
P08 independent account/device pins and P09 notes. Verification status and exact
receipts are recorded in TEST_EVIDENCE; implementation alone is not acceptance.

## Shared access

Use `/auth/notes.html`. Choose Private or Shared when creating a new group. A private
group is never converted by changing its server flag. Members and access provides
EN/RU controls for owner/editor/reader, invitations, role changes, removal, archive,
key maintenance and ownership transfer. Compare the exact target account fingerprint
through an independently trusted channel and confirm the full retained history,
including retained versions/trash, before inviting. An invitation card contains
public signed evidence and sealed envelopes, never plaintext or private keys.

The target imports the card after independently comparing the original creator's
fingerprint and the shared history pin, explicitly accepts, and waits for the owner to finish all historical/current grants. Pending
admission does not authorize content or key endpoints. Activation is one real SQL
transaction after exact recipient coverage and current policy/roster comparisons.
A recipient verifies every signed frame and the actual unwrapped key commitment;
incorrect sealed contents enter KEY_REPAIR_REQUIRED, not a replacement random key.

The immutable genesis pin retains the original creator identity after ownership
transfer; the signed policy establishes the current owner. Owner transfer uses a proposal, the incoming owner's exact co-signature and recent
trusted authentication by both accounts. The incoming owner records consent through
its own current session; finalization rechecks that consent/session/device and
leaves exactly one owner. Private ownership transfer is prohibited. Archive allows
reads, removal, ownership transfer and key maintenance, while blocking content writes.

Removing a member immediately denies server content access and blocks new writes.
A new epoch excludes that account from all new distribution records. Previously
exposed keys/plaintext/backups remain readable to their holders. Signed roster
changes independently suspend publication even if an unsigned service flag is false.
Existing members import a fresh independently exchanged card when a new account is
introduced; PINNED_ACCOUNT_REQUIRED preserves drafts and explains this action.
Any current member, including a reader, may execute exact mandatory roster maintenance;
a reader may neither write content nor certify history or change membership. Optional
rotation is owner/editor only. Same-account certified-device distribution extends
existing access without copying device identity secrets or admitting another account.

## History and local work

Protected public proofs include independently pinned account roots, complete signed
rosters, genesis and the ordered policy/epoch/history journal. Both portable Worker
and native Rust replay signatures, roles, context, predecessor heads, complete grant
coverage and verified roster chronology. Known prefixes/heads cannot regress. A
fresh client imports a history checkpoint through the independently verified public
card; the API's clock or an old valid signature is not a historical trust anchor.

A writer closes the exact retained inventory only from its protected witnesses and
previous independently anchored inventory. The server compares it to all actual
immutable revisions and parents. Missing witness/ancestry stays explicit. Newly signed
backdated content from removed writers is refused unless its exact revision/digest
is already independently witnessed or anchored. Readers cannot endorse unknown history.
This does not prove universal freshness or prevent every isolated malicious-server fork.

Unsent edits remain encrypted under random L. Signed security attempts persist before
transport, retain identical bytes through lost responses/restart and bind exact final
family/group/operation/body/state on acknowledgement. Prepared epoch keys live separately
under L until final commit is acknowledged. Cancellation discards the candidate and
burns its exposed commitment; a new attempt uses fresh key material and operation IDs.
A committed retry cannot reactivate cancelled staging. Local encryption, protected
references, G installation and attempt acknowledgement commit atomically. Generic
read/save/eviction cannot export or overwrite the protected key-bearing evidence.

Create a shared copy previews the source/destination audience and requires explicit
confirmation. It copies the selected entry into a shared thread using fresh object,
revision, DEK and epoch encryption. Source history remains private. Private preferences,
history/trash and attachment references are not silently copied. A protected audience
digest prevents queue/send after recipient changes without a new confirmation.

Account closure requires recent trusted self authentication, explicit confirmation
and resolution of all shared ownership/membership through signed owner policy first.
It disables server access and schedules retained private ciphertext for the separate
P13 retention workflow. It does not physically purge content, erase local drafts,
rewrite retained signed identity evidence or appoint an administrator as group owner.

## API and persistence

`p10-shared` contains closed additive request/reply/proof/private-custody shapes.
The finalized routes supersede the unimplemented P03 P10 placeholders; original P02
bytes and the supplied spec are unchanged. This routing decision is recorded in
DECISIONS. `/groups/{id}/journal` serves bounded complete public proof; `/invites`,
`/accept`, `/policy`, `/owner-consent`, `/epoch/begin`, `/epoch/page`, `/epoch/commit`,
`/history` and `/cancel` are scoped under the group. `/me/group-invitations` discovers
pending target intents. `/me/close-account` is a separate self-only access closure.
Existing own-device/recovery envelope routes remain current-member scoped.

Exact signed public-roster lookup with `root` is available to a trusted device for
independent contact verification; unrelated lookups without that pin stay concealed.
There is no account directory or plaintext content lookup. IDs, graph/roles, public
keys, ciphertext sizes and activity remain service-visible metadata.

An additive migration retains shared genesis, immutable journal/security receipts,
recent owner consents and account-closure requests. Existing staging/pages are reused.
Account locks precede group locks; related accounts are sorted and rechecked after
locking. CAS/quota/projections/immutable evidence/receipts and final sync allocation
commit together. Normal rekeys cannot consume the security reserve; only exact
mandatory maintenance can. No production migration is performed by development tests.

Bounds are explicit: 20 members, 1,000 signed group events, 3 MiB committed journal,
1 MiB/500-record grant pages, 16 MiB staged grants, 5,000 retained revisions for a
single history closure, 4 MiB HTTP control, 512 KiB protected local proof/control,
and inherited 512 draft/attempt/witness records. A bound returns RESOURCE_LIMIT and
preserves work. P11 owns scalable snapshot/delta convergence, indexes and compaction;
P12 owns physical files, P13 physical purge/full export and P14/P15 complete hosts.

## Reproduce checks

Use the existing checkout and pinned runtime; no worktree. Default checks are read-only.
Install both frozen QR and Markdown projects before building the shared static bundle.

```sh
source scripts/runtime-env.sh
python3 scripts/dev-stack.py up
python3 scripts/dev-stack.py check
python3 scripts/p06-stack.py up
python3 scripts/p06-stack.py check
python3 scripts/check-p10.py
cargo test --manifest-path packages/vault-native/Cargo.toml --locked --all-features -j4 -- --test-threads=1
node experiments/p01/p10-native-interop.mjs
```

Attack tests reset only the marked disposable P06 database, sequentially with P03
outage checks: reset then `node packages/protocol/p10-http.mjs`; reset again then
`node experiments/p01/p10-browser.mjs`. Hosted Chromium retains real TLS trust, CSP
and its sandbox. Local cloud sandbox is BLOCKED, not a substitute. Windows runs
actual MSVC/DPAPI/SQLite and the official-header ABI check. Native adapter tests use
explicit modeled receipts; the real HTTP/SQL and persistent three-browser UI are
separate mandatory jobs. Artifacts contain public checks/source hashes only.

Full G1 physical Hello/iPhone/memory/network and qualified G2/G3 review remain open.
This is software development, not deployment, a production security release or audit.
Source rollback is an ordinary revert; preserve local work and use a separately
reviewed data-preserving plan before any deployed schema rollback.
