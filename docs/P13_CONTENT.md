# P13 protected content and independent recovery

This guide describes the candidate implementation. Exact final acceptance and
phase completion are recorded separately in docs/evidence/p13 and PROGRESS.

## Content UX and custody

The EN/RU notes UI indexes only cached, independently verified note payloads and
verified encrypted file manifests. Search never calls a server search endpoint.
Pages, tokens, snippets and file names remain encrypted under the installation's
local vault key L. The signed p13-content-v1 manifest prevents older readers from
silently downgrading an active vault. Generic storage/eviction cannot modify this
namespace. Source changes require an explicit rebuild, and coverage distinguishes
not indexed, unavailable, keys pending, unanchored, stale and bounded results.

The native Search coordinator reads real cryptographically verified Cached note
operations and stores its index in protected SQLite/WAL records. Verified native file names are indexed from authenticated manifest display fields,
and the typed metadata API returns no DEK or nonce prefix. Native age helpers
use maintained age 0.12.1. Windows host/dialog/WebView2 coordination remains P14;
browser software acceptance is not physical iPhone or WebView2 evidence.

Safe Markdown uses the existing DOM-safe renderer. Text/raster/PDF viewers never
execute document HTML/SVG or external URLs. Maintained Mozilla PDF.js operates in
separate workers with no vault/device keys, API connections, dynamic code evaluation
or active PDF actions. Parent cancellation terminates both workers. Text is capped
at 1 MiB, raster input at 16 MiB and 4 million pixels, PDF at 8 MiB/32 pages with
bounded inflation and CPU. Unsupported documents remain explicitly downloadable.

A thumbnail is a PNG at most 256 by 256 and 256 KiB. Protected custody verifies the
source, creates a distinct encrypted P12 file and signs its source/derived manifest
link. The server checks current writer/certificate/policy and quota. Readers may
preview locally; preview never grants upload authority. Linked derived files stay
referenced while their source exists. No thumbnail key or plaintext name enters SQL.

## History, retention and local work

The version UI compares current/saved text and restores with a fresh revision under
current authority. A compacted payload is explicitly unavailable; its signed
ancestry remains. Existing favorites, order and read markers remain private.

Retention is report-first and explicitly applied by the current group owner. Keep
30 days of note payloads, then daily snapshots for 90 days, then monthly snapshots,
plus current/conflict heads, explicit pins and snapshot/export references. Trash
expires after 30 days. Only an object with exclusively soft-delete heads may lose
its expired trash payload; signed tombstone/ancestry evidence remains indefinitely.
Retained entries keep their historical file references. Removing those references
requires successful eligible compaction of the containing revision in the same
transaction. Public signed records are never rewritten into fictitious history.

File retention conservatively keeps referenced ancestry, conflicts, attachments,
unfinished uploads and snapshot/export/derived links. Three versions is a soft
target and cannot override a strong reference. Unattached recovery lasts 30 days.
Content quota releases follow successful compaction/deletion; DB pages, backups
and overhead are separate physical storage. No production purge/scheduler is
enabled by development acceptance.

Downloaded-cache controls show interrupted/complete and pinned ciphertext and
require explicit confirmation to evict. They cannot delete an upload source,
immutable attempt or unsent edit. Job controls can forget only COMPLETE imports
or acknowledged LINKED thumbnails; publication/file journals remain. A completed
import ID that is forgotten cannot subsequently be resumed as a fresh attempt.

## Portable profile

Use standard age v1/X25519 with a new independent export identity for each attempt.
The host receives age ciphertext and, only after authenticated EOF, a separate
recovery document. Keep the recovery document separately; archive plus document
allows access to this captured content. Root/device private keys, root recovery
secret R, group secrets G, sessions and passkeys are never exported.

The inner archive preserves the frozen P02 strict USTAR paths, ordered inventory
pages, signed footer and original ciphertext frames. Selected object/manifest/file
DEKs exist only inside outer encryption. The additive p13-public-proof-v1 identity
document contains independently pinned identities, full roster/security journals
and group state/history evidence. Readers unable to understand this proof profile
must reject it. Original P02 corpora and frame signatures are unchanged.

The reader uses two passes over the same seekable archive and authenticates EOF,
footer, all inventory counts/digests, original historical signatures, context,
note/file AEAD and full file hashes before any live destination mutation. Tar paths
are generated/validated; links, sparse tricks, duplicate paths, missing footer,
trailing records, wrong kit and altered/truncated streams fail closed. It never
extracts a keys directory or an unencrypted archive into temporary storage.

Bounds are explicit: 116,010,000,000 ciphertext bytes including overhead,
4,008,003 tar entries, 8 MiB file chunks, 64 MiB aggregate validation metadata and
bounded notes/group proof catalogs. A single file remains at most 1,000,000,000
plaintext bytes. The whole-account stream avoids a giant Blob and is a desktop
job. A 24-hour maximum lease and resource bounds can require a smaller selection.
Export pins never bypass later account/device/group revocation. Renewal requires
new server-observed resource progress; that is not proof of client durable output.
The UI shows a conservative space/time estimate at an explicitly assumed rate
before starting, and refuses a selection estimated to exceed the remaining lease.
An interrupted age stream restarts with a new identity rather than reusing a nonce.

## Import and offline recovery

The PWA standard importer accepts an immutable archive Blob up to 1.1 GB plus its
separate kit. It fully validates before creating even the default new private
destination. The user reviews source and current destination audience, then copies
current retained tips with fresh IDs/DEKs/current epoch/signatures. Original
history stays independently verifiable provenance in the source archive, and
does not become live historical authorship or an identity/session join.

An encrypted import journal binds its stable import ID, archive hash, destination,
immutable note/file associations and receipts. Lost acknowledgements retry the
same operation. Lock/crash/pause preserves journals; resuming requires selecting
the same archive and kit. Already published content remains visible when stopped.
Recovered files receive durable note-container references before completion, so
they cannot silently expire as unattached uploads. Quota/current-authority failures
must be reconciled before proceeding; no burned identity is reused.

Clean offline inspect, using no original API or device cache:

```bash
node scripts/p13-offline.mjs --archive backup.age --kit backup.kit.json
```

Explicit plaintext recovery into a new folder:

```bash
node scripts/p13-offline.mjs --archive backup.age --kit backup.kit.json \
  --output recovered --plaintext-confirm
```

The CLI authenticates everything before writing selected plaintext, stages only
explicitly requested final content, fsyncs and publishes a new folder atomically.
It never overwrites an existing destination. Cancellation removes only its own
incomplete folder. SDK dependencies must be installed from isolated frozen locks;
no original service credentials are required. The PWA also explicitly saves a
selected note as plaintext JSON, separately from its encrypted portable archive.

## Checks and limits

Run scripts/check-p13.py read-only, and serial native all-feature tests under the
Argon gate. Dedicated P13 Linux HTTP/sandbox browser and Windows native gates
supplement all 22 inherited jobs. Actual 1 GB tests are not silently skipped.
Final receipts must match the exact clean head, Git tree/input bytes and platform
artifact ZIP digest. Never replace these with development counts or fabricated
hardware/audit results. Qualified G2/G3, full physical G1/U11/U12 and iPhone memory
remain OPEN/NOT_RUN. P14 packages/completes the Windows host; P15 accepts iPhone;
P16 owns deployment, capacity and production restore.
