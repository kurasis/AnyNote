# P12 encrypted files and quota lifecycle

Initial P12 code passed all twenty-two mandatory hosted gates; a subsequent
final-head run exposed a protected snapshot publication race now under revalidation. This guide
describes the product path; PROGRESS and TEST_EVIDENCE own exact execution evidence. Physical iPhone/Hello,
memory/network lifecycle and qualified external review remain separate open gates.

Files use the frozen P02 file context, independently authenticated manifest key
wrap, signed ordered ciphertext inventory and XChaCha20-Poly1305 chunks. The
maximum original size is exactly 1,000,000,000 bytes: 120 chunks, 1,755,648 final
plaintext bytes and 1,000,001,920 data ciphertext bytes before manifest/wrap costs.
Each version selects fresh data/manifest keys and a 16-byte nonce prefix. No
filename, plaintext hash, key, source path or preview enters server metadata.

The protected native/Worker journal hashes the actual source before encryption,
persists the immutable context/keys/source commitments, and verifies each reopened
chunk before any nonce reuse. A retry regenerates identical ciphertext only from
proven identical bytes. Stable local intent identifiers remain separate from
immutable publication handles. Expired/cancelled attempts cannot restart under the
same upload/version/operation identity. Reconcile receipts first, burn the old
attempt, and prepare fresh keys/IDs under current signed authority. A confirmed
copy verifies the selected source and destination audience, retains the original
and encrypts a complete new version. Changing the audience requires confirmation
again. Generic local mutation/eviction cannot overwrite these records or parts.

The additive file profile is bound in the device-signed local vault manifest.
Older readers refuse it before private mutation; stripping its unsigned metadata
marker also fails manifest validation. Existing encrypted drafts, immutable note
attempts, history witnesses and root pins stay intact. Browser local transaction
completion is subject to browser/OS durability and eviction, rather than a claimed
hardware fsync guarantee.

Upload sessions bind uploader account/device, group, version, operation and exact
public context. Binary PUT accepts at most 8,388,624 bytes and measures received
bytes, hashes ciphertext and fsyncs the private file/directory before acknowledgement.
Other control requests retain their 4 MiB limit. Same-index different bytes fail.
No part is a visible committed file. A new durable part renews the 72-hour inactivity
lease, bounded to seven days overall; duplicate/empty keepalives cannot extend it.

Reservation includes exact tag costs and bounded manifest/key-wrap overhead.
Global/group/uploader accounting is serialized, shared bytes count once, and
conversion to actual encrypted bytes occurs in the manifest commit transaction.
The immutable receipt, event and quota change commit together. Committed unattached
files remain recoverable for thirty days and count against quota. Note attachment
is a second immutable publication; acknowledgement loss/conflict keeps both file
and local note intent. Current policy/roster/epoch and same-group references are
rechecked. Security maintenance retains its restricted reserve at full user quota.

Lock order is actor/security, GC coordination, group, upload/file, quota, then the
commit-order counter last. Snapshot file pins commit before the lease is exposed.
File manifests are paginated at the captured watermark and verified into protected
witnesses before publishing a sync cursor. Signed file ancestry participates in
membership/history closure. Downloaded payload loss differs from missing signed
history; P13 owns complete retention/history/export policy.

Every manifest/chunk/page request reauthorizes current access. Range consumers
fetch and authenticate complete intersecting AEAD chunks for an exact immutable
version; a range result never certifies a complete file. Full export checks all
parts and the full digest. The last browser chunk is withheld until that final
check, preventing a bad full digest from looking like a successful streamed file.
Native hosts use selected handles and fixed verified HTTPS/bearer routes; renderer
commands expose neither keys/credentials nor a generic path/URL proxy. Native
application packaging/OS dialogs remain P14; physical PWA acceptance remains P15.

Explicit browser export uses a bounded writable sink or a single-use window-bound
service-worker MessageChannel. Plaintext is not placed in OPFS/Cache Storage or
sent to a remote helper. Background/lock/termination pauses work and fences late
results. No continuous iOS background transfer or universal successful Files save
is claimed. Interrupted output remains incomplete. Filenames are sanitized and
export does not automatically open executables or active HTML/SVG documents.

Downloaded ciphertext has a separate replaceable cache namespace: 1 GiB automatic
PWA budget and 5 GiB native budget. User pins require an explicit additional budget
and space decision. Complete inventory/key verification precedes offline availability.
Unsynced uploads/drafts never enter automatic eviction. Browser eviction and actual
physical capacity remain platform limits; failed caching cannot erase a remote file.

Cleanup releases only expired staging and eligible unattached ciphertext, preserving
entry/conflict/parent references, active snapshot pins and pending uploads. Quota
stays charged through physical deletion eligibility/success. The collector shares
the pin boundary, retains compact manifests/receipts and scans old orphan ciphertext
with a bounded durable cursor. Expired snapshot leases release pins under that same
boundary. `files:reconcile` reports durable journal/counter differences before an
explicit `--correct` decision. A pre-P12 accounting baseline is not an independently
proven physical inventory; operator restore/physical reconciliation remains P16.

Current bounded profiles: 512 local attempts, 1,000 independently witnessed file
manifests and 1,000 captured file versions per snapshot; eight manifests per file
page. Exceeding a bound preserves work and returns a limit error. Full large-scale
operational capacity and independent composition review are not inferred from
software tests.

## Software acceptance trace

The public source receipts identify the full clean Git tree and raw input hashes;
acceptance.json records every mandatory job and downloaded ZIP digest. These
software outcomes do not close physical or qualified review.

| Acceptance | Exercised software path |
| --- | --- |
| U01–U02 | Incompressible actual 1 GB native/HTTP/PWA, zero and 8 MiB boundaries; exact 120-part/tag/final-byte accounting and upfront oversize denial |
| U03–U04 | Missing/corrupt/truncated/range parts, authenticated full digest, exact same/changing PUT and commit retries |
| U05–U06 | Genuine partial socket disconnect, response-body loss after committed headers, protected lock/reopen/reselect, same/wrong source and fresh burned attempt |
| U07 | Actual shared reader denial, role downgrade/removal, epoch restart and owner-transfer fences; retained source/intent |
| U08–U09 | Concurrent near-limit reservations, real collector/commit race, receipt-trigger transaction rollback and pin-protected explicit cleanup |
| U10 | Actual MSVC native selected-handle 1 GB/resume/export, cache/corruption/atomic output and sampled transfer-phase working set; full packaged WebView2/physical matrix remains P14/G1 |
| U11–U12 | OPEN/NOT_RUN here: installed owner iPhone 1 GB Files save, background/lock/force-close/low-space and measured memory; P15 final acceptance |
| U13–U14 | Actual 72-hour expiry/collection, immutable operation identity and cross-account/group manifest/chunk/session/pin denial |
| U15 | Safe export filename/path/device-name handling, originals opaque and never automatically opened/decoded; bounded preview viewers remain P13 |
| U16 | Actual SQL/log, protected SQLite/WAL and shipped IndexedDB/OPFS inspection; server/caches contain ciphertext and public framing only |
| U17 | Actual content-quota-full revoke/rekey/reader maintenance, ordinary file reservation denial and exact security-byte journal reconciliation |

[File HTTP](evidence/p12/initial/http-report.json), [authority races](evidence/p12/initial/membership-report.json),
[shipped PWA](evidence/p12/initial/browser-report.json), [Linux source](evidence/p12/initial/linux-source-report.json),
[Windows source](evidence/p12/initial/windows-source-report.json) and [all gates](evidence/p12/initial/acceptance.json)
contain public metadata only. Complete phase scope and open release gates remain
separate from a successful software pipeline.

Browser export uses an ordinary navigation to the worker's attachment response;
setting an anchor download attribute bypassed interception in the observed Chromium
flow. A separate real 64 MiB hosted diagnostic proved the transport correction;
the full 1 GB acceptance then verified both online and offline saved hashes.
The channel waits for authenticated complete-stream acknowledgement; browser/OS
persistence after delivery remains the explicitly documented physical boundary.
The inherited static-cache check now waits for all nine exact permitted resources,
including the three note assets; partial/empty caches do not satisfy the check.
No API/auth/recovery/export responses enter Cache Storage. Platform job budgets
allow the retained repeated 1 GB native evidence runs without skipping assertions.
