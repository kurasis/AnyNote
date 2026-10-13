# P12 encrypted files and quota lifecycle

Implementation is undergoing final verification. This guide describes the product
path; PROGRESS and TEST_EVIDENCE own actual acceptance. Physical iPhone/Hello,
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
