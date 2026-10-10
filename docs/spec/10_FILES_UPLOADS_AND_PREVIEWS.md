# Large Files, Upload Protocol, and Safe Previews

## 1. Exact limits and budgets

Maximum original file: 1,000,000,000 bytes. Default plaintext chunk: 8,388,608 bytes (8 MiB). A maximum-size file has 120 chunks; the final plaintext chunk is 1,755,648 bytes. AEAD tags and manifests add overhead and are included in reservation calculations. Empty files use only their authenticated manifest.

Initial concurrency: up to 4 chunks per Windows transfer, 1–2 on PWA, plus an account/global ceiling. Initial target crypto/transfer working memory is at most approximately 64 MiB beyond application/UI baseline on mobile and 128 MiB on Windows. These are measured targets, not guaranteed browser RSS. Bound buffers and transfer concurrency even if a benchmark is faster with unbounded Promise.all.

Do not load a 1 GB file with File.arrayBuffer(), concatenate all chunks, or build a giant in-memory plaintext Blob as the only export path. File size must not determine working memory linearly.

## 2. Upload lifecycle

1. User selects source; client checks supported size and local/remote space estimates.
2. Create immutable file/version IDs and random keys; persist encrypted upload descriptor.
3. Reserve upper-bound ciphertext bytes and create a device-bound upload session.
4. Read source in bounded chunks, encrypt locally, and persist/send according to platform strategy.
5. PUT each part with index, expected ciphertext length, and digest. Server verifies bytes and acknowledges immutable storage.
6. Persist acknowledgements and finish encrypted manifest/signature.
7. Commit with exact ordered part inventory and expected group policy/epoch.
8. Backend validates storage, lengths, permission and epoch, then commits the file version, quota and event as an unattached object.
9. Client journals that receipt, then publishes a separately signed entry revision binding the exact file-version ID. It marks the attachment synchronized only after both commits succeed. A conflicted note publication preserves the committed file in the Unattached Files recovery view.

The server can infer the exact original length from fixed tag overhead and unpadded chunk lengths; this is accepted metadata leakage and allows enforcing the 1 GB limit without plaintext content inspection. Never upload the original filename as multipart metadata; binary part requests use opaque IDs.

## 3. Server staging implementation

Nginx and PHP accept only bounded part-sized requests on the upload route, with a small allowance for framing. Do not set all endpoints to allow arbitrary 1 GB bodies. Use binary streaming input or bounded temporary files; never base64-encode binary parts in JSON.

Recommended local-store path: Laravel authenticates request and writes ciphertext to a private temporary file while enforcing byte limits/hash; fsync/close and atomically rename into immutable staging; record acknowledgement. Inspect PHP/Nginx buffering settings and disk temporary paths under load. Both buffering and fully streamed modes require physical-space accounting.

At commit, recheck every part and current authorization. Complete bytes with no commit are not visible files. DB and filesystem crash recovery must reclaim unreferenced parts without deleting committed data. Janitor cancellation/commit races are resolved using upload state locks and immutable references.

## 4. Resume and source identity

Persist encryption version/key descriptor, nonce prefix, source metadata, prepared ciphertext, verified chunk digests, and server acknowledgements in encrypted local state. Plain filename/mtime/size matching is not proof that a reselected file is identical.

Windows should use native file handles and stable source checks while reading; detect modification during transfer. PWA may lose its selected File object after restart. Offer reselect and verify content against stored per-chunk information before reusing any prepared state. Store plaintext verification hashes only inside encrypted local state/manifest.

Safe fallback: if source identity cannot be proved, cancel/expire prior session and restart with new version/key. Do not re-encrypt changed bytes under previously used nonce/key positions. Resume by retransmitting identical prepared ciphertext wherever possible.

Staging expires after 72 hours without activity. Server extension of activity is bounded by account limits and actual progress; a client cannot reserve disk forever through empty keepalives. Expired session returns UPLOAD_EXPIRED and never silently resets the same upload ID.

## 5. Download and export

Fetch/verify/decrypt manifest first, then download requested ciphertext chunks. Verify each before passing plaintext to a renderer or export sink. Final export completes only when the entire inventory and optional full digest verify. Write to an incomplete destination then atomically finalize where the platform supports it; on failure remove or clearly mark incomplete output.

Windows streams from Rust to a user-selected destination; filenames are sanitized for Windows reserved names, forbidden characters, traversal, alternate data streams, and collisions. External open requires a deliberate export/temp-file workflow and cleanup policy. No automatic executable launch.

iOS PWA export is a mandatory feasibility gate. OPFS can hold encrypted chunks, but OPFS is not the user's Files directory and availability of browser file primitives does not prove gigabyte export works [SRC-13]. Test a bounded-memory browser download/export pipeline on real supported iPhones. A reviewed service-worker-assisted same-origin streaming response may be considered, but it must not persist plaintext in Cache Storage or fetch remote helper code.

If the only viable tested path requires a temporary plaintext export file, that is an explicit user-authorized export exception: explain disk usage, use an isolated temporary location, clean up best-effort, and do not claim secure erasure. If no reliable 1 GB export path exists for the selected iOS target, the feature is not complete. Propose a native iOS client or clearly limited mobile mode for owner approval; do not silently lower the agreed file limit or decrypt on the server.

## 6. Local cache

Default automatic downloaded-file cache: 1 GiB on iPhone and 5 GiB on Windows. The 1 GiB mobile cap can contain one maximum decimal-1-GB file plus framing; it is not a guarantee of physical free space. User-pinned offline files have an explicit additional budget and free-space check; they do not silently bypass physical limits. Preview cache uses least-recently-used eviction. Unsynced encrypted drafts/upload material are not automatic eviction candidates.

Request persistence on PWA, inspect estimated quota, handle QuotaExceededError, and disclose that OS/browser cleanup may still remove local content [SRC-12]. A full local cache does not delete remote files. “Available offline” is shown only after all required chunks and keys are locally durable and verified.

## 7. Previews

Required v1: bounded text, common raster images, and PDF using a maintained isolated viewer. All original files up to the limit can be stored, but arbitrary 1 GB documents are not promised an inline preview. Show a clear download option for unsupported or resource-heavy content.

Generate thumbnails on a client, encrypt them as independent derived attachments, and charge quota. Limit decoded image dimensions/pixel count and document complexity. Decompression bombs, malformed PDFs, huge images, and recursive archives must not consume unbounded memory. Original archives are stored as opaque data; server never extracts them.

Do not inline SVG/HTML as active documents in the main app. A PDF viewer must not have access to native commands or device secrets; disable active scripting/embedded launch actions. A supported safe renderer can process bounded plaintext through a narrowly scoped isolated view.

Disable automatic external image loading and remote link previews. Opening a link uses a safe scheme allowlist and external browser where appropriate. No server SSRF-based URL unfurling.

## 8. Malware and scanning

The server cannot inspect encrypted originals with an ordinary antivirus. Do not upload plaintext for server scanning, content detection, OCR, or format conversion. Client/OS scanning on explicitly exported content may be offered, but no unverified claim of malware-free attachments. Trusted participants can accidentally share malicious files.

## 9. Storage optimizations

No global plaintext deduplication or convergent encryption. Idempotent retry reuses the same ciphertext within one immutable upload; this is not cross-user deduplication. Within-group references may share a committed file version when authorization/context is unchanged. Cross-group copies re-encrypt with new IDs/keys.

Compression, content-defined chunking, delta updates of large files, and media transcoding are deferred. A new file version is a complete independently encrypted version in v1, simplifying correctness at 100 GB scale.

## 10. Reviewed edge-case rules

For plaintext length S and chunk size C: n=0 when S=0, otherwise ceil(S/C). Every nonfinal chunk plaintext length is exactly C, final length is S-(n-1)*C, and each ciphertext length adds exactly 16 bytes for this AEAD profile. Thus data-chunk bytes for the maximum file are 1,000,001,920 before the manifest/envelopes. Reservation uses exact derived upper bounds plus bounded manifest/key-wrap overhead, not a guessed 1 GB. Reject mismatched declared size, wrong final-part length, extra parts and unknown format; manifest plaintext fields must agree with signed public framing.

Bound pending-control and chunk state durably. Before encryption at an index, persist enough immutable source commitment to prove reuse is safe, or on crash restart that file version with new keys. Persisting a nonce prefix alone is insufficient if the source can change. Retry sends byte-identical ciphertext; reselect never relies solely on size/mtime/name.

A key-epoch change during an unfinished upload returns REKEY_RESTART_REQUIRED. The safe v1 path aborts that old publication and starts a new version with new file-data/manifest keys and nonce prefix under the current epoch. This can resend the full file; do not merely rewrap the old DEK and claim revocation. Preserve the source/local recovery descriptor and release old reservation safely. Ordinary network interruptions within an unchanged epoch still resume parts.

Committed unattached files count against quota and appear in a recovery view. Keep them for 30 days unless the user attaches/deletes them; warn before expiry. GC may delete an expired unattached version only after checking no entry revision, conflict, snapshot/export or pin now references it under the same transaction/lock rules. Cancellation after file commit is not upload cancellation; use an explicit unattached-file delete action.

For a service-worker-assisted plaintext export, bytes are generated locally and must never be sent to a remote helper or Cache Storage. Use a narrow authenticated MessageChannel/capability bound to the initiating window and export job; if the active worker cannot handle the operation, fail rather than fall through to network. Long iOS exports may pause/cancel on backgrounding. Any temporary plaintext file is an explicit export exception, never ordinary cache.

Client-derived preview generation is best-effort and cannot block original-file commit. A reader may generate a local encrypted preview without shared write privileges; uploading a shared preview requires writer permission and binds its source version and own ciphertext in a signed record. Treat inline raster/PDF decode as resource-bounded even when the sender is trusted.
