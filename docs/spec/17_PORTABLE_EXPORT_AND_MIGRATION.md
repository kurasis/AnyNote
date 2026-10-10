# Portable Encrypted Export, Offline Recovery, and Migration

## 1. Three different operations

| Operation | Purpose | Secret material |
| --- | --- | --- |
| Server backup | Restore the running service and its metadata/ciphertext | Operational backup secret; users still need their content recovery/device keys |
| Portable encrypted export | Recover selected accessible content independently of the original service | Separate user-held export identity/secret |
| Plaintext export | Save a document or notes for use outside the vault | Output is intentionally readable; clear user action required |

None replaces the others. A recovery code without surviving ciphertext cannot reconstruct deleted files. A server backup without client keys cannot decrypt user content.

## 2. Portable export baseline

Windows MUST support a streaming export of selected groups or the entire accessible account corpus. Do not require iPhone to export all 100 GB. iPhone must support the agreed individual-file export workflow and may support a bounded notes export after platform testing.

Use a maintained implementation of the standard age v1 file format as the outer encrypted container, with a fresh random X25519 export identity generated locally. This export identity is independent of account R and all device keys. The age format supplies an established streaming encrypted-file envelope; the application still defines and validates its inner archive/manifest [SRC-19]. P02/P13 must record the chosen library and interoperable test vector. Do not invent a new password-protected ZIP cipher.

The user saves the export identity separately in a checksummed recovery document. The archive is encrypted to the corresponding public recipient. Do not put the private identity in the archive's public header or beside the archive without explicit informed choice. The UI shows which content/history/trash is included before starting.

## 3. Inner archive profile

Use an uncompressed streaming tar or another documented bounded streaming archive selected by ADR. Export paths are generated opaque IDs, never original user paths. No symbolic links, hard links, device files, executable hooks, or unrestricted extraction instructions. The archive contains:

- export-header.json: format/version, export ID, source service ID, account root fingerprint, snapshot/checkpoint references, inclusion policy, and creation metadata.
- identity/: public account identities, required device certificates/roster evidence, and signed group-policy/epoch evidence.
- records/: original signed encrypted object revisions and required ciphertext manifests.
- chunks/: selected immutable file ciphertext chunks, deduplicated only by exact selected ciphertext identity.
- keys/: only the object/file/manifest DEKs needed for the selected export, inside the encrypted outer container. Do not export account root private keys, device private keys, passkeys, sessions, or unrelated group epoch keys.
- inventory/: bounded pages listing exact generated paths, sizes, digests, object relationships, and key references.
- export-footer.json and signature: final inventory commitment, record counts, checkpoint, and exporter device signature.

DEKs in keys/ are plaintext only within the already encrypted outer stream and in protected processing memory. They must never be written as an unencrypted staging directory. Original content files remain in their original ciphertext format inside the outer archive. Original notes may be decrypted only as needed for optional user-requested plaintext export.

The final footer and authenticated end of the age stream are mandatory. A truncated archive cannot be treated as a complete export. Completion is shown only after the output is flushed and the full archive digest is available.

## 4. Export authenticity and user kit

Recipient encryption alone does not identify who produced an archive. Verify the signed inventory/footer against the exporting device and pinned account identity. The export recovery document records the expected account root fingerprint, export ID, format version, archive SHA-256, and the independent private export identity. Its secrecy/integrity and independent storage are part of the recovery model.

Do not trust a public identity embedded in an archive as its own proof of authenticity. The user kit or previously verified local identity is the independent anchor. Show a clear unverified-source state if the archive is intentionally imported without that anchor; never silently merge it into trusted identity history.

## 5. Snapshot, streaming, and cancellation

Export against a consistent source snapshot/watermark. Freeze selected revision/file references, then fetch immutable bytes as needed. If a source is deleted or unavailable before fetched, fail or explicitly produce an incomplete export that cannot be labelled verified; do not omit it silently.

Show bytes completed, estimated output/disk needs, selected content, and cancellation. Use a .partial destination until successful finalization. On resume, use a documented outer-format checkpoint strategy or safely restart to a new export identity/file; never append arbitrary encryption state blindly. The initial version MAY restart interrupted whole-vault exports if clearly stated; normal per-file transfers still require resumability.

Keep local source keys and export identity only as long as required. A user can retain the export identity intentionally; the app must not silently become its only storage location. The export file is a standalone artifact not counted as additional remote quota unless uploaded back into the service.

## 6. Offline verification and recovery tool

Deliver a documented offline importer/viewer mode in the Windows client or a small companion utility using the same maintained libraries. It must operate without the original API, accept the export identity, authenticate the container/footer, verify inventory and historical author evidence, decrypt selected records, and export ordinary files/Markdown after explicit user action.

A clean-machine test must demonstrate recovery with only the encrypted export, its independent kit, the documented reader, and no original device cache/server. Keep a human-readable format guide sufficient for future recovery if the original application is discontinued.

## 7. Import into a live service

Validate archive and local resource bounds before writing into the destination. Never automatically join old memberships or import sessions/device identity keys. Let the user choose a new private destination group by default. Copy recovered current content with new destination IDs, fresh DEKs, and the destination group's current epoch. Original signatures/history can be retained as provenance attachments, not falsely presented as newly authored live events.

An explicit advanced history import may preserve a view of old revisions, but destination access rules govern who can read them. Reusing old ciphertext with a changed group ID/AAD is forbidden. Estimate/reserve quota and show missing/deleted/unavailable items. Partial import is resumable and idempotent through an import ID; cancellation leaves no invisible committed orphan data.

## 8. Acceptance

Test empty export, one note, one 1 GB file, multiple groups with distinct keys, selective current-only export, full retained history, malformed tar paths, duplicate inventory paths, forged identity, wrong export secret, altered/truncated stream, missing footer, quota exhaustion during import, and clean offline recovery. Inspect temporary directories and logs for secret keys/plaintext. A successful age decryption alone is not sufficient; inner inventory and authorized content verification must also succeed.

## 9. Validation-before-import and resource limits

A streaming container may authenticate early chunks before the final footer establishes the complete signed inventory. Early plaintext is provisional. Do not mutate a live destination, trust imported identities, or report verified recovery until authenticated end-of-stream, final digest, signature, every selected record and inventory consistency pass. Use two passes over a seekable archive, or stage original ciphertext plus keys encrypted under a temporary local vault key. Never unpack the inner keys directory into plaintext temporary storage. On cancellation/failure remove only the app-owned staged artifacts.

The importer enforces declared and observed item counts, integer bounds, path uniqueness, nesting, per-record limits, total ciphertext size and available local space. Permit the agreed 100 GB corpus plus explicit framing overhead without allowing an unbounded archive. Reject unsafe tar metadata, links, sparse expansion tricks, duplicate paths, extra records after the footer and trailing container data not permitted by the selected format. The writer and reader freeze the exact archive profile in P02/P13. Export identities are generated afresh per new export; an interrupted age stream is restarted unless a reviewed checkpoint profile exists.

Exports never widen access: include only keys and revisions the exporting account is allowed to retrieve and decrypt at snapshot creation, rechecking authorization while fetching. The snapshot lease from files 07/16 pins references but does not bypass later revocation. A 24-hour maximum lease can limit a whole-corpus export on a slow link; show the estimate before starting and allow smaller exports. Do not promise arbitrary-duration or indefinitely resumable whole-vault export in v1.

For cross-account group history, include the necessary public identities, certified authors, policy ancestry and historical inclusion evidence for every selected record, not only the exporting account's certificate. History whose authorization is unanchored is quarantined with an explicit status; it must not become a newly trusted live history by import. Provenance is separate from the destination author's new publication signature.
