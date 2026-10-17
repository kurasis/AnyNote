# Windows transfer-memory follow-up

The owner authorized remediation of the historical339361792-byte native/helper
working-set growth above128MiB. The target and the pre-transfer application
baseline are unchanged; helper startup remains included. Physical device-budget
acceptance is separate. No new numbered product phase or production release is
introduced.

## Implementation

The native helper compiles each frozen schema reference on its first validation,
before examining the input. It keeps the same AJV strict/own-property options,
formats and semantic predicates. The helper's V8 size policy reduces nursery and
heap growth without imposing a smaller old-space ceiling on valid metadata.
Production bundling is minified; the existing asset hash/permission checks remain.

Pipe input allocates from the checked frame length instead of maintaining an
always-present16MiB staging buffer. Export members return zeroed storage for reuse.
Small archive-input frames retain independent ownership for prefetch. Output writes
the header and borrowed body under one serialized asynchronous permit; the caller
keeps ownership until completion and zeroes recovered plaintext afterward.

The age adapter feeds at most64KiB per destination pull, preventing its synchronous
transform from enqueueing128 encrypted outputs from one8MiB member. The tar reader
reuses its large member storage only after the awaited visitor and zeroization.
SHA-256 updates reach maintained libsodium in64KiB slices, avoiding permanent WASM
heap growth just to hash a whole chunk. Crypto, archive bytes, caps, signatures,
authority, cancellation and transport fences remain mandatory.

## Measurement and regression gate

The installed Windows workflow retains its original OS working-set baseline and
sampled native/helper increase. Samples are serialized and attributed separately
to upload, download, export, offline inspection, import and recovered download.
Every phase needs repeated actual OS observations; export/inspection/import also
need repeated helper observations. A separate original JSON receipt is retained
before an assertion can fail. The existing Windows job now fails if coverage is
missing or native/helper growth exceeds134217728bytes. All30 ordinary gates remain.
Sampled working sets do not establish unsampled maxima or physical-device memory.

The first revised ordinary Windows run at a364813 passed with baseline138821632
bytes (helper0), peak222121984 and growth83300352 (79.4MiB),277 samples and repeated
coverage in all six transfer phases. Actual signed ZIP refusal, genuine NSIS
upgrade and vendor positive/tampered checks also passed. The entire cohort was
29/30 because the separate browser-content search assertion failed. The next
ordinary cohort must pass after the explicitly offline local-search scheduling
correction; this intermediate Windows PASS does not authorize merge by itself.

## Development evidence and remaining validation

Linux development reproduced helper-only export RSS430276608bytes. Iterative
bounded streaming/buffers/hash/startup changes reduced it to127283200bytes in a
later diagnostic. These separate random1GB runs include scheduling and allocator
variation and do not measure the installed Windows native/helper budget.

An actual authenticated random1GB archive was independently read by Go age and
fully verified/recovered with both helpers. The original helper peaked at
408203264bytes; an intermediate implementation peaked at162082816bytes. A later
zero-copy/size-policy diagnostic recovered all120parts with the complete hash and
peaked at149311488bytes. This remains above128MiB even for that Linux helper alone;
it is an honest improvement, not budget closure or a Windows/device substitute.

Local development passed72 maintained client tests, the unchanged6728 parser/
schema differential cases,512 envelope and512 tar-header denials,112 native vault
tests including genuine1GB, the restricted native frozen-archive bridge and62
release-native HTTPS/API checks including real1GB export/recovery/import. Three
pipe regressions cover fragmentation, selective prefetch, buffer zeroization,
oversize/truncation and simultaneous duplex backpressure. The saved19-command
startup and frozen179-file check passed. These are dirty development receipts;
the final branch requires fresh ordinary PR and merged-main Windows/1GB/30-job
evidence. No physical, independent-review, signing or production gate is closed.

## New live ZIP advisories discovered by the required gate

The first exact-source PR security run failed on newly published
RUSTSEC-2026-0367/0368/0369 for frozen zip4.6.1 and8.6.0. Its original report and
upstream responses are preserved in [ZIP development evidence](evidence/windows-memory/zip-development/index.json).
The vulnerable library versions are not silently upgraded or declared patched.

The Windows updater now checks signed/hash-bound bytes for PE/MZ before calling
Tauri install dispatch. Even a correctly signed ZIP is unsupported; the genuine
NSIS upgrade remains mandatory. The pinned infer ZIP detector requires a PK
prefix, disjoint from the admitted MZ prefix. New native offset/header negatives
and a correctly signed symlink-ZIP Windows case exercise this boundary.

zip8.6.0 is solely a libsodium-sys-stable build dependency, absent from the normal
runtime closure. Its exact crate source verifies the entire archive against the
pinned vendor minisign key before extraction, including local override inputs.
The actual frozen extraction/verification functions, driven directly with their
locked build dependencies, extracted157 authentic vendor files and rejected a
one-byte mutation before creating any installed file. Every new ordinary Windows
run repeats that positive/negative check. Rust crate archives/member hashes,
dependency kinds, signature-before-extraction and updater call ordering are
rechecked by `scripts/p17-zip-review.py`; unknown versions/advisories still fail.

These are scoped input/authority dispositions with executable regression gates,
not an upstream fix, a universal ZIP-safety assertion or independent review.
Vendor/signing/build-host compromise and any future archive/target/profile need
separate review. All179 original frozen files remain unchanged. Full Windows
negative/update acceptance and final ordinary PR/main cohorts remain pending.
