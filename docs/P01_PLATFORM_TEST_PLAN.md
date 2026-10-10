# P01 physical platform test plan

Status: **NOT RUN / BLOCKED**. No physical Windows/iPhone has been attached.
These are procedures and required future harness capabilities, not passed tests.
The primitive CLI/worker is a useful prerequisite, not the complete platform
harness. Do not replace missing physical evidence with GitHub Linux results.

## Evidence record for every trial

Record date, source commit, executable/bundle hash, device model/RAM, exact OS
build, browser/WebView2 version, provider/authenticator, installation mode,
available storage, network, procedure, result artifact and PASS/FAIL/BLOCKED.
Use fabricated identities and CSPRNG synthetic files only. Record hashes and
content-free counters; never record real passkeys, private keys or recovery kits.

Use at least two supported iPhones: an older/lower-memory candidate and a
current model. Minimum OS support remains a candidate until measured.

## W01 — DPAPI baseline and actual Hello key-operation gating

Prerequisites: actual Windows 11 x64 with current WebView2, Rust MSVC and C++
Build Tools; a future isolated key-wrapper probe, not yet implemented. Review
official CNG/Windows Hello API semantics before choosing a wrapper (ADR required).

1. Generate an independent random synthetic local key L in native memory. Wrap
   under DPAPI user scope and verify restart/unwrapping for the same Windows
   user; other-user access must fail. Record that same-user malware may unwrap.
2. Evaluate a supported CNG/Hello construction that gates the **actual unwrap
   operation**, including supported TPM/provider behavior. A successful UI
   consent dialog followed by ordinary DPAPI unwrap is not Hello key protection.
3. Attempt key use before consent, with consent cancellation, after Windows lock,
   suspend/resume and fresh process restart. Direct native calls must not bypass
   the intended cryptographic gate. Compare key hashes locally; do not export L.
4. Test no-TPM/no-Hello/provider failure and alternate configured wrappers.
   Do not silently enable a weaker fallback. The weakest enabled wrapper limits
   security; report fallback behavior explicitly.
5. Test a stale lock-generation reply and unauthorized IPC/window context when
   the actual adapter is available. No raw-key or generic filesystem API.

Acceptance: operation-level protection evidenced with positive and bypass tests,
or a documented unsupported result with concrete owner options. CI Windows
compilation alone cannot prove real Hello user presence or physical TPM behavior.

## I01 — Installed PWA crypto/storage baseline

Prerequisites: dedicated controlled HTTPS synthetic app/API origins, reviewed
test-only harness packaging, physical iPhones and a storage/export adapter. The
current loopback test page is not remotely exposed and is not an installed PWA.

1. Install from Safari to Home Screen. Record Safari/OS/provider versions.
2. Run the committed native/browser fixture corpus in the real PWA worker.
   Confirm invalid key/AAD/tag and signature cases stop without readable output.
3. Probe IndexedDB/OPFS, storage estimate/persistence request, denial and forced
   quota exhaustion. Store ordinary cache/outbox content as ciphertext only.
4. Measure actual native/browser process memory with available platform tooling,
   distinguish crypto incremental memory from overall application baseline.
5. Clear origin storage; enrollment/recovery should be required rather than an
   exception loop. This step depends on future recovery harness support.

## I02 — Passkey login and optional PRF

Prerequisites: synthetic WebAuthn verifier with exact RP ID/HTTPS origin,
one-use challenges and no-store responses; a local wrapper probe. Not built yet.

Test sign-in and local unlock separately for each provider/credential type.
Record ordinary assertion user verification, PRF availability/enabled/results,
and background behavior during the system sheet. A login without PRF must not
be labeled an unlock. A synced passkey must not clone device identity keys.
Inspect server-bound serialization: no PRF output, local KEK or recovery secret.
Test strong-phrase fallback with exact libsodium Argon2id profile at 64 MiB /
opslimit 3, bounds before allocation, one job at a time, and measured latency.
Do not silently lower KDF cost to close a feasibility gate.

## I03 — Exact 1 GB upload/download/decrypt/save to Files

Prerequisites: immutable chunk upload/session/manifest journal and a reviewed
bounded export sink in an isolated synthetic harness. These parts are not yet
implemented. OPFS alone is not an iOS Files export pipeline.

1. Generate a **1,000,000,000-byte** CSPRNG source, record its SHA-256 and move
   that synthetic source to the phone. Verify 120 parts, final length 1,755,648;
   ciphertext data 1,000,001,920 plus separately accounted manifest/envelopes.
2. Select the source through Files. Process at most 1–2 bounded chunks in a
   worker; upload ciphertext only. Keep titles/filenames/content keys off server.
3. From a fresh authorized synthetic recipient with no uploader cache, obtain
   the manifest/key chain, download/verify/decrypt, then explicitly save to Files.
   Compare exact output length and SHA-256 independently. No whole-file
   `arrayBuffer`, concatenated plaintext Blob or remote plaintext helper.
4. Measure memory, transfer duration and physical disk use. If a temporary
   plaintext export is necessary, it must be an explicit export exception with
   documented cleanup and no secure-erasure claim, never normal cache storage.
5. Repeat under network interruption mid-part and after commit response loss;
   background/lock; force termination; source reselect; modified source; low
   physical space; OPFS quota failure; and a PWA update with unsynced state.
6. Record paused/needs-source/restart states honestly. Retry unchanged prepared
   ciphertext; changed source or epoch must use fresh version/keys/nonces.
   No unverified partial export may be labeled complete.

Acceptance: genuine installed-PWA Files output on the selected physical targets,
bounded measured pipeline and honest lifecycle recovery. If unavailable or
failing, leave U11/U12 and G1 blocked. Present tested options before changing the
agreed mobile file limit or platform; never introduce server decryption.

## Initial target matrix

| Target | Hardware / OS / provider | Evidence | Status |
| --- | --- | --- | --- |
| Windows 11 x64 + WebView2/Hello | Not supplied | W01 pending probe and physical execution | BLOCKED |
| Lower-memory iPhone installed PWA | Not supplied | I01–I03 | BLOCKED |
| Current iPhone installed PWA | Not supplied | I01–I03 | BLOCKED |
| Linux native/Node | Cloud host, Rust/Node pinned | P01 report | Separate primitive/file evidence |
| Real desktop Chromium worker | Hosted Ubuntu runner | P01 CI report when executed | Separate browser evidence |
