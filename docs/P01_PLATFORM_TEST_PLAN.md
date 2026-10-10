# P01 physical platform test plan

Status: **NOT RUN / BLOCKED**. No physical Windows/iPhone has been attached.
These are procedures and required future harness capabilities, not passed tests.
The primitive CLI/worker is a useful prerequisite, not the complete platform
harness. Do not replace missing physical evidence with GitHub Linux results.

[Owner instructions](P01_OWNER_TRIALS.md) and an
[unfilled capture template](evidence/p01-physical-template.json) are prepared.
Independent host export memory/fault/cleanup results are in TEST_EVIDENCE.md;
physical statuses below remain unchanged. The private HTTPS host is not ready.

## Evidence record for every trial

Record date, source commit, executable/bundle hash, device model/RAM, exact OS
build, browser/WebView2 version, provider/authenticator, installation mode,
available storage, network, procedure, result artifact and PASS/FAIL/BLOCKED.
Use fabricated identities and CSPRNG synthetic files only. Record hashes and
content-free counters; never record real passkeys, private keys or recovery kits.

Use at least two supported iPhones: an older/lower-memory candidate and a
current model. Minimum OS support remains a candidate until measured.

## W01 — Actual PRF/TPM protection of a random local key

Prerequisites: actual Windows 11 x64 with current WebView2, Rust MSVC and C++
Build Tools; use the isolated [native probe](../experiments/p01/windows-hello/README.md). Follow
ADR-003 and the [preserved working reference](reference/passkeylocal/README.md),
including its generated native ABI and independent official-header validation.

1. Generate independent random synthetic L in native memory. Use the reference's
   native WebAuthn PRF with creation-time evaluation, fresh required UV and exact
   credential/RP/route checks; inner RSA-OAEP-SHA256 envelope uses a separately
   verified Platform KSP TPM key. Verify public area/Name on creation and reopen.
   Use new fixed AnyNote-owned namespaces. Test the enrollment round trip and
   authenticate an actual synthetic encrypted local vault before session success.
2. Verify that unlock requires the fresh PRF output to open the authenticated
   outer envelope. Direct TPM decrypt alone must not expose L from the stored
   envelope. A successful consent boolean is not decrypt capability. If DPAPI
   is measured as an independent baseline, record same-user malware access and
   do not call it Hello gating; never select it as a silent fallback.
3. Attempt key use before authorization, with cancellation, after Windows lock,
   suspend/resume and fresh process restart. Direct native calls must not bypass
   the intended cryptographic gate. Compare key hashes locally; do not export L.
4. Test absent API 9/PRF/TPM/Hello and provider failures; reject unsupported paths.
   Do not silently enable a weaker fallback. The weakest enabled wrapper limits
   security; report fallback behavior explicitly.
5. Test a stale lock-generation reply and unauthorized IPC/window context when
   the actual adapter is available. No raw-key or generic filesystem API.

Acceptance: operation-level protection evidenced with positive and bypass tests,
or a documented unsupported result with concrete owner options. CI Windows
compilation alone cannot prove real Hello user presence or physical TPM behavior.
Use the existing account and disposable synthetic objects. Preserve the upstream
owner's completed diagnostics; do not request its excluded second-account manual
test or reset Hello/TPM. Account isolation remains unverified by this procedure.

## I01 — Installed PWA crypto/storage baseline

Prerequisites: dedicated trusted HTTPS synthetic host and physical iPhones.
[The prepared PWA harness](../experiments/p01/PHYSICAL_HARNESS.md) has a manifest,
worker, ciphertext storage probes, file selection and explicit bounded export
adapters. No HTTPS host is deployed or physical installed-PWA trial completed.

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

The isolated harness now tests selected File -> ciphertext upload/download ->
verified explicit OPFS export on Chrome. It also prepares an experimental
verified disk File -> separate Web Share action for physical evaluation. This
is not a production immutable session/manifest journal or recipient protocol.
OPFS, canShare or a resolved share promise alone is not an iOS Files pass.

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
| Windows 11 x64 + WebView2/Hello | Owner reports Windows 11 Pro 25H2; Hello planned; exact build/provider/WebView2 pending capture | W01 native probe built; physical execution NOT RUN | NOT RUN |
| Lower-memory iPhone installed PWA | Not supplied | I01–I03 | BLOCKED |
| Current iPhone installed PWA | Owner reports iPhone 17 Pro, iOS 26.7.1; exact build/storage/provider pending capture | I01–I03 | NOT RUN |
| Linux native/Node | Cloud host, Rust/Node pinned | P01 report | Separate primitive/file evidence |
| Real desktop Chromium worker | Hosted Ubuntu 24.04, Chrome 154.0.8037.97 | Run 38052778078, 663 primitive checks and 1 GB generated-stream round-trip PASS | Separate browser evidence; physical/mobile memory unresolved |
