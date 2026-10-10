# Known limitations

- P00 is complete; an isolated P01 synthetic native/Node/browser-worker harness
  exists. No production application authentication, device trust, encrypted vault, Laravel
  service, manifests or resume is implemented. The isolated selected-file PWA
  harness and experimental disk-File sharing candidate do not establish iOS Files
  export or a real recipient/recovery path.
- Rust/Cargo 1.99.0 and Node 24.21.0/npm 11.19.0 are installed and activated
  through scripts/runtime-env.sh; experiment dependencies have lockfiles. PHP,
  Composer, MariaDB and Nginx are still not prepared (P03).
- Physical Windows/Hello/WebView2 and iPhone PWA tests cannot run on this Linux
  cloud host. P01 must distinguish host experiments from actual platform evidence.
- Qualified independent protocol/security review has not taken place. Synthetic
  experiments may proceed; production security assurance remains gated.
- GitHub API read/PR/Actions access now works, and both earlier P00 runs passed.
  Hosted Ubuntu provides actual Chromium-worker evidence. The cloud Chromium
  sandbox itself cannot start (helper ownership / read-only namespace mapping);
  it was not disabled. Native-only mode labels browser NOT RUN explicitly.
- Browser aggregate RSS is a sampled desktop metric with shared-page double
  counting, not evidence of the 64 MiB iPhone budget. WASM heap alone does not
  include JS/network/UI buffers. Physical memory/export evidence remains required.
- Selected-file export now has its own per-phase RSS report and real abort/fault
  checks. The initial 1 GB export/readback sampled increment was 104,976 KiB,
  upload 416,692 KiB; this does not verify the mobile 64 MiB budget. A 25 ms
  requested timer does not guarantee sample cadence. OPFS abort preserves the
  prior committed output in the tested failures before close; arbitrary physical
  sinks or rollback after OS close/commit are not established by these tests.
- The physical runbook, bounded file helper and hash/source Windows collector
  are ready. Owner reports the private HTTPS host is not ready. Reachability,
  phone certificate trust and actual installation remain unverified. The local
  Windows certificate procedure is optional, manual and unexecuted here.
- Owner-reported targets are Windows 11 Pro 25H2 with Hello planned and iPhone
  17 Pro / iOS 26.7.1. Exact builds/providers are uninspected; the required older
  or lower-memory iPhone remains unspecified. The working passkeylocal source
  is now adapted into a built/tested native synthetic AnyNote probe; its physical
  PRF/TPM operations remain unrun. Hosted Windows reports API 7, below the API 9
  route requirement, and creates no native objects.
- Production signing, release publishing, deployment and clean-host backup
  restoration have not been performed or authorized by the push/merge preference.
- The cloud disk is too small for a 100 GB capacity drill; dedicated synthetic
  resources are required at P16.
- Browser-origin compromise, unlocked endpoint compromise, prior recipient
  copies and malicious-server freshness limits remain inherent specification
  boundaries, not bugs declared fixed by this baseline.

- The simplified iPhone ZIP runs local ciphertext OPFS transport; network/API
  upload/download and resume are NOT RUN there. Exact 1 GB requires about
  3.1 GB browser quota and worker synchronous OPFS support. A verified staged
  disk File can still be rejected by the physical Web Share provider. System
  Files save/reselect require owner interaction; hosted sharing is mocked.
- Windows one-EXE tests use the scoped GPL native adapter and static CRT, but
  are unsigned synthetic tooling. Actual native capability may remain BLOCKED
  even when crypto/KDF/local 1 GB checks pass. Cancellation is recognized only
  from HELLO_CANCELLED, lock rejection only from STALE. No full physical gate
  or all-negative-matrix pass follows from positive fresh-process unlock.

- Owner-reported 0.1.0 Windows result establishes reported local checks and
  available API 9/build 26200/Hello route only. `operations=[]`; native enrollment,
  TPM binding and fresh authorization remain unverified. The kit admission bug
  is corrected in 0.1.1; a new owner run is required for those results.
- Owner reported the iPhone PWA restarted after saving to Files, losing the old
  memory-only report. A terminated 0.1.0 report cannot be recovered retroactively.
  0.1.1 persists diagnostics before handoff and survives hosted page destruction,
  but origin eviction/clearing or denied storage can still remove/prevent them.
  Real updated iPhone Files/hash/restart and process-memory acceptance remain OPEN.

- Owner 0.1.1 Windows report now supplies positive enrollment/fresh-process
  authenticated PRF/TPM unlock, native cancellation and cleanup. Win+L lock
  screen is owner-confirmed with native STALE rejection, but the old report
  cannot attribute STALE using actual event counters. New instrumentation
  requires a WTS lock event as well; prompt timing still needs observation.
- Owner 0.1.1 iPhone report confirms physical Safari local checks and diagnostic
  recovery, not installed-PWA or actual Files byte/hash acceptance. Wrong
  selected size is explained by the owner's JSON/other-file selection; the .bin
  was not verified. Do not infer corruption or an OS save failure from this.
- Same-origin prior-report migration reads only the documented v011 sibling
  key. A different path/origin, eviction or separate browser/PWA storage may
  prevent recovery. Retry does not turn a mismatched file into a success.

- Owner 0.1.2 Windows run has zero lifecycle events and HELLO_CANCELLED at the
  lock step: NOT PROVEN, consistent with the absent screen. Positive unlock,
  cancellation and cleanup retain their separate scope. Earlier lock observations
  are separate runs. API request acceptance is not lock/pending-prompt proof.
- Owner confirms iPhone 0.1.2 restart at 1 GB Web Share. 0.1.3 defaults to an
  experimental SW attachment stream; actual PWA/Safari download and device
  memory remain OPEN. The OS may terminate SW work, deny downloads or require
  Safari. No background guarantee or mobile acceptance follows from host tests.
- Retain generated synthetic exports until selection verification or a new
  trial's exact marked cleanup. Dynamic streams are never cached; expired or
  replayed tickets cannot resume. Other site data/old reports are preserved.
  No network/backend or production plaintext-stream path is added.
