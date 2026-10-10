# Next bounded task

## P01-PHYSICAL-TRIALS — platform memory, export sink and fault evidence

Prerequisite: P01-CRYPTO-INTEROP and P01-LOCAL-UNLOCK host reports recorded.
Read AGENTS.md, progress, decisions, limitations, P01_PLATFORM_TEST_PLAN.md,
experiments/p01/PHYSICAL_HARNESS.md and windows-hello/README.md. Preserve
original specification bytes and unrelated changes. This remains P01; G1 is open.

Objective: establish which prepared native/PWA paths work on the actual supplied
platforms, improve bounded export/fault handling from measured evidence and
record the exact remaining platform constraints.

1. Continue independent host work: measure actual selected-file export process
   memory separately from generated-stream RSS; add meaningful interruption,
   corrupt/truncated download, export abort and orphan-cleanup checks where the
   changed implementation needs them. Do not infer a 64 MiB iPhone pass from WASM
   heap or a desktop aggregate metric. Preserve exact 1,000,000,000-byte trials.
2. Verify the compiled Windows probe source/hash and actual capability report.
   Target Windows 11 Pro 25H2 with Hello planned (already supplied). On the
   existing physical account, use only disposable native objects: roundtrip;
   cancellation/lock; explicit enroll -> new-process unlock -> cleanup; verify
   the real synthetic vault and exact ownership deletion. Capture actual build,
   API/provider and prompt observations. Hosted API 7 is expected BLOCKED, not
   permission for fallback. No reset/policy changes or repeated upstream trials.
3. Prepare a trusted private HTTPS test host when its access/certificate are
   available; do not publish an unauthenticated test server publicly or deploy
   production. The manifest/worker/server and runbook already exist. No cloud
   localhost preview or TLS verification bypass. Synthetic data only.
4. Target iPhone 17 Pro / iOS 26.7.1 (already supplied, owner-reported) installed
   from Safari. Capture actual capabilities/KDF/storage and device memory.
   Evaluate the bounded verified disk File -> separate Web Share candidate or
   another supported sink. Independently inspect the actual Files output and
   hash/length; canShare, a share completion or OPFS file alone is insufficient.
   Test small sizes before the exact 1 GB file; no whole-file buffer/Blob fallback.
5. Run I01–I03 lifecycle/low-space/source-reselect procedures as implemented.
   Current backgrounding locks and requires fresh session/keys; matching source
   is not resume. Do not claim production manifests/recipient trust or recovered
   progress before those parts exist. Clear only owned marked test export state.
6. The older/lower-memory second iPhone remains unspecified. Complete independent
   host checks while physical access/target/HTTPS prerequisites are absent; do not
   request already supplied OS/model strings again. Mark precise parts NOT RUN
   or BLOCKED. If a real iOS sink/1 GB trial fails, present measured options
   before changing the agreed scope. P03 tooling is an independent permitted
   track after P00 and may proceed when physical work has no executable next step.
7. Record actual reports, exact sources, limitations and next bounded task;
   run checks, push and merge tested completed work automatically as authorized.

Invariants: no real secrets/user vaults, key-bearing frontend/native replies,
plaintext server, silent software/DPAPI fallback, verification/sandbox bypass,
permission/protection bypass or fabricated hardware/audit evidence.

Exit: reviewable platform/fault evidence and concrete supported/blocked sink
constraints. P01/G1 remains open until physical acceptance is actually recorded;
qualified review and production protocol/release gates are not replaced by CI.
