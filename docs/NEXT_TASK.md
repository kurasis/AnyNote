# Next bounded task

## P01-LOCAL-UNLOCK — local wrapper and storage feasibility probes

Prerequisite: P01-CRYPTO-INTEROP host/CI evidence recorded. Read progress,
decisions, limitations, current Git state and specification 04, 05, 10, 11 and
13. Preserve the original spec and unrelated work. This remains P01; do not
claim its physical G1 gate complete or start production key custody prematurely.

Objective: evaluate supported local unlock/key wrappers and PWA storage/export
capabilities with synthetic keys/files before choosing production adapters.

Scope:

1. Add an isolated native/browser Argon2id v1.3 probe using exact libsodium
   opslimit/memlimit/salt semantics. Start at 64 MiB / opslimit 3; reject bounds
   before allocation and serialize KDF jobs. Measure genuine browser latency
   without silently lowering the cost. Verify cross-binding outputs and wrong
   phrase behavior; use public synthetic fixtures only.
2. Add Chrome/browser OPFS and IndexedDB capability/quota/persistence probes and
   ciphertext-only durability inspection. Record denial/exhaustion accurately.
   Actual iPhone behavior remains a separate physical test.
3. Read the preserved passkeylocal handoff/source in
   docs/reference/passkeylocal; verify its SHA256SUMS before extraction. The
   working installer-source reference is c18894e..., current handoff is 15f54f00...;
   exact SHAs are in PROVENANCE.json. Use ADR-003's native PRF + separately
   verified Platform KSP TPM design to protect independent synthetic random L.
   Reuse the tested PRF creation input, generated ABI/independent-header checks,
   exact per-key TPM proof and lifecycle invariants with fresh AnyNote namespaces.
   Do not port KDBX password-component semantics or upstream native objects.
   Build a minimal real-provider Windows probe; no raw-key frontend API or silent
   DPAPI/consent/software fallback. Hosted Windows can check MSVC/ABI and failure
   handling but cannot stand in for physical Hello. Retain licensing/notices when
   importing source and record that choice before packaging.
4. Prepare the controlled-HTTPS physical PWA harness for selected-file source
   and bounded explicit export, plus lifecycle/reselect tests. Do not mistake
   OPFS or a desktop download for saving 1 GB into iOS Files. Keep it isolated
   from future production auth, protocol and app bundles.
5. Target the supplied Windows 11 Pro 25H2 with Hello planned and iPhone 17 Pro
   / iOS 26.7.1 (owner-reported, not inspected). Capture actual build/provider
   during physical trials; do not ask for already supplied strings again.
   Physical Windows and at least two iPhone targets are required to close P01/G1;
   the older/lower-memory iPhone remains unspecified. Continue the
   independent probes if devices are unavailable; report exact blocked parts.
6. Update evidence, ADRs, risks, limitations and next task; run meaningful checks,
   then push and merge automatically as authorized.

Invariants: synthetic data, real crypto/provider operations, exact agreed 1 GB
limit, no plaintext server fallback, no verification/sandbox bypass and no
invented physical-platform success. Application wire contracts await P02;
qualified review remains an external production gate.

Exit: reproducible wrapper/storage feasibility evidence and concrete platform
constraints. P01 remains IN PROGRESS/BLOCKED until the complete physical
acceptance path is evidenced. If a genuine iOS export failure requires changing
scope/platform, present tested options for owner decision. P03 tooling is an
independent permitted track after P00, but cannot replace these gates.
