# Next bounded task

## P01-CRYPTO-INTEROP — synthetic feasibility harness

Prerequisite: P00 baseline verified. Read progress/decisions/limitations, then
specification 04, 05, 10, 11 and 13. Read the mandatory initial chapters if this
is a fresh session. Inspect actual Git state and preserve unrelated changes.

Objective: establish a maintained native libsodium binding and browser/WASM
binding can exchange XChaCha20-Poly1305, Ed25519 and sealed-box outputs using
public synthetic fixtures; measure bounded chunk processing. This is feasibility,
not the frozen application protocol or production crypto implementation.

Scope:

1. Pin/install Rust 1.99.0 and Node 24.21.0 with verification intact; reconcile
   selected versions with actual available security revisions in an ADR.
2. Create isolated `experiments/p01` with exact lockfiles and documented commands.
3. Produce native→JS and JS→native fixtures; reject wrong key/tag/context and
   report exact library/provider/toolchain versions. Browser-worker execution
   must be exercised separately; a Node-only result is not browser acceptance.
4. Measure synthetic incompressible chunk encryption/decryption memory; preserve
   the decimal 1 GB requirement. Avoid whole-file memory buffers.
5. Prepare reproducible physical Windows key-gating and iPhone 1 GB export/resume
   procedures. Mark these BLOCKED while the devices are unavailable.
6. Update decisions/progress/risks/evidence and the next bounded task. Run actual
   meaningful checks, commit, push and merge automatically as authorized.

Invariants: synthetic data only, no primitive implementation by hand, no server
plaintext fallback, no real key custody, no fabricated physical evidence.

Exclusions: application UI/auth, device enrollment protocol, production crypto,
Laravel business logic and a complete P03 scaffold. P03 tooling can proceed
independently after P00; final wire contracts need P02.

Exit: repeatable interop harness with positive and negative evidence plus exact
unmet platform gates. P01 remains IN PROGRESS/BLOCKED until its complete physical
feasibility criteria are evidenced. Recovery: discard generated public fixtures
and scratch outputs; no user data exists.
