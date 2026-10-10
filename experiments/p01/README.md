# P01 synthetic feasibility experiment

This directory is isolated from application code. It exercises maintained
libsodium bindings and bounded file processing with **synthetic nonsecret data**.
It is not the frozen AnyNote protocol, an audit, production key custody, an
authenticated backend or a usable vault.

## Pinned prerequisites

- Rust 1.99.0; Node 24.21.0 (bundled npm 11.19.0).
- `libsodium-rs` 0.2.5 / `libsodium-sys-stable` 1.24.0, native libsodium 1.0.22.
- `libsodium-wrappers-sumo` / `libsodium-sumo` 0.8.4, WASM libsodium 1.0.22.
- esbuild 0.28.2 and Playwright Core 1.64.0.
- Real Chrome/Chromium, with a working sandbox, supplied by the host. Set
  `CHROMIUM_EXECUTABLE` if it is not found at a usual platform path.
- Linux bootstrap: C compiler, make, pkg-config, curl, tar, xz and sha256sum.

Native source/binaries bundled in the sodium crate retain the upstream Minisign
verification. `fetch-latest` is disabled; no signature/hash/TLS checks are bypassed.
Only the exact esbuild postinstall is allowed by npm's `allowScripts` policy.

## Reproduce on the cloud/Linux host

From the repository root:

```sh
bash scripts/install-p01-toolchains.sh
source scripts/runtime-env.sh
npm --prefix experiments/p01 ci --cache /workspace/.cache/npm --no-audit --no-fund
cargo build --manifest-path experiments/p01/native/Cargo.toml --locked --release -j 4
cargo fmt --manifest-path experiments/p01/native/Cargo.toml --check
cargo clippy --manifest-path experiments/p01/native/Cargo.toml --locked --release -j 4 -- -D warnings
cargo test --manifest-path experiments/p01/native/Cargo.toml --locked --release -j 4
cd experiments/p01
npm test
npm run test:large
```

The cloud bootstrap defaults to `/workspace/.toolchains`; set `ANYNOTE_TOOLCHAINS`
to a writable directory on a different Linux host. It keeps toolchain files
outside the checkout. Source activation for each new shell/task; live processes
are not retained. No development server needs to stay running after a test.

`npm test` exercises file sizes 0, 1, 8 MiB−1, 8 MiB, 8 MiB+1 and rejects decimal
1 GB+1. `test:large` additionally processes **1,000,000,000 bytes**, 120 chunks,
last plaintext chunk 1,755,648 bytes, data ciphertext 1,000,001,920 bytes. The
native test creates a real incompressible file, writes ciphertext chunks, then
decrypts to an explicit synthetic export and verifies length/SHA-256. The browser
worker generates an incompressible stream, uploads/downloads ciphertext through
a loopback-only bounded server and compares recovered bytes plus whole-stream
SHA-256. It does not save to iOS Files or exercise a real file picker.

The runner starts/stops only its own local server and browser, removes its own
temporary synthetic files, preserves command failure exits, and writes results
under ignored `artifacts/`. It fetches no remote browser scripts/helpers. CSP
allows only local bundled scripts/workers plus `wasm-unsafe-eval` for WASM;
ordinary eval and inline scripts remain disabled.

## Browser sandbox limitation in the current cloud container

The provided Chromium sandbox helper is owned by `nobody`, and user namespace
mapping is read-only. Chromium with its sandbox enabled fails before page load.
Do not disable sandboxing to disguise this failure. Run the browser suite on
the GitHub Ubuntu runner or another correctly configured host.

The explicit native-only command performs useful independent work and reports
`PASS_NATIVE_BROWSER_NOT_RUN`, never browser success:

```sh
node run.mjs --native-only --large
```

## Interoperability evidence

Live Rust, Node and Chromium worker producers use the same public seeds and
binary messages, then every relevant consumer verifies/decrypts them. Each
direction executes 39 positive/negative checks: exact AEAD bytes, invalid
key/AAD/nonce/ciphertext/tag/truncation, exact Ed25519 key/signature and invalid
signature/message/signer, sealed-box opening and invalid recipient/corruption.
Committed producer fixtures are then consumed by all three runtimes.

Fixtures label all key material **PUBLIC NONSECRET SYNTHETIC**. AEAD/signature
bytes are deterministic. Sealed boxes use CSPRNG ephemeral keys: their committed
bytes are stable test input, not reproducible generation from the recipient seed.
They prove recipient confidentiality interop, not authorized-sender verification.
The schemas/prefixes are experiment-only and must not become application formats.

Initial fixture recording uses `node run.mjs --write-fixtures`; a corresponding
manual Actions input permits real browser production of the initial corpus.
Normal CI never regenerates fixtures and fails when a fixture is absent or bad.
Review public generated fixtures before committing. No report contains random
benchmark keys or real user data.

## Local unlock/storage and physical-harness continuation

`npm test` / `test:large` now also consume committed public Argon2id13 vectors
in native Rust, Node and a real Chromium worker. Profile v1 validates 64–256 MiB
and opslimit 3–10 before allocation; measured vectors use exactly 64 MiB / 3,
32-byte outputs and 16-byte salts. UTF-8 includes an embedded NUL without
normalization/truncation. Wrong phrases cannot open the synthetic key wrapper;
invalid profiles and concurrent worker jobs are rejected. No weaker retry exists.
Upper-bound acceptance does not mean a 256 MiB device measurement was performed.

IndexedDB/OPFS tests store ciphertext only, reopen through a new worker after
page reload and verify exact bytes/digests. Persistence results are permissions,
not promises against eviction. Readonly denial and a genuine QuotaExceededError
under a CDP-injected 1 MiB origin quota are labeled separately from physical disk
exhaustion. The bounded quota trial attempts only 2 MiB of opaque random bytes.

The selected-file suite uses real browser Files at 0, 1, 8 MiB+1 and, for large
runs, decimal 1 GB. It verifies bounded ciphertext transfer and writes an explicit
temporary plaintext OPFS export, then reads the saved File back and compares
hashes against independent Node SHA-256. OPFS exports are removed after tests.
Matching reselect, changed source, oversize-before-read and locked export are
checked; this does not implement restart/resume or an authorized fresh recipient.

See [Windows probe](windows-hello/README.md) for native PRF/TPM build/trial
commands and scoped GPL-3.0-only source licensing, and
[private HTTPS PWA harness](PHYSICAL_HARNESS.md) for physical preparation and
explicit Files-sink limitations. No native provider code enters browser bundles.

## Measurements and remaining gates

Native RSS uses Linux `VmHWM`; browser memory samples aggregate process RSS
through CDP and `/proc` every 25 ms. Shared pages may be counted twice and short
peaks may be missed. Reports describe exact environment/method; these measurements
cannot certify a 64 MiB iPhone budget. No forced garbage collection is used.

Bulk synthetic browser source generation uses native Web Crypto CSPRNG calls
of at most 64 KiB. Initial measurements isolated expensive per-byte entropy
bridging in `libsodium.randombytes_buf` for an 8 MiB test source; it was not an
AEAD slowdown. Libsodium still generates the small file keys/prefixes. Actual
uploads will read selected files instead of generating random source data.
Phase timings and optional WASM linear-heap measurements distinguish these costs;
WASM heap size alone is not total worker/process memory.

No full encrypted manifest/key-envelope path, trust/roles, source reselect,
crash resume, quota, lifecycle lock, passkeys/PRF, Windows Hello, WebView2 or
physical iPhone export is implemented by this experiment. Physical procedures
are in [the P01 platform plan](../../docs/P01_PLATFORM_TEST_PLAN.md). P01/G1
cannot be declared verified until that evidence exists.
