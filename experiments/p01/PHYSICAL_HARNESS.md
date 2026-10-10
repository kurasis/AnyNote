# Private synthetic PWA harness

The test-only page, dedicated worker, manifest and service worker prepare
controlled physical trials. They are separate from production application/auth
and native Windows code. No public deployment or trusted HTTPS certificate has
been configured by this task. Use only disposable synthetic files.

Owner actions and capture template: [physical trial runbook](../../docs/P01_OWNER_TRIALS.md).
Windows LAN certificate option: [manual private HTTPS procedure](../../docs/P01_PRIVATE_HTTPS_WINDOWS.md).

## Serve with trusted HTTPS

From this directory after frozen npm installation:

```sh
node serve-physical.mjs --cert /outside/checkout/test-cert.pem --key /outside/checkout/test-key.pem
```

The default listener is 127.0.0.1:8443. An explicit `--host`/`--port` can bind a
private test host reachable from the phone. Configure a certificate the phone
already trusts and a controlled network; do not disable TLS verification. Never
commit private keys. Open the configured host's `/physical/` path and install
from Safari to Home Screen. No cloud localhost preview is supplied.

The process owns a new temporary directory containing ciphertext only. It
serves locally bundled scripts under CSP, bounds uploads to one 8 MiB+16 part,
and deletes its own temporary data on orderly SIGINT/SIGTERM shutdown. It is a
single-trial private test transport with no auth or recipient protocol; never
expose it as a public service. Each new trial needs a fresh server session.

## Supported experiment and explicit limits

- Probe actual secure context, OPFS/IndexedDB, quota/persistence outcomes and
  bounded export-picker availability. Report denied persistence honestly.
- Select a real synthetic File, read at most one 8 MiB source part, encrypt and
  upload ciphertext only. File names are not transmitted or logged.
- The live worker retains a random test key and bounded ciphertext inventory.
  Download verifies lengths/digests/tags before writing to an explicitly chosen
  File System Access writable sink; whole output length/hash is verified before
  successful close. Keys do not enter screen state or storage.
- A browser with no tested bounded Files sink displays **BLOCKED**. There is no
  whole-file plaintext Blob, OPFS-as-Files claim or server decryption fallback.
  A user-selected output is the explicit plaintext export exception.
- An additional **experimental** iPhone candidate prepares a verified disk file
  in a marked temporary OPFS export directory, then offers Web Share of that
  existing File on a separate explicit click. It does not concatenate plaintext
  buffers or send plaintext to a server. `canShare` and a resolved `share` promise
  do not prove saving to Files or bounded OS/browser IPC memory; physical 1 GB
  output/hash/memory evidence is required before accepting this candidate.
- The share sheet may background the app: crypto keys still lock, while the
  already authorized explicit export remains available to that in-flight sheet.
  Completion/cancellation cleans its test directory where possible. Termination
  can leave marked test exports; the explicit cleanup control removes only
  directories bearing this harness's purpose marker. There is no secure-erasure
  claim or reliance on pagehide as the only cleanup mechanism.
- Hidden/pagehide locks and invalidates the live trial. Reselect checks exact
  size/full hash; changed bytes require fresh keys. Matching source alone is
  not resume. Termination/reload loses the live key; restart with a new session.

Automated Chrome tests use **explicit temporary plaintext OPFS export sinks**,
read back the saved File in bounded slices and compare to an independently
computed Node SHA-256. Those test outputs are removed afterward. This verifies
the browser streaming/writable mechanics and actual File reading, not an iOS
Files output, fresh recipient, production manifest or physical interruption.
Normal OPFS/IndexedDB durability probes separately store ciphertext only.

Selected-file upload and export/readback now have separate desktop process RSS
samplers. Real worker/HTTP/OPFS fault trials cover corrupted/truncated second
parts, decoded gzip expansion beyond the claimed part length, lifecycle lock
before a delayed download, exclusive writable denial and marked orphan removal
after reload. The first-part writes are aborted before commit and the prior
committed OPFS output must remain unchanged. This does not establish atomic
abort semantics for every physical OS sink or a rollback after close/commit.
Physical low disk and interruption acceptance still require device evidence.

Target supplied: iPhone 17 Pro, iOS 26.7.1 (owner-reported). Record actual build,
browser/provider, installation, memory/storage, source commit and actual saved
file hash per P01_PLATFORM_TEST_PLAN.md. The older/lower-memory iPhone remains
unspecified. Until physical evidence exists, 1 GB iOS Files export, installed-PWA
PRF/login, low disk, lifecycle/resume and mobile memory gates stay open.
