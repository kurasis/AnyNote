# AnyNote P01 iPhone test kit

Unzip **the contents of this ZIP** into your trusted HTTPS site's web directory:
`<web-root>/anynote-p01-v012/`. The result must include
`<web-root>/anynote-p01-v012/index.html`, not an extra nested folder.

Open `https://YOUR-TEST-SITE/anynote-p01-v012/` in Safari on the iPhone. For the
installed PWA trial, use Share -> Add to Home Screen and open that app.
Tap **Run all automatic tests** and keep it in the foreground. No Node.js,
PHP, database, external libraries, certificates to generate, or accounts needed.
The existing site must have a certificate trusted by the phone.

The same button then offers **Save 1 GB to Files**, **Verify saved Files output**
and **Save report**. Choose Save to Files in the system share sheet, then select
that exact saved file. Send the single `anynote-p01-device-report.json` back.
You can delete the disposable exported `.bin` from Files afterwards.

Automatic coverage: three frozen cross-runtime crypto corpora; three public
64 MiB Argon2id vectors and fourteen invalid profiles; ciphertext-only IDB/OPFS
reopen; real readonly denial; generated sources 0, 1, 8 MiB+1 and exactly
1,000,000,000 bytes; 8 MiB bounded encryption/decryption; independently streamed
source/output hashes; second-part corruption/truncation/overflow rejection with
old staged output preserved; lock invalidation; marked temporary cleanup.

The file is generated and encrypted **on the phone**. The transport is local
OPFS ciphertext storage, not a backend/network transfer. About 3.1 GB of free
browser quota is required. No giant in-memory plaintext Blob fallback exists.
Browser quota is an estimate; real exhaustion can still fail. Backgrounding
locks the experiment. A retained marked trial is cleaned on the next run.

The report keeps network/resume, passkeys/PRF, actual device memory, older-phone,
physical low-space, force-close and update gates open. A selected file hash is
actual byte evidence, but share completion alone never proves a Files save.
This experimental kit does not declare P01 or production acceptance complete.

Serve `.js` as `text/javascript`, `.webmanifest` as `application/manifest+json`,
`.png` as `image/png`. Keep these files together. Hosting must permit same-origin
workers and bundled WebAssembly (`script-src 'self' 'wasm-unsafe-eval'`), with no
remote scripts. Configure response headers `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer` and CSP `frame-ancestors 'none'` where available.
Do not disable HTTPS verification or sandboxing. Remove this isolated directory
when testing is finished. Assets contain no server endpoints or test secrets.

BUILD.json identifies source; SHA256SUMS.txt covers packaged assets. Sodium
redistribution notices are included; no native GPL Hello code is in this ZIP.

## Retained diagnostics

The kit saves a small diagnostic report before the system Files handoff. Reopen
the same app/address after a restart to verify the sample already saved, or use
**Save report now**. Copyable report text is also available. A terminated 0.1.0
memory-only report cannot be reconstructed. Clearing/evicting site storage still
removes diagnostics. **Run a new trial** explicitly replaces the last record.

## 0.1.2: lock evidence and wrong-file retry

Use `<web-root>/anynote-p01-v012/` for this update and open its URL. The page
must show **Test kit 0.1.2**. Add/open that address from Home Screen for the
installed-PWA trial; a Safari-tab report with `installed_pwa=false` remains a
browser result. Keep the earlier report and sample; no site-data clearing.

When checking Files, choose **synthetic-export-….bin**, exactly
1,000,000,000 bytes. Do not choose `anynote-p01-device-report.json`: that small
file is the log to send back. A wrong size/hash remains FAIL, but the primary
button allows another selection without regenerating the sample. The report
records selected and expected sizes, never the selected personal filename.

If the earlier report was retained in the documented sibling
`anynote-p01-v011/` on the **same origin/browser storage**, 0.1.2 copies that
one known diagnostic checkpoint to its own path and offers another sample
selection, including old report-stage failures. The old checkpoint is preserved.
Other site storage keys are never scanned. Different origins, cleared/evicted
storage or separate Safari/PWA stores cannot supply that record; run a fresh
trial only when no report is restored. No live keys/file handles are restored.

Windows Win+L should show the Windows lock/sign-in screen. A fingerprint/PIN
request for **Windows sign-in** is expected after locking. The old test request
must be rejected as STALE. The newer EXE records native WTS lock/unlock, suspend
and owner-window-close counters. Guided lock PASS now requires the actual
recorded WTS lock event plus failed STALE unlock, rather than STALE alone. The
owner still needs to observe that the prompt was pending; no full negative
matrix or physical acceptance is inferred. The 0.1.1 owner already confirmed
the lock screen appeared; its positive Hello/cancel/cleanup findings are retained.
