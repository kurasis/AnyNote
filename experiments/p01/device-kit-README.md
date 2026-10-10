# AnyNote P01 iPhone test kit

Unzip **the contents of this ZIP** into your trusted HTTPS site's web directory:
`<web-root>/anynote-p01/`. The result must include
`<web-root>/anynote-p01/index.html`, not an extra nested folder.

Open `https://YOUR-TEST-SITE/anynote-p01/` in Safari on the iPhone. For the
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
