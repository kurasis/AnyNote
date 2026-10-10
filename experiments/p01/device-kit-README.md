# AnyNote P01 static iPhone test kit 0.1.4

Unzip all contents into `<web-root>/anynote-p01-v014/`, with `index.html`
directly inside. Open `https://YOUR-TEST-SITE/anynote-p01-v014/` in Safari.
Use Share -> Add to Home Screen and launch that app for the installed-PWA trial.
The page must display Test kit 0.1.4. No Node/PHP/backend/account is required.

Tap **Run all automatic tests**, keeping the page foreground. Allow about
3.1 GB browser quota. The same button then offers **Download 1 GB sample**,
**Verify saved Files output**, and **Save report**. The download is streamed
from the verified synthetic disk output in 256 KiB reads via a scoped service
worker attachment. It does not send 1 GB through system Share or build a giant
Blob. Find its synthetic-export-….bin in Downloads/Files and select that file
for exact 1,000,000,000-byte/SHA-256 verification. JSON is the small log, not
the sample. Send only `anynote-p01-device-report.json` back. Delete the
disposable saved .bin afterwards. Stream completion alone is not Files proof.

If the installed PWA denies the download, try this same new URL in Safari
and retain each report; Safari success does not pass installed-PWA acceptance.
**Use system Share instead** is optional/experimental: the owner reported a
0.1.2 restart there. The new route still needs physical iOS download testing.
Actual process memory, network/backend/resume, passkeys, older iPhone and
physical low-space tests remain separate gates. No production acceptance.

Diagnostics are persisted before download. Reopening retains the report and
can validate/reopen the marked synthetic output without keys or saved handles.
Only the documented same-origin sibling v012/v011 diagnostic keys are read;
old records and unrelated site data are preserved. If old diagnostics exist
but no .bin was saved, run one fresh trial to generate the stream candidate.
Wrong selected size/hash remains FAIL, with retry and report available.
An active stream holds the exclusive kit Web Lock; wait for completion and
reopen before recovery. New trials clean only purpose-marked kit leftovers.
Do not clear site data to update. Eviction/denied/different PWA/browser storage
can prevent recovery. No background completion/durability guarantee.

Hosting: serve .js as text/javascript, .css as text/css, .webmanifest as
application/manifest+json and .png as image/png with a trusted HTTPS certificate.
Do not add a server catch-all that intercepts this directory's SW download
route; the scoped controlling service worker answers it. CSP must allow
self scripts/workers/connect and wasm-unsafe-eval, as in index.html; retain
object-src/base-uri/form-action none. Do not disable sandbox or TLS. Service
worker caches approved static assets only, never dynamic export responses.
All paths are relative. BUILD.json and SHA256SUMS.txt identify exact source,
version and asset hashes; bundled sodium ISC license notices accompany them.

0.1.4 persists short-lived synthetic download tickets in a dedicated path-scoped
IndexedDB store. Browser termination of the SW before clicking cannot erase
that prepared ticket. Expiry and atomic single-use consumption remain intact;
no exported bytes, vault keys or crypto handles are stored there. Streaming
in progress can still be terminated by the OS; no background guarantee.
