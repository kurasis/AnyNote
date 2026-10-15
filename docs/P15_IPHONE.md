# iPhone PWA development and acceptance

P15 is in development. Implementation and prepared checks below are not completed
browser, physical-device or release acceptance. P14 remains software accepted;
its production signing, memory and physical limitations remain.

## Installation and navigation

The static entry `/auth/notes.html` has a stable `/auth/` manifest scope,
standalone display and original local 192/512 PNG icons. On iPhone use Safari's
Share → Add to Home Screen, then launch that icon. Notes exposes EN/RU
installation/storage help. Mobile navigation selects groups, threads or note,
with Back, safe-area spacing and 16px inputs. Desktop retains three panes.

Local unlock, account sign-in, device proof and group authority remain separate.
Hide/pagehide masks content and disposes its Worker. BFCache restoration reloads
into a fresh locked document on Account, Devices and Notes. New unlock rechecks
online access; offline view authenticates retained local content.

## Durability and operating-system boundaries

Local-save acknowledgement follows the encrypted transaction. The existing
500ms autosave delay means forced termination can lose an unacknowledged last
edit. Save locally before leaving; acknowledged drafts, immutable attempts and
outbox remain protected. Background completion is not guaranteed.

Network pause aborts owned requests without erasing source commitments. Resume
reselects the same bytes and reconciles the old operation. Import/export pause
fences its UI generation and closes transient export custody; protected import
journals and published content remain. Reinspect the same archive/kit to resume
import; a new export uses a fresh identity. Files/share outputs are explicit
plaintext copies outside the vault. System sheets may suspend or reload iOS.
No giant plaintext Blob or server decryption fallback is added.

Storage estimates and persistence decisions are not capacity/eviction guarantees.
Persistence is requested only by a user gesture. Zero quota differs from an
unavailable estimate. Keep an independent recovery copy and separate kit.

## Static update and optional notifications

An exact static allowlist is fetched with cookies omitted and redirects refused.
API/auth responses, query-bearing requests and export routes are never cached.
The revision binds every cached byte and the worker/stream code. Failed install
removes only its candidate cache; activation preserves encrypted databases and
unrelated caches.

Update first saves the editor and locks custody. A downloaded worker waits for
all controlled windows to close; no skipWaiting or force-update message exists.
Reopen and unlock. Optional push reception ignores payload text/links and shows
only neutral EN/RU activity; clicks open the fixed notes entry. Push delivery and
subscription are not configured by this development work.

## Validation

Run `source scripts/runtime-env.sh && python3 scripts/check-p15.py` from the
checkout. It checks manifest/icons, preserves the 179-file baseline, executes six
worker policy tests and builds the actual UI. This does not run a browser.

The new mandatory `pwa-linux-http-browser` job supplements the original 25 gates.
It uses genuine multi-account production API/crypto, trusted TLS, strict CSP,
sandboxed Chromium, WebAuthn and Worker/IndexedDB/OPFS. P12 generates an actual
incompressible 1,000,000,000-byte source, uploads, locks/reselects, downloads and
compares full hashes. P15 adds mobile/keyboard viewports, encrypted portable
export, independent offline full-hash recovery, private import and a real
waiting-worker update retaining a newer draft. These browser steps are prepared;
they have not yet passed at this source.

Memory separates sampled aggregate Chromium RSS from renderer/dedicated-Worker
V8 heap/backing storage, with baselines, observed peaks/increases and requested
cadence. Samples can be delayed and agents restart. Unsampled/OS/shared/external
memory and physical iPhone budgets are not inferred from these values.

`p15-evidence.py` refuses dirty/unpassed source receipts. Final acceptance must
archive exact public raw reports, independently verify artifact ZIP digests and
compare all source-input bytes with actual Git blobs. Never publish private kit,
QR, credentials or raw local-store fixtures.

## Compatibility and open gates

Owner target: iPhone 17 Pro / iOS 26.7.1. No new physical trial is authorized; the
trusted private HTTPS host is not ready. iOS 18.x is only a minimum candidate.
Desktop Chromium at a mobile viewport is not physical Safari PWA, Files/provider,
PRF, storage, lifecycle or iPhone memory evidence. The prior physical Files-save
reload observation is not closed by hosted downloads. G1/U11/U12 and qualified
G2/G3 remain OPEN/NOT_RUN, as do production operations/signing and arbitrary
100GB capacity. The existing optional PRF wrapper/strong phrase fallback remain.
