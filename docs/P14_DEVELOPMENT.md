# P14 Windows application development

Base: merged P13 `7aaf3b770b739c2bd554bd6feb7e653c00dbe3b9`.
The phase is in progress; these changes are not phase acceptance evidence.

The native coordinator and Tauri main window use existing native custody,
OAuth, signed note/file authority, encrypted journals and P13 portable formats.
The renderer has no generic key/signing/path/SQL/HTTP command. Native selected
files and jobs are generation bound. Real main-HWND WTS and suspend messages
invalidate native generation before UI notifications. Idle uses Windows user
input rather than job activity. Public profiles separate local custody scopes.

The compiled Node helper uses a pinned runtime, no addons, restricted filesystem
permissions, anonymous bounded frames and a cancellation watchdog. Device,
group, root keys and bearer credentials are not passed to it. Native export
signing accepts only the independently computed fixed inventory footer. Recovery
uses the maintained P13 offline reader before any destination writes.

Still required: complete import/recovery and lifecycle correctness tests; native
sync/offline and all product workflows; isolated previews and cache controls;
current-authority shared/device flows; signed-updater policy integration;
dependency/license inventories; actual Windows WebView2/API/SQL acceptance and
incompressible 1 GB round trips; all 24 inherited gates and exact-source evidence;
P15 handoff, preserved-data install/start, normal guarded merge and final
configuration save/readback. No physical, production signing or audit result is
implied by this development branch.

## Current development verification

The native HTTP development harness now passes 49 checks against the actual owned
HTTPS/Laravel/MariaDB stack: maintained PKCE loopback, signed notes, delta/offline
projection, private preferences, exact receipt recovery, archive/trash/restore,
verified device roster, shared history/epoch changes, and a small-file complete
portable recovery/import round trip. This is dirty-development evidence, not the
final exact-source or Windows acceptance receipt. The earlier real native 1 GB
round trip remains separately recorded; the expanded final gigabyte run is pending.

The native test suite also verifies more than 16 MiB of recovered note payloads in
separate encrypted records, immutable source/alias recovery, kit/output recovery,
protected profile trust and pending setup, cache preservation, and maintained
update signatures. The static capability audit preserves 179 original specification,
P02 fixture and pre-P14 lock files and grants only five typed main-window commands
plus event subscription. Static results do not prove actual runtime denial.

Windows commit 01b6bc6 built the single NSIS installer successfully. Its backend
setup failed because the static test site's esbuild dependencies were not installed;
PHP/MariaDB were running. The next workflow installs those frozen dependencies and
adds installed-release startup/debug denial, an explicitly instrumented real WebView2
host, actual native dialogs, software HWND lifecycle, encrypted SQL and full 1 GB
upload/download/export/offline recovery/fresh import. These added scenarios have not
yet passed Windows. Physical session/Hello/TPM and independent review remain open.

The owner installer clears WebView2 remote-debug overrides before starting threads.
Only the separate integration-harness executable permits local CI CDP observation;
its report identifies that distinction and both executable hashes. Authentication,
TLS validation, native custody and per-window permissions remain active in the
instrumented software test. No sandbox or signature bypass is introduced.

## Native device, sharing and recovery development

Actual owned-API development runs pass 33 native pairing checks and 17 native
sharing checks. These exercise both pairing directions, independent custodians,
verified transcripts, replay and substitution denial, recipient-only key delivery,
revocation fencing, independent public cards, admission/history, role-loss draft
preservation and jointly consented ownership. Native group creation now retains
one protected genesis request and metadata draft across a lost server receipt.
These results are development observations, not final exact-source acceptance.

The Windows backend runner exposed two real integration faults: a selected file
was still held by its synthetic writer, and Windows PHP cannot open/fsync a
directory through its streams API. Synthetic writers now await close. Production
Linux file and directory fsync remain required. Only the marked disposable
Windows Actions backend binds a separately pinned helper performing real Windows
FlushFileBuffers on its own volume, in addition to existing per-file fsync. This
is an explicitly scoped CI storage adapter, not a production Windows backend or
a claim that PHP directory fsync works on Windows. The next Windows run must
prove the primitive and complete actual gigabyte and WebView2 workflows.

The expanded native development round trip passes 49 checks: selected-file copy
into a shared group with fresh IDs/keys, recovered metadata, a placeholder for a
pruned/deleted source thread, remapped authenticated attachments, pause, lock,
source reselect and same-job import resume. Import reconciles expired/cancelled
or obsolete-epoch uploads before fresh preparation and retains superseded IDs.
The selected source and original archive remain immutable recovery inputs.

The Windows GUI acceptance now includes explicit clipboard handoff with a native
confirmation and best-effort 30-second/lock cleanup, preserving another app's
clipboard value. Only a verified saved note can enter that native clipboard
route. QR PNG save uses a native exclusive destination. Actual clipboard, updater
HTTPS/tamper/candidate installation and WebView2 tests remain pending execution.
An ephemeral CI-only maintained CLI signer is deleted after producing public
fixtures; its key is never included in artifacts or application resources.

Windows bd9d7da failed to compile a pairing confirmation's Arc reference, before
backend/gigabyte/WebView acceptance. The corrected reference and separately
cacheable native release build are included in the next run. The failure is not
platform acceptance, and cached/stale installer output is not a new candidate.

The next development batch reaches 50 native API checks including a durable
recovered destination title. A real release-mode 1,000,000,000-byte round trip
passed the earlier 49 checks, with fresh shared-file copy, complete standard-age
recovery/import and final SHA-256 equality. That dirty development run measured
239,673,344 native and 812,802,048 helper peak bytes. These lifetime peaks are
not an incremental Windows memory-target pass. A fixed bounded helper input
buffer replaces quadratic growing-frame copies; the independent frozen archive
bridge test passes, and a fresh gigabyte measurement remains required.

The desktop now includes canonical tag/checklist editing, keyboard publication,
a modal group/thread destination picker, stricter preview origin checks, explicit
Permissions-Policy/frame-ancestors, all lock-path clipboard cleanup, and a final
exact-source receipt collector. A Windows gate also found a provider import style
issue; the maintained Pint formatter fixed it and all 102 PHP files pass lint.
No required failed check has been bypassed. See P14_WINDOWS.md for the operator
and build guide; installed GUI/update acceptance is still pending.

After the fixed helper frame buffer, the expanded release-mode gigabyte round
trip passes all 50 checks. Observed peaks are 239,906,816 native and 405,811,200
helper bytes, compared with the earlier 812,802,048 helper peak. This is an actual
Linux development measurement; source was dirty because unrelated host acceptance
work continued during the run. It is not final exact-source/Windows acceptance
or a formal same-process incremental-memory-target claim.

Updater requests now have independent generation cancellation, bounded request
timeouts, HTTPS-only clients and a single-operation permit. Windows acceptance
also stages a native SENT_UNKNOWN immutable outbox before installation, verifies
its exact attempt/draft digest after the actual upgrade/restart, and publishes
that original attempt. Actual raster/PDF workers are exercised in isolated native
preview windows. These expanded Windows checks are pending the next source run.

The native API regression run now passes 57 checks, including an actual server
commit whose receipt is withheld from native custody, a newer saved edit, exact
receipt reconciliation, retention of that newer edit and its subsequent fresh
publication. Host reconciliation checks receipts before send/writer authorization.
Definitive conflict/access/rekey refusals classify the immutable attempt while
retaining its original record and draft; uncertain network outcomes stay pending.
The UI keeps the newer protected draft visible after an older receipt is recovered.

The native sharing suite now passes 20 checks, including a server-committed
receiver publication whose receipt is withheld until after a role downgrade.
The receiver acknowledges that exact receipt without another send or writer
authorization; an unrelated unpublished draft remains protected and blocked.
The expanded case also exposed a stale history inventory: access/history
operations now capture current verified peer publications before preparation.
An explicit native-confirmed pending-access cancellation reconciles its result
before retiring the pending key. UI entry creation and attachment preservation
were corrected during host review. Final Windows acceptance remains outstanding.

Windows 0ab095a built the installer, passed native tests, real filesystem flush,
pairing33 and sharing17. Its native gigabyte run uploaded the original and fresh
shared copy, then failed during import when the fifteen-minute OAuth access
token expired. The verified raw artifact's last API failure is401SESSION_EXPIRED;
no signature/TLS/storage check was disabled. This is not a completed host receipt.

Native control and binary transports now serialize request/credential rotation
and proactively invoke the maintained protected one-use refresh before expiry.
The durable unknown-refresh marker still requires fresh login after uncertainty.
A feature-only test can shorten its synthetic cached expiry, never extend server
authorization or expose credentials. Actual small API62 checks pass with forced
expiry/rotation through both control and binary transports, followed by complete
file/export/import flows. Windows full acceptance
must now exercise real expiry during its longer run.

The complete reusable setup succeeded. A separate clean-source repeat at97a128e
preserved all1018 tracked files,31 persistent content/security tables and every
TLS/OAuth file byte-for-byte. Native all-feature tests, including the real gigabyte
case, remained enabled; release tests use the same assertions as the shipped
profile. A final merged-head setup/start and configuration readback remain due.

CI input uses real Windows SendInput only for an owned synthetic foreground app,
then stops input and waits the unchanged five-minute idle/generation fence. It
does not disable idle. Native generation also follows an underlying vault timeout
so a previously auto-locked vault cannot leave previews under an old host scope.
These new Windows UI checks remain pending; physicalG1 is not inferred.
