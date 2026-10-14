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

The native HTTP development harness now passes 40 checks against the actual owned
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
