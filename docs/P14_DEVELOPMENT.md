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
