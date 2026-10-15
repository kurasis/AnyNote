# P14 Windows application development

Base: merged P13 `7aaf3b770b739c2bd554bd6feb7e653c00dbe3b9`.
Historical development observations. Accepted software results are in
evidence/p14 and TEST_EVIDENCE.md; earlier pending/failed entries below retain
their original scope and do not override that final evidence.

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

The c524a65 Windows fail-fast check identified the exact dirty-source cause:
maintained Tauri command permission files under permissions/autogenerated. Only
that generated directory is ignored; hand-written permissions are still visible.
The post-build audit now checks all five generated allow/deny command pairs and
retains its exact report hash in final source evidence. Source drift is not hidden.
Windows UI evidence now records current working-set baselines and sampled deltas
across the full gigabyte workflow, separately from lifetime OS peaks and WebView2
shared-page sums. The initial target is reported as an observation, not an
unmeasured performance guarantee. Actual execution is still pending.

The complete preserved-data setup also passes at c524a65 after the session fix:
all1018 tracked files,31 persistent tables and TLS/OAuth files remain identical.
The real gigabyte native test remains enabled. Later changes in this batch affect
generated-output accounting and test observations, not product runtime code.

At clean da83624 the Linux release native coordinator passes all62 checks with an
actual incompressible1,000,000,000-byte source, fresh shared copy, downloads/full
SHA-256, standard-age export, separate kit, complete offline validation and fresh
import/download. Source hash:Q9DtNs-u1-xZmv7jCWOyqwN_lNQrW0f5nL7hXSufHdY.
Observed lifetime OS peaks:239,656,960 native and403,738,624 helper bytes. These are
not baseline-subtracted Windows/mobile memory measurements. A first trial failed
closed before export with real insufficient disk space; only generated compiler
caches were cleared, preserving source/recovery data, before the successful run.

Windows da83624 passes the generated permission audit, clean source checks,
pairing33/sharing20, real Tauri instrumented host and0.14.1 candidate installer
build. It stops before GUI execution because the test CA import returns no usable
receipt. The CI trust helper now converts public PEM to DER, computes an independent
thumbprint, refuses a pre-existing root, records cleanup intent before OS mutation,
and checks the exact certificate bytes in the current-user root store. PowerShell
errors terminate and retain sanitized diagnostics; no TLS bypass is introduced.
The full GUI/upgrade test is still pending. Its idle case now opens a live sensitive
preview immediately before waiting the unchanged five-minute idle policy.

CI caches the public Cargo registry plus native and complete desktop build outputs
after successful compilation, including when later acceptance fails. Candidate
preparation no longer overwrites Cargo's executable with instrumented bytes; the
separate explicit harness path is passed only to the owned GUI runner.

The hosted CurrentUser certificate-store operation was independently bounded and
reproduced a45-second timeout; cleanup succeeded. The main run's cancellation
trace confirms it was still inside trust's installed=checked call, before the
WebView2 runner started. An isolated hosted LocalMachine operation verifies the
same exact DER bytes and removes the certificate in3.9 seconds. Its hosted-only,
bounded variant also passes in2.1 seconds. Both GitHub ZIP digests and actual helper
source bytes were independently verified. This is CI infrastructure evidence,
not an owner application privilege, physical-platform result or TLS exception.

The test helper now requires a GitHub-hosted Windows runner, uses that confirmed
machine root store, records cleanup intent, verifies exact bytes and bounds OS
calls. A distinct early workflow step checks trust before the installer, and
cleanup preserves every failure while still attempting stop. Complete compiler
caches are saved before GUI acceptance. The main cancelled run saved the warmed
registry/desktop cache successfully; all24 inherited jobs passed at bdda809.

The GUI runner emits only fixed phase labels and bounds stalled CDP calls. It
checks the real signed HTTPS updater metadata before expensive gigabyte workflows,
then retains the full tamper/install/restart/outbox checks after those workflows.
Failed ephemeral signer commands discard process output and throw a generic
error instead of exposing Node's retained stdout/stderr. The full Windows GUI,
gigabyte and actual upgrade acceptance remain pending; P14 is still active.

The early full-host step at a350118 times out while reading the machine root
store through a child Windows PowerShell process, before any store mutation or
WebView2 run. A diagnostic matching its PowerShell parent and Python3.14.8 passes
with explicit closed stdin and noninteractive child commands. Its raw ZIP digest
and exact helper bytes were independently verified. Service commands now close
unused stdin and add -NonInteractive to PowerShell; explicit PHP/SQL control
request bodies still use their intended input pipe. TLS and exact root checks
remain enabled. Complete Windows GUI acceptance is still pending.

The first real GUI attempt at ba68828 reaches owner installation but times out
on its HWND check. Inspection finds an unclosed foreach block in the PowerShell
memory helper; the entire helper fails parsing, including foreground operations.
An isolated Windows diagnostic exercises original-parser rejection, corrected
parser/compilation, real process memory, and an owned WinForms HWND with neutral
SendInput. Its test step completed successfully, but retrieval of the final raw
report and verification of its source bytes and ZIP digest remain pending:
GitHub API and ordinary Git authentication stopped working. This diagnostic
cannot establish Tauri acceptance.

The missing brace is fixed and formatted. The full workflow now parses the helper
before compilation. HWND waits preserve helper errors and process-exit status;
legacy PowerShell is explicitly noninteractive. The complete Tauri/1GB/upgrade
acceptance remains pending. No assertion, sandbox, authority or TLS check was
removed to accept a failed runtime.


At 000d815 the real owner installer starts its HWND and rejects debugging
injection, then the separately instrumented binary cannot expose CDP. The pinned
Tauri builder documents that different browser arguments require different data
directories; both binaries were using the same WebView2 data scope. The explicit
integration feature now uses a per-process temporary browser directory shared by
its main and preview windows. Native encrypted profile paths remain normal and
unchanged. The harness checks its real HWND and retains process-exit diagnostics
before connecting CDP. This is a pending runtime correction, not acceptance.

After GitHub reconnection the isolated helper diagnostic raw report, ZIP digest
and exact helper Git bytes were verified successfully; see retained development
receipts at closure. The diagnostic remains separate from Tauri acceptance.


The db8658f run still has no CDP endpoint. A short source-bound binary diagnostic
on the hosted Windows runtime confirms a real HWND, active renderer/browser
processes and the intended isolated directory, but no remote-debugging argument
in the actual browser process command line. Explicit environment user-data
selection works; environment debugging arguments are absent in both trials.
The CI-only builder now passes fixed loopback CDP flags through the maintained
native additional_browser_args option for both main and preview windows. This
retains Wry defaults and does not add owner-release debugging or native rights.
The new actual runtime result is still required.

A complete local setup attempt stops on a P09 storage-abort test with
STALE_WRITER after unusually long scheduling delays. The unmodified isolated
suite then passes all eight tests. The failed setup receipt is not accepted;
the complete preserved-data scenario must pass before closure. No writer lease,
authorization timeout or assertion is extended or disabled.


The pure P09 injected-storage-abort unit case now holds its own Date clock using
Node's scoped mock timers. A host scheduling pause cannot turn its expected
INSUFFICIENT_STORAGE into unrelated lease expiry before the injected write. Its
exact error/unchanged-record/key assertions remain intact. The independent vault
suite still expires the actual stored lease and rejects a stale writer; no
production timeout, clock, lease or authority check was changed.


The separate direct-options probe cannot see the PR-scoped Cargo cache and is
cancelled during cold dependency compilation at its eight-minute budget. No CDP
result or report exists for that attempt. The main PR workflow now runs an early
actual empty-profile WebView2/React/typed-IPC preflight before backend, pairing and
installer work, using its valid PR cache. It kills only the owned process tree
and removes only the verified empty synthetic profile directory. Its separate
source-bound report is required in the final receipt; the complete installed
1 GB/upgrade suite remains mandatory and unchanged.


At 3841045 the early real WebView2/React/typed-IPC preflight passes, but native
sharing stops at the first OAuth loopback completion after its unchanged
five-minute deadline. A real Windows Rust 1.99 TCP diagnostic reproduces the
accepted socket inheriting nonblocking mode: reading before delayed headers
returns WouldBlock immediately, while explicitly restoring blocking waits 250 ms
and reads successfully. Its raw ZIP digest was verified.

The production loopback listener now explicitly restores blocking mode on each
accepted loopback stream before its existing bounded timeouts. Global deadline,
request parsing, Host/state/issuer/PKCE and one-use checks remain intact. A real
delayed-header IPv4/IPv6 regression covers the race. The synthetic driver/helper
adds fixed failure categories and HTTP/network status only; no callback URL,
OAuth code, state, verifier or credentials enter logs. Full Windows integration
still needs to pass at the corrected source.


At 17c60f0 the Windows native test command succeeds with the new delayed-callback
case, then the P06 evidence producer rejects its old exact four-test expectation.
The producer is updated to require all five named tests and the exact five-pass
summary, runs them serially and records the new count. This retains strict
execution evidence rather than accepting a missing or skipped regression.


The corrected Windows OAuth flow then passes pairing and sharing. The first
installed GUI unlock attempt stops on an absent button: its generic onboarding
button/password predicates also match the previous Create screen while profile
loading/selection is asynchronous. The harness now waits for the exact saved
account button and then the actual Unlock button, verifies the persisted profile
scope through the existing read-only typed command, and retains full publication,
lock and file assertions. It does not mutate React state or bypass native unlock.


Failed GUI runs now preserve only their compiled CI harness, native fixture
driver, synthetic next-version installer and a source/binary-digest manifest.
The normal owner artifact still has one NSIS setup. No vault, credentials,
private key, runtime profile or source data enters the diagnostic bundle. The
manifest explicitly says BUILT_UNVERIFIED: binary reuse can diagnose a test but
cannot substitute for fresh exact-source all-25 application acceptance.


## Windows renderer view fence

Full Windows run38710404757 passed actual installation, unlock and updater
preflight, then published the keyboard-created thread through the real API but
failed to show it. A source-bound reused-binary diagnostic (run38714510343,
compiled source c67e3b1) reproduced STALE_CAPABILITY in the renderer while the
native vault remained unlocked; the UI had cleared the selected group.

The renderer previously used STALE_CAPABILITY for both protected generation
changes and selection/view changes. A late reply from the previous view could
therefore clear the current UI, including via background access polling. View
changes now reject only the stale UI result as STALE_VIEW, which the UI discards.
Protected-generation changes still raise STALE_CAPABILITY and mask/recheck the
vault. Native authorization, lifecycle fences and custody are unchanged. The
original real keyboard/publication scenario remains required in fresh-source
Windows acceptance; the reused-binary observation is not phase acceptance.


## Actual Windows clipboard sequence and native consent

Fresh-source run38715520150 passed real keyboard/thread/checklist/tag publication
with the renderer view fix, then could not locate native clipboard confirmation
through the original UI Automation tree. Reused-binary run38718567329 found the
owned Win32 dialog and pressed its real Yes button; copy and actual clipboard
text checks passed. Automation now recognizes only the exact owned process,
visible AnyNote #32770 dialog and enabled native Button ID6 with No ID7. A bounded
SendMessageTimeout presses that real button. Consent and native authorization
remain required. UI Automation providers for file dialogs are bound to actual visible owned
HWNDs rather than the incomplete desktop-child PID query. Failure diagnostics
contain HWND classes/state only.

The next actual 30-second clearing assertion failed. Std-only Windows probe
run38719329544 established that the sequence was 2 before CloseClipboard but 5
after it, with exactly unchanged native Unicode and PowerShell text after more
than 30 seconds. The original marker therefore rejected its own finalized copy.
The native writer now records the sequence after CloseClipboard and then checks
that its own HWND remains the clipboard owner. Capturing sequence before the
ownership check fences an intervening other-app copy; later copies change the
sequence. The existing exact-text and sequence checks still protect another
application's clipboard value. The original full 30-second and later-copy UI
assertions remain mandatory; OS diagnosis alone is not application acceptance.


## Primitive CDP errors are distinct from successful values

Fresh-source run38719871883 passed real clipboard copy and actual 30-second
clearing after the sequence fix. The next native-denial assertion failed because
the test CDP client discarded primitive string rejections: V8 returns their code
in exception.value, without exception.description. The unchanged client converted
an actual INVALID_REQUEST-shaped rejection to WEBVIEW_EVALUATION_FAILED. Real
Node/V8 Inspector reproduced that exact wire response; the original client failed
the regression, while the corrected client passes four real Runtime cases.

The client now preserves primitive rejection strings as well as Error descriptions.
Successful error-looking strings remain successful values, so the denial helper
still requires an actual rejection matching the expected exact code. Early real
WebView2 preflight now also checks unknown profile operations and extra fields,
before backend/installer/gigabyte work. Product parsing/permissions, the original
invalid raw HTTP/path denials and actual 1 GB workflows are unchanged. The CI
cache generation advances once to retain rebuilt native-auth/host artifacts for
subsequent documentation-only heads; Cargo fingerprints and every test remain
required. Reused
compiled full-host diagnostics remain separate from fresh-source/all-25 acceptance.


Reused full-host diagnosis run38724260983 confirmed native dialog edit ID1148
and Button ID1 were exposed as ControlType.Pane, so ControlType-based selectors
could not select files. The CI actor now uses visible owned Win32 #32770 dialog
HWNDs, exact native Edit filename IDs/ancestry and Button ID1. Bounded WM_SETTEXT
and WM_GETTEXT round-trip the fixture path; the actual Open/Save button is pressed
and its native dialog must close. Native file selection/handle validation and
all original gigabyte assertions remain required. Only control classes, IDs and
state are recorded on failure, never filenames or contents. Full reused diagnosis
continues separately; fresh-source CI must still execute the entire application.


A later Save dialog exposed its filename Edit as ID1001 with a logical UIA
FileNameControlHost, while the expected Win32 ancestor was absent. File selection
now requires one unique visible/enabled native Edit with the known filename IDs
inside the exact owned #32770 dialog, plus its native accept Button ID1. Ambiguous
fields fail closed. Native control ID/parent-class metadata is available on failure.
The CI job compiles its embedded C# automation before expensive native builds.

An additional 4096-byte installed Open/Save/export/separate-kit/complete offline
validation/fresh-import/download preflight exercises every dialog transition
before the full gigabyte workflow. The original entire gigabyte block remains
byte-identical; no 1 GB/hash/memory/idle/update assertion is removed or reduced.
The short round trip is additional coverage and never substitutes for 1 GB.


The added small preflight immediately caught an output-path mismatch: the native
download job completed after a closed Save dialog, but the requested fixture
output did not exist. A native WM_SETTEXT/WM_GETTEXT echo alone did not prove
that the modern Save controller committed that filename. The CI actor now
focuses the exact owned filename edit, selects/clears it, types Unicode through
real SendInput, verifies the entered text and commits by focusing the native
accept button. Every input checks owned foreground/focus. Its synthetic neutral
heartbeat pauses only during dialog interaction; native idle policy stays intact.
The same exact requested output and full hash assertions remain required. The test actor
also drains any in-flight neutral input before filename typing or process stop,
so its own heartbeat cannot redirect focus during text entry.

The real Unicode-input diagnosis run38731280193 completed the additional native
4096-byte upload/download with the requested destination and exact SHA, then
failed at small export with BRIDGE_CLOSED. This remains a development failure,
not gigabyte/export acceptance. Terminal native job failures are now asserted
outside the generic retrying condition, so a finished failure is reported
immediately instead of being swallowed until the 20-minute polling timeout.
The complete original gigabyte workflow and its assertions are unchanged.

## Canonical installed resource path and restricted helper

Public-only startup diagnosis run38735436373 isolated a Windows runtime path
failure. The pinned packaged helper answers normally with CREATE_NO_WINDOW and
read-only asset handles, but a verbatim `\\?\D:\...` script path causes Node
24.21's exact-file permission matcher to terminate with ERR_ACCESS_DENIED before
any protocol frame. Tauri 2.12's resource directory comes from its canonicalized
starting executable, so installed resources use this spelling. The bridge now
uses pinned dunce 1.0.5 to simplify only paths with identical DOS semantics before
passing the script argument and exact same read allowlist to Node. Runtime/script
hash verification, held read-only handles, cleared environment, no-addons,
permission mode and the filesystem/network boundary remain unchanged. No vault
keys entered the public startup probe; its captured stderr is from synthetic
public input only. The existing actual frozen-archive bridge recovery test now
canonicalizes the resource path, covering installed Windows path semantics.
Fresh exact-source/full installed-host acceptance remains required.


Fresh source f904aed passed all 24 inherited gates, 13 Windows native tests,
pairing/sharing and the complete additional small installed recovery preflight.
Run38736291441 then completed actual keyboard/clipboard/previews and real
1,000,000,000-byte upload/download/hash/export/separate-kit/offline inspection,
but the confirmed large fresh-import job did not yield a completed result before
the unchanged 20-minute deadline; its last state/counters were not recorded. Full host/native-HTTP/idle/update acceptance is
still pending. The polling actor now records only fixed state/error codes and
decimal byte/time counters, excluding IDs, paths, names, content and keys, so
a future refusal or stall identifies its last public progress.

## Windows full-duplex pipe backpressure

Public-only run38744494720 reproduced a Windows transport deadlock mechanism
with the exact pinned packaged Node runtime: an 8 MiB process.stdout write blocks
the event loop from consuming the parent's pending input while the parent has not
yet read output. Maintained asynchronous fs.write on inherited descriptor 1
consumes input under output backpressure and produces the exact same 8 MiB SHA.
Both variants retain no-addons, permission mode, exact script read access and a
cleared environment; neither receives vault/archive/device keys.

The trusted helper now serializes bounded asynchronous descriptor writes, handles
short writes, caps pending frames and wipes completed owned frame buffers. The
frame format, read-only script allowlist and runtime/script pins are unchanged.
A real child-process regression holds stdout back while sending 8 MiB stdin,
then verifies concurrent frame order, lengths and complete SHA. It runs before
native compilation on Windows and during cloud setup. The actual frozen archive
also recovers successfully with the new bundled helper on Linux. Fresh full
Windows multipart/gigabyte/import/idle/update acceptance remains required.

## Prefetch requests while receiving a recovered part

Fresh run38744944190 at 4abd1c3 completed real gigabyte upload/download/hash,
export/kit and offline inspection. Fresh import then refused INVALID_BRIDGE_FRAME
promptly instead of hanging. The recovered-part handler assumed the next helper
frame must be plaintext. A validated reader may issue its bounded archive-prefetch
request while its visitor is emitting part data. The handler now services only
that same checked selected-source request while awaiting the part, rechecks job
cancellation/generation each iteration, and still requires the exact plaintext
frame type and declared length. All other frame types and invalid offsets fail.

A real inherited-pipe regression reproduced INVALID_BRIDGE_FRAME before this
change and passes afterwards, including invalid-offset, wrong-length and foreign
frame refusals. Its public peer receives no vault/archive keys or path capability.
There are now fourteen native tests. Existing full gigabyte bytes/hash assertions,
resource limits and the completion deadline are unchanged; full Windows acceptance
remains pending.


## Actual gigabyte/idle completion and updater restart readiness

Fresh run38749347031 at 72daa1e completed the unchanged genuine gigabyte
upload/download/export/offline-validation/fresh-import/download hashes, real
five-minute idle/preview closure and installer rerun/fresh-process draft read.
Its first metadata-tamper assertion was blocked by WRITER_BUSY after a deliberately
killed process. Focused run38755429870 identified that code. The test now waits
for an ordinary typed native diagnostic to acquire its lease after restart,
retrying only WRITER_BUSY for at most fifteen seconds. The existing ten-second
lease, generation/fence rules and exact tamper assertions are unchanged.

With readiness restored, focused run38756424699 passed bad claims, wrong version
and altered-payload refusals, but the signed candidate did not replace the
registered installed application. Public exact-installer control run38758156134
showed passive mode waiting on an owned Installer Language dialog, while quiet
mode completed with exit0, a changed installed executable and version0.14.1.
The maintained updater now uses quiet Windows install mode after the existing
explicit native confirmation. Signing/version/hash/scope checks remain mandatory.
The normal current-user installer retains its EN/RU language selector. Complete
fresh-source app updater/retained outbox/profile scan/native gigabyte/all25 closure
remains pending; these development observations do not claim that acceptance.


GitHub access was restored before acceptance. Diagnostic run38666079720
completed PASS; its original-parser failure, corrected parser/compilation, real
process memory, owned WinForms HWND and neutral SendInput were verified against
the raw ZIP digest and exact Git helper bytes. The standalone diagnostic retains
its infrastructure-only scope; full installed acceptance is separately recorded.


At af53a19 the first local full setup stopped on native file_part STALE_WRITER.
The unchanged isolated full gigabyte test then passed; lease, clock, all 120
chunks, hash and source assertions were retained. The separate historical
observation records that refusal and retry without claiming full setup success.
The final complete setup receipt above is its own later actual execution.


Historical content-free native control/filename observations and exact Git
helper blobs are retained in evidence/p14/development/native-dialog-observations.json.
Additional small native recovery preflight does not replace the unchanged genuine
1 GB workflow; its original block identity is recorded separately.


Canonical Windows helper regression run38737907729 records the real
BRIDGE_CLOSED before the fix and original authenticated plaintext recovery after
the fix on the same pinned packaged runtime and frozen archive. The helper and
workflow Git bytes, raw job-log digest and original installer artifact ZIP digest
were independently verified; the tested fixed bridge bytes match the accepted
application source. This historical diagnosis remains separate from complete
fresh-source installed-host and all-25 acceptance.


Windows real-pipe regression run38749648491 reproduced the prior
next-frame-only refusal and passed with bounded archive-prefetch handling,
including invalid-offset, wrong-size and unrelated-frame refusals. Its raw
artifact digest and both executed source hashes were reconstructed from exact
Git inputs and the recorded counterexample generator. The repaired imports
module bytes match the accepted application source. This public framing test
remains separate from final installed-host/gigabyte acceptance.
