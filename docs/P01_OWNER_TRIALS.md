# One-file owner device trials

The owner requested one Windows executable and one ready-to-upload iPhone ZIP.
Use the [P01 test release](https://github.com/kurasis/AnyNote/releases/tag/v0.1.3-p01-device-kit).
These are unsigned synthetic experiments, not a production release or installer.
No real accounts, secrets, passwords, vaults or administrator access are needed.

## Windows

Download [AnyNote-P01-Windows-x64.exe](https://github.com/kurasis/AnyNote/releases/download/v0.1.3-p01-device-kit/AnyNote-P01-Windows-x64.exe) and double-click it.
Press OK to start. Crypto, public 64 MiB Argon2id and an exact 1 GB local disk
round-trip run automatically. Keep about 3.1 GB free on the system drive.

Use normally configured Windows Hello on the existing Windows account. Follow
the dialogs: confirm the positive prompts, cancel when instructed, and optionally
select the disclosed automatic session-lock test. Press OK, leave the next
Hello prompt pending without touching the sensor, and wait 8 seconds for the
Windows lock screen; Win+L is not required. Cancel skips this step. Each native operation runs in a
fresh process of the **same EXE**. No PowerShell script, Rust installation,
separate helper, manual hash command or source-file preparation is required.

One JSON report is saved in `%LOCALAPPDATA%/AnyNoteP01Reports/trial-*.json`;
the report folder opens automatically and the final dialog gives its path
(Ctrl+C copies dialog text). Send that report
back. It contains executable SHA-256, embedded source commit, actual native
capabilities and content-free operation results, never key/credential bytes.
A real API/provider block stays BLOCKED, with no software fallback.

An existing Hello journal is cleaned without overwriting enrollment; run the
same EXE again afterwards. Failed cleanup remains explicit and retains the
journal. Normally completed disk trials are removed. The next local run cleans
only UUID-named trials carrying this kit's exact marker; concurrent kit runs are
refused. Never reset Hello/TPM, weaken execution policy or delete a retained
journal to hide a failure. The upstream excluded second-account test remains
excluded. The EXE embeds the scoped GPL license (`--license`) and the test release
links exact corresponding source. Advanced developer commands remain in the
[Windows experiment README](../experiments/p01/windows-hello/README.md).

## iPhone

Download [AnyNote-P01-iPhone.zip](https://github.com/kurasis/AnyNote/releases/download/v0.1.3-p01-device-kit/AnyNote-P01-iPhone.zip).
Unzip its **contents** into the test site's web root under `anynote-p01-v013/`:
`<web-root>/anynote-p01-v013/index.html` must exist. No extra nested ZIP directory.
Open `https://YOUR-TEST-SITE/anynote-p01-v013/` in Safari on the iPhone. The existing
HTTPS certificate must already be trusted by that phone. No Node.js, PHP,
database, external libraries or new certificate setup is required.

For the required installed-PWA trial, use Safari Share -> Add to Home Screen
and open the installed app. Tap **Run all automatic tests** and leave it in
the foreground. The kit creates its own random source files, runs crypto/KDF,
storage, exact 1 GB bounded local ciphertext/export/hash and negative checks,
and cleans marked leftover trials. Allow about 3.1 GB free browser quota.

The **same button** then offers **Download 1 GB sample**, **Verify saved Files
output** and **Save report**. The browser receives a streaming attachment from
the verified synthetic disk output, in 256 KiB service-worker reads; no
gigabyte Blob or system Web Share is used by default. Find the download in
Downloads/Files, then select that exact synthetic-export-….bin when asked.
Selected size/SHA-256 must match; stream completion alone is not a Files pass.
Send back only the small `anynote-p01-device-report.json`.

If the installed PWA denies downloading, reopen the same new URL in Safari
and try there, saving each available report. Safari success is a separate
result, not installed-PWA acceptance. The optional **Use system Share instead**
retains the earlier experimental handoff; 0.1.2 physically restarted there.
Hide/background still invalidates keys. No physical download/memory guarantee
follows from host tests. The ZIP README contains hosting details.

## Remaining physical gates

Targets supplied by the owner: Windows 11 Pro 25H2 with Hello available in the owner-supplied API 9/build 26200 report, iPhone
17 Pro / iOS 26.7.1. These are reported targets, not inspected hardware.
The owner subsequently ran the installed iPhone PWA; the hosting address and
configuration remain uninspected. Packaging does not deploy it.
This kit's ciphertext transport is **local OPFS**, not a network/backend test.
The earlier network harness remains available in the experiment and its
[private HTTPS developer runbook](P01_PRIVATE_HTTPS_WINDOWS.md).

Actual device process memory, second older/lower-memory iPhone, physical low
space, provider changes, force-close/resume, production passkeys/enrollment and
update with pending writes stay NOT RUN until separately evidenced. Hosted
Share mocks are UI integration evidence only. No kit result automatically
closes P01/G1 or establishes production acceptance. The original
[physical template](evidence/p01-physical-template.json) remains unfilled.

## Retained diagnostics

The kit saves a small diagnostic report before the system Files handoff. Reopen
the same app/address after a restart to verify the sample already saved, or use
**Save report now**. Copyable report text is also available. A terminated 0.1.0
memory-only report cannot be reconstructed. Clearing/evicting site storage still
removes diagnostics. **Run a new trial** explicitly replaces the last record.

## 0.1.3 update and retry

The page must show **Test kit 0.1.3** at `/anynote-p01-v013/`. Keep the earlier
reports and site storage. The new path reads only the known sibling v012/v011
diagnostic keys on the same origin/browser store; it preserves those records.
If a 0.1.3 staged output was retained, recovery validates its exact purpose
marker, size and hash before offering download again; no keys or file handles
are restored. If only old diagnostics exist and no .bin was saved, choose
**Run a new trial** once to generate the new stream candidate.

Choose the 1 GB .bin, not the JSON log. Wrong selections record sizes and allow
retry without another trial. Missing/cleared/evicted/separate Safari/PWA storage
cannot recover old evidence. A busy download owns the kit lock; let it finish
and reopen the page before retrying. No arbitrary site data is enumerated.

Windows requests lock only after the disclosed optional step is selected. Its
timer is removed on completion/close. The report records OS request outcome
and actual WTS events separately; accepted request alone is not a lock PASS.
The old pending test must fail STALE with a real WTS lock. Signing back into
Windows may require fingerprint/PIN. If no screen appears, cancel the prompt
and send the report. The 0.1.2 owner cancellation/zero-event result remains
NOT PROVEN, separate from the earlier 0.1.1 owner-confirmed screen/STALE run.
