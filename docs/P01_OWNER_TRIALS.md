# One-file owner device trials

The owner requested one Windows executable and one ready-to-upload iPhone ZIP.
Use the [P01 test release](https://github.com/kurasis/AnyNote/releases/tag/v0.1.2-p01-device-kit).
These are unsigned synthetic experiments, not a production release or installer.
No real accounts, secrets, passwords, vaults or administrator access are needed.

## Windows

Download [AnyNote-P01-Windows-x64.exe](https://github.com/kurasis/AnyNote/releases/download/v0.1.2-p01-device-kit/AnyNote-P01-Windows-x64.exe) and double-click it.
Press OK to start. Crypto, public 64 MiB Argon2id and an exact 1 GB local disk
round-trip run automatically. Keep about 3.1 GB free on the system drive.

Use normally configured Windows Hello on the existing Windows account. Follow
the dialogs: confirm the positive prompts, cancel when instructed, and optionally
press Win+L while the next prompt is pending. Each native operation runs in a
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

Download [AnyNote-P01-iPhone.zip](https://github.com/kurasis/AnyNote/releases/download/v0.1.2-p01-device-kit/AnyNote-P01-iPhone.zip).
Unzip its **contents** into the test site's web root under `anynote-p01-v012/`:
`<web-root>/anynote-p01-v012/index.html` must exist. No extra nested ZIP directory.
Open `https://YOUR-TEST-SITE/anynote-p01-v012/` in Safari on the iPhone. The existing
HTTPS certificate must already be trusted by that phone. No Node.js, PHP,
database, external libraries or new certificate setup is required.

For the required installed-PWA trial, use Safari Share -> Add to Home Screen
and open the installed app. Tap **Run all automatic tests** and leave it in
the foreground. The kit creates its own random source files, runs crypto/KDF,
storage, exact 1 GB bounded local ciphertext/export/hash and negative checks,
and cleans marked leftover trials. Allow about 3.1 GB free browser quota.

The **same button** then guides **Save 1 GB to Files**, **Verify saved Files
output** and **Save report**. Choose Save to Files in the system share sheet,
then select that exact saved sample when asked. The page hashes it in 8 MiB
parts and checks the exact length; it never assembles 1 GB plaintext buffers.
Send back the single `anynote-p01-device-report.json`. Delete the disposable
`.bin` from Files after testing; do not send the 1 GB sample.

If the browser cannot share a verified disk File, the report says BLOCKED. A
resolved share alone is never called a Files pass. Hide/background invalidates
keys; system handoff of an explicitly authorized export remains an intentional
exception. Selected-file byte/hash evidence is distinct from Files provenance
and physical review. The ZIP README has MIME/CSP details for the site operator.

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
