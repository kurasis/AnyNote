# One-file owner device trials

The owner requested one Windows executable and one ready-to-upload iPhone ZIP.
Use the [P01 test release](https://github.com/kurasis/AnyNote/releases/tag/v0.1.0-p01-device-kit).
These are unsigned synthetic experiments, not a production release or installer.
No real accounts, secrets, passwords, vaults or administrator access are needed.

## Windows

Download [AnyNote-P01-Windows-x64.exe](https://github.com/kurasis/AnyNote/releases/download/v0.1.0-p01-device-kit/AnyNote-P01-Windows-x64.exe) and double-click it.
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

Download [AnyNote-P01-iPhone.zip](https://github.com/kurasis/AnyNote/releases/download/v0.1.0-p01-device-kit/AnyNote-P01-iPhone.zip).
Unzip its **contents** into the test site's web root under `anynote-p01/`:
`<web-root>/anynote-p01/index.html` must exist. No extra nested ZIP directory.
Open `https://YOUR-TEST-SITE/anynote-p01/` in Safari on the iPhone. The existing
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

Targets supplied by the owner: Windows 11 Pro 25H2 with Hello planned, iPhone
17 Pro / iOS 26.7.1. These are reported targets, not inspected hardware.
The HTTPS host was not ready when reported; packaging does not deploy it.
This kit's ciphertext transport is **local OPFS**, not a network/backend test.
The earlier network harness remains available in the experiment and its
[private HTTPS developer runbook](P01_PRIVATE_HTTPS_WINDOWS.md).

Actual device process memory, second older/lower-memory iPhone, physical low
space, provider changes, force-close/resume, production passkeys/enrollment and
update with pending writes stay NOT RUN until separately evidenced. Hosted
Share mocks are UI integration evidence only. No kit result automatically
closes P01/G1 or establishes production acceptance. The original
[physical template](evidence/p01-physical-template.json) remains unfilled.
