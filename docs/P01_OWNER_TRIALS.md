# Owner actions for the physical P01 gate

These procedures use disposable synthetic data. Hosted tests are recorded
separately. Owner-supplied targets are Windows 11 Pro 25H2 with Hello planned
and iPhone 17 Pro / iOS 26.7.1; capture actual builds without repeating those
questions. No remote access to these devices is assumed.

## 1. Windows: capture capabilities first

Use the existing physical account and its normally configured Windows Hello.
No Hello/TPM reset or security-policy change is required. Download the
`p01-windows-synthetic-probe` artifact from the successful
[run 38057370071](https://github.com/kurasis/AnyNote/actions/runs/38057370071),
then extract it. This is an unsigned native synthetic probe, not an installer.
The frozen executable has SHA-256
`2b6352037b5f65cd266bb745eb6e62c53fa4aaa3508fc6a473425f3335584da1`
and embedded source `4dae7264e23fb0fa5bc904bdebe63d4ab36d3c46`.
Artifacts expire after 14 days; do not substitute an unverified newer EXE.
If expired, use a newer successful run's source and executable receipt together
or build the pinned source using windows-hello/README.md and retain build evidence.

Get the current repository (which contains the collector) and run from its root
in PowerShell. Replace the example EXE path with the extracted file's real path:

```powershell
$probe='C:\P01\target\release\anynote-p01-windows-hello.exe'
$expectedHash='2b6352037b5f65cd266bb745eb6e62c53fa4aaa3508fc6a473425f3335584da1'
$expectedSource='4dae7264e23fb0fa5bc904bdebe63d4ab36d3c46'
& .\experiments\p01\windows-hello\scripts\collect-physical.ps1 -Probe $probe -ExpectedSha256 $expectedHash -ExpectedSource $expectedSource -Operation capabilities
```

The collector checks hash/source before enrollment or unlock. It captures only
OS build/version, hardware model/RAM and content-free probe reports in a new
`P01-physical-results/trial-*.json`. No usernames, hostnames, key material or
credential IDs are requested. Return that capability record first. If the
report is BLOCKED (for example API below 9), stop enrollment/unlock; report the
exact capability result. Use existing approved execution settings; record any
enforced binary/script block rather than weakening policy.

## 2. Windows: only after the capability route is eligible

Select each operation explicitly with the same verified EXE and collector:

```powershell
& .\experiments\p01\windows-hello\scripts\collect-physical.ps1 -Probe $probe -ExpectedSha256 $expectedHash -ExpectedSource $expectedSource -Operation roundtrip
```

Complete actual OS prompts for the positive trial. This authenticates a real
synthetic encrypted vault and attempts exact ownership cleanup. Record actual
prompts and the outcome, including cleanup failures. A second disposable trial
deliberately cancels a prompt; it must not report unlocked. For a lock trial,
press Win+L while authorization is pending, return to the account and record
the invalidated result. Closing the probe window also cancels.

For a fresh-process trial, use separate collector invocations with
`-Operation enroll`, then `-Operation unlock`, then `-Operation cleanup`.
Each invocation launches a new native process. Run cleanup after failed/cancelled
trials as well. A retained journal must remain until its exact objects are
removed; never delete it to hide failure. The fixed synthetic directory is
`%LOCALAPPDATA%/AnyNoteP01Hello`. Do not repeat the upstream excluded
second-account test. Per-operation native success is not complete G1 acceptance.

## 3. iPhone: prepare a reachable trusted private HTTPS origin

Required: a computer that can run Node 24.21.0, a private network reachable
from the phone, and a certificate/key for that host already trusted by iPhone.
The server has no login and must stay on the controlled test network. No public
deployment, port forwarding or TLS verification bypass is part of this task.
Certificate keys must stay outside the repository and out of chat.

From the repository root on the chosen host:

```powershell
node --version
npm --prefix experiments/p01 ci --no-audit --no-fund
Set-Location experiments/p01
node serve-physical.mjs --cert C:\P01-TLS\test-cert.pem --key C:\P01-TLS\test-key.pem --host YOUR_PRIVATE_LAN_IP --port 8443
```

Replace the host/certificate paths with actual trusted values; the default
127.0.0.1 listener cannot be reached by the phone. Open the configured HTTPS
host's `/physical/` path in Safari and install to Home Screen. If a reachable
trusted host is absent, this prerequisite remains BLOCKED. The cloud checkout
does not publish a phone-accessible preview. A local certificate option is
described in [the Windows HTTPS runbook](P01_PRIVATE_HTTPS_WINDOWS.md).

Record `git rev-parse HEAD` and `Get-FileHash dist/physical-worker.js` /
`Get-FileHash dist/physical-page.js` (SHA256) from experiments/p01 after the
server builds them. Use a fresh trial origin or clear only this synthetic
harness origin before testing a different build; its cached static assets
must not be mistaken for a newer source version.

## 4. iPhone: small files, then the exact 1 GB trial

Create files on the computer in a dedicated disposable directory. The helper
uses CSPRNG bytes in at most 8 MiB buffers, refuses overwrites and prints
size/SHA-256. Run commands from experiments/p01 in a second terminal:

```powershell
node synthetic-file.mjs create C:\P01-Data\small.bin 32768
node synthetic-file.mjs inspect C:\P01-Data\small.bin
node synthetic-file.mjs create C:\P01-Data\boundary.bin 8388609
node synthetic-file.mjs create C:\P01-Data\one-gb.bin 1000000000
Get-FileHash C:\P01-Data\one-gb.bin -Algorithm SHA256
```

Move only these synthetic sources to the phone's Files app through the chosen
private route. Record exact source length/hash. Start with the small file.
The HTTPS transport is single-trial: restart the server with Ctrl+C between
different uploads so old ciphertext cannot conflict with a new trial.

1. Launch the installed PWA. Capture storage/export capabilities, the public
   64 MiB Argon2id measurement and ciphertext-storage result. Record actual OS
   build, installation mode and available storage.
2. Select the synthetic file, encrypt/upload, then prepare the verified
   temporary disk export. Click Share separately and choose Save to Files if
   the system actually offers it. If unavailable, record BLOCKED without a
   full-file Blob alternative. `canShare` or a resolved share is insufficient.
3. Inspect the actual file saved in Files. Copy that output back to the computer
   via the private route and run `synthetic-file.mjs inspect OUTPUT_PATH` or
   Get-FileHash plus file length. Compare independently to the source receipt.
4. Repeat at 8 MiB+1 and 1,000,000,000 bytes only after smaller trials succeed.
   Record timings, output length/hash and actual device memory. Desktop RSS and
   WASM heap do not satisfy the mobile process-memory budget. If Mac/Instruments
   or equivalent device tooling is unavailable, memory is NOT MEASURED.
5. On separate disposable trials, background/lock during transfer, terminate and
   reopen, interrupt networking, reselect unchanged/modified source, cancel Share
   and use the marked-export cleanup control. Current interruption loses the
   live key and requires a fresh server/session; this is not production resume.
   No partial output may be called verified. Low physical space stays NOT RUN
   when no safe test condition is available; do not fill or erase personal data.

Return the filled [trial template](evidence/p01-physical-template.json), the
content-free Windows collector records and small-file/1 GB size/hash outcomes.
Do not send synthetic 1 GB data, certificate/private keys or personal analytics.
Keep observed FAIL/BLOCKED/NOT RUN distinct from PASS. The second older/lower-memory
iPhone remains unspecified; a single tested model only supports a narrow claim.
PRF login/recipient recovery/production resume are not implemented by this harness.
