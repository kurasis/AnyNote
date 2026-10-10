#!/usr/bin/env python3
"""Publish only the frozen, successful P01 kit using the Actions job token."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

REPO = "kurasis/AnyNote"
RUN = "38076947436"
SOURCE = "566ec84a6630794f266a2ab4bdfea8a170457e6a"
TAG = "v0.1.4-p01-device-kit"


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True)


def api(path):
    return json.loads(gh("api", f"repos/{REPO}/{path}"))


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def only(root, name):
    matches = list(root.rglob(name))
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one {name}")
    return matches[0]


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REPOSITORY") != REPO:
        raise RuntimeError("Publication requires this repository's explicit Actions job")
    run = api(f"actions/runs/{RUN}")
    if (run["head_sha"] != SOURCE or run["status"] != "completed"
            or run["conclusion"] != "success" or run["path"] != ".github/workflows/p01.yml"):
        raise RuntimeError("Frozen source/run is not successfully verified")
    if any(release["tag_name"] == TAG for release in api("releases")):
        raise RuntimeError("Refusing to overwrite an existing release")
    with tempfile.TemporaryDirectory(prefix="anynote-kit-publication-") as temporary:
        root = Path(temporary)
        windows, iphone, assets = root / "windows", root / "iphone", root / "assets"
        assets.mkdir()
        gh("run", "download", RUN, "--repo", REPO, "--name", "p01-windows-synthetic-probe", "--dir", str(windows))
        gh("run", "download", RUN, "--repo", REPO, "--name", "p01-iphone-device-kit", "--dir", str(iphone))
        win_report = json.loads(only(windows, "device-kit-hosted.json").read_text(encoding="utf-8-sig"))
        phone_report = json.loads(only(iphone, "device-kit-report.json").read_text())
        exe, bundle = only(windows, "AnyNote-P01-Windows-x64.exe"), only(iphone, "AnyNote-P01-iPhone.zip")
        if (win_report["source_commit"] != SOURCE or win_report["executable_sha256"] != sha(exe)
                or win_report["physical_acceptance"] is not False
                or win_report["local_checks"]["status"] != "PASS"
                or win_report["local_checks"]["file"]["bytes"] != 1_000_000_000
                or win_report["local_checks"]["crypto"]["checks"] != 51
                or phone_report["status"] != "PASS" or phone_report["source_commit"] != SOURCE
                or phone_report["os_share_mocked"] is not True
                or phone_report["pending_share_page_destroyed_and_report_restored"] is not True
                or phone_report["restored_selected_output_hash"] is not True
                or phone_report["report_download_restart_retained"] is not True
                or phone_report["denied_checkpoint_blocks_before_work"] is not True
                or phone_report["wrong_json_size_recorded"] is not True
                or phone_report["wrong_json_retry_after_reload"] is not True
                or phone_report["legacy_failed_report_offers_retry"] is not True
                or phone_report["real_service_worker_stream_download"] is not True
                or phone_report["streamed_download_bytes"] != 1_000_000_000
                or phone_report["stream_download_selected_hash"] is not True
                or phone_report["cancelled_stream_releases_lock"] is not True
                or phone_report["download_replay_rejected"] is not True
                or phone_report["arbitrary_export_path_rejected"] is not True
                or phone_report["unmarked_export_rejected"] is not True
                or phone_report["retained_staged_export_reopened_and_hashed"] is not True
                or phone_report["prepared_ticket_survives_actual_service_worker_stop"] is not True):
            raise RuntimeError("Asset runtime/source/hash evidence mismatch")
        with zipfile.ZipFile(bundle) as archive:
            if archive.testzip() is not None or json.loads(archive.read("BUILD.json"))["source_commit"] != SOURCE:
                raise RuntimeError("ZIP CRC/source receipt mismatch")
            receipt = archive.read("SHA256SUMS.txt").decode().splitlines()
            names = []
            for line in receipt:
                digest, name = line.split("  ", 1)
                if Path(name).name != name or hashlib.sha256(archive.read(name)).hexdigest() != digest:
                    raise RuntimeError("Static asset hash/name mismatch")
                names.append(name)
            if set(archive.namelist()) != set(names + ["SHA256SUMS.txt"]):
                raise RuntimeError("Unreceipted ZIP asset")
        copies = [(exe, exe.name), (bundle, bundle.name),
                  (only(windows, "device-kit-hosted.json"), "hosted-windows-report.json"),
                  (only(iphone, "device-kit-report.json"), "hosted-browser-report.json"),
                  (only(windows, "pe-dependencies.txt"), "windows-pe-dependencies.txt"),
                  (Path("experiments/p01/windows-hello/LICENSE"), "Windows-GPL-3.0-LICENSE.txt")]
        for path, name in copies:
            shutil.copyfile(path, assets / name)
        files = sorted(assets.iterdir())
        checksums = assets / "SHA256SUMS.txt"
        checksums.write_text("".join(f"{sha(path)}  {path.name}\n" for path in files))
        files.append(checksums)
        notes = root / "notes.md"
        notes.write_text(f"""Download the single file for your device; other attachments are optional evidence/license/checksums.

- **Windows:** double-click `AnyNote-P01-Windows-x64.exe`. Confirm the positive Hello prompts, cancel when instructed, and optionally select the disclosed automatic lock trial. After selecting it, leave the next prompt pending without touching the sensor; the test requests Windows lock once after 8 seconds. Win+L is not required. Windows sign-in afterwards may need fingerprint/PIN. The report folder opens automatically; send its one JSON back. No installer, PowerShell, VC runtime or extra DLL is needed.
- **iPhone:** unzip the ZIP contents into `<web-root>/anynote-p01-v014/`, with `index.html` directly inside. Open `https://YOUR-TEST-SITE/anynote-p01-v014/`; the page must show **Test kit 0.1.4**. Add to Home Screen and launch that app for the PWA trial. Tap **Run all automatic tests**, then **Download 1 GB sample**. Find the downloaded `synthetic-export-….bin` in Downloads/Files, select it for exact size/SHA-256 verification and send only the small JSON report. No Node/PHP/account/backend setup.

**Changed in 0.1.4:** The owner confirmed physical 0.1.2 restarts at 1 GB Web Share. The default now downloads the verified synthetic disk output through a scoped service-worker streaming attachment, with 256 KiB reads, single-use five-minute capability and no export cache; it does not pass a gigabyte File into system Share or build a giant Blob. Diagnostics and generated owner/name metadata are saved before the request. Short-lived synthetic download tickets use a dedicated path-scoped IndexedDB store with atomic consumption, so stopping an idle service worker does not erase a prepared link. No file bytes or vault keys are stored in that table. Active streams can still be interrupted by the OS. Reopen after interruption to recheck and reuse a retained marked disk output without keys/handles. A sent stream alone cannot pass Files: selected bytes must independently match.

If the PWA denies the download, try the same new URL in Safari and preserve both reports; Safari success is a separate result, not installed-PWA acceptance. **Use system Share instead** remains optional/experimental. A physical iOS rerun is still required; hosted Chromium success does not establish iPhone memory or Files/PWA support. If an earlier v012/v011 diagnostic is restored but no .bin was saved, choose **Run a new trial** once. Same-origin/browser storage is required; prior known records and other site data are preserved, no keys restored and no automatic rerun. Keep the new directory to avoid the older installed static cache.

The owner 0.1.2 Windows JSON passed enrollment, fresh-process actual-vault authentication, explicit cancellation and exact cleanup, but the lock step returned HELLO_CANCELLED with zero WTS events. It remains **NOT PROVEN**, separate from the owner-confirmed earlier 0.1.1 screen/STALE run. The new selected system lock is a one-shot request only while unlock remains pending; completion/close removes its timer. OS request accepted/denied/not-requested is logged separately. Only an actual WTS lock plus failed STALE unlock passes the lock step; owner observation is still needed for prompt timing. No Hello reset, TPM/policy change or verification bypass.

Allow about 3.1 GB free system/browser quota and keep automatic work foreground. Browser/OS may terminate workers or deny downloads. An active stream holds the kit lock; let it finish and reopen before recovery. Delete the disposable .bin from Files after testing; do not upload it. Save/copy the JSON at any intermediate step.

These are **unsigned P01 synthetic test artifacts**, not a production release/deployment. Local ciphertext OPFS transport is not network/backend/resume acceptance. Actual device memory, older phone, low physical space, provider/account-copy and broader lifecycle/passkey gates remain OPEN. Hosted system Share is explicitly mocked; the separate 1 GB service-worker attachment and selected-file hash use the real sandboxed Chromium download stack. Hosted Hello remains BLOCKED at API 7, with no objects and no OS lock requested. No complete G1 result is claimed.

Exact build source: `{SOURCE}`. Automatic **Source code** archives from this tag contain the corresponding modifications and pinned build inputs. Windows code/modifications are GPL-3.0-only; license text is embedded (`--license`) and attached. This does not choose a license for the rest of AnyNote. The iPhone ZIP includes sodium ISC notices.

Validation: [source feasibility {RUN}](https://github.com/{REPO}/actions/runs/{RUN}) and [baseline 38076947435](https://github.com/{REPO}/actions/runs/38076947435). Full 1 GB native/Node/browser interop/network/fault suite; sandboxed nested-path kit with actual 1 GB streaming download and disk picker/hash, cancelled stream releasing its lock, replay/unknown/arbitrary-path/unmarked-output rejection, pending mocked-Share page destruction/recovery, real service-worker stop after ticket preparation and exact cleanup. Native Windows regression/independent C-header ABI, 51 crypto/KDF/exact 1 GB disk checks and system-only PE imports. Build reviewed/merged in [PR #8](https://github.com/{REPO}/pull/8); publication verifies frozen CI/source/receipts and actual downloaded release bytes using the scoped Actions token.

EXE SHA-256: `{sha(exe)}`. ZIP SHA-256: `{sha(bundle)}`.

[Owner runbook](https://github.com/{REPO}/blob/{TAG}/docs/P01_OWNER_TRIALS.md).
""")
        subprocess.run(["gh", "release", "create", TAG, *(str(path) for path in files),
                        "--repo", REPO, "--target", SOURCE, "--prerelease", "--title",
                        "P01 device kit 0.1.4: persistent download links and selected OS lock",
                        "--notes-file", str(notes)], check=True)
        # Verify the actually published downloads, not only the upload response.
        downloaded = root / "published"
        gh("release", "download", TAG, "--repo", REPO, "--pattern", "AnyNote-P01-*", "--dir", str(downloaded))
        for name in [exe.name, bundle.name]:
            if sha(downloaded / name) != sha(assets / name):
                raise RuntimeError("Published download hash mismatch")
        if api(f"git/ref/tags/{TAG}")["object"]["sha"] != SOURCE:
            raise RuntimeError("Published tag/source mismatch")
        print("PASS: published EXE/ZIP downloads and exact source tag verified")


if __name__ == "__main__":
    main()
