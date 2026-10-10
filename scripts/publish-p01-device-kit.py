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
RUN = "38074016248"
SOURCE = "a225e3f099551b95aa1893f941de522f543e8f44"
TAG = "v0.1.2-p01-device-kit"


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
                or phone_report["legacy_failed_report_offers_retry"] is not True):
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
        notes.write_text(f"""Download only the file for your device. Other attachments are optional evidence, checksums and license notices.

- **Windows:** download `AnyNote-P01-Windows-x64.exe`, double-click and press OK. Crypto, public 64 MiB Argon2id and an exact 1 GB local disk trial run automatically. Follow the Hello confirmation/cancel/lock dialogs. The report folder opens afterwards; send the one JSON report back. No installer, PowerShell, fixture generator, VC runtime or extra DLL is needed.
- **iPhone:** unzip the contents of `AnyNote-P01-iPhone.zip` into `<web-root>/anynote-p01-v012/` on the existing trusted HTTPS test site. Open `https://YOUR-TEST-SITE/anynote-p01-v012/` in Safari. For the PWA trial, Share -> Add to Home Screen and open the app. Tap **Run all automatic tests**; the same button then guides Save to Files, selecting that saved file for exact size/SHA-256 verification, and saving one report. No Node.js, PHP, account, database or source-file preparation needed.

**Changed in 0.1.2:** The owner confirmed the Windows lock screen appeared after Win+L. Fingerprint/PIN waiting for Windows sign-in is expected; the old test authorization was rejected as STALE. New logs record WTS lock/unlock, suspend and owner-close events; guided lock PASS requires a native lock event plus failed STALE unlock. All PRF/TPM/security/cancellation gates stay intact. The existing owner positive enrollment/fresh-process/cancellation/cleanup results are preserved; a repeat is optional for the new event telemetry.

On iPhone, choose **synthetic-export-….bin (1 GB)** for file verification, not the small JSON report. Wrong size/hash remains FAIL but allows another selection without a new automatic trial; selected/expected sizes are recorded, personal filenames are not. The report stays available for downloading/copying at intermediate steps and after restart. On the same site/browser storage, the new path can restore the one documented sibling `anynote-p01-v011/` diagnostic checkpoint, including old failed selection, while preserving that original record. Different origins, cleared storage or separate Safari/PWA stores cannot provide it; only run a new trial if no report is restored. The page displays **Test kit 0.1.2**. Use the Home Screen app for installed-PWA evidence: the supplied 0.1.1 phone report was physical Safari, not installed mode. Its actual .bin size/hash remains unverified because JSON/another file was selected; this alone is not an OS save failure.

The new directory avoids the old installed static cache without clearing site data. Prior 0.1.1 report/source provenance is retained; no keys/file handles are restored.

Allow about 3.1 GB free system/browser storage. Keep the phone page in the foreground. Confirm system prompts and Files choices yourself; delete the disposable saved `.bin` afterwards.

These are **unsigned P01 synthetic test artifacts**, not a production release or deployment. The static kit uses local ciphertext OPFS transport; network/backend/resume, actual device memory, older-phone, physical low-space and broader passkey/lifecycle gates remain open. Hosted sharing is explicitly mocked; hosted Hello is BLOCKED at API 7 with no native objects created. No complete physical acceptance is inferred.

Build source: `{SOURCE}`. This tag's automatic **Source code** downloads provide exact corresponding modified source and pinned build inputs. The Windows experiment/modifications are GPL-3.0-only; full text is embedded (`--license`) and attached. This does not choose a license for the rest of AnyNote. Sodium ISC notices are included in the iPhone ZIP.

Validation: [feasibility run {RUN}](https://github.com/{REPO}/actions/runs/{RUN}) and [baseline run 38074016234](https://github.com/{REPO}/actions/runs/38074016234). Full 1 GB native/Node/browser interop/export/fault checks; sandboxed nested-path kit with real page destruction during pending mocked Share, retained logs, activated wrong-JSON size/retry across reload, legacy failed-report migration and restored selected 1 GB output hash; 105 Windows routine tests plus independent Microsoft C-header ABI; one-EXE 51 frozen crypto/KDF checks and exact 1 GB disk output/cleanup; PE imports contain system DLLs only. Build tree merged through [PR #7](https://github.com/{REPO}/pull/7).

Windows SHA-256: `{sha(exe)}`. iPhone ZIP SHA-256: `{sha(bundle)}`.

[Owner runbook](https://github.com/{REPO}/blob/{TAG}/docs/P01_OWNER_TRIALS.md). The cloud upload endpoint rejected its injected credential; this publication uses the repository's scoped Actions token after revalidating successful CI, source and downloaded receipts. No production site is deployed.
""")
        subprocess.run(["gh", "release", "create", TAG, *(str(path) for path in files),
                        "--repo", REPO, "--target", SOURCE, "--prerelease", "--title",
                        "P01 device kit 0.1.2: lock evidence and retryable Files selection",
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
