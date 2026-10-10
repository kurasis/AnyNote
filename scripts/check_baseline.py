#!/usr/bin/env python3
"""Validate the P00 repository baseline, not application behavior.

Standard library only. Run from any directory; --root supports isolated
negative validation and fresh-clone checks without modifying the checkout.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


TRACKING_DOCS = (
    "DECISIONS.md", "DEPENDENCIES.md", "DEVELOPMENT.md", "KNOWN_LIMITATIONS.md",
    "NEXT_TASK.md", "PROGRESS.md", "REPOSITORY_ASSESSMENT.md", "REQUIREMENTS.md",
    "RISK_REGISTER.md", "TEST_EVIDENCE.md",
)


def verify(root: Path) -> list[str]:
    errors: list[str] = []
    spec = root / "docs/spec"
    documents = sorted(spec.glob("[0-9][0-9]_*.md"))
    expected_numbers = [f"{number:02}" for number in range(21)]
    if [p.name[:2] for p in documents] != expected_numbers:
        errors.append("Specification must contain exactly one document for each 00–20")

    manifest_path = spec / "SHA256SUMS.txt"
    manifest: dict[str, str] = {}
    if not manifest_path.is_file():
        errors.append("Missing specification checksum manifest")
    else:
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([0-9]{2}_[A-Z0-9_]+\.md)", line)
            if not match:
                errors.append("Malformed specification checksum entry")
                continue
            digest, name = match.groups()
            if name in manifest:
                errors.append(f"Duplicate checksum entry: {name}")
            manifest[name] = digest
        if set(manifest) != {p.name for p in documents}:
            errors.append("Checksum manifest does not exactly cover specification documents")
        for name, digest in manifest.items():
            path = spec / name
            if not path.is_file():
                errors.append(f"Missing specification document: {name}")
            elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                errors.append(f"Specification checksum mismatch: {name}")

    for name in TRACKING_DOCS:
        path = root / "docs" / name
        if not path.is_file() or not path.stat().st_size:
            errors.append(f"Missing or empty tracking document: {name}")

    markdown = [root / "README.md", root / "AGENTS.md"]
    markdown.extend(sorted((root / "docs").rglob("*.md")))
    for path in markdown:
        if not path.is_file():
            errors.append(f"Missing document: {path.relative_to(root)}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"Invalid UTF-8: {path.relative_to(root)}")
            continue
        # Current documents use simple inline Markdown links, not HTML/reference links.
        for target in re.findall(r"\[[^\]\n]*\]\(([^\s)]+)\)", text):
            parts = urlsplit(target)
            if parts.scheme or parts.netloc or not parts.path:
                continue
            local = (path.parent / unquote(parts.path)).resolve()
            if not local.is_relative_to(root):
                errors.append(f"Link escapes repository: {path.relative_to(root)} -> {target}")
            elif not local.exists():
                errors.append(f"Broken local link: {path.relative_to(root)} -> {target}")
        # An unmatched Markdown fence makes later text render incorrectly.
        fences = [line for line in text.splitlines() if re.match(r"^\s*(`{3,}|~{3,})", line)]
        if len(fences) % 2:
            errors.append(f"Unclosed code fence: {path.relative_to(root)}")

    progress = root / "docs/PROGRESS.md"
    if progress.is_file():
        rows = re.findall(r"^\| (P\d{2}) \| ([^|]+) \|", progress.read_text(), re.M)
        if [phase for phase, _ in rows] != [f"P{number:02}" for number in range(19)]:
            errors.append("Progress must track exactly P00–P18 in order")
        allowed = {"NOT STARTED", "IN PROGRESS", "IMPLEMENTED / UNVERIFIED", "BLOCKED", "VERIFIED"}
        for phase, status in rows:
            if status.strip() not in allowed:
                errors.append(f"Unknown phase status: {phase}")

    scope_path = root / "config/product-scope.json"
    try:
        scope = json.loads(scope_path.read_text())
        required = {
            "specification_version": "1.1.0",
            "max_plaintext_file_bytes": 1_000_000_000,
            "global_committed_ciphertext_quota_bytes": 100_000_000_000,
            "chunk_plaintext_bytes": 8_388_608,
            "aead_tag_bytes": 16,
            "required_clients": ["windows-webview2", "ios-installed-pwa"],
            "required_backend": ["laravel", "mariadb", "nginx", "php-fpm"],
            "required_group_types": ["private", "shared"],
            "interface_languages": ["en", "ru"],
        }
        for name, expected in required.items():
            if scope.get(name) != expected:
                errors.append(f"Locked scope changed: {name}; explicit owner decision/ADR required")
        length = scope["max_plaintext_file_bytes"]
        chunk = scope["chunk_plaintext_bytes"]
        count = (length + chunk - 1) // chunk
        last = length - (count - 1) * chunk
        ciphertext = length + count * scope["aead_tag_bytes"]
        if (count, last, ciphertext) != (120, 1_755_648, 1_000_001_920):
            errors.append("Maximum-file chunk/framing arithmetic disagrees with specification")
        if ciphertext > scope["ios_cache_soft_cap_bytes"]:
            errors.append("One maximum encrypted file exceeds the selected iOS cache soft cap")
        if 2 * ciphertext > scope["account_pending_reservation_cap_bytes"]:
            errors.append("Two maximum encrypted files exceed account pending budget")
    except (OSError, ValueError, KeyError, TypeError, ZeroDivisionError) as exc:
        errors.append(f"Invalid product scope: {type(exc).__name__}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        print("FAIL: Python 3.12+ is required", file=sys.stderr)
        return 1
    errors = verify(args.root.resolve())
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: 21 original specification checksums, UTF-8/local links/fences, tracking records")
    print("PASS: locked scope; 120 chunks; final part 1755648 bytes; data ciphertext 1000001920 bytes")
    print("Scope: repository integrity only; this command does not run application/platform/security tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
