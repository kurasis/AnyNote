#!/usr/bin/env python3
"""Package only the receipt-listed static kit with reproducible ZIP metadata."""
from pathlib import Path
import hashlib
import zipfile

root = Path(__file__).resolve().parents[1]
source = root / "experiments/p01/dist/device-kit"
target = root / "experiments/p01/artifacts/AnyNote-P01-iPhone.zip"
lines = (source / "SHA256SUMS.txt").read_text().splitlines()
names = []
for line in lines:
    digest, name = line.split("  ", 1)
    if Path(name).name != name or hashlib.sha256((source / name).read_bytes()).hexdigest() != digest:
        raise SystemExit("Invalid packaged asset receipt")
    names.append(name)
names.append("SHA256SUMS.txt")
target.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for name in sorted(names):
        info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o100644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, (source / name).read_bytes(), compresslevel=9)
with zipfile.ZipFile(target) as archive:
    if archive.testzip() is not None:
        raise SystemExit("ZIP CRC verification failed")
print(f"PASS: {target.name}, {len(names)} root-level assets, CRC and SHA-256 verified")
