#!/usr/bin/env python3
"""Install the pinned Linux x64 secret scanner after archive SHA-256 verification."""

import hashlib
import io
from pathlib import Path
import platform
import tarfile
import urllib.request

VERSION = '8.30.1'
DIGEST = '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'
ROOT = Path(__file__).resolve().parents[1]


def main():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise RuntimeError('This pinned scanner installer currently supports Linux x64 only')
    target = ROOT / '.local/tools' / f'gitleaks-{VERSION}'
    target.mkdir(parents=True, exist_ok=True)
    archive = target / 'verified.tar.gz'
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != DIGEST:
        data = urllib.request.urlopen(
            f'https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_linux_x64.tar.gz',
            timeout=60).read()
        if hashlib.sha256(data).hexdigest() != DIGEST:
            raise RuntimeError('Official secret-scanner archive checksum mismatch')
        archive.write_bytes(data)
    with tarfile.open(fileobj=io.BytesIO(archive.read_bytes())) as bundle:
        for name in ['gitleaks', 'LICENSE']:
            member = bundle.extractfile(name)
            if member is None:
                raise RuntimeError('Pinned archive is missing an expected file')
            (target / name).write_bytes(member.read())
    (target / 'gitleaks').chmod(0o755)
    print('PASS: pinned Gitleaks archive SHA-256 and installer')


if __name__ == '__main__':
    main()
