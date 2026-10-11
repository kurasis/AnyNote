#!/usr/bin/env python3
"""Scan the complete Git-visible source tree, excluding ignored local runtime state."""

from pathlib import Path
import base64
import shutil
import secrets
import string
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / '.local/tools/gitleaks-8.30.1/gitleaks'


def scan(path):
    return subprocess.run([str(SCANNER), 'dir', str(path), '--no-banner', '--redact',
                           '--config', str(ROOT / '.gitleaks.toml')], cwd=ROOT).returncode


def main():
    with tempfile.TemporaryDirectory(prefix='anynote-secret-scan-') as name:
        export = Path(name)
        files = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others',
                                         '--exclude-standard'], cwd=ROOT).decode().split('\0')
        for relative in set(files) - {''}:
            source = ROOT / relative
            if not source.is_file():
                continue
            if source.is_symlink() or not source.resolve().is_relative_to(ROOT):
                raise RuntimeError('Source scan refuses symlinks or escaping paths')
            target = export / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        if scan(export) != 0:
            raise RuntimeError('Source secret scan failed; findings are redacted')
    for relative in ['sentinel.txt', 'docs/reference/passkeylocal/PROVENANCE.json',
                     'docs/evidence/p03-foundation-local.json',
                     'fixtures/protocol/p02/vectors.json',
                     'fixtures/protocol/p02/identity-vectors.json',
                     'fixtures/protocol/p02/state-vectors.json',
                     'fixtures/protocol/p02/group-vectors.json']:
        with tempfile.TemporaryDirectory(prefix='anynote-scanner-negative-') as name:
            # Recognizable synthetic PAT shape; no credential is used or committed.
            token = 'ghp_' + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
            sentinel = Path(name) / relative
            sentinel.parent.mkdir(parents=True, exist_ok=True)
            sentinel.write_text('github_token = "' + token + '"\n')
            if scan(name) != 1:
                raise RuntimeError('Scanner did not reject the disposable fake-token sentinel')
    for relative, field in [('vectors.json', 'file_data_key'), ('vectors.json', 'key_wrap_digest'),
                            ('identity-vectors.json', 'root_signing_key'),
                            ('identity-vectors.json', 'recovery_encryption_key'),
                            ('identity-vectors.json', 'device_encryption_key'),
                            ('state-vectors.json', 'channel_key'), ('state-vectors.json', 'device_signing_key'),
                            ('state-vectors.json', 'device_encryption_key'),
                            ('group-vectors.json', 'key_commitment'), ('group-vectors.json', 'recovery_encryption_key'),
                            ('group-vectors.json', 'device_encryption_key'),
                            ('group-vectors.json', 'encryption_key_fingerprint')]:
        with tempfile.TemporaryDirectory(prefix='anynote-scanner-negative-') as name:
            sentinel = Path(name) / 'fixtures/protocol/p02' / relative
            sentinel.parent.mkdir(parents=True)
            # Fixed PUBLIC mutation keeps upstream alphabet/entropy heuristics stable.
            # Random all-letter values can be suppressed by its default allowlist.
            value = base64.urlsafe_b64encode(bytes((i * 7 + 13) % 256 for i in range(32))).decode().rstrip('=')
            sentinel.write_text('{"' + field + '": "' + value + '"}\n')
            if scan(name) != 1:
                raise RuntimeError('Scanner did not reject a changed fixture sentinel: ' + relative + ':' + field)
    # Keep the actual frozen PUBLIC scanner fragment and mutate its full field.
    # This verifies that a chunk-boundary false-positive exemption does not
    # hide changed keys elsewhere in the same complete fixture.
    with tempfile.TemporaryDirectory(prefix='anynote-scanner-fragment-negative-') as name:
        sentinel = Path(name) / 'fixtures/protocol/p02/group-vectors.json'
        sentinel.parent.mkdir(parents=True)
        original = (ROOT / 'fixtures/protocol/p02/group-vectors.json').read_text()
        known = 'EmxlFwbk8mBEr3qi_p_t-DIlQJfRYXNpLPs8e8zp4_A'
        mutation = base64.urlsafe_b64encode(bytes((i * 7 + 13) % 256 for i in range(32))).decode().rstrip('=')
        assert known in original
        sentinel.write_text(original.replace(known, mutation))
        if scan(name) != 1:
            raise RuntimeError('Scanner hid a changed full field inside the frozen public fragment')
    print('PASS: Git-visible source scan; 7 fake-token path negatives and 12 changed key/digest fixture negatives plus full-fixture fragment mutation')


if __name__ == '__main__':
    main()
