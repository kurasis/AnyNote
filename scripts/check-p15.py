#!/usr/bin/env python3
"""PWA install policy, actual static build and executable cache/update tests."""
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
manifest = json.loads((ROOT / 'apps/notes-web/manifest.webmanifest').read_text())
assert manifest['id'] == manifest['start_url'] == '/auth/notes.html'
assert manifest['scope'] == '/auth/' and manifest['display'] == 'standalone'
assert len(manifest['icons']) == 2
for size, icon in zip((192, 512), manifest['icons']):
    assert icon == {'src': f'/auth/icon-{size}.png', 'sizes': f'{size}x{size}',
                    'type': 'image/png', 'purpose': 'any maskable'}
    raw = (ROOT / 'apps/notes-web' / f'icon-{size}.png').read_bytes()
    assert raw[:8] == b'\x89PNG\r\n\x1a\n'
    assert struct.unpack('>II', raw[16:24]) == (size, size)
for command in [
    ['python3', 'scripts/check_baseline.py'],
    ['python3', 'scripts/check-p14.py'],
    ['node', '--test', 'apps/notes-web/test-pwa.mjs'],
    ['node', 'experiments/p01/p06-build.mjs'],
]:
    subprocess.run(command, cwd=ROOT, check=True)
print('PASS: PWA installation assets, preserved 179-file baseline, executed worker policy and actual bundled UI')
