#!/usr/bin/env python3
"""Read-only protected content and frozen protocol checks; no service reset."""
import subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
for command in [
    ['python3', 'scripts/p03-contracts.py'],
    ['python3', 'scripts/p13-browser-inventory.py'],
    ['node', '--test', '--test-concurrency=1', 'packages/protocol/content/test-content.mjs', 'packages/protocol/content/test-portable.mjs', 'packages/protocol/content/test-offline.mjs', 'packages/protocol/content/test-archive-ui.mjs', 'packages/content-browser/test-preview.mjs'],
]:
    subprocess.run(command, cwd=ROOT, check=True)
print('PASS: protected search, strict resource guards, complete offline recovery and frozen format; physical platform acceptance remains separate')
