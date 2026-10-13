#!/usr/bin/env python3
"""Read-only P11 closed framing and actual maintained-crypto transaction tests."""
import subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
for command in [
    ['python3', 'scripts/p03-contracts.py'],
    ['node', '--test', '--test-concurrency=1', 'packages/protocol/sync/test-sync.mjs'],
]:
    subprocess.run(command, cwd=ROOT, check=True)
print('PASS: P11 portable staged snapshot, atomic cursor, rollback fence and paged local parts')
