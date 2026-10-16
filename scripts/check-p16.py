#!/usr/bin/env python3
"""Read-only P16 offline operations checks; never starts/resets a service."""
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
subprocess.run(['python3','scripts/check_baseline.py'],cwd=ROOT,check=True)
subprocess.run(['python3','scripts/test-operations.py'],cwd=ROOT,check=True)
for path in ['scripts/p16-recover.mjs','packages/protocol/p16-acceptance.mjs','packages/protocol/p16-capacity.mjs','packages/protocol/p16-fixture.mjs']:
    subprocess.run(['node','--check',path],cwd=ROOT,check=True)
print('PASS: real signed age malformed-backup suite and maintained operations syntax; clean-host/1GB/scale acceptance is a separate executed drill')
