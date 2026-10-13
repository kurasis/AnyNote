#!/usr/bin/env python3
"""Read-only P12 maintained-crypto, source identity, immutable journal and range checks."""
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
for command in [['python3','scripts/p03-contracts.py'],['node','--test','--test-concurrency=1','packages/protocol/files/test-files.mjs']]:
    subprocess.run(command,cwd=ROOT,check=True)
print('PASS: P12 protected file journals, source identity, authenticated ranges and local profile guard')
