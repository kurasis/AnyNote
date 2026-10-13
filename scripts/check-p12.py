#!/usr/bin/env python3
"""Read-only P12 maintained-crypto, source identity, immutable journal and range checks."""
import subprocess,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
for command in [['python3','scripts/p03-contracts.py'],['node','--test','--test-concurrency=1','packages/protocol/files/test-files.mjs','packages/protocol/files/test-sink.mjs']]:
    subprocess.run(command,cwd=ROOT,check=True)
errors=json.loads((ROOT/'packages/contracts/p02-errors.json').read_text())['errors']
local={e['code'] for e in errors if e['local_only']}
for path in (ROOT/'apps/api/app').rglob('*.php'):
    assert not local.intersection(re.findall(r"'([A-Z][A-Z0-9_]{3,})'",path.read_text())),f'Local-only error in server transport: {path}'
print('PASS: P12 protected file journals, source identity, authenticated ranges and local profile guard')
