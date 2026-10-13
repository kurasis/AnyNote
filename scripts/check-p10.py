#!/usr/bin/env python3
"""Read-only P10 closed transport, frozen predicate port and protected multi-account workflows."""
import subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[1]
for command in [['python3','scripts/p03-contracts.py'],['python3','scripts/p10-port-group.py'],['node','--test','--test-concurrency=1','packages/protocol/shared/test-shared.mjs']]:
 subprocess.run(command,cwd=root,check=True)
print('PASS: P10 read-only contracts, frozen predicates and five maintained-crypto protected suites')
