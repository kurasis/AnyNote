#!/usr/bin/env python3
"""Read-only P08 contract/dependency provenance and actually executed workflow checks."""
import hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
qr=ROOT/'apps/devices-web'; lock=qr/'package-lock.json'; inventory=json.loads((qr/'dependency-inventory.json').read_text());packages=json.loads(lock.read_text())['packages']
assert inventory['lock_sha256']==hashlib.sha256(lock.read_bytes()).hexdigest()
actual=[dict(name=k.split('node_modules/')[-1],version=v['version'],resolved=v['resolved'],integrity=v['integrity'],license=v['license']) for k,v in packages.items() if k]
assert sorted(actual,key=lambda p:p['name'])==sorted(inventory['packages'],key=lambda p:p['name'])
assert len(actual)==4 and all(x['resolved'].startswith('https://registry.npmjs.org/') and x['integrity'].startswith('sha512-') for x in actual)
for name,metadata in inventory['primary_metadata'].items():
 record=next(v for v in actual if v['name']==name);assert all(record[k]==metadata[k] for k in ['version','license','integrity'])
subprocess.run(['python3','scripts/p03-contracts.py'],cwd=ROOT,check=True)
subprocess.run(['node','--test','--test-concurrency=1','packages/protocol/devices/test-workflow.mjs'],cwd=ROOT,check=True)
print('PASS: P08 closed additive contracts, four exact QR dependency/license/SRI records and workflow attack suites')
