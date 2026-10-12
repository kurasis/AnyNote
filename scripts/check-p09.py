#!/usr/bin/env python3
"""Read-only frozen P09 provenance, closed transport and protected workflow checks."""
import hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=ROOT/'apps/notes-web'
lock=json.loads((p/'package-lock.json').read_text())
inventory=json.loads((p/'dependency-inventory.json').read_text())
assert inventory['lock_sha256']==hashlib.sha256((p/'package-lock.json').read_bytes()).hexdigest()
actual=[dict(name=k.split('node_modules/')[-1],**{n:v[n] for n in ['version','resolved','integrity','license']}) for k,v in lock['packages'].items() if k]
assert sorted(actual,key=lambda x:x['name'])==inventory['packages'] and len(actual)==7
primary=next(x for x in actual if x['name']=='markdown-it')
assert primary['version']==inventory['primary_metadata']['version']=='15.0.2'
assert primary['license']==inventory['primary_metadata']['license']=='MIT'
assert primary['integrity']==inventory['primary_metadata']['dist.integrity']
assert all(x['resolved'].startswith('https://registry.npmjs.org/') and x['integrity'].startswith('sha512-') for x in actual)
subprocess.run(['python3','scripts/p03-contracts.py'],cwd=ROOT,check=True)
subprocess.run(['node','--test','--test-concurrency=1','packages/protocol/notes/test-notes.mjs'],cwd=ROOT,check=True)
print('PASS: P09 seven exact Markdown SRI/license records, closed read-only contracts and protected workflow suites')
