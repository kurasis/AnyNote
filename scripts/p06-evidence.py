#!/usr/bin/env python3
"""Public exact-source receipt after successful phase commands; never collects credentials."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone
ROOT=Path(__file__).resolve().parents[1]
paths=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0')
inputs=[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in sorted(paths) if p and p.startswith(('apps/api/','apps/auth-web/','packages/auth-native/','packages/contracts/','packages/protocol/auth-','packages/protocol/p06-','experiments/p01/p06-','scripts/p06','scripts/check-p06','infra/dev/p06-'))]
role=sys.argv[1]
assert role in ['linux','windows']
assert (role=='windows')==(sys.platform=='win32')
tests=subprocess.run(['cargo','test','--manifest-path',str(ROOT/'packages/auth-native/Cargo.toml'),'--locked','-j','4'],cwd=ROOT,text=True,capture_output=True,check=True)
assert 'test result: ok. 4 passed; 0 failed; 0 ignored' in tests.stdout, 'Native tests did not execute'
print('PASS: four executed native adapter tests')
result={'purpose':'P06 exact-source and executed adapter verification receipt','role':role,'status':'PASS','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'source_tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip(),'source_tree_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),'timestamp':datetime.now(timezone.utc).isoformat(),'python_version':sys.version.split()[0],'platform':sys.platform,'native_adapter_tests':4,'inputs':inputs,'physical_acceptance':False,'independent_review':'NOT_RUN'}
if role=='linux':
 for name in ['http','browser']:
  p=json.loads((ROOT/f'artifacts/p06/{name}-report.json').read_text());assert p['status']=='PASS' and p['source_commit']==result['source_commit']
(ROOT/'artifacts/p06').mkdir(parents=True,exist_ok=True)
(ROOT/'artifacts/p06/source-report.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS: public source receipt',role,len(inputs),'inputs; no physical/audit claim')
