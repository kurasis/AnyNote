#!/usr/bin/env python3
"""Public source receipt. Only completed software checks qualify; no hardware/audit claim."""
import hashlib,json,subprocess,sys
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1]
role=sys.argv[1]
assert role in ['linux','windows'] and (role=='windows')==(sys.platform=='win32')
tests=subprocess.run(['cargo','test','--manifest-path','packages/vault-native/Cargo.toml','--locked','--all-features','-j','4','--','--test-threads=1'],cwd=ROOT,text=True,encoding='utf-8',capture_output=True,check=True)
assert '16 passed; 0 failed; 0 ignored' in tests.stdout,'The 16 native custody tests did not execute'
assert 'custody::tests::portable_compound_bytes_require_both_keys_and_exact_descriptor ... ok' in tests.stdout
if role=='windows':assert 'actual_windows_wts_registration_and_message_fences_without_hello_objects ... ok' in tests.stdout
paths=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0')
prefixes=('packages/vault-native/','packages/crypto-core/','packages/auth-native/','packages/protocol/vault/','packages/protocol/auth-client','packages/protocol/p07-','apps/auth-web/','apps/vault-web/','experiments/p01/windows-hello/','experiments/p01/p07-','experiments/p01/p06-build','infra/dev/p06-','scripts/p07','scripts/check-p07')
inputs=[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in sorted(paths) if p and p.startswith(prefixes)]
report={'purpose':'P07 exact-source and actually executed native custody receipt','status':'PASS','role':role,'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'source_tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip(),'source_tree_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),'timestamp':datetime.now(timezone.utc).isoformat(),'python_version':sys.version.split()[0],'native_custody_tests':16,'portable_container_test':'PASS','os_message_scope':'Actual WTS registration with injected software messages' if role=='windows' else 'Portable boundary invalidation','hello_tpm_objects_created':False,'physical_acceptance':False,'independent_review':'NOT_RUN','inputs':inputs}
if role=='linux':
 for name in ['http','browser']:
  other=json.loads((ROOT/f'artifacts/p07/{name}-report.json').read_text());assert other['status']=='PASS' and other['source_commit']==report['source_commit']
(ROOT/'artifacts/p07').mkdir(parents=True,exist_ok=True)
(ROOT/'artifacts/p07/source-report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: public custody receipt',role,len(inputs),'inputs; physical/independent-review gates remain separate')
