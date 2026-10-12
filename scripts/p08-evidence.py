#!/usr/bin/env python3
"""Only actual clean-source executions count; no hardware or qualified audit claim."""
import hashlib,json,subprocess,sys
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1];role=sys.argv[1];assert role in ['linux','windows'] and (role=='windows')==(sys.platform=='win32')
test=subprocess.run(['cargo','test','--manifest-path','packages/vault-native/Cargo.toml','--locked','--all-features','-j','4','--','--test-threads=1'],cwd=ROOT,text=True,encoding='utf-8',capture_output=True,check=True)
assert '9 passed; 0 failed; 0 ignored' in test.stdout
assert 'native_fresh_recovery_rejects_substituted_root_and_recovers_keys_only_after_activation ... ok' in test.stdout
assert 'native_two_connections_and_aborted_sql_write_preserve_acknowledged_control ... ok' in test.stdout
assert '15 passed; 0 failed; 0 ignored' in test.stdout
if role=='windows':assert 'actual_windows_wts_registration_and_message_fences_without_hello_objects ... ok' in test.stdout
paths=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0');prefixes=('packages/vault-native/','packages/crypto-core/','packages/auth-native/','packages/protocol/','packages/contracts/','packages/api-client/','apps/api/','apps/auth-web/','apps/vault-web/','apps/devices-web/','experiments/p01/p08-','experiments/p01/p06-build','infra/dev/p06-','scripts/p08','scripts/check-p08','.github/workflows/')
inputs=[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in sorted(paths) if p and p.startswith(prefixes)]
report={'purpose':'P08 exact-source trusted-device and recovery software receipt','status':'PASS','role':role,'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'source_tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip(),'source_tree_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),'timestamp':datetime.now(timezone.utc).isoformat(),'python_version':sys.version.split()[0],'native_device_tests':9,'preserved_native_custody_tests':15,'hello_tpm_objects_created':False,'physical_acceptance':False,'independent_review':'NOT_RUN','inputs':inputs}
assert not report['source_tree_dirty'],'Acceptance requires clean source'
if role=='linux':
 for name in ['http','browser']:
  other=json.loads((ROOT/f'artifacts/p08/{name}-report.json').read_text());assert other['status']=='PASS' and other['source_commit']==report['source_commit'] and not other['source_tree_dirty'];report[name+'_checks']=other['checks']
(ROOT/'artifacts/p08').mkdir(parents=True,exist_ok=True);(ROOT/'artifacts/p08/source-report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: P08 clean exact-source receipt',role,len(inputs),'inputs')
