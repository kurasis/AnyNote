#!/usr/bin/env python3
"""Bind actual Windows host receipts and installer bytes to every tracked source input."""
import hashlib,json,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
assert sys.platform=='win32','Actual Windows execution required'
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT)
def sha(path):return hashlib.file_digest(path.open('rb'),'sha256').hexdigest()
head=git('rev-parse','HEAD').decode().strip()
assert not git('status','--porcelain'),'Refuse dirty-source acceptance'
reports={}
for name,minimum in [('windows-host-preflight.json',3),('native-pairing-development.json',33),('native-sharing-development.json',20),('native-http-development.json',62),('windows-webview-development.json',35)]:
 path=ROOT/'artifacts/p14'/name;value=json.loads(path.read_text(encoding='utf-8'))
 assert value['status']=='PASS' and value['source_commit']==head and not value['source_tree_dirty']
 assert value['checks']>=minimum and value['physical_acceptance'] is False
 if 'large_file' in value:assert value['large_file']['status']=='PASS' and value['large_file']['bytes']==1000000000
 if name.startswith('windows-webview'):
  assert value['updater']['status']=='PASS' and value['updater']['production_signing'] is False
  assert value['updater']['unsupported_signed_zip_rejected']is True
  assert value['memory']['transfer']['samples']>=2 and value['memory']['transfer']['baseline_bytes']['native']>0
  transfer=value['memory']['transfer']
  assert transfer['initial_native_helper_target_bytes']==134217728
  assert transfer['target_observation']=='OBSERVED_WITHIN_INITIAL_TARGET' and transfer['observed_increase_bytes']['native_helper']<=134217728
  assert all(transfer['phases'][phase]['samples']>=2 for phase in ['upload','download','export','inspect','import','recovered-download'])
  assert all(transfer['phases'][phase]['helper_samples']>=2 for phase in ['export','inspect','import'])
 reports[name]={'path':'artifacts/p14/'+name,'sha256':sha(path),'checks':value['checks']}
budget=ROOT/'artifacts/p14/memory-budget-development.json';value=json.loads(budget.read_text(encoding='utf-8'))
assert value['status']=='PASS' and value['source_commit']==head and not value['source_tree_dirty'] and value['physical_acceptance']is False
assert value['memory']==json.loads((ROOT/'artifacts/p14/windows-webview-development.json').read_text(encoding='utf-8'))['memory']
reports[budget.name]={'path':'artifacts/p14/'+budget.name,'sha256':sha(budget)}
vendor=ROOT/'artifacts/p14/signed-vendor-zip-development.json';value=json.loads(vendor.read_text(encoding='utf-8'))
assert value['status']=='PASS' and value['source_commit']==head and not value['source_tree_dirty'] and value['platform']=='win32'
assert [v['case']for v in value['cases']]==['authentic','tampered'] and all(v['status']=='PASS'for v in value['cases'])
assert value['cases'][0]['exit_code']==0 and value['cases'][0]['installed_files']>0 and value['cases'][1]['exit_code']!=0 and value['cases'][1]['installed_files']==0
assert value['untrusted_extraction_before_verification']is False and value['upstream_zip_fixed']is False
reports[vendor.name]={'path':'artifacts/p14/'+vendor.name,'sha256':sha(vendor)}
observer=ROOT/'artifacts/p14/installer-observation.json';value=json.loads(observer.read_text(encoding='utf-8'))
assert value['status']=='PASS' and value['source_commit']==head and not value['source_tree_dirty']
assert value['rm_read_handle_registers_test_process'] is True and value['metadata_polling_registers_test_process'] is False
reports[observer.name]={'path':'artifacts/p14/'+observer.name,'sha256':sha(observer)}
capability=ROOT/'artifacts/p14/backend-filesystem-capability.json'
value=json.loads(capability.read_text(encoding='utf-8'));assert value['file_fsync'] is True
assert value['ci_directory_durability_adapter']['status']=='PASS' and value['ci_directory_durability_adapter']['primitive']=='Windows FlushFileBuffers volume'
reports[capability.name]={'path':'artifacts/p14/'+capability.name,'sha256':sha(capability)}
audit=ROOT/'artifacts/p14/capability-audit.json';value=json.loads(audit.read_text(encoding='utf-8'))
assert value['status']=='PASS' and value['source_commit']==head and not value['source_tree_dirty'] and value['unchanged_files']==179
reports[audit.name]={'path':'artifacts/p14/'+audit.name,'sha256':sha(audit)}
installers=list((ROOT/'apps/desktop/src-tauri/target/release/bundle/nsis').glob('*.exe'));assert len(installers)==1
paths=sorted(p for p in git('ls-files','-z').decode().split('\0') if p and not p.startswith(('docs/evidence/','artifacts/')))
inputs=[{'path':p,'sha256':sha(ROOT/p)} for p in paths]
report={'purpose':'P14 exact-source actual Windows installed host software receipt','status':'PASS','source_commit':head,'source_tree':git('rev-parse','HEAD^{tree}').decode().strip(),'source_tree_dirty':False,'role':'windows','timestamp':datetime.now(timezone.utc).isoformat(),'reports':reports,'installer':{'path':str(installers[0].relative_to(ROOT)).replace('\\','/'),'sha256':sha(installers[0]),'production_signed':False},'inputs':inputs,'physical_acceptance':False,'independent_review':'NOT_RUN'}
(ROOT/'artifacts/p14/source-report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print('PASS: actual Windows host receipt,',len(inputs),'tracked inputs; physical and production signing remain separate')
