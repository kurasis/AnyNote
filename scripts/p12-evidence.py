#!/usr/bin/env python3
"""Public exact-source P12 software receipt; physical and independent review remain unrun."""
import hashlib,json,re,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
role=sys.argv[1]
assert role in ['linux','windows'] and (role=='windows')==(sys.platform=='win32')
def git(*a):return subprocess.check_output(['git',*a],cwd=ROOT,text=True).strip()
assert not git('status','--porcelain'),'Receipt requires clean source'
commit=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}');paths=git('ls-files').splitlines();before={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in paths}
result=subprocess.run(['cargo','test','--manifest-path','packages/vault-native/Cargo.toml','--locked','--all-features','-j','4','--','--test-threads=1'],cwd=ROOT,capture_output=True,text=True,encoding='utf-8',check=True)
assert 'p12_native_incompressible_gigabyte_durable_resume_and_export ... ok' in result.stdout
assert not git('status','--porcelain') and git('rev-parse','HEAD')==commit and git('rev-parse','HEAD^{tree}')==tree
assert before=={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in paths}
report={'purpose':'P12 exact-source encrypted file software receipt','status':'PASS','role':role,'source_commit':commit,'source_tree':tree,'source_tree_dirty':False,'timestamp':datetime.now(timezone.utc).isoformat(),'physical_acceptance':False,'independent_review':'NOT_RUN','native_tests_executed':sum(int(x) for x in re.findall(r'test result: ok\. (\d+) passed',result.stdout)),'native_gigabyte_test':True,'inputs':[{'path':p,'sha256':before[p]} for p in paths if p.startswith(('packages/','apps/','scripts/','infra/','experiments/p01/','.github/workflows/'))]}
if role=='linux':
    for directory,name in [('p12','http'),('p12','membership'),('p10','browser')]:
        value=json.loads((ROOT/f'artifacts/{directory}/{name}-report.json').read_text());assert value['status']=='PASS' and value['source_commit']==commit and not value['source_tree_dirty'];report[name+'_checks']=value['checks']
    assert value['p12_files']['gigabyte_bytes']==1000000000 and value['chromium_sandbox'] is True
(ROOT/'artifacts/p12').mkdir(parents=True,exist_ok=True);(ROOT/'artifacts/p12/source-report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: P12 source receipt',role,report['native_tests_executed'],'actual native tests')
