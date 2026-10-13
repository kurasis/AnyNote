#!/usr/bin/env python3
"""Public exact-source P12 software receipt; physical and independent review remain unrun."""
import hashlib,json,re,subprocess,sys,time,tempfile
import importlib.util
from pathlib import Path
memory_spec=importlib.util.spec_from_file_location("p12_memory",Path(__file__).with_name("p12-memory.py"))
memory_module=importlib.util.module_from_spec(memory_spec);memory_spec.loader.exec_module(memory_module)
Sampler=memory_module.Sampler
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
role=sys.argv[1]
assert role in ['linux','windows'] and (role=='windows')==(sys.platform=='win32')
def git(*a):return subprocess.check_output(['git',*a],cwd=ROOT,text=True).strip()
assert not git('status','--porcelain'),'Receipt requires clean source'
commit=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}');paths=git('ls-files').splitlines();before={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in paths}
with tempfile.TemporaryDirectory(prefix='anynote-p12-private-test-') as directory:
    output_path=Path(directory)/'native-output.log'
    with output_path.open('w+b') as output, output_path.open('rb') as observation:
        process=subprocess.Popen(['cargo','test','--manifest-path','packages/vault-native/Cargo.toml','--locked','--all-features','-j','4','--','--test-threads=1','--nocapture'],cwd=ROOT,stdout=output,stderr=output)
        samples=Sampler(process.pid);active=False;seen=False
        while process.poll() is None:
            progress=observation.read()
            if b'P12_FILE_MEMORY_BEGIN' in progress:active=True;seen=True
            if active:samples.sample()
            if b'P12_FILE_MEMORY_END' in progress:active=False
            time.sleep(0.25)
        assert process.returncode==0,'Native execution failed; private local test output is not a public receipt'
        stdout=output_path.read_text(encoding='utf-8')
assert seen and 'P12_FILE_MEMORY_END' in stdout and 'p12_native_incompressible_gigabyte_durable_resume_and_export ...' in stdout
assert not git('status','--porcelain') and git('rev-parse','HEAD')==commit and git('rev-parse','HEAD^{tree}')==tree
assert before=={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in paths}
report={'purpose':'P12 exact-source encrypted file software receipt','status':'PASS','role':role,'source_commit':commit,'source_tree':tree,'source_tree_dirty':False,'timestamp':datetime.now(timezone.utc).isoformat(),'physical_acceptance':False,'independent_review':'NOT_RUN','native_tests_executed':sum(int(x) for x in re.findall(r'test result: ok\. (\d+) passed',stdout)),'native_gigabyte_test':True,'native_file_memory':samples.report(),'inputs':[{'path':p,'sha256':before[p]} for p in paths if p.startswith(('packages/','apps/','scripts/','infra/','experiments/p01/','.github/workflows/'))]}
if role=='linux':
    for directory,name in [('p12','http'),('p12','membership'),('p10','browser')]:
        value=json.loads((ROOT/f'artifacts/{directory}/{name}-report.json').read_text());assert value['status']=='PASS' and value['source_commit']==commit and not value['source_tree_dirty'];report[name+'_checks']=value['checks']
    assert value['p12_files']['gigabyte_bytes']==1000000000 and value['chromium_sandbox'] is True
(ROOT/'artifacts/p12').mkdir(parents=True,exist_ok=True);(ROOT/'artifacts/p12/source-report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: P12 source receipt',role,report['native_tests_executed'],'actual native tests')
