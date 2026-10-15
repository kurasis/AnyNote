#!/usr/bin/env python3
"""Record only compiled CI binaries for diagnosis; never private runtime profiles."""
import hashlib,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
assert sys.platform=='win32' and os.environ.get('GITHUB_ACTIONS')=='true'
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,text=True).strip()
def one(directory):
    items=list((ROOT/directory).glob('*.exe'));assert len(items)==1,'Exactly one compiled candidate/owner installer required'
    return items[0]
assert not git('status','--porcelain'),'Refuse dirty source binary provenance'
paths={'harness':ROOT/'.local/p14-tools/instrumented-host.exe','native_driver':ROOT/'packages/windows-native/target/release/p14-integration.exe','candidate':one('.local/p14-candidate'),'owner_installer':one('apps/desktop/src-tauri/target/release/bundle/nsis')}
entries={}
for role,path in paths.items():
    with path.open('rb') as f:assert f.read(2)==b'MZ','Expected a compiled Windows binary'
    with path.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
    entries[role]={'path':path.relative_to(ROOT).as_posix(),'sha256':digest,'bytes':path.stat().st_size}
report={'purpose':'Built CI binaries only; reuse is diagnostic, never fresh-source application acceptance','status':'BUILT_UNVERIFIED','source_commit':git('rev-parse','HEAD'),'source_tree':git('rev-parse','HEAD^{tree}'),'source_tree_dirty':False,'binaries':entries,'physical_acceptance':False}
out=ROOT/'artifacts/p14';out.mkdir(parents=True,exist_ok=True);(out/'ui-diagnostic-binaries.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print('Recorded four source-bound compiled CI binaries; no application acceptance or private profiles')
