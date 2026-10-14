#!/usr/bin/env python3
"""Static Windows capability/frozen-baseline audit. Runtime and physical evidence is separate."""
import hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE='7aaf3b770b739c2bd554bd6feb7e653c00dbe3b9'
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT)
files=git('ls-tree','-r','--name-only',BASE).decode().splitlines()
frozen=[name for name in files if name.startswith(('docs/spec/','fixtures/protocol/p02/')) or Path(name).name in ['Cargo.lock','package-lock.json','composer.lock']]
for name in frozen:
    if (ROOT/name).read_bytes()!=git('show',BASE+':'+name):raise RuntimeError('Frozen pre-P14 baseline changed: '+name)
config=json.loads((ROOT/'apps/desktop/src-tauri/tauri.conf.json').read_text(encoding='utf-8'))
cap=json.loads((ROOT/'apps/desktop/src-tauri/capabilities/main.json').read_text(encoding='utf-8'))
expected={'allow-product','allow-profile','allow-file-job','allow-open-link','allow-update','core:event:allow-listen','core:event:allow-unlisten'}
assert cap['windows']==['main'] and set(cap['permissions'])==expected and len(cap['permissions'])==len(expected)
assert 'remote' not in cap and 'webviews' not in cap
window=config['app']['windows'];assert len(window)==1 and window[0]['label']=='main' and window[0]['devtools'] is False and window[0]['incognito'] is True
assert config['app']['security']['capabilities']==['main']
csp=config['app']['security']['csp'];assert "default-src 'none'" in csp and "script-src 'self'" in csp and "object-src 'none'" in csp and "frame-src 'none'" in csp and 'unsafe-' not in csp and 'https:' not in csp
update=config['plugins']['updater'];assert update['requireSignedVersion'] is True and update['allowDowngrades'] is False and update['pubkey']==''
assert config['bundle']['targets']==['nsis'] and config['bundle']['windows']['nsis']['installMode']=='currentUser'
assert config['bundle']['windows']['webviewInstallMode']=={'type':'downloadBootstrapper','silent':True}
source=(ROOT/'apps/desktop/src-tauri/src/main.rs').read_text(encoding='utf-8');assert 'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS' in source and '#[cfg(not(feature = "integration-harness"))]' in source
commands=(ROOT/'apps/desktop/src-tauri/build.rs').read_text(encoding='utf-8');assert all('"'+name.removeprefix('allow-').replace('-','_')+'"' in commands for name in expected if name.startswith('allow-'))
report={'purpose':'P14 static installed-host capability and unchanged-baseline audit','status':'PASS','source_commit':git('rev-parse','HEAD').decode().strip(),'source_tree_dirty':bool(git('status','--porcelain').strip()),'frozen_baseline':BASE,'unchanged_files':len(frozen),'baseline_digest':hashlib.sha256('\n'.join(frozen).encode()).hexdigest(),'main_permissions':sorted(expected),'preview_native_permissions':[],'scope':'Static configuration only; actual runtime denials, installer, WebView2 and hardware have separate receipts','physical_acceptance':False}
out=ROOT/'artifacts/p14';out.mkdir(parents=True,exist_ok=True);(out/'capability-audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
