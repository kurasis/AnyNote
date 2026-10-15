import json,subprocess,hashlib,base64,shutil
from pathlib import Path
out=Path('.local/p14-bridge-probe');out.mkdir(parents=True,exist_ok=False)
setups=list(Path('apps/desktop/src-tauri/target/release/bundle/nsis').glob('*.exe'));assert len(setups)==1
subprocess.run([str(setups[0].resolve()),'/S','/D='+str(out.resolve())],check=True,timeout=180)
resources=out/'resources';manifest=json.loads((resources/'runtime-manifest.json').read_text());target=Path('apps/desktop/src-tauri/resources');target.mkdir(parents=True,exist_ok=True)
for name,key in [('node.exe','node_sha256'),('custody.mjs','script_sha256')]:
 p=resources/name;assert base64.urlsafe_b64encode(hashlib.sha256(p.read_bytes()).digest()).decode().rstrip('=')==manifest[key];shutil.copyfile(p,target/name)
bridge=Path('packages/windows-native/src/bridge.rs');fixed=Path('scripts/p14-fixed-bridge.rs').read_bytes();command=['cargo','test','--manifest-path','packages/windows-native/Cargo.toml','--locked','-j','4','--test','bridge','--','--test-threads=1']
before=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=480)
print('BEFORE canonical-path real native pipe regression:',before.stdout,before.stderr,flush=True)
assert before.returncode!=0 and 'BRIDGE_CLOSED' in before.stdout+before.stderr
bridge.write_bytes(fixed)
after=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=480)
print('AFTER canonical-path real native pipe regression:',after.stdout,after.stderr,flush=True)
assert after.returncode==0
print(json.dumps({'status':'PASS','scope':'actual native Bridge with exact packaged runtime and frozen authenticated archive; canonical Windows script path','before':'BRIDGE_CLOSED','after':'verified original plaintext recovered','binary_source_commit':'af53a1946816b566140016c06feb62a22b4f29a2'}))
