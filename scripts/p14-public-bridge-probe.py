import json,struct,subprocess,os,hashlib,base64
from pathlib import Path
out=Path('.local/p14-bridge-probe');out.mkdir(parents=True,exist_ok=False)
setups=list(Path('apps/desktop/src-tauri/target/release/bundle/nsis').glob('*.exe'));assert len(setups)==1
subprocess.run([str(setups[0].resolve()),'/S','/D='+str(out.resolve())],check=True,timeout=180)
resources=out/'resources';manifest=json.loads((resources/'runtime-manifest.json').read_text());node=resources/'node.exe';script=resources/'custody.mjs'
assert base64.urlsafe_b64encode(hashlib.sha256(script.read_bytes()).digest()).decode().rstrip('=')==manifest['script_sha256']
reports=[]
for message in [{'mode':'public-startup-probe'},{'mode':'export','header':{},'signer':{},'kit':{}}]:
 b=json.dumps(message).encode();command=[str(node.resolve()),'--no-addons','--disable-proto=throw','--permission','--allow-fs-read='+str(script.resolve()),str(script.resolve())]
 r=subprocess.run(command,input=struct.pack('>II',1,len(b))+b,capture_output=True,timeout=30,env={'NODE_NO_WARNINGS':'1','SystemRoot':os.environ['SystemRoot']})
 reports.append({'public_synthetic_request':message,'exit_code':r.returncode,'stdout_hex':r.stdout.hex()[:4096],'stderr':r.stderr.decode(errors='replace')[:8192]})
print(json.dumps({'purpose':'No secret public startup probe of exact packaged Windows runtime','binary_source_commit':'af53a1946816b566140016c06feb62a22b4f29a2','reports':reports},indent=2))
assert all(r['stdout_hex'].startswith('0000000a') for r in reports)
