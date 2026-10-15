import json,struct,subprocess,os,hashlib,base64,ctypes
from pathlib import Path
out=Path('.local/p14-bridge-probe');out.mkdir(parents=True,exist_ok=False)
setups=list(Path('apps/desktop/src-tauri/target/release/bundle/nsis').glob('*.exe'));assert len(setups)==1
subprocess.run([str(setups[0].resolve()),'/S','/D='+str(out.resolve())],check=True,timeout=180)
resources=out/'resources';manifest=json.loads((resources/'runtime-manifest.json').read_text());node=resources/'node.exe';script=resources/'custody.mjs'
assert base64.urlsafe_b64encode(hashlib.sha256(script.read_bytes()).digest()).decode().rstrip('=')==manifest['script_sha256']
reports=[]
kernel=ctypes.WinDLL('kernel32',use_last_error=True);kernel.CreateFileW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p];kernel.CreateFileW.restype=ctypes.c_void_p;kernel.CloseHandle.argtypes=[ctypes.c_void_p]
for variant in ['no-window','locked-assets','verbatim-paths']:
 message={'mode':'public-startup-probe'}
 handles=[]
 if variant=='locked-assets':
  for path in [node,script]:
   handle=kernel.CreateFileW(str(path.resolve()),0x80000000,1,None,3,0x00200000,None);assert handle not in [None,ctypes.c_void_p(-1).value];handles.append(handle)
 b=json.dumps(message).encode();command=[str(node.resolve()),'--no-addons','--disable-proto=throw','--permission','--allow-fs-read='+str(script.resolve()),str(script.resolve())]
 if variant=='verbatim-paths':
  command[0]='\\\\?\\'+command[0];command[-1]='\\\\?\\'+command[-1];command[-2]='--allow-fs-read='+command[-1]
 r=subprocess.run(command,creationflags=0x08000000,input=struct.pack('>II',1,len(b))+b,capture_output=True,timeout=30,env={'NODE_NO_WARNINGS':'1','SystemRoot':os.environ['SystemRoot']})
 for handle in handles:assert kernel.CloseHandle(handle)
 reports.append({'variant':variant,'public_synthetic_request':message,'exit_code':r.returncode,'stdout_hex':r.stdout.hex()[:4096],'stderr':r.stderr.decode(errors='replace')[:8192]})
print(json.dumps({'purpose':'No secret public startup probe of exact packaged Windows runtime','binary_source_commit':'af53a1946816b566140016c06feb62a22b4f29a2','reports':reports},indent=2))
assert all(r['stdout_hex'].startswith('0000000a') for r in reports)
