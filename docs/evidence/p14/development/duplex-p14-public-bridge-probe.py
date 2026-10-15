import json,subprocess,hashlib,base64,threading,os
from pathlib import Path
out=Path('.local/p14-duplex-probe');out.mkdir(parents=True,exist_ok=False)
setups=list(Path('apps/desktop/src-tauri/target/release/bundle/nsis').glob('*.exe'));assert len(setups)==1
subprocess.run([str(setups[0].resolve()),'/S','/D='+str(out.resolve())],check=True,timeout=180)
resources=out/'resources';manifest=json.loads((resources/'runtime-manifest.json').read_text());node=resources/'node.exe';assert base64.urlsafe_b64encode(hashlib.sha256(node.read_bytes()).digest()).decode().rstrip('=')==manifest['node_sha256']
reports=[];size=8388608
for variant in ['stdout','async-fd-write']:
 code="import {write} from 'node:fs';const data=Buffer.alloc(8388608,97);let count=0;process.stdin.on('data',b=>{count+=b.length;});process.stdin.on('end',()=>{if(count!==8388608)process.exitCode=1;});"
 code+= "process.stdout.write(data);" if variant=='stdout' else "await new Promise((resolve,reject)=>{let offset=0;const next=()=>write(1,data,offset,data.length-offset,null,(error,n)=>{if(error)return reject(error);if(!n)return reject(Error('NO_PROGRESS'));offset+=n;offset===data.length?resolve():next();});next();});"
 script=out/(variant+'.mjs');script.write_text(code,encoding='utf-8');command=[str(node.resolve()),'--no-addons','--disable-proto=throw','--permission','--allow-fs-read='+str(script.resolve()),str(script.resolve())]
 child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=0x08000000,env={'NODE_NO_WARNINGS':'1','SystemRoot':os.environ['SystemRoot']});errors=[]
 def send():
  try:child.stdin.write(b'b'*size);child.stdin.close()
  except Exception as e:errors.append(type(e).__name__)
 timer=threading.Timer(20,child.kill);timer.start();writer=threading.Thread(target=send);writer.start();writer.join(3);before_read=not writer.is_alive();output=child.stdout.read();stderr=child.stderr.read().decode(errors='replace');code=child.wait(timeout=5);writer.join(5);timer.cancel()
 reports.append({'variant':variant,'input_finished_before_output_read':before_read,'output_bytes':len(output),'output_sha256':hashlib.sha256(output).hexdigest(),'exit_code':code,'writer_errors':errors,'stderr':stderr[:8192]})
print(json.dumps({'purpose':'Public synthetic full-duplex Windows pipe probe; no vault or archive keys','binary_source_commit':'af53a1946816b566140016c06feb62a22b4f29a2','node_sha256':manifest['node_sha256'],'reports':reports},indent=2))
assert reports[0]['input_finished_before_output_read'] is False
assert reports[1]['input_finished_before_output_read'] is True
assert all(r['exit_code']==0 and r['output_bytes']==size and not r['writer_errors'] for r in reports)
assert reports[0]['output_sha256']==reports[1]['output_sha256']
