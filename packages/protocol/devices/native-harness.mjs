// Explicit synthetic integration harness. No raw-key export in product/native IPC.
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {resolve} from 'node:path';
export async function nativeHarness(input){
 const exe=resolve(import.meta.dirname,'../../vault-native/target/debug/p08-integration'+(process.platform==='win32'?'.exe':''));
 const child=spawn(exe,[],{stdio:['pipe','pipe','pipe']}),lines=createInterface({input:child.stdout});let waiting=[],ended=false;
 lines.on('line',line=>{const next=waiting.shift();if(next){try{next.resolve(JSON.parse(line));}catch{next.reject(Error('NATIVE_INVALID_PUBLIC_RESULT'));}}});
 child.on('exit',()=>{ended=true;for(const next of waiting)next.reject(Error('NATIVE_PROCESS_ENDED'));waiting=[];});child.stderr.on('data',()=>{});
 const call=request=>new Promise((resolve,reject)=>{if(ended)return reject(Error('NATIVE_PROCESS_ENDED'));waiting.push({resolve,reject});child.stdin.write(JSON.stringify(request)+'\n');});
 const device=await call(input);
 return {device,call,close:async()=>{child.stdin.end();await new Promise(done=>ended?done():child.once('exit',done));lines.close();}};
}
