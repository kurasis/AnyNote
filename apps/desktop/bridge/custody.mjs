// Installed trusted native helper. No network, filesystem paths, device/group/root keys or renderer RPC.
import {writePortable,PortableReader} from '../../../packages/protocol/content/portable.mjs';
import {wire} from '../../../packages/protocol/adapters/codecs/identity-codec.mjs';
import {strictJson} from '../../../packages/protocol/src/strict-json.mjs';
const CAP=16777216,queue=[],waiters=[];let pending=Buffer.alloc(0),ended=false;
process.stdin.on('data',b=>{pending=Buffer.concat([pending,b]);pump();});process.stdin.on('end',()=>{ended=true;pump();});
function accepts(w,frame){return !w.kinds||w.kinds.includes(frame.kind);}
function pump(){
 while(pending.length>=8){const kind=pending.readUInt32BE(0),size=pending.readUInt32BE(4);if(size>CAP){process.exitCode=1;process.stdin.destroy();for(const w of waiters.splice(0))w.reject(Error('RESOURCE_LIMIT'));return;}if(pending.length<8+size)break;queue.push({kind,bytes:Buffer.from(pending.subarray(8,8+size))});pending=pending.subarray(8+size);if(queue.length>=4){process.stdin.pause();break;}}
 for(let i=0;i<waiters.length;){const w=waiters[i],index=queue.findIndex(f=>accepts(w,f));if(index>=0){waiters.splice(i,1);w.resolve(queue.splice(index,1)[0]);}else if(ended){waiters.splice(i,1);w.reject(Error('BRIDGE_CLOSED'));}else i++;}
 if(queue.length<4)process.stdin.resume();
}
async function take(kinds){const index=queue.findIndex(f=>!kinds||kinds.includes(f.kind));if(index>=0){const frame=queue.splice(index,1)[0];pump();return frame;}if(ended)throw Error('BRIDGE_CLOSED');return new Promise((resolve,reject)=>{waiters.push({kinds,resolve,reject});pump();});}
async function send(kind,bytes=Buffer.alloc(0)){if(bytes.length>CAP)throw Error('RESOURCE_LIMIT');const h=Buffer.alloc(8);h.writeUInt32BE(kind);h.writeUInt32BE(bytes.length,4);await new Promise((resolve,reject)=>process.stdout.write(Buffer.concat([h,bytes]),e=>e?reject(e):resolve()));}
const json=(v)=>Buffer.from(JSON.stringify(v)),expect=async k=>{const f=await take([k]);if(f.kind!==k)throw Error('INVALID_BRIDGE_FRAME');return f.bytes;},ack=async()=>{const b=await expect(9);if(b.length)throw Error('INVALID_BRIDGE_FRAME');};
const clear=v=>{if(v&&typeof v==='object')for(const k of Object.keys(v)){clear(v[k]);if(typeof v[k]==='string')v[k]='';}};
let init,reader;
try{
 init=strictJson(await expect(1),65536);globalThis.fetch=()=>{throw Error('OFFLINE_ONLY');};
 if(init.mode==='export'){
  async function* entries(){for(;;){await send(11);const f=await take();if(f.kind===4)break;if(f.kind!==2)throw Error('INVALID_BRIDGE_FRAME');const meta=strictJson(f.bytes,4096),bytes=await expect(3);if(bytes.length!==meta.bytes)throw Error('INVALID_BRIDGE_FRAME');try{yield {path:meta.path,bytes};}finally{bytes.fill(0);}}}
  const result=await writePortable({header:init.header,signer:init.signer,kit:init.kit,entries:entries(),sign:async bytes=>{await send(5,bytes);return expect(6);},sink:{async write(bytes){await send(7,bytes);await ack();},async finish(){await send(12);await ack();},async abort(){await send(10,json({error:'EXPORT_INTERRUPTED'}));}}});
  await send(8,json(result));clear(result);
 }else if(init.mode==='inspect'){
  const source=()=>{let offset=0;return new ReadableStream({async pull(controller){await send(13,json({offset:String(offset),bytes:65536}));const frame=await take([3,4]);if(frame.kind===4){controller.close();return;}if(frame.kind!==3||frame.bytes.length>65536)throw Error('INVALID_BRIDGE_FRAME');offset+=frame.bytes.length;controller.enqueue(frame.bytes);}});};
  reader=new PortableReader(source,init.kit);clear(init.kit);const report=await reader.validate();
  await send(8,json(report));await ack();
  await reader.recover({
   async note(revision,payload){await send(14,json({revision,payload}));await ack();},
   async fileStart(version,context,metadata){await send(15,json({version,context,metadata,source:reader.fileSource(version)}));await ack();},
   async filePart(version,index,bytes){await send(16,json({version,index,bytes:bytes.length}));await send(3,bytes);await ack();},
   async fileFinish(version){await send(17,json({version}));await ack();}
  });await send(18,json({verified:true}));
 }else throw Error('INVALID_BRIDGE_MODE');
}catch(e){try{await send(10,json({error:/^[A-Z_]{3,64}$/.test(e.message)?e.message:'OFFLINE_INTEGRITY_FAILURE'}));}catch{}process.exitCode=1;}
finally{reader?.close();clear(init);for(const f of queue)f.bytes.fill(0);pending.fill(0);process.stdin.destroy();}
