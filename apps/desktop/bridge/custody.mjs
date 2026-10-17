// Installed trusted native helper. No network, filesystem paths, device/group/root keys or renderer RPC.
import {writePortable,PortableReader} from '../../../packages/protocol/content/portable.mjs';
import {wire} from '../../../packages/protocol/adapters/codecs/identity-codec.mjs';
import {strictJson} from '../../../packages/protocol/src/strict-json.mjs';
import {sendFrame as send} from './framed-output.mjs';
import {frameReader} from './framed-input.mjs';
const frames=frameReader(process.stdin),take=kinds=>frames.take(kinds);
const json=(v)=>Buffer.from(JSON.stringify(v)),expect=async k=>{const f=await take([k]);if(f.kind!==k)throw Error('INVALID_BRIDGE_FRAME');return f.bytes;},ack=async()=>{const b=await expect(9);if(b.length)throw Error('INVALID_BRIDGE_FRAME');};
const clear=v=>{if(v&&typeof v==='object')for(const k of Object.keys(v)){clear(v[k]);if(typeof v[k]==='string')v[k]='';}};
let init,reader;
try{
 init=strictJson(await expect(1),65536);globalThis.fetch=()=>{throw Error('OFFLINE_ONLY');};
 if(init.mode==='export'){
  async function* entries(){for(;;){await send(11);const f=await take();if(f.kind===4)break;if(f.kind!==2)throw Error('INVALID_BRIDGE_FRAME');const meta=strictJson(f.bytes,4096),bytes=await expect(3);try{if(bytes.length!==meta.bytes)throw Error('INVALID_BRIDGE_FRAME');yield {path:meta.path,bytes};}finally{frames.release(bytes);}}}
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
finally{reader?.close();clear(init);frames.close();}
