// Downloaded replaceable ciphertext only. Unsynced uploads never enter this namespace.
import {strictJson} from '../src/strict-json.mjs';
import {ensure,id} from '../vault/store.mjs';
import {envelopeDigest} from '../adapters/codecs/codec.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {hash} from '../adapters/primitives.mjs';
export const MOBILE_CACHE=1073741824,WINDOWS_CACHE=5368709120;
export class CipherCache {
 constructor(budget=MOBILE_CACHE){ensure(Number.isSafeInteger(budget)&&budget>=0,'RESOURCE_LIMIT');this.budget=budget;}
 async root(){ensure(navigator.storage?.getDirectory,'STORAGE_UNAVAILABLE');return navigator.storage.getDirectory().then(r=>r.getDirectoryHandle('anynote-p12-downloaded-ciphertext-v1',{create:true}));}
 name(group,version){ensure(id(group)&&id(version),'INVALID_RECORD');return group+'_'+version;}
 async #read(dir){const file=await (await dir.getFileHandle('manifest.json')).getFile();ensure(file.size<=262144,'RESOURCE_LIMIT');return strictJson(new Uint8Array(await file.arrayBuffer()),262144);}
 async #write(dir,name,bytes){const w=await (await dir.getFileHandle(name,{create:true})).createWritable();try{await w.write(bytes);await w.close();}catch(e){await w.abort().catch(()=>{});throw e;}}
 async begin(record,{pinned=false,extraBudget=0,confirm=false}={}){
  const h=record.envelope.header,c=h.context,name=this.name(c.group_id,c.file_version_id),bytes=Number(h.manifest_ciphertext_bytes)+48+h.framing.parts.reduce((n,p)=>n+Number(p.ciphertext_bytes),0);
  ensure(!pinned||confirm===true&&Number.isSafeInteger(extraBudget)&&extraBudget>=bytes,'CONFIRMATION_REQUIRED');const estimate=await navigator.storage.estimate();ensure(Number.isFinite(estimate.quota)&&Number.isFinite(estimate.usage)&&estimate.quota-estimate.usage>=bytes+65536,'INSUFFICIENT_STORAGE');
  await navigator.storage.persist?.();const root=await this.root(),entries=[];let used=0;
  for await(const [key,handle]of root.entries()){if(handle.kind!=='directory')continue;const data=await this.#read(handle).catch(()=>null);if(data){used+=data.bytes;entries.push({key,...data});}}
  for(const e of entries.sort((a,b)=>a.touched-b.touched)){if(used+bytes<=this.budget+(pinned?extraBudget:0))break;if(!e.pinned&&e.name!==name){await root.removeEntry(e.key,{recursive:true});used-=e.bytes;}}
  ensure(used+bytes<=this.budget+(pinned?extraBudget:0),'INSUFFICIENT_STORAGE');const dir=await root.getDirectoryHandle(name,{create:true}),data={version:1,name,bytes,touched:Date.now(),pinned,complete:false,record,parts:[]};await this.#write(dir,'manifest.json',new TextEncoder().encode(JSON.stringify(data)));return {dir,data};
 }
 async put(job,index,ciphertext){const expected=job.data.record.envelope.header.framing.parts[index];ensure(expected&&expected.index===String(index)&&Number(expected.ciphertext_bytes)===ciphertext.length&&hash(ciphertext)===expected.ciphertext_digest,'INTEGRITY_FAILURE');await this.#write(job.dir,String(index),ciphertext);if(!job.data.parts.includes(index))job.data.parts.push(index);await this.#write(job.dir,'manifest.json',new TextEncoder().encode(JSON.stringify(job.data)));}
 async finish(job){ensure(job.data.parts.length===job.data.record.envelope.header.framing.parts.length,'INCOMPLETE_FILE');const complete={...job.data,complete:true};await this.#write(job.dir,'manifest.json',new TextEncoder().encode(JSON.stringify(complete)));job.data=complete;}
 async verify(vault,group,version){const dir=await (await this.root()).getDirectoryHandle(this.name(group,version)),data=await this.#read(dir);ensure(data.complete===true&&data.name===this.name(group,version),'OFFLINE_UNAVAILABLE');let reader;
  try{reader=await vault.notes('files',['open',{group_id:group,file_version_id:version,record:data.record}]);for(let index=0;index<Number(reader.chunks);index++){const file=await (await dir.getFileHandle(String(index))).getFile();ensure(file.size<=8388624,'RESOURCE_LIMIT');const cipher=new Uint8Array(await file.arrayBuffer()),result=await vault.notes('files',['decrypt',{reader_id:reader.reader_id,ciphertext:cipher}]);result.plaintext.fill(0);}await vault.notes('files',['complete',{reader_id:reader.reader_id}]);return {available_offline:true,envelope_digest:envelopeDigest(wire(data.record.envelope))};}finally{if(reader)await vault.notes('files',['close',{reader_id:reader.reader_id}]).catch(()=>{});}
 }
}
