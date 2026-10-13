// Runs inside protected custody. No DEK, source hash/path or plaintext name leaves the journal.
import {FileWriter,FileReader} from '../adapters/files.mjs';
import {sodium,b64,hash} from '../adapters/primitives.mjs';
import {createHash} from '../adapters/bytes.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {canonicalBytes} from '../adapters/core.mjs';
import {envelopeDigest} from '../adapters/codecs/codec.mjs';
const check=(v,c)=>{if(!v)throw Object.assign(Error(c),{code:c});};
const random=()=>b64(sodium.randombytes_buf(16));
export const CHUNK=8388608;
export const fileControlId=scope=>b64(sodium.crypto_generichash(16,canonicalBytes(wire({purpose:'AnyNote/P12/file-control',scope}))));
export const fileIds=c=>new Map([[c.id,'file-control'],...c.transfers.map(t=>[t.record_id,'file-transfer']),...(c.witnesses??[]).map(w=>[w.record_id,'file-evidence'])]);
const wipe=v=>{if(v instanceof Uint8Array)sodium.memzero(v);else if(v&&typeof v==='object')for(const k of Object.keys(v)){wipe(v[k]);if(typeof v[k]==='string')v[k]='';}};
const source=s=>{check(s&&Number.isSafeInteger(s.size)&&s.size>=0&&s.size<=1000000000&&typeof s.slice==='function','RESOURCE_LIMIT');return s;};
const read=async(s,i)=>{const bytes=new Uint8Array(await s.slice(i*CHUNK,Math.min(s.size,(i+1)*CHUNK)).arrayBuffer());check(bytes.length===Math.min(CHUNK,s.size-i*CHUNK),'SOURCE_CHANGED');return bytes;};
async function identity(s){
 const parts=[],digest=createHash('sha256');for(let i=0;i<Math.ceil(s.size/CHUNK);i++){const p=await read(s,i);try{digest.update(p);parts.push(hash(p));}finally{sodium.memzero(p);}}
 return {size:s.size,parts,digest:digest.digest('base64url')};
}
export class FileWorkflow {
 #control;#readers=new Map();
 constructor({scope,load,readRecord,persist,authority}){Object.assign(this,{scope,load,readRecord,persist,authority});}
 close(){for(const r of this.#readers.values())r.close();this.#readers.clear();wipe(this.#control);this.#control=undefined;}
 async #ready(){this.#control??=await this.load()??{purpose:'p12-file-control',version:1,id:fileControlId(this.scope),transfers:[],witnesses:[]};check(this.#control.id===fileControlId(this.scope)&&this.#control.transfers.length<=512,'INTEGRITY_FAILURE');}
 async #get(id){const ref=this.#control.transfers.find(t=>t.draft_id===id);check(ref,'TRANSFER_NOT_FOUND');const data=await this.readRecord(ref.record_id,'file-transfer');check(data.draft_id===id&&data.context.group_id===ref.group_id,'LOCAL_CONTEXT_MISMATCH');return {ref,data};}
 async #save(ref,data){await this.persist(this.#control,[{id:ref.record_id,kind:'file-transfer',data}]);}
 async command(op,x={}){
  await this.#ready();
  if(op==='list')return this.#control.transfers.map(t=>({...t}));
  if(op==='history'){
   const out=[];for(const w of (this.#control.witnesses??[]).filter(w=>w.group_id===x.group_id)){const data=await this.readRecord(w.record_id,'file-evidence'),e=data.envelope,c=e.header.context;check(envelopeDigest(wire(e))===w.envelope_digest,'INTEGRITY_FAILURE');out.push({object_kind:'file-manifest',object_id:c.file_id,revision_id:c.file_version_id,envelope_digest:w.envelope_digest,parents:c.parents,payload_status:'retained'});}return out;
  }
  if(op==='prepare'){
   const s=source(x.source),auth=await this.authority(x.group_id,true);let writer;
   try{const identityProof=await identity(s);
    check(this.#control.transfers.length<512,'RESOURCE_LIMIT');
    const context={contract:'p02-file-c1',protocol:'anynote',protocol_version:1,service_id:this.scope.service_id,group_id:x.group_id,file_id:x.file_id??random(),file_version_id:random(),operation_id:random(),author:structuredClone(auth.author),policy:structuredClone(auth.policy),parents:x.parents??[],file_format:'xchacha20poly1305-chunks-c1',manifest_schema:1};
    writer=new FileWriter(wire(context),s.size);writer.bindSource(identityProof.digest);
    const ref={draft_id:random(),record_id:random(),group_id:x.group_id,state:'NEEDS_SOURCE',file_version_id:context.file_version_id},data={purpose:'p12-file-transfer',version:1,draft_id:ref.draft_id,upload_id:random(),context,source:identityProof,name:x.name??s.name??'download.bin',media:x.media??'application/octet-stream',writer:writer.checkpoint(),acknowledged:[],record:null,receipt:null,state:'NEEDS_SOURCE'};
    this.#control.transfers.push(ref);await this.#save(ref,data);return {draft_id:ref.draft_id,request:{version:1,upload_id:data.upload_id,context,plaintext_bytes:String(s.size)}};
   }finally{writer?.close();wipe(auth);}
  }
  if(op==='request'){const {data}=await this.#get(x.draft_id);return {version:1,upload_id:data.upload_id,context:data.context,plaintext_bytes:String(data.source.size)};}
  if(op==='reselect'){
   const {ref,data}=await this.#get(x.draft_id),s=source(x.source),auth=await this.authority(ref.group_id,true);
   try{check(same(auth.policy,data.context.policy),'REKEY_RESTART_REQUIRED');check(same(await identity(s),data.source),'SOURCE_CHANGED');data.state=ref.state='READY';await this.#save(ref,data);return {state:'READY',next:data.writer.next};}finally{wipe(auth);}
  }
  if(op==='part'){
   const {ref,data}=await this.#get(x.draft_id),auth=await this.authority(ref.group_id,true);let p,writer;
   try{
    check(same(auth.policy,data.context.policy),'REKEY_RESTART_REQUIRED');check(data.receipt===null&&data.record===null,'INVALID_TRANSFER_STATE');
    const s=source(x.source),index=x.index;check(Number.isSafeInteger(index)&&index>=0&&index<=data.writer.next&&index<data.source.parts.length&&s.size===data.source.size,'INVALID_CHUNK_INDEX');
    p=await read(s,index);check(hash(p)===data.source.parts[index],'SOURCE_CHANGED');
    writer=FileWriter.resume(data.writer);let cipher;
    if(index===data.writer.next){cipher=writer.encryptNext(p);data.writer=writer.checkpoint();data.state=ref.state='UPLOADING';await this.#save(ref,data);}
    else{
     // Rebuild only the proven index, retaining the immutable key/prefix/context.
     const state=structuredClone(data.writer);state.next=index;state.parts=state.parts.slice(0,index);writer.close();writer=FileWriter.resume(state);cipher=writer.encryptNext(p);check(hash(cipher)===data.writer.parts[index].ciphertext_digest,'INTEGRITY_FAILURE');wipe(state);
    }
    return {upload_id:data.upload_id,index:String(index),ciphertext:cipher};
   }finally{if(p)sodium.memzero(p);writer?.close();wipe(auth);}
  }
  if(op==='ackPart'){
   const {ref,data}=await this.#get(x.draft_id),part=data.writer.parts[Number(x.part.index)];check(part&&same(part,x.part),'CIPHERTEXT_MISMATCH');if(!data.acknowledged.includes(x.part.index))data.acknowledged.push(x.part.index);await this.#save(ref,data);return {acknowledged:data.acknowledged.length};
  }
  if(op==='finish'){
   const {ref,data}=await this.#get(x.draft_id),auth=await this.authority(ref.group_id,true);let writer;
   try{check(same(auth.policy,data.context.policy),'REKEY_RESTART_REQUIRED');if(!data.record){check(data.acknowledged.length===data.source.parts.length,'INCOMPLETE_FILE');writer=FileWriter.resume(data.writer);data.record=writer.finish(data.name,data.media,auth.key,auth.signing);data.state=ref.state='COMMIT_UNKNOWN';await this.#save(ref,data);}return {upload_id:data.upload_id,request:{version:1,record:data.record}};}finally{writer?.close();wipe(auth);}
  }
  if(op==='committed'){
   const {ref,data}=await this.#get(x.draft_id),r=x.receipt,c=data.context;check(data.record&&r.state==='COMMITTED'&&r.upload_id===data.upload_id&&r.group_id===c.group_id&&r.file_id===c.file_id&&r.file_version_id===c.file_version_id&&r.operation_id===c.operation_id&&r.envelope_digest===envelopeDigest(wire(data.record.envelope)),'CIPHERTEXT_MISMATCH');
   check(data.receipt===null||same(data.receipt,r),'IDEMPOTENCY_MISMATCH');data.receipt=structuredClone(r);data.state=ref.state='UNATTACHED';await this.#save(ref,data);await this.#observe(data.record.envelope);return {state:'UNATTACHED',attachment:{file_id:c.file_id,file_version_id:c.file_version_id,envelope_digest:r.envelope_digest}};
  }
  if(op==='attachment'){const {data}=await this.#get(x.draft_id);check(data.receipt,'FILE_NOT_COMMITTED');return {file_id:data.context.file_id,file_version_id:data.context.file_version_id,envelope_digest:data.receipt.envelope_digest};}
  if(op==='burn'){
   const {ref,data}=await this.#get(x.draft_id);check(x.confirm===true&&!data.receipt,'CONFIRMATION_REQUIRED');check(x.status?.upload_id===data.upload_id&&['CANCELLED','EXPIRED'].includes(x.status.state),'RECONCILIATION_REQUIRED');data.state=ref.state='SUPERSEDED';await this.#save(ref,data);return {state:'SUPERSEDED',source_retained:true};
  }
  if(op==='open'||op==='observe'){
   const record=x.record,c=record?.envelope?.header?.context;check(c?.group_id===x.group_id&&c?.file_version_id===x.file_version_id,'CONTEXT_MISMATCH');const auth=await this.authority(x.group_id,false,record.envelope);try{const reader=new FileReader(wire(record),auth.key,auth.publicKey,wire(c)),id=random(),metadata=reader.metadata();await this.#observe(record.envelope);if(op==='observe'){reader.close();return {state:'VERIFIED',file_version_id:c.file_version_id,envelope_digest:envelopeDigest(wire(record.envelope)),...metadata};}this.#readers.set(id,reader);return {reader_id:id,plaintext_bytes:record.envelope.header.framing.plaintext_bytes,chunks:record.envelope.header.framing.chunk_count,...metadata};}finally{wipe(auth);}
  }
  if(op==='decrypt'){const reader=this.#readers.get(x.reader_id);check(reader,'RESUME_REQUIRED');return {plaintext:reader.decryptNext(x.ciphertext)};}
  if(op==='range'){const reader=this.#readers.get(x.reader_id);check(reader,'RESUME_REQUIRED');return {plaintext:reader.decryptAt(x.index,x.ciphertext),file_complete:false};}
  if(op==='complete'){const reader=this.#readers.get(x.reader_id);check(reader,'RESUME_REQUIRED');try{return reader.finish();}finally{reader.close();this.#readers.delete(x.reader_id);}}
  if(op==='close'){this.#readers.get(x.reader_id)?.close();this.#readers.delete(x.reader_id);return {state:'PAUSED'};}
  check(false,'INVALID_FILE_COMMAND');
 }
 async #observe(envelope){
  const c=envelope.header.context,digest=envelopeDigest(wire(envelope));this.#control.witnesses??=[];const old=this.#control.witnesses.find(w=>w.file_version_id===c.file_version_id);if(old){check(old.envelope_digest===digest,'ROLLBACK_QUARANTINE');return;}
  check(this.#control.witnesses.length<1000,'RESOURCE_LIMIT');const record_id=random();this.#control.witnesses.push({record_id,group_id:c.group_id,file_version_id:c.file_version_id,envelope_digest:digest});await this.persist(this.#control,[{id:record_id,kind:'file-evidence',data:{purpose:'p12-file-evidence',version:1,envelope}}]);
 }
}
