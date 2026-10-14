import {AuthClient,boundedResponse} from '../auth-client.mjs';
import {strictJson} from '../src/strict-json.mjs';
import {ensure} from '../vault/store.mjs';
import {CHUNK} from './workflow.mjs';
export function safeFilename(value){
 ensure(typeof value==='string','INVALID_FILENAME');let n=value.normalize('NFC').replace(/[\x00-\x1f\x7f<>:"/\\|?*]/g,'_').replace(/[. ]+$/g,'').replace(/[. ]+(?=\.)/g,'_').slice(0,120);
 if(!n||n==='.'||n==='..')n='download.bin';if(/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(n))n='_'+n;return n;
}
export class FilesClient {
 #csrf;
 constructor(auth){ensure(auth instanceof AuthClient,'AUTH_CLIENT_REQUIRED');this.auth=auth;}
 async call(path,method='GET',body,signal){
  ensure(/^\/(?:groups\/[A-Za-z0-9_-]{22}\/(?:uploads|files)|uploads\/[A-Za-z0-9_-]{22}(?:\/(?:commit|parts\/(?:0|[1-9][0-9]{0,2})))?|files\/[A-Za-z0-9_-]{22}\/(?:manifest|chunks\/(?:0|[1-9][0-9]{0,2})|unattached)|me\/(?:storage|unattached-files)|snapshots\/[A-Za-z0-9_-]{22}\/files)(?:\?(?:after=[A-Za-z0-9_-]{22}|start=(?:0|[1-9][0-9]{0,3})))?$/.test(path),'INVALID_FILE_PATH');
  const write=method!=='GET',binary=method==='PUT';if(write)this.#csrf??=(await this.auth.csrf()).csrf_token;
  if(binary)ensure(body instanceof Uint8Array&&body.length>=16&&body.length<=CHUNK+16,'RESOURCE_LIMIT');else if(body!==undefined)ensure(JSON.stringify(body).length<=262144,'RESOURCE_LIMIT');
  const response=await this.auth.fetcher(this.auth.issuer+'/api/v1'+path,{method,credentials:'include',cache:'no-store',redirect:'error',signal,headers:{Accept:'application/json',...(write?{'X-CSRF-TOKEN':this.#csrf}:{}),...(body!==undefined?{'Content-Type':binary?'application/octet-stream':'application/json'}:{})},...(body!==undefined?{body:binary?body:JSON.stringify(body)}:{})});
  const isChunk=response.ok&&/\/chunks\//.test(path),limit=isChunk?CHUNK+16:response.ok?1048576:4096,bytes=await boundedResponse(response,limit);if(isChunk)return bytes;
  const value=strictJson(bytes,limit);if(!response.ok){this.#csrf=undefined;throw Object.assign(Error(value.error?.code??'FILE_DENIED'),{status:response.status});}
  return value;
 }
}
export class TransferManager {
 #active=new Set();
 constructor({vault,transport,active=()=>true,progress=()=>{},cache=null}){Object.assign(this,{vault,transport,active,progress,cache});}
 pause(){for(const c of this.#active)c.abort();this.#active.clear();}
 command(op,x={}){ensure(this.active(),'RESUME_REQUIRED');return this.vault.notes('files',[op,x]);}
 async upload(source,group_id,draft_id=null){
  ensure(draft_id!==null||(source instanceof Blob&&source.size<=1000000000),'RESOURCE_LIMIT');const abort=new AbortController();this.#active.add(abort);
  try{
   if(!draft_id)draft_id=(await this.command('prepare',{source,group_id})).draft_id;
   const request=await this.command('request',{draft_id});ensure(request.context.group_id===group_id,'CONTEXT_MISMATCH');
   let status;try{status=await this.transport.call('/uploads/'+request.upload_id,'GET',undefined,abort.signal);}catch(e){if(e.message!=='NOT_FOUND')throw e;status=await this.transport.call('/groups/'+group_id+'/uploads','POST',request,abort.signal);}
   ensure(status.upload_id===request.upload_id&&status.file_version_id===request.context.file_version_id&&status.group_id===group_id,'CONTEXT_MISMATCH');
   if(status.state==='COMMITTED'){await this.command('committed',{draft_id,receipt:status.receipt});return {draft_id,receipt:status.receipt};}
   ensure(!['CANCELLED','EXPIRED'].includes(status.state),'UPLOAD_EXPIRED');
   const local=(await this.command('list')).find(t=>t.draft_id===draft_id);
   if(local?.state==='COMMIT_UNKNOWN'){const finish=await this.command('finish',{draft_id}),receipt=await this.transport.call('/uploads/'+finish.upload_id+'/commit','POST',finish.request,abort.signal);await this.command('committed',{draft_id,receipt});return {draft_id,receipt};}
   ensure(source instanceof Blob&&source.size<=1000000000,'SOURCE_IDENTITY_REQUIRED');
   await this.command('reselect',{draft_id,source});
   for(let index=0;index<Math.ceil(source.size/CHUNK);index++){
    ensure(!abort.signal.aborted,'RESUME_REQUIRED');const p=await this.command('part',{draft_id,source,index});
    try{const ack=await this.transport.call('/uploads/'+p.upload_id+'/parts/'+index,'PUT',p.ciphertext,abort.signal);await this.command('ackPart',{draft_id,part:ack});this.progress({draft_id,state:'UPLOADING',bytes:Math.min(source.size,(index+1)*CHUNK),total:source.size});}finally{p.ciphertext.fill(0);}
   }
   const finish=await this.command('finish',{draft_id});const receipt=await this.transport.call('/uploads/'+finish.upload_id+'/commit','POST',finish.request,abort.signal);await this.command('committed',{draft_id,receipt});this.progress({draft_id,state:'UNATTACHED',bytes:source.size,total:source.size});return {draft_id,receipt};
  }catch(e){this.progress({draft_id,state:['SOURCE_CHANGED','REKEY_RESTART_REQUIRED','UPLOAD_EXPIRED'].includes(e.message)?'RESTART_REQUIRED':'NEEDS_SOURCE',code:e.message});throw e;}finally{this.#active.delete(abort);}
 }
 async copy(source,draft_id,destination_group,preview_digest){const made=await this.command('copy',{source,draft_id,destination_group,preview_digest,confirm:true});return this.upload(source,destination_group,made.draft_id);}
 async restart(source,group_id,old_draft_id){const request=await this.command('request',{draft_id:old_draft_id});ensure(request.context.group_id===group_id,'CONTEXT_MISMATCH');const status=await this.transport.call('/uploads/'+request.upload_id);if(status.state==='COMMITTED'){await this.command('committed',{draft_id:old_draft_id,receipt:status.receipt});return {draft_id:old_draft_id,receipt:status.receipt};}if(['EXPIRED','CANCELLED'].includes(status.state))await this.command('burn',{draft_id:old_draft_id,confirm:true,status});else await this.cancel(old_draft_id);const made=await this.command('prepare',{source,group_id,previous_draft_id:old_draft_id});return this.upload(source,group_id,made.draft_id);}
 async cancel(draft_id){const request=await this.command('request',{draft_id}),status=await this.transport.call('/uploads/'+request.upload_id,'DELETE');await this.command('burn',{draft_id,confirm:true,status});return status;}
 async download(group_id,file_version_id,sink){
  ensure(sink&&typeof sink.write==='function'&&typeof sink.finish==='function'&&typeof sink.abort==='function','SINK_REQUIRED');const abort=new AbortController();this.#active.add(abort);abort.signal.addEventListener('abort',()=>{void sink.abort();},{once:true});let reader,cacheJob,complete;
  try{
   const record=await this.transport.call('/files/'+file_version_id+'/manifest','GET',undefined,abort.signal);reader=await this.command('open',{group_id,file_version_id,record});if(this.cache)cacheJob=await this.cache.begin(record).catch(()=>null);
   for(let index=0;index<Number(reader.chunks);index++){
    ensure(!abort.signal.aborted,'RESUME_REQUIRED');const ciphertext=await this.transport.call('/files/'+file_version_id+'/chunks/'+index,'GET',undefined,abort.signal),p=await this.command('decrypt',{reader_id:reader.reader_id,ciphertext});if(cacheJob){try{await this.cache.put(cacheJob,index,ciphertext);}catch{cacheJob=null;}}
    try{if(index===Number(reader.chunks)-1)complete=await this.command('complete',{reader_id:reader.reader_id});await sink.write(p.plaintext);this.progress({state:'DOWNLOADING',bytes:Math.min(Number(reader.plaintext_bytes),(index+1)*CHUNK),total:Number(reader.plaintext_bytes)});}finally{p.plaintext.fill(0);ciphertext.fill(0);}
   }
   complete??=await this.command('complete',{reader_id:reader.reader_id});await sink.finish();if(cacheJob)await this.cache.finish(cacheJob).catch(()=>{});return {...complete,available_offline:Boolean(cacheJob?.data.complete)};
  }catch(e){await sink.abort();throw e;}finally{if(reader)await this.command('close',{reader_id:reader.reader_id}).catch(()=>{});this.#active.delete(abort);}
 }
 async range(group_id,file_version_id,offset,length,sink){
  ensure(Number.isSafeInteger(offset)&&Number.isSafeInteger(length)&&offset>=0&&length>=0&&length<=1000000000,'RESOURCE_LIMIT');const abort=new AbortController();this.#active.add(abort);abort.signal.addEventListener('abort',()=>{void sink.abort();},{once:true});let reader;
  try{const record=await this.transport.call('/files/'+file_version_id+'/manifest','GET',undefined,abort.signal);reader=await this.command('open',{group_id,file_version_id,record});ensure(offset+length<=Number(reader.plaintext_bytes),'INVALID_CHUNK_INDEX');
   for(let index=Math.floor(offset/CHUNK);length>0&&index<=Math.floor((offset+length-1)/CHUNK);index++){ensure(!abort.signal.aborted,'RESUME_REQUIRED');const ciphertext=await this.transport.call('/files/'+file_version_id+'/chunks/'+index,'GET',undefined,abort.signal),p=await this.command('range',{reader_id:reader.reader_id,index,ciphertext});try{await sink.write(p.plaintext.subarray(Math.max(0,offset-index*CHUNK),Math.min(p.plaintext.length,offset+length-index*CHUNK)));}finally{p.plaintext.fill(0);ciphertext.fill(0);}}
   await sink.finish();return {verified_range:{offset,length},file_complete:false};
  }catch(e){await sink.abort();throw e;}finally{if(reader)await this.command('close',{reader_id:reader.reader_id}).catch(()=>{});this.#active.delete(abort);}
 }
}
