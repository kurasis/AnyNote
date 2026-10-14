// Protected import journal and bounded recovery channel. No live mutation before
// complete archive validation; original history remains provenance, not live authorship.
import {PortableReader} from './portable.mjs';
import {sodium,b64,hash} from '../adapters/primitives.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {canonicalBytes} from '../adapters/core.mjs';
import {ensure,id} from '../vault/store.mjs';
const random=()=>b64(sodium.randombytes_buf(16));
function clear(value){if(value instanceof Uint8Array)value.fill(0);else if(value&&typeof value==='object')for(const key of Object.keys(value)){clear(value[key]);if(typeof value[key]==='string')value[key]='';}}
class RecoveryChannel{
 #pending;#waiter;#resume;#error;#done=false;#closed=false;#work;
 constructor(reader){this.reader=reader;}
 #offer(event){ensure(!this.#closed&&!this.#pending,'IMPORT_CANCELLED');return new Promise((resolve,reject)=>{this.#pending=event;this.#resume={resolve,reject};this.#waiter?.();this.#waiter=undefined;});}
 async next(){
  if(this.#pending){clear(this.#pending);this.#pending=undefined;this.#resume?.resolve();this.#resume=undefined;}
  if(!this.#work)this.#work=this.reader.recover({fileStart:(revision,context,metadata)=>this.#offer({kind:'file-start',revision,context,metadata}),filePart:(revision,index,bytes)=>this.#offer({kind:'file-part',revision,index,bytes}),fileFinish:revision=>this.#offer({kind:'file-finish',revision}),note:(revision,payload)=>this.#offer({kind:'note',revision,payload})}).then(()=>{this.#done=true;this.#waiter?.();},e=>{this.#error=e;this.#done=true;this.#waiter?.();});
  while(!this.#pending&&!this.#done)await new Promise(resolve=>this.#waiter=resolve);
  if(this.#error)throw this.#error;return this.#done?{kind:'done'}:this.#pending;
 }
 close(){this.#closed=true;this.#resume?.reject(Error('IMPORT_CANCELLED'));this.#resume=undefined;clear(this.#pending);this.#pending=undefined;this.reader.close();this.#done=true;this.#error=Error('IMPORT_CANCELLED');this.#waiter?.();}
}
export class ProtectedImport{
 #reader;#channel;#state;#pending;#heldEvent;#closed=false;
 constructor({jobs,scope,destination,apply}){Object.assign(this,{jobs,scope,destination,apply});}
 async begin({source,kit,import_id,destination_group}){
  ensure(source instanceof Blob&&source.size<=1100000000,'RESOURCE_LIMIT');ensure(import_id===undefined||id(import_id),'INVALID_CONTENT_COMMAND');
  const reader=new PortableReader(()=>source.stream(),kit);let accepted=false;
  try{const report=await reader.validate();
   this.#reader=reader;this.#channel=new RecoveryChannel(reader);let state;if(import_id)state=await this.jobs.job(import_id,'import-state');const context=await this.destination(state?.destination.group_id),audience_digest=hash(canonicalBytes(wire(context)));
   if(import_id){ensure(destination_group===undefined||destination_group===state.destination.group_id,'IDEMPOTENCY_MISMATCH');ensure(state.purpose==='p13-import-job'&&state.version===1&&state.archive_sha256===kit.archive_sha256&&state.export_id===kit.export_id&&state.destination.group_id===context.group_id,'IDEMPOTENCY_MISMATCH');ensure(!['COMPLETE','CANCELLED'].includes(state.state),'IMPORT_FINISHED');state.state='READY';}
   else state={purpose:'p13-import-job',version:1,import_id:random(),archive_sha256:kit.archive_sha256,export_id:kit.export_id,kit:structuredClone(kit),destination:context,audience_digest,state:'READY',files:[],notes:[],threads:[],published:0,pending:null};
   // A standard import copies retained tips. Full old signed history stays in the
   // independently verifiable original archive; it does not become live history.
   const parents=new Set(report.notes.flatMap(n=>n.context.parents.map(p=>p.revision_id))),tips=report.notes.filter(n=>!parents.has(n.context.revision_id)&&n.payload_status==='retained'&&n.context.action!=='soft-delete');
   state.selected_notes=tips.map(n=>n.context.revision_id);state.unavailable=report.notes.filter(n=>n.payload_status==='pruned').length;state.source_scope=report.header.selection;
   this.#state=state;await this.jobs.saveJob(state.import_id,'import-state',state);accepted=true;
   return {import_id:state.import_id,state:'READY',preview:{source_root:report.header.root_fingerprint,source_service:report.header.service_id,source_export_id:report.header.export_id,source_scope:report.header.selection,destination:context,notes:tips.length,files:report.files.length,unavailable:state.unavailable,history:'original-archive-provenance-only'},audience_digest,live_destination_mutations:0};
  }finally{if(!accepted)reader.close();}
 }
 async confirm(digest){ensure(this.#state&&!this.#closed&&digest===this.#state.audience_digest,'COPY_CONFIRMATION_REQUIRED');const now=await this.destination(this.#state.destination.group_id);ensure(same(now,this.#state.destination),'COPY_CONFIRMATION_REQUIRED');this.#state.state='IMPORTING';await this.jobs.saveJob(this.#state.import_id,'import-state',this.#state);return {state:'IMPORTING'};}
 async next(response){
  ensure(this.#state?.state==='IMPORTING'&&!this.#closed,'IMPORT_CONFIRMATION_REQUIRED');ensure(same(await this.destination(this.#state.destination.group_id),this.#state.destination),'COPY_CONFIRMATION_REQUIRED');
  if(this.#pending){ensure(response,'IMPORT_RECEIPT_REQUIRED');await this.apply('response',{state:this.#state,pending:this.#pending,response});this.#pending=undefined;await this.jobs.saveJob(this.#state.import_id,'import-state',this.#state);}
  else ensure(response===undefined,'INVALID_CONTENT_COMMAND');
  if(this.#state.destination.group_id===null){const result=await this.apply('destination',{state:this.#state});ensure(result?.request,'INVALID_CONTENT_COMMAND');this.#pending=result;this.#state.pending=result;await this.jobs.saveJob(this.#state.import_id,'import-state',this.#state);return {state:'IMPORTING',import_id:this.#state.import_id,request:result.request,published:this.#state.published};}
  for(let count=0;count<100;count++){
   const event=this.#heldEvent??await this.#channel.next();this.#heldEvent=undefined;if(event.kind==='done'){
    const result=await this.apply('finish',{state:this.#state});if(result?.request){this.#pending=result;const {request,...metadata}=result;this.#state.pending={...metadata,request:{method:request.method,path:request.path,kind:request.kind}};await this.jobs.saveJob(this.#state.import_id,'import-state',this.#state);return {state:'IMPORTING',import_id:this.#state.import_id,request,published:this.#state.published};}
    this.#state.state='COMPLETE';await this.jobs.saveJob(this.#state.import_id,'import-state',this.#state);this.#reader.close();this.#closed=true;return {state:'COMPLETE',import_id:this.#state.import_id,published:this.#state.published,unavailable:this.#state.unavailable};}
   if(event.kind==='note'&&!this.#state.selected_notes.includes(event.revision))continue;
   const result=await this.apply('event',{state:this.#state,event,reader:this.#reader});if(result?.repeat)this.#heldEvent=event;await this.jobs.saveJob(this.#state.import_id,'import-state',this.#state);
   if(result?.request){this.#pending=result;const {request,...metadata}=result;this.#state.pending={...metadata,request:{method:request.method,path:request.path,kind:request.kind}};await this.jobs.saveJob(this.#state.import_id,'import-state',this.#state);return {state:'IMPORTING',import_id:this.#state.import_id,request:result.request,published:this.#state.published};}
  }return {state:'IMPORTING',import_id:this.#state.import_id,continue:true,published:this.#state.published};
 }
 async cancel(){ensure(this.#state,'IMPORT_NOT_STARTED');this.#state.state='PAUSED';await this.jobs.saveJob(this.#state.import_id,'import-state',this.#state);const report={cancelled:true,import_id:this.#state.import_id,published:this.#state.published,visible_files:this.#state.files.filter(f=>f.attachment).length,pending_work_preserved:true};this.close();return report;}
 close(){this.#closed=true;this.#channel?.close();this.#channel=undefined;this.#reader?.close();this.#reader=undefined;clear(this.#state);this.#state=undefined;}
}
