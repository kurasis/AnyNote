import {FilesClient} from '../files/client.mjs';
import {envelopeDigest} from '../adapters/codecs/codec.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {AuthClient,boundedResponse} from '../auth-client.mjs';
import {strictJson} from '../src/strict-json.mjs';
import {syncValue,syncHash} from './codec.mjs';
import {ensure} from '../vault/store.mjs';

// Closed transport. Independent identity, signature and transaction checks live in custody.
export class SyncClient {
 #csrf;
 constructor(auth){ensure(auth instanceof AuthClient,'AUTH_CLIENT_REQUIRED');this.auth=auth;}
 async call(path,requestKind,responseKind,body,method=requestKind?'POST':'GET'){
  ensure(/^\/(?:sync(?:\/ack)?|snapshots(?:\/[A-Za-z0-9_-]{22}(?:\/(?:pages|catalog|renew)|\/revisions\/[A-Za-z0-9_-]{22})?)?)(?:\?(?:[a-z]+=[A-Za-z0-9_-]+)(?:&[a-z]+=[A-Za-z0-9_-]+)*)?$/.test(path),'INVALID_SYNC_PATH');
  if(requestKind)syncValue(requestKind,body);const write=method!=='GET';if(write)this.#csrf??=(await this.auth.csrf()).csrf_token;
  const response=await this.auth.fetcher(this.auth.issuer+'/api/v1'+path,{method,credentials:'include',cache:'no-store',redirect:'error',headers:{Accept:'application/json',...(write?{'X-CSRF-TOKEN':this.#csrf}:{}),...(requestKind?{'Content-Type':'application/json'}:{})},...(requestKind?{body:JSON.stringify(body)}:{})});
  const limit=response.ok?(responseKind==='snapshot-bundle'?4194304:1048576):4096,value=strictJson(await boundedResponse(response,limit),limit);
  if(!response.ok){this.#csrf=undefined;throw Object.assign(Error(value.error?.code??'SYNC_DENIED'),{status:response.status});}
  syncValue(responseKind,value);
  const parts=path.split('?')[0].split('/');
  if(parts[1]==='snapshots'&&parts[2])ensure((value.snapshot_id??value.descriptor?.snapshot_id??value.page?.snapshot_id)===parts[2],'CONTEXT_MISMATCH');
  if(parts[4])ensure(value.item?.revision_id===parts[4],'CONTEXT_MISMATCH');
  if(requestKind==='snapshot-request')ensure(value.scope.group_id===body.group_id,'CONTEXT_MISMATCH');
  if(requestKind==='ack-request')ensure(value.cursor.generation===body.cursor.generation&&value.cursor.sequence===body.cursor.sequence,'CONTEXT_MISMATCH');
  return value;
 }
}
const id=()=>{const b=crypto.getRandomValues(new Uint8Array(16));return btoa(String.fromCharCode(...b)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');};
export class Synchronizer {
 #running;
 constructor({transport,vault,notes,authorize,group,active=()=>true}){Object.assign(this,{transport,vault,notes,authorize,group,active});}
 command(op,x={}){ensure(this.active(),'SYNC_PAUSED');return this.vault.notes('sync',[op,x]);}
 catchUp(){if(this.#running)return this.#running;this.#running=this.#catchUp().catch(async e=>{if(['SYNC_CURSOR_EXPIRED','POLICY_CHANGED','ROSTER_CHANGED','REKEY_REQUIRED','HISTORY_CLOSURE_REQUIRED','NOT_FOUND','ACCESS_REVOKED'].includes(e.message)){await this.#abandonStage();return this.snapshot();}if(['CIPHERTEXT_MISMATCH','INVALID_SIGNATURE','CONTEXT_MISMATCH','ROOT_PIN_MISMATCH','SYNC_GAP','INVALID_SYNC_DTO','RESTORE_QUARANTINE'].includes(e.message))await this.command('quarantine',{state:e.message==='RESTORE_QUARANTINE'?'RESTORE_QUARANTINE':'QUARANTINED',digest:syncHash({code:e.message})});throw e;}).finally(()=>{this.#running=undefined;});return this.#running;}
 async #abandonStage(){const s=await this.command('status');if(s.stage){try{await this.transport.call('/snapshots/'+s.stage.result.descriptor.snapshot_id,'','cancel-result',undefined,'DELETE');}catch(e){if(!['NOT_FOUND','SYNC_CURSOR_EXPIRED','SESSION_EXPIRED','DEVICE_REVOKED','AUTH_REQUIRED'].includes(e.message))throw e;}}await this.command('deltaCancel');await this.command('snapshotCancel');}
 async snapshot(){
  let s=await this.command('status');ensure(s.state!=='RESTORE_QUARANTINE','RESTORE_QUARANTINE');
  if(!s.stage){const result=await this.transport.call('/snapshots','snapshot-request','snapshot-result',{version:1,operation_id:id(),purpose:'resync',group_id:s.scope.group_id});s=await this.command('snapshotStart',result);}
  const d=s.stage.result.descriptor,path='/snapshots/'+d.snapshot_id;
  try{
   // Restarting an interrupted lease resumes exact pages/items; duplicates are verified.
   for(let start=Number(s.stage.catalog_next);start<Number(s.stage.result.catalog_count);){const page=await this.transport.call(path+'/catalog?start='+start,null,'catalog-page');for(const g of page.groups)await this.group(g.group_id,g);s=await this.command('catalog',page);if(page.next===null)break;start=Number(page.next);}
   if(s.stage.result.catalog_count==='0')s=await this.command('catalog',await this.transport.call(path+'/catalog',null,'catalog-page'));
   if(s.stage.result.files){
    const transport=new FilesClient(this.notes.auth),inventory=[];let start=0;
    do{const page=await transport.call(path+'/files?start='+start);ensure(page.snapshot_id===d.snapshot_id&&page.start===String(start)&&Array.isArray(page.items),'SYNC_GAP');for(const record of page.items){const c=record.envelope.header.context;await this.vault.notes('files',['observe',{group_id:c.group_id,file_version_id:c.file_version_id,record}]);inventory.push({group_id:c.group_id,file_id:c.file_id,file_version_id:c.file_version_id,envelope_digest:envelopeDigest(wire(record.envelope))});}if(page.next===null)break;ensure(Number(page.next)===start+page.items.length&&page.items.length>0,'SYNC_GAP');start=Number(page.next);}while(start<1000);
    s=await this.command('snapshotFiles',{inventory});
   }
   // A page may have been committed before its bodies. Replay already saved pages
   // for item recovery without re-appending their inventory receipts.
   for(let n=0;n<Number(d.page_count);n++){const page=await this.transport.call(path+'/pages?index='+n,null,'snapshot-page-result');if(n>=s.stage.pages)s=await this.command('snapshotPage',page);for(const item of page.page.items)await this.command('snapshotItem',await this.transport.call(path+'/revisions/'+item.revision_id,null,'snapshot-bundle'));}
   s=await this.command('snapshotFinish');await this.transport.call(path,'','cancel-result',undefined,'DELETE');return s;
  }catch(e){if(['SYNC_CURSOR_EXPIRED','POLICY_CHANGED','ROSTER_CHANGED','REKEY_REQUIRED','HISTORY_CLOSURE_REQUIRED','NOT_FOUND','ACCESS_REVOKED'].includes(e.message)){await this.#abandonStage();}throw e;}
 }
 async #catchUp(){
  await this.authorize();let s=await this.command('status');ensure(s.state!=='RESTORE_QUARANTINE','RESTORE_QUARANTINE');ensure(s.state!=='QUARANTINED','SYNC_QUARANTINE');
  if(!s.cursor||s.stage)s=await this.snapshot();
  for(let pages=0;pages<100;pages++){
   const c=s.cursor,page=s.pending??await this.transport.call('/sync?generation='+c.generation+'&sequence='+c.sequence+(s.scope.group_id?'&group='+s.scope.group_id:''),null,'delta-page');
   // Security changes refresh the actual signed authority then take a consistent
   // snapshot. No unsigned hint is treated as an authorization instruction.
   if(page.events.some(e=>e.revision_id===null||e.kind==='file')){if(s.pending)await this.command('deltaCancel');s=await this.snapshot();continue;}
   if(!s.pending)await this.command('deltaStart',page);
   for(const event of page.events){await this.group(event.group_id);const state=await this.notes.call('/objects/'+event.object_id,null,'object-state'),result=await this.notes.call('/objects/'+event.object_id+'/revisions/'+event.revision_id,null,'bundle-result'),c=result.bundle.envelope.header.context;
    await this.command('deltaItem',{version:1,item:{group_id:event.group_id,object_id:event.object_id,object_kind:c.object_kind,revision_id:event.revision_id,envelope_digest:event.digest,payload_status:c.action==='soft-delete'?'tombstone':'retained'},reference:state.object,bundle:result.bundle});
   }
   s=await this.command('deltaFinish');await this.transport.call('/sync/ack','ack-request','ack-result',{version:1,cursor:s.cursor,group_id:s.scope.group_id});if(page.complete)return s;
  }
  // Bounded work yields to the visible host, which schedules another catch-up.
  return {...s,catch_up_pending:true};
 }
}

export class VisiblePoller {
 #timer;#running=false;#backoff=0;#stopped=true;
 constructor({catchUp,onError,visible=()=>!document.hidden,online=()=>navigator.onLine,random=Math.random,setTimer=(fn,ms)=>globalThis.setTimeout(fn,ms),clearTimer=id=>globalThis.clearTimeout(id)}){Object.assign(this,{catchUp,onError,visible,online,random,setTimer,clearTimer});}
 start(){this.#stopped=false;this.resume();}
 stop(){this.#stopped=true;this.clearTimer(this.#timer);}
 resume(){this.clearTimer(this.#timer);if(!this.#stopped&&this.visible()&&this.online())this.#timer=this.setTimer(()=>this.#tick(),0);}
 async #tick(){if(this.#stopped||this.#running||!this.visible()||!this.online())return;this.#running=true;
  try{await this.catchUp();this.#backoff=0;}catch(e){if(e.message==='SYNC_PAUSED'){this.#backoff=0;}else{this.#backoff=this.#backoff?Math.min(60000,this.#backoff*2):15000;this.onError(e);}}
  finally{this.#running=false;if(!this.#stopped&&this.visible()&&this.online()){const base=this.#backoff||5000,delay=Math.min(60000,base+Math.floor(this.random()*Math.min(1000,base/10)));this.#timer=this.setTimer(()=>this.#tick(),delay);}}
 }
}
