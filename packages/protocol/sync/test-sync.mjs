import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,phrase} from '../notes/test-fixture.mjs';
import {VaultEngine} from '../vault/engine.mjs';
import {common,digest} from '../adapters/codecs/protocol-codec.mjs';
import {groupCodecForProfile} from '../adapters/codecs/group-codec.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {sodium,b64} from '../adapters/primitives.mjs';
import {pageReceipt,snapshotCommitment,catalogCommitment,checkedDelta} from './codec.mjs';
import {preparePaged,readPaged,rotatePagedFrame} from './paged-local.mjs';
const id=()=>b64(sodium.randombytes_buf(16)),notes=(f,op,args=[])=>f.old.engine.notes(f.old.cap,op,structuredClone(args)),sync=(f,op,x={})=>notes(f,'sync',[op,x]);
const gc=groupCodecForProfile('p02-group-c2');
async function scenario(){
 const f=await fixture(),made=await notes(f,'prepareGroup'),g=made.group_id,genesis={...made.request,group_id:g};
 const status={version:1,group_id:g,kind:'private',owner_account_id:f.pins.account_id,state:'active',membership:made.request.commit.body.intent.body.membership,key_epoch:'0',epoch_digest:gc.groupDigest('epoch-intent',wire(made.request.commit.body.intent)),history_checkpoint_digest:null,rekey_required:false,history_closure_required:false,restore_quarantined:false,settings:false,genesis};await notes(f,'group',[status]);
 const values=[];for(let i=0;i<2;i++){
  const draft=await notes(f,'save',[{draft_id:null,group_id:g,object_id:null,object_kind:'thread',thread_id:null,action:'create',parents:[],archived:false,content:{title:'P11 secret title '+i,markdown:'',metadata_kind:'content',tags:[],checklist:[],summary_entry_id:null,preferences:[]}}]),queued=await notes(f,'queue',[draft.draft_id]),sent=await notes(f,'send',[queued.attempt_id]),bundle=sent.request.bundle,c=bundle.envelope.header.context,hash=digest('envelope',wire(bundle.envelope));
  values.push({version:1,item:{group_id:g,object_kind:'thread',object_id:c.object_id,revision_id:c.revision_id,envelope_digest:hash,payload_status:'retained'},bundle,reference:{object_id:c.object_id,object_kind:'thread',thread_id:null,archived:false,tombstoned:false,created_sequence:String(i+1),updated_sequence:String(i+1),heads:[{revision_id:c.revision_id,envelope_digest:hash}]}});
 }
 values.sort((a,b)=>a.item.object_id<b.item.object_id?-1:1);const snapshot_id=id(),page={...common('snapshot-page'),snapshot_id,page_index:'0',items:values.map(v=>v.item)},scope={...f.pins,group_id:g},cursor={generation:id(),sequence:'2'},result={version:1,scope,descriptor:{...common('snapshot-descriptor'),snapshot_id,account_id:f.pins.account_id,device_id:f.old.scope.device_id,snapshot_purpose:'resync',watermark:cursor,created_at:String(Date.now()),expires_at:String(Date.now()+1800000),page_count:'1',item_count:'2',inventory_digest:snapshotCommitment([pageReceipt(page)])},catalog_count:'1',catalog_digest:catalogCommitment([status])};
 return {...f,values:values.map(v=>({...v,snapshot_id})),page,result,status,cursor};
}
async function close(f){f.initial.dispose();await f.old.engine.close();await f.fresh.engine.close();sodium.memzero(f.keys.signing.privateKey);sodium.memzero(f.keys.encryption.privateKey);}
async function stage(f){await sync(f,'snapshotStart',f.result);await sync(f,'catalog',{version:1,snapshot_id:f.result.descriptor.snapshot_id,start:'0',groups:[f.status],next:null});await sync(f,'snapshotPage',{version:1,scope:f.result.scope,page:f.page});}
test('partial snapshot is encrypted, survives restart, preserves outbox and publishes only after complete atomic apply',async()=>{
 const f=await scenario();try{
  await stage(f);await sync(f,'snapshotItem',f.values[0]);assert.equal((await notes(f,'summary')).witnessed,0);assert.equal((await sync(f,'status')).cursor,null);
  await assert.rejects(()=>sync(f,'snapshotFinish'),/SYNC_GAP/);await f.old.engine.globalLock();f.old.engine=new VaultEngine(f.old.store);f.old.cap=(await f.old.engine.unlock(phrase)).capability;
  await sync(f,'snapshotItem',f.values[1]);const before=structuredClone(f.old.store.rows);f.old.store.failAfter=1;await assert.rejects(()=>sync(f,'snapshotFinish'),/INSUFFICIENT_STORAGE/);assert.deepEqual(f.old.store.rows,before);assert.equal((await sync(f,'status')).cursor,null);f.old.store.failAfter=Infinity;
  const done=await sync(f,'snapshotFinish');assert.deepEqual(done.cursor,f.cursor);assert.equal(done.projection.length,2);const summary=await notes(f,'summary');assert.equal(summary.witnessed,2);assert.equal(summary.drafts.length,2);assert.equal(summary.drafts[0].state,'SENT_UNKNOWN');assert(!JSON.stringify([...f.old.store.rows]).includes('P11 secret title'));
 }finally{await close(f);}
});
test('malformed inventory, forged content and changed root cannot advance the durable cursor',async()=>{
 const f=await scenario();try{
  await stage(f);const forged=structuredClone(f.values[0]);forged.bundle.envelope.signature=b64(sodium.randombytes_buf(64));forged.item.envelope_digest=digest('envelope',wire(forged.bundle.envelope));await assert.rejects(()=>sync(f,'snapshotItem',forged),/CONTEXT_MISMATCH/);
  const bad=structuredClone(f.values[0]);bad.bundle.ciphertext=b64(sodium.randombytes_buf(32));await assert.rejects(()=>sync(f,'snapshotItem',bad),/CIPHERTEXT_MISMATCH/);assert.equal((await sync(f,'status')).cursor,null);
  await sync(f,'snapshotItem',f.values[0]);await sync(f,'snapshotItem',f.values[1]);await sync(f,'snapshotFinish');const root=structuredClone(f.result);root.scope.root_fingerprint=b64(sodium.randombytes_buf(32));await assert.rejects(()=>sync(f,'snapshotStart',root),/ROOT_PIN_MISMATCH/);
  const rollback=structuredClone(f.result);rollback.descriptor.watermark.sequence='1';assert.equal((await sync(f,'snapshotStart',rollback)).state,'RESTORE_QUARANTINE');assert.deepEqual((await sync(f,'status')).cursor,f.cursor);await assert.rejects(()=>sync(f,'snapshotStart',f.result),/RESTORE_QUARANTINE/);
 }finally{await close(f);}
});
test('filtered ranges count hidden scanned events and reject gaps, duplicate hints and scope substitution',()=>{
 const pins={service_id:id(),account_id:id(),root_fingerprint:b64(sodium.randombytes_buf(32))},group=id(),cursor={generation:id(),sequence:'5'},page={version:1,scope:{...pins,group_id:group},from_cursor:cursor,next_cursor:{...cursor,sequence:'8'},watermark:{...cursor,sequence:'9'},scanned_count:'3',events:[],complete:false};assert.equal(checkedDelta(page,cursor,pins,group),page);
 for(const changed of [{scanned_count:'2'},{complete:true},{scope:{...page.scope,account_id:id()}},{next_cursor:{...cursor,sequence:'10'}},{next_cursor:{...cursor,generation:id()}}])assert.throws(()=>checkedDelta({...page,...changed},cursor,pins,group));
});
test('paged public proof exceeds the old frame limit, binds every part, rotates L and retains private candidate only in the root',async()=>{
 const scope={service_id:id(),account_id:id(),device_id:id(),profile_id:id()},pins={service_id:scope.service_id,account_id:scope.account_id,root_fingerprint:b64(sodium.randombytes_buf(32))},key=sodium.randombytes_buf(32),next=sodium.randombytes_buf(32),root=id(),candidate={service_id:scope.service_id,group_id:id(),key_epoch:'1',epoch_digest:b64(sodium.randombytes_buf(32)),group_secret:b64(sodium.randombytes_buf(32))},data={proof:{text:'x'.repeat(700000)},pending_key:candidate};
 try{const prepared=preparePaged(scope,pins,root,'group-evidence',data,key),rows=new Map(prepared.records.map(r=>[r.id,r]));assert.equal(prepared.records.length,3);assert.deepEqual(await readPaged(prepared.frame,scope,pins,root,'group-evidence',key,async id=>rows.get(id)),data);assert(!JSON.stringify(prepared).includes(candidate.group_secret));
  const rotated=rotatePagedFrame(prepared.frame,scope,pins,root,key,next);for(const r of rows.values())r.frame=rotatePagedFrame(r.frame,scope,pins,r.id,key,next);assert.deepEqual(await readPaged(rotated,scope,pins,root,'group-evidence',next,async id=>rows.get(id)),data);const missing=[...rows.keys()][1];rows.delete(missing);await assert.rejects(()=>readPaged(rotated,scope,pins,root,'group-evidence',next,async id=>rows.get(id)),/RECORD_NOT_FOUND/);
 }finally{sodium.memzero(key);sodium.memzero(next);}
});
