import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture, phrase} from '../notes/test-fixture.mjs';
import {VaultEngine} from '../vault/engine.mjs';
import {common, digest} from '../adapters/codecs/protocol-codec.mjs';
import {groupCodecForProfile} from '../adapters/codecs/group-codec.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {contentControlId} from './local.mjs';
import {tokens, indexDocument} from './search.mjs';
const gc=groupCodecForProfile('p02-group-c2');
const notes=(f,op,args=[])=>f.old.engine.notes(f.old.cap,op,args);
const content=(f,op,x={})=>notes(f,'content',[op,x]);
async function group(f){const g=await notes(f,'prepareGroup');const {version,commit,pages}=g.request;await notes(f,'group',[{version,group_id:g.group_id,kind:'private',owner_account_id:f.pins.account_id,state:'active',membership:{version:'0',digest:commit.body.intent.body.membership.digest},key_epoch:'0',epoch_digest:gc.groupDigest('epoch-intent',wire(commit.body.intent)),history_checkpoint_digest:null,rekey_required:false,history_closure_required:false,restore_quarantined:false,settings:false,genesis:{version,group_id:g.group_id,commit,pages}}]);return g;}
async function publish(f,g,title){const saved=await notes(f,'save',[{draft_id:null,group_id:g.group_id,object_id:null,object_kind:'thread',thread_id:null,action:'create',parents:[],archived:false,content:{title,markdown:'',metadata_kind:'content',tags:[],checklist:[],summary_entry_id:null,preferences:[]}}]);const a=await notes(f,'queue',[saved.draft_id]),sent=await notes(f,'send',[a.attempt_id]),c=sent.request.bundle.envelope.header.context,ed=digest('envelope',wire(sent.request.bundle.envelope));await notes(f,'ack',[a.attempt_id,{receipt:{...common('mutation-receipt'),operation_id:c.operation_id,revision_id:c.revision_id,envelope_digest:ed,status:'COMMITTED',cursor:{generation:c.service_id,sequence:'1'}},heads:[{revision_id:c.revision_id,envelope_digest:ed}]}]);return c.revision_id;}
async function close(f){f.initial.dispose();await f.old.engine.close();await f.fresh.engine.close();}

test('real verified local search persists encrypted, survives restart, and refuses generic eviction',async()=>{
 const f=await fixture();try{const g=await group(f),revision=await publish(f,g,'P13 Секретная заметка Unicode');
  assert.equal((await content(f,'coverage')).not_indexed,1);
  assert.equal((await content(f,'index',{revision_ids:[revision]})).indexed,1);
  const result=await content(f,'search',{query:'секретная Unicode'});assert.equal(result.results.length,1);assert.equal(result.coverage.indexed,1);
  const disk=JSON.stringify({state:f.old.store.state,rows:[...f.old.store.rows.values()]});assert(!disk.includes('Секретная'));assert(!disk.includes('секретная'));
  assert.equal(f.old.store.state.content_profile,'p13-content-v1');
  const fence=await f.old.engine.lease(f.old.cap);
  for(const row of f.old.store.rows.values())if(row.frame.contract==='p13-content-v1')await assert.rejects(()=>f.old.engine.evict(f.old.cap,fence,row.id),/RESERVED_RECORD/);
  await f.old.engine.globalLock();await assert.rejects(()=>content(f,'search',{query:'Unicode'}),/VAULT_LOCKED/);
  f.old.engine=new VaultEngine(f.old.store);f.old.cap=(await f.old.engine.unlock(phrase)).capability;
  assert.equal((await content(f,'search',{query:'Unicode'})).results.length,1);
 }finally{await close(f);}
});
test('new source content requires an explicit complete rebuild rather than false no-match coverage',async()=>{
 const f=await fixture();try{const g=await group(f),first=await publish(f,g,'P13 original indexed title');await content(f,'index',{revision_ids:[first]});
  const second=await publish(f,g,'P13 later unindexed title');const stale=await content(f,'search',{query:'original'});assert.equal(stale.rebuild_required,true);assert.equal(stale.coverage.indexed,0);assert.equal(stale.coverage.stale,1);
  await assert.rejects(()=>content(f,'index',{revision_ids:[second]}),/INDEX_REBUILD_REQUIRED/);
  await assert.rejects(()=>content(f,'clearIndex',{confirm:false}),/CONFIRMATION_REQUIRED/);
  await content(f,'clearIndex',{confirm:true});await content(f,'index',{revision_ids:[first,second]});assert.equal((await content(f,'coverage')).indexed,2);
  assert.equal((await content(f,'search',{query:'later',group_id:g.group_id})).results.length,1);
 }finally{await close(f);}
});
test('failed protected index transaction retains old state and a stripped signed profile cannot unlock',async()=>{
 const f=await fixture();try{const g=await group(f),revision=await publish(f,g,'P13 atomic index source');const before=structuredClone(f.old.store.rows),meta=structuredClone(f.old.store.state);
  f.old.store.failAfter=1;await assert.rejects(()=>content(f,'index',{revision_ids:[revision]}),/INSUFFICIENT_STORAGE/);assert.deepEqual(f.old.store.rows,before);assert.equal(f.old.store.state.content_profile,meta.content_profile);
  f.old.store.failAfter=Infinity;await content(f,'index',{revision_ids:[revision]});assert(f.old.store.rows.has(contentControlId(f.old.scope)));
  await f.old.engine.globalLock();delete f.old.store.state.content_profile;await assert.rejects(()=>f.old.engine.unlock(phrase),/INTEGRITY_FAILURE/);
 }finally{await close(f);}
});
test('Unicode token bounds disclose truncation without treating repeated words as lost coverage',()=>{
 assert.deepEqual(tokens('Привет ПРИВЕТ hello ＨＥＬＬＯ'),['привет','hello']);
 const context={object_kind:'entry',group_id:'group',object_id:'entry',revision_id:'revision',thread_id:'thread',action:'create'};
 assert.equal(indexDocument(context,{title:'same same',markdown:''},'digest').token_coverage,'complete');
 assert.equal(indexDocument(context,{title:'x'.repeat(65),markdown:''},'digest').token_coverage,'bounded');
});
