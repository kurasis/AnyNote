import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,phrase} from '../notes/test-fixture.mjs';
import {VaultEngine} from '../vault/engine.mjs';
import {FileReader} from '../adapters/files.mjs';
import {un64,hash} from '../adapters/primitives.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {envelopeDigest} from '../adapters/codecs/codec.mjs';
import {CHUNK} from './workflow.mjs';
import {safeFilename} from './client.mjs';
import {groupCodecForProfile} from '../adapters/codecs/group-codec.mjs';
const gc=groupCodecForProfile('p02-group-c2');
async function setup(){const f=await fixture(),v=f.old;const made=await v.engine.notes(v.cap,'prepareGroup'),p=made.request.commit.body,group={version:1,group_id:made.group_id,kind:'private',owner_account_id:f.pins.account_id,state:'active',settings:false,membership:{version:'0',digest:p.intent.body.membership.digest},key_epoch:'0',epoch_digest:gc.groupDigest('epoch-intent',wire(made.request.commit.body.intent)),history_checkpoint_digest:null,rekey_required:false,history_closure_required:false,restore_quarantined:false,genesis:{...made.request,group_id:made.group_id}};await v.engine.notes(v.cap,'group',[group]);return {f,v,group,call:(op,x={})=>v.engine.notes(v.cap,'files',[op,x])};}
test('immutable source commitments survive lock/reopen and reject changed bytes before nonce reuse',async()=>{
 const {v,group,call}=await setup(),bytes=new Uint8Array(CHUNK+1);crypto.getRandomValues(bytes.subarray(0,65536));const blob=new Blob([bytes]),made=await call('prepare',{group_id:group.group_id,source:blob,name:'SECRET-P12-NAME.txt'}),p=await call('part',{draft_id:made.draft_id,source:blob,index:0});assert.equal(p.ciphertext.length,CHUNK+16);
 const stored=JSON.stringify([...v.store.rows.values()]);assert(!stored.includes('SECRET-P12-NAME'));assert(!stored.includes('source_digest'));assert.equal(v.store.state.file_profile,'p12-files-v1');
 const wrong=new Blob([new Uint8Array(CHUNK+1)]);await assert.rejects(call('part',{draft_id:made.draft_id,source:wrong,index:0}),/SOURCE_CHANGED/);await v.engine.globalLock();v.engine=new VaultEngine(v.store);v.cap=(await v.engine.unlock(phrase)).capability;
 const retry=await v.engine.notes(v.cap,'files',['part',{draft_id:made.draft_id,source:blob,index:0}]);assert.deepEqual(retry.ciphertext,p.ciphertext);assert.equal((await v.engine.notes(v.cap,'files',['list',{}]))[0].draft_id,made.draft_id);
});
test('durable storage failure and oversized sources cannot expose a partial prepared publication',async()=>{
 const {v,group,call}=await setup();v.store.failAfter=0;await assert.rejects(call('prepare',{group_id:group.group_id,source:new Blob(['secret'])}),/INSUFFICIENT_STORAGE/);v.store.failAfter=Infinity;assert.equal((await call('list')).length,0);await assert.rejects(call('prepare',{group_id:group.group_id,source:{size:1000000001}}),/RESOURCE_LIMIT/);
});
test('manifest commit receipt is bound and quota acknowledgement loss retains unattached encrypted intent',async()=>{
 const {v,group,call}=await setup(),source=new Blob(['public synthetic random bytes']),made=await call('prepare',{group_id:group.group_id,source}),part=await call('part',{draft_id:made.draft_id,source,index:0});await call('ackPart',{draft_id:made.draft_id,part:{index:'0',ciphertext_bytes:String(part.ciphertext.length),ciphertext_digest:hash(part.ciphertext)}});const finished=await call('finish',{draft_id:made.draft_id});assert.deepEqual(await call('finish',{draft_id:made.draft_id}),finished);
 const c=finished.request.record.envelope.header.context,receipt={version:1,state:'COMMITTED',upload_id:finished.upload_id,group_id:c.group_id,file_id:c.file_id,file_version_id:c.file_version_id,operation_id:c.operation_id,envelope_digest:envelopeDigest(wire(finished.request.record.envelope)),ciphertext_bytes:'1000',cursor:{generation:c.operation_id,sequence:'1'}};
 await assert.rejects(call('committed',{draft_id:made.draft_id,receipt:{...receipt,file_version_id:c.operation_id}}),/CIPHERTEXT_MISMATCH/);const saved=await call('committed',{draft_id:made.draft_id,receipt});assert.equal(saved.state,'UNATTACHED');assert.deepEqual((await call('committed',{draft_id:made.draft_id,receipt})).attachment,saved.attachment);
 const opened=await call('open',{group_id:c.group_id,file_version_id:c.file_version_id,record:finished.request.record});const p=await call('decrypt',{reader_id:opened.reader_id,ciphertext:part.ciphertext});assert.equal(new TextDecoder().decode(p.plaintext),'public synthetic random bytes');assert.equal((await call('complete',{reader_id:opened.reader_id})).complete,true);
});
test('the signed file profile cannot be stripped to reopen a legacy local manifest',async()=>{
 const {v,group,call}=await setup();await call('prepare',{group_id:group.group_id,source:new Blob(['profile'])});assert.equal(v.store.state.manifest.body.file_profile,'p12-files-v1');v.engine.lock();delete v.store.state.file_profile;const before=structuredClone(v.store.rows);v.engine=new VaultEngine(v.store);await assert.rejects(v.engine.unlock(phrase),/INTEGRITY_FAILURE/);assert.deepEqual(v.store.rows,before);
});
test('independent authenticated range never certifies a complete export and rejects corrupt/truncated parts',async()=>{
 const {group,call}=await setup(),source=new Blob(['range data']),made=await call('prepare',{group_id:group.group_id,source}),part=await call('part',{draft_id:made.draft_id,source,index:0});await call('ackPart',{draft_id:made.draft_id,part:{index:'0',ciphertext_bytes:String(part.ciphertext.length),ciphertext_digest:hash(part.ciphertext)}});const finished=await call('finish',{draft_id:made.draft_id}),record=finished.request.record;
 const opened=await call('open',{group_id:group.group_id,file_version_id:record.envelope.header.context.file_version_id,record}),range=await call('range',{reader_id:opened.reader_id,index:0,ciphertext:part.ciphertext});assert.equal(new TextDecoder().decode(range.plaintext),'range data');assert.equal(range.file_complete,false);await assert.rejects(call('complete',{reader_id:opened.reader_id}),/INCOMPLETE_FILE/);
 const another=await call('open',{group_id:group.group_id,file_version_id:record.envelope.header.context.file_version_id,record});await assert.rejects(call('range',{reader_id:another.reader_id,index:0,ciphertext:part.ciphertext.subarray(1)}),/CHUNK_DIGEST_MISMATCH/);
});
test('export names cannot form paths, alternate data streams or Windows device names',()=>{
 for(const name of ['CON','con.txt','LPT1.log','NUL','COM9'])assert.match(safeFilename(name),/^_/);for(const name of ['../a.html','..\\..\\a.exe','x:y','<script>'])assert(!/[<>:"/\\|?*]/.test(safeFilename(name)));assert.equal(safeFilename('CON .txt'),'CON_.txt');
});
