import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {VaultEngine} from './engine.mjs';
import {sodium,deviceKeys,b64,hash,randomKey,Buffer} from '../adapters/primitives.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {sealObject} from '../adapters/objects.mjs';
import {digest,decode} from '../adapters/codecs/protocol-codec.mjs';
const phrase='public synthetic purple harbor paper lantern';
const ident=()=>b64(sodium.randombytes_buf(16));
const draft=()=>JSON.parse(Buffer.from(readFileSync(new URL('../../../fixtures/protocol/p02/v1/bytes/draft-0000.hex',import.meta.url),'utf8').trim(),'hex').toString());
class Store {
 constructor(scope){this.scope=scope;this.state=undefined;this.rows=new Map();this.queue=Promise.resolve();this.failAfter=Infinity;}
 transaction(write,fn){const action=async()=>{let n=0;const rows=structuredClone(this.rows);let state=structuredClone(this.state);const result=await fn({get:async()=>structuredClone(state),set:async s=>{state=structuredClone(s);},read:async id=>structuredClone(rows.get(id)),put:async row=>{if(++n>this.failAfter)throw Error('INSUFFICIENT_STORAGE');rows.set(row.id,structuredClone(row));},count:async()=>rows.size,list:async()=>[...rows.keys()],remove:async id=>rows.delete(id),each:async fn=>{for(const row of rows.values())await fn(structuredClone(row));}});if(write){this.state=state;this.rows=rows;}return result;};const r=this.queue.then(action);this.queue=r.catch(()=>{});return r;}
 close(){}
}
async function fixture(){const sample=draft(),scope={service_id:sample.context.service_id,account_id:sample.context.author.account_id,device_id:sample.context.author.device_id,profile_id:ident()},store=new Store(scope),engine=new VaultEngine(store),keys=deviceKeys(),secrets={device_signing_secret:b64(keys.signing.privateKey),device_encryption_secret:b64(keys.encryption.privateKey),group_keys:[]},secretMarker=secrets.device_signing_secret,pins={service_id:scope.service_id,account_id:scope.account_id,root_fingerprint:hash(randomKey())};await engine.initialize(phrase,secrets,pins);const cap=(await engine.unlock(phrase)).capability;return {scope,store,engine,keys,secretMarker,pins,cap};}
const expect=(fn,code)=>assert.rejects(fn,e=>e.message===code);
test('atomic local draft/outbox, immutable publication and encrypted inspector',async()=>{
 const f=await fixture(),d=draft(),bundle=sealObject(wire(d.payload),randomKey(),f.keys.signing.privateKey),o={draft_id:d.draft_id,attempt_id:bundle.envelope.header.context.operation_id,revision_id:bundle.envelope.header.context.revision_id,state:'QUEUED',bundle,attempt_digest:digest('bundle',wire(bundle)),receipt:null};decode('outbox',wire(o));
 const first=ident(),second=ident(),fence=await f.engine.lease(f.cap),before=structuredClone(f.store.rows);f.store.failAfter=1;
 await expect(()=>f.engine.save(f.cap,fence,[{id:first,kind:'draft',data:structuredClone(d)},{id:second,kind:'outbox',data:structuredClone(o)}]),'INSUFFICIENT_STORAGE');assert.deepEqual(f.store.rows,before);
 f.store.failAfter=Infinity;await f.engine.save(f.cap,fence,[{id:first,kind:'draft',data:structuredClone(d)},{id:second,kind:'outbox',data:structuredClone(o)}]);assert.deepEqual(await f.engine.read(f.cap,first,'draft'),d);
 const inspector=JSON.stringify({state:f.store.state,rows:[...f.store.rows.values()]});assert(!inspector.includes(f.secretMarker));assert(!inspector.includes(d.payload.markdown??'public synthetic plaintext marker that cannot appear'));
 const changed=structuredClone(o);changed.attempt_id=ident();await expect(()=>f.engine.save(f.cap,fence,[{id:second,kind:'outbox',data:changed}]),'ATTEMPT_CONTEXT_MISMATCH');
 const update=structuredClone(o);update.state='SENT_UNKNOWN';await f.engine.save(f.cap,fence,[{id:second,kind:'outbox',data:update}]);const reverse=structuredClone(o);await expect(()=>f.engine.save(f.cap,fence,[{id:second,kind:'outbox',data:reverse}]),'INVALID_OUTBOX_TRANSITION');
 await expect(()=>f.engine.evict(f.cap,fence,first),'UNSYNCED_WORK_PROTECTED');
 f.engine.lock();await expect(()=>f.engine.read(f.cap,first,'draft'),'VAULT_LOCKED');const reopened=new VaultEngine(f.store);const r=(await reopened.unlock(phrase)).capability;assert.deepEqual(await reopened.read(r,first,'draft'),d);await expect(()=>reopened.read(r,f.store.state.vault_id,'vault-secrets'),'SECRET_EXPORT_FORBIDDEN');
});
test('global generation, leader replacement and stale lease fences',async()=>{
 const f=await fixture(),second=new VaultEngine(f.store),cap2=(await second.unlock(phrase)).capability,l1=await f.engine.lease(f.cap);await expect(()=>second.lease(cap2),'WRITER_BUSY');
 f.store.state.lease.expires=Date.now()-1;f.store.state.lease.issued=f.store.state.lease.expires-10000;const l2=await second.lease(cap2);
 await expect(()=>f.engine.save(f.cap,l1,[{id:ident(),kind:'draft',data:draft()}]),'STALE_WRITER');assert(l2!==l1);
 await second.globalLock();await expect(()=>f.engine.read(f.cap,ident(),'draft'),'STALE_CAPABILITY');await expect(()=>second.read(cap2,ident(),'draft'),'VAULT_LOCKED');
});
test('tamper, pinned-root substitution, known rollback and fresh nonce after full rollback',async()=>{
 const f=await fixture(),id=ident(),fence=await f.engine.lease(f.cap),d=draft();await f.engine.save(f.cap,fence,[{id,kind:'draft',data:structuredClone(d)}]);const old=structuredClone(f.store.rows.get(id));await f.engine.save(f.cap,fence,[{id,kind:'draft',data:structuredClone(d)}]);assert.notEqual(old.frame.nonce,f.store.rows.get(id).frame.nonce);f.store.rows.set(id,old);await expect(()=>f.engine.read(f.cap,id,'draft'),'ROLLBACK_QUARANTINE');
 f.store.state.lease=null;const newProcess=new VaultEngine(f.store);let c=(await newProcess.unlock(phrase)).capability;const n=await newProcess.lease(c);await newProcess.save(c,n,[{id,kind:'draft',data:draft()}]);assert.notEqual(old.frame.nonce,f.store.rows.get(id).frame.nonce);
 const row=f.store.rows.get(id);row.frame.ciphertext=b64(sodium.randombytes_buf(Buffer.from(row.frame.ciphertext,'base64url').length));const third=new VaultEngine(f.store);c=(await third.unlock(phrase)).capability;await expect(()=>third.read(c,id,'draft'),'INTEGRITY_FAILURE');
 f.store.state.pins.root_fingerprint=hash(randomKey());const fourth=new VaultEngine(f.store);await expect(()=>fourth.unlock(phrase),'INTEGRITY_FAILURE');
});
test('PRF salt/credential binding, explicit phrase fallback and wrapper removal',async()=>{
 const f=await fixture(),credential=b64(randomKey()),prepared=await f.engine.preparePrf(f.cap,credential),prf=randomKey(),copy=Uint8Array.from(prf);await f.engine.addPrf(f.cap,credential,prf,prepared);assert(prf.every(x=>x===0));f.engine.lock();
 const info=await f.engine.info(),w=info.wrappers.find(w=>w.method==='webauthn-prf');assert.equal((await f.engine.prfOptions(w.id)).salt,prepared.salt);await expect(()=>f.engine.unlockPrf(w.id,b64(randomKey()),Uint8Array.from(copy)),'PRF_UNAVAILABLE');await expect(()=>f.engine.unlockPrf(w.id,credential,randomKey()),'INTEGRITY_FAILURE');
 const c=(await f.engine.unlockPrf(w.id,credential,copy)).capability;await f.engine.removeWrapper(c,w.id,phrase);assert.equal((await f.engine.info()).wrappers.length,1);const c2=(await f.engine.unlock(phrase)).capability;await expect(async()=>f.engine.removeWrapper(c2,(await f.engine.info()).wrappers[0].id,phrase),'PHRASE_FALLBACK_REQUIRED');
});
test('empty origin, wrong phrase, excessive KDF, namespace isolation and reserve records',async()=>{
 const f=await fixture();f.engine.lock();await expect(()=>f.engine.unlock('other synthetic purple harbor paper lantern'),'INTEGRITY_FAILURE');f.store.state.wrappers[0].parameters.memlimit=1073741824;await expect(()=>f.engine.unlock(phrase),'SCHEMA_MISMATCH');
 const empty=new VaultEngine(new Store({...f.scope,profile_id:ident()}));assert.equal((await empty.info()).state,'enrollment-required');
 const g=await fixture(),fence=await g.engine.lease(g.cap);await expect(()=>g.engine.save(g.cap,fence,[{id:g.store.state.vault_id,kind:'draft',data:draft()}]),'RESERVED_RECORD');
 const moved=new Store({...g.scope,account_id:ident()});moved.state=structuredClone(g.store.state);moved.rows=structuredClone(g.store.rows);await expect(()=>new VaultEngine(moved).unlock(phrase),'INTEGRITY_FAILURE');
});
