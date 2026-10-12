import test from 'node:test';
import assert from 'node:assert/strict';
import {VaultEngine} from '../vault/engine.mjs';
import {initialRoot,registrationRequest} from '../auth-client.mjs';
import {sodium,deviceKeys,b64,hash,randomKey,Buffer,un64} from '../adapters/primitives.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {stateDigest} from '../adapters/codecs/state-codec.mjs';
import {controlId} from './workflow.mjs';
import {phraseKek,unwrapLocalKey,openLocal} from '../adapters/local.mjs';
const phrase='public synthetic purple harbor paper lantern',ident=()=>b64(sodium.randombytes_buf(16));
class Store {
 constructor(scope){this.scope=scope;this.state=undefined;this.rows=new Map();this.queue=Promise.resolve();this.failAfter=Infinity;}
 transaction(write,fn){const action=async()=>{let n=0;const rows=structuredClone(this.rows);let state=structuredClone(this.state);const result=await fn({get:async()=>structuredClone(state),set:async s=>{state=structuredClone(s);},read:async id=>structuredClone(rows.get(id)),put:async row=>{if(++n>this.failAfter)throw Error('INSUFFICIENT_STORAGE');rows.set(row.id,structuredClone(row));},count:async()=>rows.size,list:async()=>[...rows.keys()],remove:async id=>rows.delete(id),each:async fn=>{for(const row of rows.values())await fn(structuredClone(row));}});if(write){this.state=state;this.rows=rows;}return result;};const r=this.queue.then(action);this.queue=r.catch(()=>{});return r;}
 close(){}
}

async function fixture(){
 const initial=await initialRoot(ident(),ident()),sid=ident(),pins={service_id:initial.identity.body.service_id,account_id:initial.identity.body.account_id,root_fingerprint:initial.fingerprint};
 const context={purpose:'device-possession-challenge',contract:'p02-state-c1',protocol:'anynote',protocol_version:1,...pins,intent:'register',challenge_id:ident(),session_binding:hash(Buffer.from('AnyNote/P06/session-binding\0'+sid)),generation:'0',roster:null,nonce:b64(randomKey()),device:initial.device,expires_at:String(Date.now()+50000)},plain={purpose:'device-encryption-proof',context,secret:b64(randomKey())},challenge={context,sealed_challenge:b64(sodium.crypto_box_seal(wire(plain),initial.keys.encryption.publicKey)),challenge_digest:stateDigest('challenge-plaintext',wire(plain))};
 const event=registrationRequest(ident(),initial,challenge).roster,snapshot={identity:initial.identity,events:[event],head:{version:'0',digest:stateDigest('event',wire(event))},generation:'0'};
 const old=await installation(pins,initial.keys,initial.device.device_id);await sync(old,snapshot);const keys=deviceKeys(),fresh=await installation(pins,keys,ident());await sync(fresh,snapshot);return {initial,pins,sid,snapshot,old,fresh,keys};
}
async function installation(pins,keys,device_id){const scope={service_id:pins.service_id,account_id:pins.account_id,device_id,profile_id:ident()},store=new Store(scope),engine=new VaultEngine(store);await engine.initialize(phrase,{device_signing_secret:b64(keys.signing.privateKey),device_encryption_secret:b64(keys.encryption.privateKey),group_keys:[]},pins);return {scope,store,engine,cap:(await engine.unlock(phrase)).capability};}
const run=(f,op,args=[])=>f.engine.devices(f.cap,op,args);
async function sync(f,s){await run(f,'snapshotStart',[s.identity,s.head,s.generation]);for(let n=0;n<s.events.length;n+=20)await run(f,'snapshotPage',[s.events.slice(n,n+20)]);return run(f,'snapshotFinish');}
async function pair(f,mode){
 const first=await run(mode==='invite'?f.old:f.fresh,mode==='invite'?'startInvite':'startOffer',[f.sid]);const scanned=await run(mode==='invite'?f.fresh:f.old,'scan',[first.qr,f.sid]);
 let response=scanned;
 if(mode==='invite')response=await run(f.old,'receive',[scanned.request.frame]);
 await run(f.fresh,'receive',[response.request.frame]);const approval=await run(f.old,'approve',[true]);await run(f.fresh,'receive',[approval.request.frame]);const confirmation=await run(f.fresh,'confirm',[true]),event=confirmation.request.event;
 const snapshot={...f.snapshot,events:[...f.snapshot.events,event],head:{version:event.body.version,digest:stateDigest('event',wire(event))},generation:event.body.generation};await sync(f.old,snapshot);await sync(f.fresh,snapshot);await run(f.old,'finishPairing');await run(f.fresh,'finishPairing');return snapshot;
}
async function readOwnedSecrets(f){const w=f.store.state.wrappers[0],{nonce,ciphertext,...descriptor}=w,kek=await phraseKek(phrase,wire(w.parameters)),key=unwrapLocalKey('phrase-wrapper',wire(w),wire(descriptor),kek);try{const row=f.store.rows.get(f.store.state.vault_id);return openLocal(wire(row.frame),key,wire(row.frame.context)).data;}finally{sodium.memzero(kek);sodium.memzero(key);}}
const rejection=(action,code)=>assert.rejects(action,e=>e.message===code);

test('both QR directions bind independent device keys, mutual confirmation and protected group delivery',async()=>{
 for(const mode of ['invite','offer']){const f=await fixture();try{
  const genesis=await run(f.old,'genesis');assert.deepEqual(await run(f.old,'genesis'),genesis,'retry preserves signed genesis bytes');const snapshot=await pair(f,mode);assert.equal(snapshot.events.length,2);
  const grant=await run(f.old,'distribute',[genesis.request,f.fresh.scope.device_id,null,true]);await run(f.fresh,'acceptKeys',[genesis.request,grant.request.records]);
  const a=await readOwnedSecrets(f.old),b=await readOwnedSecrets(f.fresh);assert.notEqual(a.device_signing_secret,b.device_signing_secret);assert.notEqual(a.device_encryption_secret,b.device_encryption_secret);assert.equal(a.group_keys[0].group_secret,b.group_keys[0].group_secret);
  const disk=JSON.stringify({meta:f.fresh.store.state,rows:[...f.fresh.store.rows.values()]});for(const marker of [a.group_keys[0].group_secret,b.device_signing_secret,b.device_encryption_secret,f.initial.kit.recovery_secret])assert(!disk.includes(marker));
  const fence=await f.fresh.engine.lease(f.fresh.cap);await rejection(()=>f.fresh.engine.evict(f.fresh.cap,fence,controlId(f.fresh.scope)),'RESERVED_RECORD');
 }finally{f.initial.dispose();await f.old.engine.close();await f.fresh.engine.close();sodium.memzero(f.keys.signing.privateKey);sodium.memzero(f.keys.encryption.privateKey);}}
});
test('partial roster/storage abort preserves acknowledged checkpoint and ciphertext',async()=>{const f=await fixture();try{
 const before=structuredClone(f.old.store.rows),oldHead=(await run(f.old,'summary')).head;await run(f.old,'snapshotStart',[f.snapshot.identity,f.snapshot.head,'0']);f.old.store.failAfter=1;
 await rejection(()=>run(f.old,'snapshotPage',[f.snapshot.events]),'INSUFFICIENT_STORAGE');f.old.store.failAfter=Infinity;
 assert.equal(f.old.store.rows.size,before.size);assert.deepEqual((await run(f.old,'summary')).head,oldHead);await sync(f.old,f.snapshot);assert.deepEqual((await run(f.old,'summary')).head,oldHead);
 }finally{f.initial.dispose();await f.old.engine.close();await f.fresh.engine.close();}});
test('known signed-chain rollback and cross-account QR cannot replace current trust',async()=>{const f=await fixture();try{
 const oldControl=structuredClone(f.old.store.rows.get(controlId(f.old.scope))),oldPages=structuredClone(f.old.store.rows);await pair(f,'invite');const nowRows=f.old.store.rows;
 nowRows.set(controlId(f.old.scope),oldControl);for(const [id,row]of oldPages)if(id!==f.old.store.state.vault_id)nowRows.set(id,row);
 await rejection(()=>run(f.old,'summary'),'ROLLBACK_QUARANTINE');
 const other=await fixture(),qr=await run(other.old,'startInvite');await rejection(()=>run(f.fresh,'scan',[qr.qr,f.sid]),'ROOT_PIN_MISMATCH');other.initial.dispose();await other.old.engine.close();await other.fresh.engine.close();
 }finally{f.initial.dispose();await f.old.engine.close();await f.fresh.engine.close();}});
test('lock destroys QR channels, keeps signed activation retry and denies stale capabilities',async()=>{const f=await fixture();try{
 const first=await run(f.old,'startInvite'),offer=await run(f.fresh,'scan',[first.qr,f.sid]),response=await run(f.old,'receive',[offer.request.frame]);await run(f.fresh,'receive',[response.request.frame]);const approval=await run(f.old,'approve',[true]);await run(f.fresh,'receive',[approval.request.frame]);const confirmation=await run(f.fresh,'confirm',[true]);
 await f.fresh.engine.globalLock();await rejection(()=>run(f.fresh,'retryConfirmation'),'VAULT_LOCKED');const reopened=new VaultEngine(f.fresh.store);f.fresh.engine=reopened;f.fresh.cap=(await reopened.unlock(phrase)).capability;assert.deepEqual((await run(f.fresh,'retryConfirmation')).request,confirmation.request);assert.equal((await run(f.fresh,'summary')).pending.state,'confirmation-retry');
 await f.old.engine.globalLock();f.old.cap=(await f.old.engine.unlock(phrase)).capability;await rejection(()=>run(f.old,'approve',[true]),'PAIRING_RESTART_REQUIRED');
 }finally{f.initial.dispose();await f.old.engine.close();await f.fresh.engine.close();}});
test('second window cannot mutate active leader state, while explicit replacement remains fenced',async()=>{const f=await fixture();try{
 const second=new VaultEngine(f.old.store),cap=(await second.unlock(phrase)).capability;await rejection(()=>second.devices(cap,'summary',[]),'WRITER_BUSY');
 f.old.store.state.lease.issued=Date.now()-20000;f.old.store.state.lease.expires=f.old.store.state.lease.issued+10000;assert.equal((await second.devices(cap,'summary',[])).state,'ACTIVE');await rejection(()=>run(f.old,'startInvite'),'WRITER_BUSY');await second.close();
 }finally{f.initial.dispose();await f.old.engine.close();await f.fresh.engine.close();}});

test('hostile QR/relay key substitution, mutation and reflection cannot produce approval',async()=>{
 for(const attack of ['key','ciphertext','reflection']){const f=await fixture();try{
  const invite=await run(f.old,'startInvite');let qr=invite.qr;
  if(attack==='key'){const decoded=JSON.parse(qr);decoded.channel_key=b64(randomKey());qr=JSON.stringify(decoded);}
  const offer=await run(f.fresh,'scan',[qr,f.sid]);
  if(attack==='key')await assert.rejects(()=>run(f.old,'receive',[offer.request.frame]),e=>e.message==='CHANNEL_AUTHENTICATION_FAILED');
  else if(attack==='ciphertext'){const frame=structuredClone(offer.request.frame),bytes=un64(frame.ciphertext);bytes[bytes.length-1]^=1;frame.ciphertext=b64(bytes);await assert.rejects(()=>run(f.old,'receive',[frame]),e=>e.message==='CHANNEL_AUTHENTICATION_FAILED');}
  else{const response=await run(f.old,'receive',[offer.request.frame]);await assert.rejects(()=>run(f.old,'receive',[response.request.frame]),e=>['CHANNEL_REFLECTION','PAIRING_ORDER'].includes(e.message));}
  assert.equal((await run(f.fresh,'summary')).state,'PENDING');assert(!f.fresh.store.rows.has('group_secret'));
 }finally{f.initial.dispose();await f.old.engine.close();await f.fresh.engine.close();}}
});
