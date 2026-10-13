// Synthetic crypto/transaction-model fixture, never an auth issuer or product storage.
import {VaultEngine} from '../vault/engine.mjs';
import {initialRoot,registrationRequest} from '../auth-client.mjs';
import {sodium,deviceKeys,b64,hash,randomKey,Buffer,un64} from '../adapters/primitives.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {stateDigest} from '../adapters/codecs/state-codec.mjs';
import {controlId} from '../devices/workflow.mjs';
import {phraseKek,unwrapLocalKey,openLocal} from '../adapters/local.mjs';
const phrase='public synthetic purple harbor paper lantern',ident=()=>b64(sodium.randombytes_buf(16));
class Store {
 constructor(scope){this.scope=scope;this.state=undefined;this.rows=new Map();this.queue=Promise.resolve();this.failAfter=Infinity;}
 transaction(write,fn){const action=async()=>{let n=0;const rows=structuredClone(this.rows);let state=structuredClone(this.state);const result=await fn({get:async()=>structuredClone(state),set:async s=>{state=structuredClone(s);},read:async id=>structuredClone(rows.get(id)),put:async row=>{if(++n>this.failAfter)throw Error('INSUFFICIENT_STORAGE');rows.set(row.id,structuredClone(row));},count:async()=>rows.size,list:async()=>[...rows.keys()],remove:async id=>rows.delete(id),each:async fn=>{for(const row of rows.values())await fn(structuredClone(row));}});if(write){this.state=state;this.rows=rows;}return result;};const r=this.queue.then(action);this.queue=r.catch(()=>{});return r;}
 close(){}
}

async function fixture(serviceId=ident()){
 const initial=await initialRoot(serviceId,ident()),sid=ident(),pins={service_id:initial.identity.body.service_id,account_id:initial.identity.body.account_id,root_fingerprint:initial.fingerprint};
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

export {phrase,fixture,installation,sync,pair,run,readOwnedSecrets,Store};
