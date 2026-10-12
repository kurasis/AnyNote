import {IndexedVault,ensure,fail,id} from './store.mjs';
import {withKdf} from './kdf.mjs';
import {VaultEngine} from './engine.mjs';
import {initialRoot,registrationRequest} from '../auth-client.mjs';
import {sodium,b64} from '../adapters/primitives.mjs';
let engine,initial,queue=Promise.resolve(),queued=0;
const operations=new Set(['open','info','initialize','unlock','lock','lease','save','read','proof','addPrf','preparePrf','prfOptions','unlockPrf','removeWrapper','evict','prepareRoot','registerRequest','commitRoot','discardRoot']);
function clean(v){if(v instanceof Uint8Array)sodium.memzero(v);else if(v&&typeof v==='object')for(const k of Object.keys(v)){clean(v[k]);if(typeof v[k]==='string')v[k]='';}}
async function run(op,args,client){
  if(op==='open'){await engine?.close();engine=new VaultEngine(await new IndexedVault(args[0]).open());return engine.info();}
  if(op==='prepareRoot'){ensure(id(args[0])&&id(args[1]),'INVALID_PROFILE');initial?.dispose();initial=await initialRoot(...args);return structuredClone({identity:initial.identity,device:initial.device,fingerprint:initial.fingerprint,kit:initial.kit});}
  if(op==='registerRequest'){ensure(initial,'NO_PREPARATION');return structuredClone(registrationRequest(args[0],initial,args[1]));}
  if(op==='discardRoot'){initial?.dispose();initial=undefined;return {state:'discarded'};}
  ensure(engine,'PROFILE_REQUIRED');
  if(op==='commitRoot'){ensure(initial&&engine.scope.device_id===initial.device.device_id&&engine.scope.account_id===initial.identity.body.account_id&&engine.scope.service_id===initial.identity.body.service_id,'LOCAL_CONTEXT_MISMATCH');try{return await withKdf(()=>engine.initialize(args[0],{device_signing_secret:b64(initial.keys.signing.privateKey),device_encryption_secret:b64(initial.keys.encryption.privateKey),group_keys:[]},{service_id:initial.identity.body.service_id,account_id:initial.identity.body.account_id,root_fingerprint:initial.fingerprint}),client);}finally{initial?.dispose();initial=undefined;}}
  if(op==='lock'){initial?.dispose();initial=undefined;await engine.globalLock();return {state:'locked'};}
  ensure(typeof engine[op]==='function','INVALID_VAULT_COMMAND');return ['initialize','unlock','removeWrapper'].includes(op)?withKdf(()=>engine[op](...args),client):engine[op](...args);
}
self.onmessage=({data:r})=>{
  if(!r||Object.keys(r).sort().join(',')!=='args,client,generation,id,op,version'||r.version!==1||!id(r.client)||!Number.isSafeInteger(r.id)||r.id<=0||!Number.isSafeInteger(r.generation)||!operations.has(r.op)||!Array.isArray(r.args)||r.args.length>6||queued>=20){clean(r?.args);postMessage({version:1,id:r?.id,error:'INVALID_VAULT_COMMAND',generation:r?.generation});return;}
  // The aggregate bound is checked before crypto/IDB work and diagnostic errors never serialize args.
  let bytes;try{bytes=JSON.stringify(r.args).length;}catch{bytes=Infinity;}
  if(bytes>8388608){clean(r.args);postMessage({version:1,id:r.id,error:'RESOURCE_LIMIT',generation:r.generation});return;}
  queued++;queue=queue.then(async()=>{let result;try{result=structuredClone(await run(r.op,r.args,r.client));postMessage({version:1,id:r.id,generation:r.generation,result});}catch(e){if(['STALE_CAPABILITY','ROLLBACK_QUARANTINE','INTEGRITY_FAILURE','LOCAL_CONTEXT_MISMATCH'].includes(e.message))engine?.lock();postMessage({version:1,id:r.id,generation:r.generation,error:/^[A-Z_]+$/.test(e.message)?e.message:'VAULT_FAILURE'});}finally{clean(r.args);clean(result);queued--;}});
};
postMessage({version:1,status:'READY'});
