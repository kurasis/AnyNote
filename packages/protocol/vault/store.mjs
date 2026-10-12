import canonicalize from 'canonicalize';
// IndexedDB transactions contain opaque routing IDs, public wrappers and encrypted frames only.
import {decode} from '../adapters/codecs/protocol-codec.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
export const fail=code=>{throw Object.assign(new Error(code),{code});};
export const ensure=(value,code)=>{if(!value)fail(code);};
export const id=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{22}$/.test(value);
export const same=(a,b)=>canonicalize(a)===canonicalize(b);
export function scope(value){
  ensure(value&&Object.keys(value).sort().join(',')==='account_id,device_id,profile_id,service_id'&&Object.values(value).every(id),'INVALID_PROFILE');return structuredClone(value);
}
export const name=s=>'anynote-vault-v1-'+[s.service_id,s.account_id,s.device_id,s.profile_id].join('-');
export function record(s,frame){const e=decode('local-envelope',wire(frame));for(const k of Object.keys(s))ensure(e.context[k]===s[k],'LOCAL_CONTEXT_MISMATCH');return e;}
const request=r=>new Promise((resolve,reject)=>{r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(Object.assign(new Error('STORAGE_FAILURE'),{code:'STORAGE_FAILURE'}));});
export class IndexedVault {
  constructor(s){this.scope=scope(s);this.db=null;}
  async open(){
    ensure(globalThis.indexedDB,'STORAGE_UNAVAILABLE');
    // Version probing never downgrades/deletes an unknown schema.
    const req=indexedDB.open(name(this.scope));
    req.onupgradeneeded=()=>{const d=req.result;d.createObjectStore('meta');d.createObjectStore('records',{keyPath:'id'});};
    let timedOut=false,rejectOpen;const timeout=setTimeout(()=>{timedOut=true;rejectOpen?.(Error('STORAGE_BUSY'));},10000);
    try{this.db=await new Promise((resolve,reject)=>{rejectOpen=reject;req.onsuccess=()=>{if(timedOut){req.result.close();return;}resolve(req.result);};req.onerror=()=>reject(new Error('STORAGE_UNAVAILABLE'));req.onblocked=()=>reject(new Error('STORAGE_BUSY'));});}finally{clearTimeout(timeout);}
    this.db.onversionchange=()=>{this.db.close();this.db=null;};
    ensure(this.db.version===1&&this.db.objectStoreNames.length===2&&this.db.objectStoreNames.contains('meta')&&this.db.objectStoreNames.contains('records'),'UNSUPPORTED_LOCAL_SCHEMA');
    return this;
  }
  async transaction(write,fn){
    ensure(this.db,'STORAGE_UNAVAILABLE');let tx;
    try{tx=this.db.transaction(['meta','records'],write?'readwrite':'readonly',write?{durability:'strict'}:undefined);}catch{fail('STORAGE_UNAVAILABLE');}
    const done=new Promise((resolve,reject)=>{tx.oncomplete=resolve;tx.onerror=()=>reject(new Error(tx.error?.name==='QuotaExceededError'?'INSUFFICIENT_STORAGE':'STORAGE_FAILURE'));tx.onabort=()=>reject(new Error(tx.error?.name==='QuotaExceededError'?'INSUFFICIENT_STORAGE':'STORAGE_ABORTED'));});
    done.catch(()=>{});
    const meta=tx.objectStore('meta'),rows=tx.objectStore('records');
    const api={get:()=>request(meta.get('state')),set:s=>request(meta.put(s,'state')),read:i=>request(rows.get(i)),put:r=>request(rows.put(r)),remove:i=>request(rows.delete(i)),count:()=>request(rows.count()),list:()=>request(rows.getAllKeys(undefined,101)),each:fn=>new Promise((resolve,reject)=>{const r=rows.openCursor();r.onerror=()=>reject(Error('STORAGE_FAILURE'));r.onsuccess=async()=>{const cursor=r.result;if(!cursor){resolve();return;}try{await fn(structuredClone(cursor.value));cursor.continue();}catch(e){reject(e);}};})};
    try{const result=await fn(api);await done;return result;}catch(e){try{tx.abort();}catch{}await done.catch(()=>{});throw e;}
  }
  close(){this.db?.close();this.db=null;}
}
export function metadata(v,s){
  ensure(v&&v.schema===1&&same(v.scope,s)&&Number.isSafeInteger(v.epoch)&&v.epoch>=1&&Number.isSafeInteger(v.revision)&&v.revision>=1,'INTEGRITY_FAILURE');
  ensure(Object.keys(v).sort().join(',')==='epoch,lease,manifest,pins,revision,rotation,schema,scope,vault_id,wrappers','INTEGRITY_FAILURE');
  ensure(id(v.vault_id),'INTEGRITY_FAILURE');
  ensure(Array.isArray(v.wrappers)&&v.wrappers.length>=1&&v.wrappers.length<=20,'INTEGRITY_FAILURE');
  for(const w of v.wrappers){const kind=w.context?.method==='argon2id13'?'phrase-wrapper':'prf-wrapper';decode(kind,wire(w));for(const k of Object.keys(s))ensure(w.context[k]===s[k],'LOCAL_CONTEXT_MISMATCH');}
  ensure(v.pins&&Object.keys(v.pins).sort().join(',')==='account_id,root_fingerprint,service_id'&&v.pins.account_id===s.account_id&&v.pins.service_id===s.service_id&&/^[A-Za-z0-9_-]{43}$/.test(v.pins.root_fingerprint),'INTEGRITY_FAILURE');
  ensure(v.rotation===null,'NATIVE_ROTATION_REQUIRES_NATIVE_HOST');const l=v.lease;ensure(l===null||(l&&Object.keys(l).sort().join(',')==='expires,fence,issued,owner'&&id(l.owner)&&Number.isSafeInteger(l.fence)&&l.fence>0&&Number.isSafeInteger(l.issued)&&Number.isSafeInteger(l.expires)&&l.expires>l.issued&&l.expires-l.issued===10000),'INTEGRITY_FAILURE');return v;
}
