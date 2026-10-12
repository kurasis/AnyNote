// Origin-wide transactional KDF admission also works without Web Locks. A dead
// worker leaves a bounded admission lease; it never leaves a phrase/result here.
import {ensure} from './store.mjs';
export async function withKdf(fn,owner){
  ensure(typeof owner==='string'&&/^[A-Za-z0-9_-]{22}$/.test(owner),'INVALID_WORKER_OWNER');const opened=indexedDB.open('anynote-vault-kdf-v1',1);opened.onupgradeneeded=()=>opened.result.createObjectStore('lease');
  const db=await new Promise((resolve,reject)=>{opened.onsuccess=()=>resolve(opened.result);opened.onerror=()=>reject(Error('STORAGE_UNAVAILABLE'));opened.onblocked=()=>reject(Error('STORAGE_BUSY'));});
  const transaction=action=>new Promise((resolve,reject)=>{const t=db.transaction('lease','readwrite'),s=t.objectStore('lease'),r=s.get('active');let failed;r.onsuccess=()=>{try{action(s,r.result);}catch(e){failed=e;t.abort();}};t.oncomplete=resolve;t.onabort=()=>reject(failed??Error('STORAGE_FAILURE'));t.onerror=()=>reject(Error('STORAGE_FAILURE'));});
  try{await transaction((s,l)=>{const now=Date.now();ensure(!l||(now>=l.issued&&now>=l.expires),'KDF_BUSY');s.put({owner,issued:now,expires:now+180000},'active');});try{return await fn();}finally{await transaction((s,l)=>{if(l?.owner===owner)s.delete('active');});}}finally{db.close();}
}

export async function releaseKdf(owner){const r=indexedDB.open('anynote-vault-kdf-v1',1);r.onupgradeneeded=()=>r.result.createObjectStore('lease');const d=await new Promise((resolve,reject)=>{r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(Error('STORAGE_UNAVAILABLE'));});try{await new Promise((resolve,reject)=>{const t=d.transaction('lease','readwrite'),s=t.objectStore('lease'),get=s.get('active');get.onsuccess=()=>{if(get.result?.owner===owner)s.delete('active');};t.oncomplete=resolve;t.onabort=()=>reject(Error('STORAGE_FAILURE'));t.onerror=()=>reject(Error('STORAGE_FAILURE'));});}finally{d.close();}}
