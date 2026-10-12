// Explicit additive P09 control/evidence profile. Frozen local draft/outbox/cache stay unchanged.
import {sodium,b64,un64,encrypt,decrypt,Buffer,hash} from '../adapters/primitives.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {canonicalBytes} from '../adapters/core.mjs';
import {strictJson} from '../src/strict-json.mjs';
import {noteValue} from './client.mjs';
import {ensure} from '../vault/store.mjs';
export const noteControlId=scope=>b64(un64(hash(Buffer.concat([Buffer.from('AnyNote/P09/local-control\0'),canonicalBytes(wire(scope))]))).subarray(0,16));
const context=(scope,pins,record_id,record_kind)=>noteValue('local-context',{purpose:'private-content-local-context',version:1,...scope,record_id,record_kind,root_fingerprint:pins.root_fingerprint});
const aad=c=>Buffer.concat([Buffer.from('AnyNote/P09/local-content\0'),canonicalBytes(wire(c))]);
export const noteFrame=frame=>noteValue('local-frame',frame);
export function sealNoteLocal(scope,pins,id,kind,data,key){
 const c=context(scope,pins,id,kind);noteValue(kind==='note-control'?'local-control':'local-evidence',data);const plain=canonicalBytes(wire(data));ensure(plain.length<=524288,'RESOURCE_LIMIT');const n=sodium.randombytes_buf(24);
 try{return noteFrame({contract:'p09-local-v1',protocol:'anynote',protocol_version:1,purpose:'private-content-local',context:c,nonce:b64(n),ciphertext:b64(encrypt(plain,aad(c),n,key))});}finally{sodium.memzero(plain);}
}
export function openNoteLocal(frame,scope,pins,id,kind,key){
 const v=noteFrame(frame),c=context(scope,pins,id,kind);ensure(same(v.context,c),'LOCAL_CONTEXT_MISMATCH');const p=decrypt(un64(v.ciphertext),aad(c),un64(v.nonce),key);
 try{return noteValue(kind==='note-control'?'local-control':'local-evidence',strictJson(p,524288));}finally{sodium.memzero(p);}
}
export const noteFrameHash=f=>hash(canonicalBytes(wire(noteFrame(f))));
