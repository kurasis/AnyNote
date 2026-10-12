// Additive P08 local format. Frozen P02 cache/export/local records are unchanged.
import {sodium,b64,un64,encrypt,decrypt,Buffer,hash} from '../adapters/primitives.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {canonicalBytes} from '../adapters/core.mjs';
import {strictJson} from '../src/strict-json.mjs';
import {deviceValue} from './client.mjs';
import {ensure} from '../vault/store.mjs';
export const localContext=(scope,root_fingerprint,record_id,record_kind)=>deviceValue('local-context',{purpose:'device-lifecycle-local-context',version:1,...scope,record_id,record_kind,root_fingerprint});
const aad=context=>Buffer.concat([Buffer.from('AnyNote/P08/local-lifecycle\0'),canonicalBytes(wire(context))]);
export function localFrame(value){return deviceValue('local-frame',value);}
export function sealLifecycle(scope,pins,record_id,record_kind,data,key){
 const context=localContext(scope,pins.root_fingerprint,record_id,record_kind),kind=record_kind==='device-control'?'local-control':'local-roster-page';deviceValue(kind,data);const plain=canonicalBytes(wire(data));ensure(plain.length<=262144,'RESOURCE_LIMIT');const nonce=sodium.randombytes_buf(24);
 try{return localFrame({contract:'p08-local-v1',protocol:'anynote',protocol_version:1,purpose:'device-lifecycle-local',context,nonce:b64(nonce),ciphertext:b64(encrypt(plain,aad(context),nonce,key))});}finally{sodium.memzero(plain);}
}
export function openLifecycle(frame,scope,pins,record_id,record_kind,key){
 const value=localFrame(frame),expected=localContext(scope,pins.root_fingerprint,record_id,record_kind);ensure(same(value.context,expected),'LOCAL_CONTEXT_MISMATCH');const plain=decrypt(un64(value.ciphertext),aad(expected),un64(value.nonce),key);
 try{const data=strictJson(plain,262144);return deviceValue(record_kind==='device-control'?'local-control':'local-roster-page',data);}finally{sodium.memzero(plain);}
}
export const lifecycleHash=frame=>hash(canonicalBytes(wire(localFrame(frame))));
