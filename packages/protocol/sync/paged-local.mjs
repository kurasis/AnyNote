// Additive bounded encrypted parts under the existing L/XChaCha20-Poly1305.
import {sodium,b64,un64,hash,Buffer,encrypt,decrypt} from '../adapters/primitives.mjs';
import {canonicalBytes} from '../adapters/core.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {strictJson} from '../src/strict-json.mjs';
import {syncValue} from './codec.mjs';
const ensure=(condition,code)=>{if(!condition)throw Object.assign(Error(code),{code});};
const context=(scope,pins,record_id,record_kind)=>syncValue('local-context',{purpose:'paged-content-context',version:1,...scope,record_id,record_kind,root_fingerprint:pins.root_fingerprint});
const aad=c=>Buffer.concat([Buffer.from('AnyNote/P11/local-pages\0'),canonicalBytes(wire(c))]);
export const pagedFrame=f=>syncValue('local-frame',f);
export function openManifest(frame,scope,pins,id,kind,key){
 const f=pagedFrame(frame),c=context(scope,pins,id,kind);ensure(same(f.context,c),'LOCAL_CONTEXT_MISMATCH');const plain=decrypt(un64(f.ciphertext),aad(c),un64(f.nonce),key);
 try{const m=syncValue('manifest',strictJson(plain,65536));ensure(m.kind===kind&&(kind==='group-evidence'||m.private===null)&&BigInt(m.bytes)>0n&&BigInt(m.bytes)<=33554432n&&new Set(m.parts.map(p=>p.record_id)).size===m.parts.length,'INTEGRITY_FAILURE');return m;}finally{sodium.memzero(plain);}
}
export function publicPartIds(frame,scope,pins,id,kind,key){const m=openManifest(frame,scope,pins,id,kind,key);try{return m.parts.map(p=>p.record_id);}finally{if(m.private)m.private.pending_key.group_secret='';}}
export function sealManifest(scope,pins,id,kind,manifest,key){
 syncValue('manifest',manifest);const c=context(scope,pins,id,kind),plain=canonicalBytes(wire(manifest)),nonce=sodium.randombytes_buf(24);
 try{ensure(plain.length<=65536,'RESOURCE_LIMIT');return pagedFrame({contract:'p11-local-v1',protocol:'anynote',protocol_version:1,purpose:'paged-content-local',context:c,nonce:b64(nonce),ciphertext:b64(encrypt(plain,aad(c),nonce,key))});}finally{sodium.memzero(plain);}
}
function sealPart(scope,pins,id,index,bytes,key){
 const c=context(scope,pins,id,'content-part'),data=syncValue('local-part',{purpose:'paged-content-part',version:1,index:String(index),bytes:String(bytes.length),digest:hash(bytes),record_bytes:b64(bytes)}),plain=canonicalBytes(wire(data)),nonce=sodium.randombytes_buf(24);
 try{return pagedFrame({contract:'p11-local-v1',protocol:'anynote',protocol_version:1,purpose:'paged-content-local',context:c,nonce:b64(nonce),ciphertext:b64(encrypt(plain,aad(c),nonce,key))});}finally{sodium.memzero(plain);}
}
function openPart(frame,scope,pins,id,index,key){
 const f=pagedFrame(frame),c=context(scope,pins,id,'content-part');ensure(same(f.context,c),'LOCAL_CONTEXT_MISMATCH');const plain=decrypt(un64(f.ciphertext),aad(c),un64(f.nonce),key);
 try{const p=syncValue('local-part',strictJson(plain,360448));ensure(p.index===String(index),'INTEGRITY_FAILURE');const bytes=un64(p.record_bytes);ensure(bytes.length>0&&bytes.length<=262144&&String(bytes.length)===p.bytes&&hash(bytes)===p.digest,'INTEGRITY_FAILURE');return bytes;}finally{sodium.memzero(plain);}
}
export function preparePaged(scope,pins,id,kind,data,key){
 const publicData=structuredClone(data),privateData=kind==='group-evidence'&&publicData.pending_key?{pending_key:publicData.pending_key}:null;delete publicData.pending_key;
 const bytes=canonicalBytes(wire(publicData)),parts=[],records=[];ensure(bytes.length>0&&bytes.length<=33554432,'RESOURCE_LIMIT');
 try{
  for(let start=0;start<bytes.length;start+=262144){const chunk=bytes.subarray(start,start+262144),record_id=b64(sodium.randombytes_buf(16)),frame=sealPart(scope,pins,record_id,parts.length,chunk,key);records.push({id:record_id,frame});parts.push({record_id,digest:hash(chunk),bytes:String(chunk.length)});
  }
  const manifest=syncValue('manifest',{purpose:'paged-content-manifest',version:1,kind,parts,digest:hash(bytes),bytes:String(bytes.length),private:privateData});return {frame:sealManifest(scope,pins,id,kind,manifest,key),records};
 }finally{sodium.memzero(bytes);if(privateData)privateData.pending_key.group_secret='';}
}
export async function readPaged(frame,scope,pins,id,kind,key,read){
 const manifest=openManifest(frame,scope,pins,id,kind,key),chunks=[];let length=0;
 try{
  for(let index=0;index<manifest.parts.length;index++){const p=manifest.parts[index],row=await read(p.record_id);ensure(row,'RECORD_NOT_FOUND');const bytes=openPart(row.frame,scope,pins,p.record_id,index,key);ensure(String(bytes.length)===p.bytes&&bytes.length<=262144&&hash(bytes)===p.digest&&(index===manifest.parts.length-1||bytes.length===262144),'INTEGRITY_FAILURE');chunks.push(bytes);length+=bytes.length;
  }
  ensure(String(length)===manifest.bytes,'INTEGRITY_FAILURE');const all=Buffer.concat(chunks);try{ensure(hash(all)===manifest.digest,'INTEGRITY_FAILURE');const value=strictJson(all,33554432);if(manifest.private){ensure(!Object.hasOwn(value,'pending_key'),'INTEGRITY_FAILURE');value.pending_key=structuredClone(manifest.private.pending_key);}return value;}finally{sodium.memzero(all);}
 }finally{for(const p of chunks)sodium.memzero(p);if(manifest.private)manifest.private.pending_key.group_secret='';}
}

export function rotatePagedFrame(frame,scope,pins,id,key,nextKey){
 if(frame.context.record_kind!=='content-part'){const m=openManifest(frame,scope,pins,id,frame.context.record_kind,key);try{return sealManifest(scope,pins,id,frame.context.record_kind,m,nextKey);}finally{if(m.private)m.private.pending_key.group_secret='';}}
 const f=pagedFrame(frame),c=context(scope,pins,id,'content-part');ensure(same(f.context,c),'LOCAL_CONTEXT_MISMATCH');const plain=decrypt(un64(f.ciphertext),aad(c),un64(f.nonce),key);
 try{const p=syncValue('local-part',strictJson(plain,360448));ensure(BigInt(p.index)<128n,'INTEGRITY_FAILURE');const bytes=openPart(frame,scope,pins,id,Number(p.index),key);try{return sealPart(scope,pins,id,Number(p.index),bytes,nextKey);}finally{sodium.memzero(bytes);}}finally{sodium.memzero(plain);}
}
