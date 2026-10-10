import { sodium } from './crypto.mjs';
import { derive } from './local-unlock.mjs';
import { capabilities, writeStorage, inspectStorage, cleanupStorage } from './storage.mjs';

const MAX = 1000000000, CHUNK = 8388608;
let busy = false, generation = 0;
let staged; // Test-only live file/key state, never a durable production transfer session.
function locked() {
  generation++;
  if (staged) sodium.memzero(staged.key);
  staged = null;
}
const digest = (bytes) => sodium.to_hex(sodium.crypto_hash_sha256(bytes));
function sizeCheck(source) {
  if (!(source instanceof Blob) || source.size > MAX) throw new Error('Select a synthetic file of at most 1,000,000,000 bytes');
}
function current(expected) { if (generation !== expected) throw new Error('PAUSED_LOCKED: restart with fresh keys after lifecycle interruption'); }
async function upload(source, origin) {
  sizeCheck(source); locked();
  const count = Math.ceil(source.size / CHUNK), key = sodium.randombytes_buf(32), prefix = sodium.randombytes_buf(16);
  const run = generation, inputHash = sodium.crypto_hash_sha256_init(), chunks = [];
  try {
    for (let index=0; index<count; index++) {
      current(run);
      const clear = new Uint8Array(await source.slice(index*CHUNK, Math.min((index+1)*CHUNK,source.size)).arrayBuffer());
      current(run); sodium.crypto_hash_sha256_update(inputHash,clear);
      const nonce = new Uint8Array(24);nonce.set(prefix);new DataView(nonce.buffer).setBigUint64(16,BigInt(index),true);
      const aad = sodium.from_string(`AnyNote.P01.PhysicalFile.v1/${index}/${count}/${source.size}/${clear.length}`);
      let cipher;
      try { cipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(clear,aad,null,nonce,key); }
      finally { sodium.memzero(clear); }
      const response = await fetch(`${origin}/ciphertext/${index}`, {method:'PUT',body:cipher});
      current(run); if (!response.ok) throw new Error(`Upload stopped at part ${index}; restart server/session before retry`);
      chunks.push({nonce, aad, bytes:cipher.length, sha256:digest(cipher)});
      postMessage({kind:'progress',phase:'encrypt-upload',index:index+1,count});
    }
    current(run);
    staged = {key,prefix,chunks,size:source.size,sha256:sodium.to_hex(sodium.crypto_hash_sha256_final(inputHash)),origin};
    return {status:'UPLOADED',bytes:source.size,chunks:count,sha256:staged.sha256,
      limitation:'Live local experimental key/inventory only; no production manifest, recipient trust or resume.'};
  } catch (error) { sodium.memzero(key); throw error; }
}
async function exportFile(sink) {
  if (!staged || !sink || sink.kind !== 'file' || typeof sink.createWritable !== 'function') throw new Error('No live upload or bounded explicit export sink');
  const prepared=staged,run=generation, outputHash=sodium.crypto_hash_sha256_init();
  const writer=await sink.createWritable(); let total=0;
  try {
    for (const [index, item] of prepared.chunks.entries()) {
      current(run);
      const response=await fetch(`${prepared.origin}/ciphertext/${index}`,{cache:'no-store'});
      const length=Number(response.headers.get('Content-Length'));
      if (!response.ok || length!==item.bytes || length>CHUNK+16) throw new Error('Invalid bounded ciphertext response');
      const cipher=new Uint8Array(await response.arrayBuffer());current(run);
      if (cipher.length!==item.bytes || digest(cipher)!==item.sha256) throw new Error('Ciphertext integrity mismatch');
      const clear=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,cipher,item.aad,item.nonce,prepared.key);
      try {sodium.crypto_hash_sha256_update(outputHash,clear);await writer.write(clear);total+=clear.length;}
      finally {sodium.memzero(clear);}
      current(run);postMessage({kind:'progress',phase:'download-decrypt-export',index:index+1,count:prepared.chunks.length});
    }
    if (total!==prepared.size || sodium.to_hex(sodium.crypto_hash_sha256_final(outputHash))!==prepared.sha256) throw new Error('Full export integrity mismatch');
    current(run);await writer.close();current(run);
    return {status:'VERIFIED_EXPORT',bytes:total,sha256:prepared.sha256,
      limitation:'Sink type/actual Files output must be recorded separately. OPFS test staging is not iOS Files.'};
  } catch (error) {await writer.abort().catch(()=>{});throw error;}
}
self.onmessage=async({data})=>{
  // Lock messages bypass the busy guard and invalidate in-flight replies/keys.
  if(data.kind==='lock'){locked();postMessage({kind:'locked'});return;}
  if(busy){postMessage({kind:'error',message:'Experiment busy'});return;}
  busy=true;
  try {
    await sodium.ready; let result;
    if(data.kind==='capabilities')result=await capabilities();
    else if(data.kind==='kdf')result=await derive(data.request);
    else if(data.kind==='storage'){
      const stored=await writeStorage();
      try{result=await inspectStorage(stored);}finally{await cleanupStorage(stored.id);}
    }else if(data.kind==='upload')result=await upload(data.source,self.location.origin);
    else if(data.kind==='export')result=await exportFile(data.sink);
    else if(data.kind==='reselect') {
      sizeCheck(data.source); if(!staged || data.source.size!==staged.size)throw new Error('Source changed; restart with fresh keys');
      const state=sodium.crypto_hash_sha256_init(),run=generation;
      for(let offset=0;offset<data.source.size;offset+=CHUNK){current(run);const bytes=new Uint8Array(await data.source.slice(offset,offset+CHUNK).arrayBuffer());current(run);sodium.crypto_hash_sha256_update(state,bytes);sodium.memzero(bytes);}
      if(sodium.to_hex(sodium.crypto_hash_sha256_final(state))!==staged.sha256)throw new Error('Source changed; restart with fresh keys');
      result={status:'SOURCE_MATCHES',resume:'NOT IMPLEMENTED; matching source is only a prerequisite'};
    }else throw new Error('Unknown experiment operation');
    postMessage({kind:'result',result});
  }catch(error){postMessage({kind:'error',message:String(error.message)});}
  finally{busy=false;}
};
