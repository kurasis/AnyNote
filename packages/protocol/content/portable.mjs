// Standard age outer stream; provisional metadata stays in memory. No live writes here.
import {encryptArchive,decryptArchive,streamFromIterator,independentExportIdentity} from '../../content-browser/age.mjs';
import {exportEntries,tarEntries,parseTar,pageCommitment,itemKind} from './archive.mjs';
import {ensure} from '../vault/store.mjs';
import {sodium,hash,b64,un64} from '../adapters/primitives.mjs';
import {createHash} from '../adapters/bytes.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {common,decode,encode,digest,signingInput} from '../adapters/codecs/protocol-codec.mjs';
import {certificateDetails,identityDetails,senderForCertificate} from '../devices/proofs.mjs';
import {activeCertificateForEvaluation,rosterDetails} from '../devices/roster.mjs';
import {verifyPortableEvidence} from './authority.mjs';
import {assemblePublicEvidence} from './evidence.mjs';
import {openExportedObject} from '../adapters/objects.mjs';
import {decode as fileDecode,checkManifestCiphertext,checkFileBundle,fileAad,chunkNonce,envelopeDigest} from '../adapters/codecs/codec.mjs';
import {strictJson} from '../src/strict-json.mjs';

export async function writePortable({header,entries,signer,sign,sink,kit,authorize=()=>{}}){
 const independent=await independentExportIdentity(),h=createHash('sha256');let bytes=0n,finished=false;
 try{const outer=await encryptArchive(streamFromIterator(tarEntries(exportEntries(wire(header),entries,signer,sign)),authorize),independent.recipient);
  for await(const part of outer){await authorize();bytes+=BigInt(part.length);ensure(bytes<=116010000000n,'RESOURCE_LIMIT');h.update(part);await sink.write(part);}
  const document=decode('export-kit',wire({...common('export-recovery-document'),...kit,export_id:header.export_id,archive_sha256:h.digest('base64url'),export_identity:independent.identity}));
  await sink.finish();finished=true;return {kit:document,archive_bytes:String(bytes),recipient:independent.recipient};
 }finally{independent.identity='';if(!finished)await sink.abort();}
}
async function scan(source,kit,visit){
 const digest=createHash('sha256');const raw=source();ensure(raw instanceof ReadableStream,'SEEKABLE_ARCHIVE_REQUIRED');
 const hashed=raw.pipeThrough(new TransformStream({transform(part,c){ensure(part instanceof Uint8Array&&part.length<=8388624,'RESOURCE_LIMIT');digest.update(part);c.enqueue(part);}}));
 const plain=await decryptArchive(hashed,kit.export_identity);await parseTar(plain,visit);ensure(digest.digest('base64url')===kit.archive_sha256,'ARCHIVE_DIGEST_MISMATCH');
}
function clear(value){if(value instanceof Uint8Array)value.fill(0);else if(value&&typeof value==='object')for(const key of Object.keys(value)){clear(value[key]);if(typeof value[key]==='string')value[key]='';}}
export class PortableReader{
 #kit;#source;#items;#header;#notes;#noteReaders;#files;#closed=false;
 constructor(source,kit){this.#source=source;this.#kit=decode('export-kit',wire(kit));}
 close(){this.#closed=true;clear(this.#kit);clear(this.#notes);if(this.#noteReaders)for(const note of this.#noteReaders.values())clear(note.key);this.#noteReaders?.clear();if(this.#files)for(const file of this.#files.values()){clear(file.key);clear(file.manifest);}this.#items?.clear();this.#source=undefined;}
 async validate(){
  ensure(!this.#closed,'VAULT_LOCKED');let metadataBytes=0,first=true,footer,header;const items=new Map(),pages=[],metadata=[],order=[];
  try{await scan(this.#source,this.#kit,({path,bytes})=>{
   if(first){ensure(path==='export-header.json','EXPORT_ORDER_MISMATCH');header=decode('export-header',bytes);first=false;return;}
   ensure(!footer,'EXPORT_ORDER_MISMATCH');if(path==='export-footer.json'){footer=decode('export-footer',bytes);return;}
   if(path.startsWith('inventory/')){ensure(path==='inventory/'+String(pages.length).padStart(8,'0')+'.json','INVALID_PAGE_ORDER');metadataBytes+=bytes.length;pages.push(new Uint8Array(bytes));}
   else{ensure(pages.length===0&&!items.has(path),'UNORDERED_OR_DUPLICATE');ensure(!order.length||path>order.at(-1),'UNORDERED_OR_DUPLICATE');order.push(path);items.set(path,{path,size:String(bytes.length),digest:hash(bytes),kind:itemKind(path)});
    if(!path.startsWith('files/')){
     if(path.startsWith('records/')){const raw=strictJson(bytes,4194304),record=decode(raw.payload_status==='pruned'?'export-pruned-record':raw.record_kind==='file-manifest'?'export-file-record':'bundle',bytes);if(record.ciphertext!==undefined){record.ciphertext='';}metadataBytes+=wire(record).length;metadata.push({path,record});}
     else{metadataBytes+=bytes.length;metadata.push({path,bytes:new Uint8Array(bytes)});}
    }}
   ensure(metadataBytes<=67108864&&items.size<=4000000,'RESOURCE_LIMIT');
  });
  ensure(header&&footer,'EXPORT_TRUNCATED');const body=footer.body,c=pageCommitment('export',pages),listed=pages.flatMap(p=>decode('export-page',p).items);
  ensure(body.export_id===header.export_id&&header.export_id===this.#kit.export_id&&header.root_fingerprint===this.#kit.exporter_root_fingerprint&&header.snapshot.snapshot_purpose==='export'&&header.snapshot.account_id===header.account_id&&header.snapshot.device_id===body.signer.device_id,'EXPORT_CONTEXT_MISMATCH');
  ensure(body.header_digest===digest('export-header',wire(header))&&same(c,{inventory_digest:body.inventory_digest,page_count:body.page_count,item_count:body.item_count}),'EXPORT_INVENTORY_MISMATCH');
  ensure(listed.length===items.size&&same(order,listed.map(x=>x.path))&&listed.every(row=>same(row,items.get(row.path)))&&listed.reduce((n,x)=>n+BigInt(x.size),0n)===BigInt(body.total_item_bytes),'EXPORT_ITEM_MISMATCH');
  const proofs=verifyPortableEvidence(assemblePublicEvidence(metadata),this.#kit),who=identityDetails(proofs.exporter.identity);ensure(who.body.account_id===header.account_id&&who.body.service_id===header.service_id,'EXPORT_IDENTITY_MISMATCH');
  const certificate=activeCertificateForEvaluation(proofs.exporter.roster,body.signer.device_id,'sign-content'),sender=senderForCertificate(certificate,rosterDetails(proofs.exporter.roster).head);
  ensure(same(body.signer,{account_id:sender.account_id,device_id:sender.device_id,root_fingerprint:sender.root_fingerprint,recovery_generation:sender.recovery_generation,roster:sender.roster_head}),'EXPORT_SIGNER_MISMATCH');
  ensure(sodium.crypto_sign_verify_detached(un64(footer.signature),signingInput('export-footer-body',wire(body)),un64(certificateDetails(certificate).body.device_signing_key)),'EXPORT_SIGNATURE_INVALID');
  const sourcePages=metadata.filter(x=>x.path.startsWith('snapshots/'));sourcePages.forEach((x,i)=>ensure(x.path==='snapshots/'+String(i).padStart(8,'0')+'.json','INVALID_PAGE_ORDER'));
  const sourceCommitment=pageCommitment('snapshot',sourcePages.map(x=>x.bytes));ensure(same(sourceCommitment,{inventory_digest:header.snapshot.inventory_digest,page_count:header.snapshot.page_count,item_count:header.snapshot.item_count}),'EXPORT_SOURCE_MISMATCH');
  const sources=new Map();for(const page of sourcePages)for(const row of decode('snapshot-page',page.bytes).items){ensure(!sources.has(row.revision_id),'DUPLICATE_REVISION_ID');sources.set(row.revision_id,row);}
  const keys=new Map();for(const x of metadata.filter(x=>x.path.startsWith('keys/'))){const key=decode('export-key',x.bytes);ensure(x.path==='keys/'+key.revision_id+'.json'&&!keys.has(key.revision_id),'EXPORT_KEY_MISMATCH');keys.set(key.revision_id,key);}
  const notes=[],noteReaders=new Map(),files=new Map(),usedChunks=new Set();
  for(const x of metadata.filter(x=>x.path.startsWith('records/'))){const record=structuredClone(x.record),isFile=record.record_kind==='file-manifest',pruned=record.payload_status==='pruned',context=record.envelope.header.context,revision=isFile?context.file_version_id:context.revision_id,object=isFile?context.file_id:context.object_id,source=sources.get(revision),group=proofs.groups.get(context.group_id),key=keys.get(revision);
   ensure(x.path==='records/'+revision+'.json'&&group&&header.selection.group_ids.includes(context.group_id),'EXPORT_SELECTION_MISMATCH');ensure(source&&source.group_id===context.group_id&&source.object_id===object&&source.object_kind===(isFile?'file-manifest':context.object_kind)&&source.envelope_digest===(isFile?envelopeDigest(wire(record.envelope)):digest('envelope',wire(record.envelope)))&&source.payload_status===(pruned?'pruned':context.action==='soft-delete'?'tombstone':'retained'),'EXPORT_SOURCE_MISMATCH');sources.delete(revision);
   ensure(header.selection.include_trash||source.payload_status!=='tombstone','EXPORT_SELECTION_MISMATCH');
   const authority=isFile?proofs.g.checkHistoricalFileForEvaluation(group,wire(record.envelope),sender):proofs.g.checkHistoricalObjectForEvaluation(group,wire(record.envelope),sender);
   if(pruned){ensure(!key,'EXPORT_KEY_MISMATCH');notes.push({context,payload_status:'pruned'});continue;}
   ensure(key&&key.service_id===context.service_id&&key.group_id===context.group_id&&key.object_id===object&&key.key_kind===(isFile?'manifest-and-file-deks':'object-dek'),'EXPORT_KEY_MISMATCH');keys.delete(revision);
   if(isFile){const h=record.envelope.header,cipher=un64(record.manifest_ciphertext);checkManifestCiphertext(wire(h),cipher);const plain=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,cipher,fileAad(wire(h),'manifest-aad'),un64(h.manifest_nonce),un64(key.object_dek));let manifest;try{manifest=fileDecode('manifest',plain);checkFileBundle(wire(h),wire(record.wrap),plain,wire(context));ensure(manifest.file_data_key===key.file_data_dek,'EXPORT_KEY_MISMATCH');}finally{plain.fill(0);}
    for(let i=0;i<Number(h.framing.chunk_count);i++){const path='files/'+revision+'/'+String(i).padStart(8,'0')+'.bin',chunk=items.get(path),part=h.framing.parts[i];ensure(chunk&&chunk.digest===part.ciphertext_digest&&chunk.size===part.ciphertext_bytes,'EXPORT_CHUNK_MISSING');usedChunks.add(path);}files.set(revision,{record,key,manifest,next:0,bytes:0,plaintext_parts:[],digest:createHash('sha256')});
   }else{noteReaders.set(revision,{key,context,public_key:certificateDetails(authority.certificate).body.device_signing_key});notes.push({context,payload_status:'retained'});}
  }
  ensure(sources.size===0&&keys.size===0,'EXPORT_SOURCE_INCOMPLETE');ensure([...items.keys()].filter(p=>p.startsWith('files/')).every(p=>usedChunks.has(p)),'EXPORT_UNUSED_CHUNK');
  // Authenticate every chunk and the full plaintext digest before exposing recovered data.
  await scan(this.#source,this.#kit,({path,bytes})=>{ensure(path==='export-header.json'||path==='export-footer.json'||path.startsWith('inventory/')||hash(bytes)===items.get(path)?.digest,'EXPORT_ITEM_MISMATCH');if(path.startsWith('records/')){const revision=path.split('/')[1].slice(0,-5),note=noteReaders.get(revision);if(note){const payload=openExportedObject(bytes,un64(note.key.object_dek),un64(note.public_key),wire(note.context));clear(payload);}return;}if(!path.startsWith('files/'))return;const [,revision,indexText]=path.split('/'),file=files.get(revision),index=Number(indexText.slice(0,-4));ensure(file&&file.next===index,'INVALID_CHUNK_INDEX');const plain=this.#decrypt(file,index,bytes);try{file.digest.update(plain);file.plaintext_parts.push(hash(plain));file.bytes+=plain.length;file.next++;}finally{plain.fill(0);}});
  for(const file of files.values())ensure(file.next===Number(file.record.envelope.header.framing.chunk_count)&&file.bytes===Number(file.record.envelope.header.framing.plaintext_bytes)&&file.digest.digest('base64url')===file.manifest.plaintext_digest,'PLAINTEXT_MISMATCH');
  ensure(!this.#closed,'VAULT_LOCKED');this.#items=items;this.#header=header;this.#notes=notes;this.#noteReaders=noteReaders;this.#files=files;return {status:'VERIFIED_OFFLINE',header:structuredClone(header),notes:notes.map(n=>({context:structuredClone(n.context),payload_status:n.payload_status})),files:[...files].map(([revision,f])=>({file_version_id:revision,original_name:f.manifest.original_name,plaintext_bytes:f.record.envelope.header.framing.plaintext_bytes})),live_destination_mutations:0};
  }catch(error){this.close();throw error;}finally{for(const x of metadata){x.bytes?.fill(0);clear(x.record);}for(const p of pages)p.fill(0);}
 }
 #decrypt(file,index,cipher){const h=file.record.envelope.header,part=h.framing.parts[index];ensure(part&&cipher.length===Number(part.ciphertext_bytes)&&hash(cipher)===part.ciphertext_digest,'CHUNK_DIGEST_MISMATCH');return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,cipher,fileAad(wire(h),'chunk-aad',BigInt(index)),chunkNonce(un64(file.manifest.nonce_prefix),BigInt(index)),un64(file.key.file_data_dek));}
 notes(){ensure(this.#notes&&!this.#closed,'EXPORT_NOT_VALIDATED');return structuredClone(this.#notes);}
 fileSource(version){ensure(this.#files&&!this.#closed,'EXPORT_NOT_VALIDATED');const file=this.#files.get(version);ensure(file,'NOT_FOUND');return {size:Number(file.record.envelope.header.framing.plaintext_bytes),parts:[...file.plaintext_parts],digest:file.manifest.plaintext_digest};}
 async recover(visitor){
  ensure(this.#items&&this.#noteReaders&&!this.#closed,'EXPORT_NOT_VALIDATED');const seen=new Set(),files=new Map([...this.#files].map(([id,file])=>[id,{file,next:0,bytes:0,digest:createHash('sha256'),started:false}]));
  for(const [id,state]of files)if(state.file.record.envelope.header.framing.chunk_count==='0'){await visitor.fileStart?.(id,structuredClone(state.file.record.envelope.header.context),{name:state.file.manifest.original_name,bytes:0});await visitor.fileFinish?.(id);state.started=true;}
  await scan(this.#source,this.#kit,async({path,bytes})=>{
   ensure(!this.#closed,'VAULT_LOCKED');if(path==='export-header.json'||path==='export-footer.json'||path.startsWith('inventory/'))return;
   ensure(!seen.has(path)&&hash(bytes)===this.#items.get(path)?.digest,'EXPORT_ITEM_MISMATCH');seen.add(path);
   if(path.startsWith('files/')){const [,id,indexText]=path.split('/'),state=files.get(id),index=Number(indexText.slice(0,-4));ensure(state&&index===state.next,'INVALID_CHUNK_INDEX');if(!state.started){await visitor.fileStart?.(id,structuredClone(state.file.record.envelope.header.context),{name:state.file.manifest.original_name,bytes:Number(state.file.record.envelope.header.framing.plaintext_bytes)});state.started=true;}const plain=this.#decrypt(state.file,index,bytes);try{state.digest.update(plain);state.bytes+=plain.length;state.next++;await visitor.filePart?.(id,index,plain);}finally{plain.fill(0);}if(state.next===Number(state.file.record.envelope.header.framing.chunk_count)){ensure(state.bytes===Number(state.file.record.envelope.header.framing.plaintext_bytes)&&state.digest.digest('base64url')===state.file.manifest.plaintext_digest,'PLAINTEXT_MISMATCH');await visitor.fileFinish?.(id);}return;}
   if(path.startsWith('records/')){const id=path.split('/')[1].slice(0,-5),note=this.#noteReaders.get(id);if(note){const payload=openExportedObject(bytes,un64(note.key.object_dek),un64(note.public_key),wire(note.context));try{await visitor.note?.(id,payload);}finally{clear(payload);}}}
  });ensure(seen.size===this.#items.size&&[...files.values()].every(s=>s.next===Number(s.file.record.envelope.header.framing.chunk_count)),'EXPORT_SOURCE_INCOMPLETE');return {verified:true,live_mutation_policy:'validated immutable input plus fresh destination custody coordinator'};
 }
 async note(revision){ensure(this.#noteReaders&&!this.#closed,'EXPORT_NOT_VALIDATED');const note=this.#noteReaders.get(revision);ensure(note,'PAYLOAD_UNAVAILABLE');let payload;try{await scan(this.#source,this.#kit,({path,bytes})=>{if(path!=='records/'+revision+'.json')return;ensure(hash(bytes)===this.#items.get(path)?.digest&&!payload,'EXPORT_ITEM_MISMATCH');payload=openExportedObject(bytes,un64(note.key.object_dek),un64(note.public_key),wire(note.context));});ensure(payload&&!this.#closed,'EXPORT_NOT_VALIDATED');return {context:structuredClone(note.context),payload,payload_status:'retained'};}catch(e){clear(payload);throw e;}}
 async file(version,sink){ensure(this.#files&&!this.#closed,'EXPORT_NOT_VALIDATED');const file=this.#files.get(version);ensure(file,'NOT_FOUND');let next=0,finished=false;try{await scan(this.#source,this.#kit,async({path,bytes})=>{if(!path.startsWith('files/'+version+'/'))return;const index=Number(path.split('/')[2].slice(0,-4));ensure(index===next++&&!this.#closed,'INVALID_CHUNK_INDEX');const plain=this.#decrypt(file,index,bytes);try{await sink.write(plain);}finally{plain.fill(0);}});ensure(next===Number(file.record.envelope.header.framing.chunk_count),'INCOMPLETE_FILE');await sink.finish();finished=true;}finally{if(!finished)await sink.abort();}}
}
