// Explicit temporary plaintext export exception; never the normal cache.
const PREFIX='anynote-p01-export-', MARKER='AnyNote P01 explicit synthetic export';
const records=new Map();
export async function prepareExport(call) {
  const id=PREFIX+crypto.randomUUID().replaceAll('-','');
  const root=await navigator.storage.getDirectory(),directory=await root.getDirectoryHandle(id,{create:true});
  try{
    const marker=await(await directory.getFileHandle('purpose.marker',{create:true})).createWritable();
    try{await marker.write(MARKER);await marker.close();}
    catch(error){await marker.abort().catch(()=>{});throw error;}
    const sink=await directory.getFileHandle('synthetic-export.bin',{create:true});
    const result=await call({kind:'export',sink});
    const file=await sink.getFile();
    if(result.status!=='VERIFIED_EXPORT'||file.size!==result.bytes)throw new Error('Unverified export cannot be shared');
    // This File is a descriptor for an existing verified disk file, not concatenated plaintext buffers.
    records.set(id,{file,result});
    return {id,bytes:file.size,sha256:result.sha256,
      can_share_file:typeof navigator.canShare==='function'&&navigator.canShare({files:[file]}),
      status:'VERIFIED_TEMPORARY_EXPORT',files_destination:'NOT VERIFIED'};
  }catch(error){await root.removeEntry(id,{recursive:true});throw error;}
}
export async function discardExport(id) {
  if(!new RegExp(`^${PREFIX}[0-9a-f]{32}$`).test(id))throw new Error('Invalid export owner');
  records.delete(id);
  try{await(await navigator.storage.getDirectory()).removeEntry(id,{recursive:true});}
  catch(error){if(error.name!=='NotFoundError')throw error;}
}
export async function shareExport(id) {
  const item=records.get(id);
  if(!item)throw new Error('No verified export to share');
  try{
    if(typeof navigator.share!=='function'||!navigator.canShare?.({files:[item.file]})){
      throw new Error('BLOCKED: Web Share of the verified disk File is unavailable; no whole-file Blob fallback');
    }
    // Called from a separate explicit click to preserve transient user activation.
    await navigator.share({files:[item.file],title:'AnyNote P01 synthetic export'});
    return {status:'SHARE_COMPLETED',files_destination:'NOT VERIFIED: independently inspect/hash the actual Files output',
      bytes:item.file.size,sha256:item.result.sha256};
  }finally{await discardExport(id);}
}
export async function removeOrphans() {
  const root=await navigator.storage.getDirectory();let removed=0;
  for await(const [name,handle] of root.entries()){
    if(handle.kind!=='directory'||!/^anynote-p01-export-[0-9a-f]{32}$/.test(name))continue;
    let marker;
    try{const file=await(await handle.getFileHandle('purpose.marker')).getFile();if(file.size>128)continue;marker=await file.text();}
    catch(error){if(error.name==='NotFoundError')continue;throw error;}
    if(marker!==MARKER)continue;
    await discardExport(name);removed++;
  }
  return {removed,scope:'Only marked explicit synthetic export directories; no secure-erasure guarantee'};
}
