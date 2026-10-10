// Isolated synthetic OPFS transaction adapter. Never a production filesystem API.
export const PREFIX='anynote-p01-device-', MARKER='AnyNote P01 disposable synthetic device kit';
export async function createTrial() {
  const root=await navigator.storage.getDirectory(),id=PREFIX+crypto.randomUUID().replaceAll('-','');
  const directory=await root.getDirectoryHandle(id,{create:true});
  try{
  const marker=await(await directory.getFileHandle('purpose.marker',{create:true})).createSyncAccessHandle();
  try{const bytes=new TextEncoder().encode(MARKER);if(marker.write(bytes)!==bytes.length)throw new Error('Short marker write');marker.flush();}finally{marker.close();}
  return {id,directory};
  }catch(error){await root.removeEntry(id,{recursive:true});throw error;}
}
export async function removeTrial(id) {
  if(!/^anynote-p01-device-[0-9a-f]{32}$/.test(id))throw new Error('Invalid synthetic owner');
  try{await(await navigator.storage.getDirectory()).removeEntry(id,{recursive:true});}
  catch(error){if(error.name!=='NotFoundError')throw error;}
}
export async function openTrialOutput(id,name) {
  if(!/^anynote-p01-device-[0-9a-f]{32}$/.test(id)
    ||!/^synthetic-export-[0-9a-f-]{36}\.bin$/.test(name))throw new Error('Invalid synthetic export');
  const directory=await(await navigator.storage.getDirectory()).getDirectoryHandle(id);
  const marker=await(await directory.getFileHandle('purpose.marker')).getFile();
  if(marker.size>128||await marker.text()!==MARKER)throw new Error('Synthetic purpose marker mismatch');
  const file=await(await directory.getFileHandle(name)).getFile();
  if(file.size!==1000000000)throw new Error('Synthetic export must be exactly 1 GB');
  return file;
}
export async function removeTrialOrphans(retain) {
  const root=await navigator.storage.getDirectory();let removed=0;
  for await(const [id,handle]of root.entries()){
    if(id===retain||handle.kind!=='directory'||!/^anynote-p01-device-[0-9a-f]{32}$/.test(id))continue;
    try{const file=await(await handle.getFileHandle('purpose.marker')).getFile();
      if(file.size>128||await file.text()!==MARKER)continue;
    }catch(error){if(error.name==='NotFoundError')continue;throw error;}
    await removeTrial(id);removed++;
  }
  return removed;
}
export async function writeBytes(directory,name,bytes) {
  const file=await directory.getFileHandle(name,{create:true}),access=await file.createSyncAccessHandle();
  try{access.truncate(0);if(access.write(bytes,{at:0})!==bytes.length)throw new Error('Short OPFS write');access.flush();}
  finally{access.close();}
  return file;
}
export function diskSink(directory) {
  let committed;
  return {kind:'file',getFile:async()=>{
    if(!committed)throw new Error('No committed synthetic output');return committed.getFile();
  },createWritable:async()=>{
    const name=`synthetic-export-${crypto.randomUUID()}.bin`;
    const file=await directory.getFileHandle(name,{create:true}),access=await file.createSyncAccessHandle();
    let offset=0,closed=false;
    const finish=()=>{if(!closed){closed=true;access.close();}};
    return {write:async(bytes)=>{
      if(closed)throw new Error('Closed synthetic writer');
      if(access.write(bytes,{at:offset})!==bytes.length)throw new Error('Short export write');offset+=bytes.length;
    },close:async()=>{
      if(closed)throw new Error('Closed synthetic writer');access.flush();finish();
      // Commit an in-memory alias only after verified close. No production path/rename guarantee.
      const previous=committed;committed=file;
      if(previous)await directory.removeEntry(previous.name);
    },abort:async()=>{finish();await directory.removeEntry(name);}};
  }};
}
