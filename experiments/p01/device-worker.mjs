import {sodium,verifyFixture} from './crypto.mjs';
import {derive,invalidProfiles,validateProfile} from './local-unlock.mjs';
import {capabilities,writeStorage,inspectStorage,cleanupStorage,deniedWrite} from './storage.mjs';
import {upload,exportFile,locked} from './physical-worker.mjs';
import {createTrial,removeTrial,removeTrialOrphans,openTrialOutput,writeBytes,diskSink} from './device-disk.mjs';
import rustFixture from './fixtures/rust.json';
import nodeFixture from './fixtures/node.json';
import browserFixture from './fixtures/browser-worker.json';
import kdfFixture from './fixtures/argon2id.json';

const CHUNK=8388608,MAX=1000000000;
let active=false,version=0,owned,transport,fault;
const originalFetch=self.fetch;
// This worker alone substitutes a bounded local ciphertext sink. No network upload is claimed.
self.fetch=async(url,options={})=>{
  const match=/^https?:\/\/[^/]+\/ciphertext\/(\d+)$/.exec(String(url));
  if(!match)return originalFetch(url,options);
  if(!transport)throw new Error('No owned local ciphertext transport');
  const index=Number(match[1]);if(!Number.isSafeInteger(index)||index<0||index>=120)throw new Error('Invalid part');
  if(options.method==='PUT'){
    const bytes=options.body;
    if(!(bytes instanceof Uint8Array)||bytes.length<16||bytes.length>CHUNK+16)throw new Error('Invalid bounded part');
    await writeBytes(transport,String(index),bytes);return new Response(null,{status:201});
  }
  const file=await(await transport.getFileHandle(String(index))).getFile();
  if(file.size<16||file.size>CHUNK+16)throw new Error('Invalid stored part');
  let body=file.stream();
  if(fault?.index===index){
    const mode=fault.mode;fault=null;
    const bytes=new Uint8Array(await file.arrayBuffer());
    if(mode==='corrupt'){bytes[0]^=1;body=bytes;}
    else if(mode==='truncate')body=bytes.subarray(0,bytes.length-1);
    else if(mode==='overflow'){
      body=new ReadableStream({start(controller){controller.enqueue(bytes);controller.enqueue(new Uint8Array(1));controller.close();}});
    }else throw new Error('Unknown local fault');
  }
  return new Response(body,{headers:{'Content-Length':String(file.size)}});
};
function progress(phase,index=0,count=0){postMessage({kind:'progress',phase,index,count});}
function current(run){if(run!==version)throw new Error('PAUSED_LOCKED: foreground restart required');}
async function hashFile(file,run){
  const hash=sodium.crypto_hash_sha256_init();
  for(let offset=0;offset<file.size;offset+=CHUNK){
    current(run);const bytes=new Uint8Array(await file.slice(offset,offset+CHUNK).arrayBuffer());
    try{sodium.crypto_hash_sha256_update(hash,bytes);}finally{sodium.memzero(bytes);}
    progress('verify-saved-file',Math.min(offset+CHUNK,file.size),file.size);
  }
  current(run);return sodium.to_hex(sodium.crypto_hash_sha256_final(hash));
}
async function generate(directory,size,run){
  const handle=await directory.getFileHandle('synthetic-source.bin',{create:true});
  const access=await handle.createSyncAccessHandle(),hash=sodium.crypto_hash_sha256_init();
  const buffer=new Uint8Array(Math.min(CHUNK,size));
  try{
    access.truncate(0);
    for(let offset=0;offset<size;offset+=CHUNK){
      current(run);const bytes=buffer.subarray(0,Math.min(CHUNK,size-offset));
      for(let part=0;part<bytes.length;part+=65536)crypto.getRandomValues(bytes.subarray(part,Math.min(part+65536,bytes.length)));
      if(access.write(bytes,{at:offset})!==bytes.length)throw new Error('Short synthetic source write');
      sodium.crypto_hash_sha256_update(hash,bytes);progress('generate-synthetic-file',Math.min(offset+bytes.length,size),size);
      // Yield to real lifecycle-lock messages; the source never lives as one large Blob.
      await new Promise(resolve=>setTimeout(resolve,0));
    }
    access.flush();
  }finally{sodium.memzero(buffer);access.close();}
  return {file:await handle.getFile(),sha256:sodium.to_hex(sodium.crypto_hash_sha256_final(hash))};
}
async function pipeline(size,run,report){
  current(run);const trial=await createTrial();owned=trial.id;
  try{
    transport=await trial.directory.getDirectoryHandle('ciphertext',{create:true});
    const source=await generate(trial.directory,size,run),sink=diskSink(trial.directory);
    const encrypted=await upload(source.file,self.location.origin);current(run);
    if(encrypted.sha256!==source.sha256)throw new Error('Independent source digest mismatch');
    const result=await exportFile(sink);current(run);
    const file=await sink.getFile();
    if(file.size!==size||await hashFile(file,run)!==source.sha256||result.sha256!==source.sha256)throw new Error('Saved disk output mismatch');
    report.files.push({status:'PASS',bytes:size,chunks:encrypted.chunks,sha256:source.sha256,
      transport:'LOCAL_OPFS_CIPHERTEXT_ONLY; no network request',export:'VERIFIED_OPFS_STAGING; Files not yet verified'});
    if(size===CHUNK+1){
      const baseline=await sink.getFile();
      for(const mode of ['corrupt','truncate','overflow']){
        fault={mode,index:1};let rejected=false;
        try{await exportFile(sink);}catch{rejected=true;}
        if(!rejected||await hashFile(await sink.getFile(),run)!==source.sha256||(await sink.getFile()).name!==baseline.name)throw new Error('Fault failed to preserve previous staged output');
        report.checks.push({name:`second-part-${mode}-abort-preserves-output`,status:'PASS'});
      }
      locked();let rejected=false;try{await exportFile(sink);}catch{rejected=true;}
      if(!rejected)throw new Error('Locked export unexpectedly succeeded');
      report.checks.push({name:'lock-invalidates-live-key',status:'PASS'});
    }
    locked();transport=null;
    if(size===MAX){
      await trial.directory.removeEntry('synthetic-source.bin');
      await trial.directory.removeEntry('ciphertext',{recursive:true});
      return {file,owner_id:trial.id};
    }
    await removeTrial(trial.id);owned=null;return null;
  }catch(error){locked();transport=null;await removeTrial(trial.id);owned=null;throw error;}
}
async function suite(report,run){
  await sodium.ready;
  report.capabilities=await capabilities();
  if(!self.isSecureContext||!report.capabilities.opfs||!report.capabilities.indexeddb)throw new Error('BLOCKED: trusted HTTPS, IndexedDB and OPFS required');
  if(typeof FileSystemFileHandle==='undefined'||typeof FileSystemFileHandle.prototype.createSyncAccessHandle!=='function')throw new Error('BLOCKED: worker OPFS synchronous access is unavailable');
  report.cleaned_orphans=await removeTrialOrphans();
  progress('cryptography');
  for(const fixture of [rustFixture,nodeFixture,browserFixture]){
    current(run);const result=await verifyFixture(fixture);
    report.checks.push({name:`frozen-${fixture.origin}-crypto`,status:'PASS',checks:result.checks.length});
  }
  progress('argon2id-64MiB');
  for(const item of kdfFixture.cases){
    current(run);const result=await derive(item.request);current(run);
    if(result.derived_hex!==item.derived_hex)throw new Error('Frozen Argon2id mismatch');
    report.checks.push({name:'public-argon2id-vector',status:'PASS',elapsed_ms:result.elapsed_ms,wasm_heap_bytes:result.wasm_heap_bytes});
  }
  for(const request of invalidProfiles(kdfFixture.cases[0].request)){
    let rejected=false;try{validateProfile(request);}catch{rejected=true;}
    if(!rejected)throw new Error('Invalid KDF profile admitted');
  }
  report.checks.push({name:'14-invalid-KDF-profiles',status:'PASS'});
  const stored=await writeStorage(async(file)=>{
    const access=await file.createSyncAccessHandle();let closed=false;
    const close=()=>{if(!closed){closed=true;access.close();}};
    return {write:async(bytes)=>{if(access.write(bytes,{at:0})!==bytes.length)throw new Error('Short ciphertext record write');},
      close:async()=>{access.flush();close();},abort:async()=>close()};
  });
  try{report.checks.push({name:'ciphertext-only-IDB-OPFS-reopen',...await inspectStorage(stored)});}
  finally{await cleanupStorage(stored.id);}
  report.checks.push({name:'actual-readonly-storage-denial',...await deniedWrite()});
  for(const size of [0,1,CHUNK+1])await pipeline(size,run,report);
  const estimate=await navigator.storage.estimate();
  report.large_storage_estimate=estimate;
  if(estimate.quota-estimate.usage<3100000000)throw new Error('BLOCKED: browser quota needs about 3.1 GB free for the exact 1 GB synthetic trial; no smaller substitution');
  return pipeline(MAX,run,report);
}
self.onmessage=async({data})=>{
  if(data.kind==='lock'){version++;locked();postMessage({kind:'locked'});return;}
  if(active){postMessage({kind:'error',message:'Device trial busy'});return;}
  active=true;const run=version;
  const report={version:1,status:'IN PROGRESS',physical_acceptance:false,
    checks:[],files:[],started_at:new Date().toISOString(),
    transport:'Local ciphertext-only OPFS adapter, not a network/backend test',
    opfs_commit:'Verified close publishes an in-memory disk-file alias; not a production atomic-path guarantee',
    files_destination:'NOT RUN',memory:'NOT MEASURED: WASM heap is not device process memory',
    remaining:['Network upload/download and resume','Actual device memory / older iPhone','Physical low-space fault','Passkeys/PRF and enrollment','Force-close/background recovery','PWA update with pending writes']};
  try{
    if(data.kind==='run'){
      const prepared=await suite(report,run);current(run);report.status='PASS_AUTOMATED_LOCAL_CHECKS';
      report.completed_at=new Date().toISOString();postMessage({kind:'result',report,...prepared});
    }else if(data.kind==='restore-export'){
      const file=await openTrialOutput(data.owner_id,data.name);owned=data.owner_id;
      await sodium.ready;
      if(await hashFile(file,run)!==data.sha256)throw new Error('Retained synthetic export digest mismatch');
      await removeTrialOrphans(owned);
      postMessage({kind:'result',file,owner_id:owned});
    }else if(data.kind==='verify-file'){
      if(!(data.file instanceof Blob)||data.file.size!==MAX)throw new Error('Saved Files output must be exactly 1,000,000,000 bytes');
      await sodium.ready;postMessage({kind:'result',result:{bytes:data.file.size,sha256:await hashFile(data.file,run)}});
    }else if(data.kind==='cleanup-orphans'){
      // Page owns the exclusive trial Web Lock; only exact marked synthetic dirs qualify.
      postMessage({kind:'result',result:{removed:await removeTrialOrphans()}});
    }else if(data.kind==='cleanup'){
      if(owned){await removeTrial(owned);owned=null;}
      postMessage({kind:'result',result:{status:'PASS',owned_temporary_export_removed:true}});
    }else throw new Error('Unknown device operation');
  }catch(error){
    locked();transport=null;
    if(owned&&data.kind!=='verify-file'){try{await removeTrial(owned);owned=null;}catch{report.cleanup='FAILED: restart and clean marked trial';}}
    report.status=String(error.message).startsWith('BLOCKED')?'BLOCKED':'FAIL';
    report.error=String(error.message);report.completed_at=new Date().toISOString();
    postMessage({kind:'error',message:String(error.message),...(data.kind==='run'?{report}:{})});
  }finally{active=false;}
};
