// Real browser worker, HTTP responses and OPFS atomic writers; no mocked crypto/sink.
import assert from 'node:assert/strict';
import { createHash, randomFillSync } from 'node:crypto';
import { open, rm } from 'node:fs/promises';
import { join } from 'node:path';

const SENTINEL='previous explicit synthetic output';
async function seedOutput(page,id) {
  await page.evaluate(async({id,text})=>{
    const directory=await(await navigator.storage.getDirectory()).getDirectoryHandle(id,{create:true});
    const writer=await(await directory.getFileHandle('output.bin',{create:true})).createWritable();
    await writer.write(text);await writer.close();
  },{id,text:SENTINEL});
}
async function unchangedOutput(page,id) {
  const found=await page.evaluate(async(id)=>{
    const directory=await(await navigator.storage.getDirectory()).getDirectoryHandle(id);
    const file=await(await directory.getFileHandle('output.bin')).getFile();
    return {size:file.size,text:file.size<128?await file.text():null};
  },id);
  assert.equal(found.size,SENTINEL.length);assert.equal(found.text,SENTINEL,'Aborted export must preserve the previously committed output');
}
async function attemptExport(page,id) {
  return page.evaluate(async(id)=>{
    const progress=[],handler=({data})=>{if(data.kind==='progress'&&data.phase==='download-decrypt-export')progress.push(data.index);};
    physicalP01.worker.addEventListener('message',handler);
    try{
      const directory=await(await navigator.storage.getDirectory()).getDirectoryHandle(id);
      const result=await physicalP01.call({kind:'export',sink:await directory.getFileHandle('output.bin')});
      return {status:'UNEXPECTED_SUCCESS',result,progress};
    }catch(error){return {status:'REJECTED',message:error.message,progress};}
    finally{physicalP01.worker.removeEventListener('message',handler);}
  },id);
}
async function lockWorker(page) {
  await page.evaluate(()=>new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{physicalP01.worker.removeEventListener('message',handler);reject(new Error('No lock acknowledgement'));},5000);
    const handler=({data})=>{if(data.kind==='locked'){clearTimeout(timer);physicalP01.worker.removeEventListener('message',handler);resolve();}};
    physicalP01.worker.addEventListener('message',handler);physicalP01.worker.postMessage({kind:'lock'});
  }));
}
async function selectSource(page,transport,scratch,size) {
  await transport.reset();
  const path=join(scratch,`fault-source-${size}.bin`),file=await open(path,'wx'),hash=createHash('sha256');
  try{
    for(let offset=0;offset<size;offset+=8388608){
      const bytes=Buffer.alloc(Math.min(8388608,size-offset));randomFillSync(bytes);hash.update(bytes);await file.write(bytes);
    }
  }finally{await file.close();}
  try{
    await page.locator('input[type=file]').setInputFiles(path);
    const uploaded=await page.evaluate(()=>physicalP01.call({kind:'upload',source:document.querySelector('input[type=file]').files[0]}));
    const expected=hash.digest('hex');assert.equal(uploaded.sha256,expected);
    return {path,expected};
  }catch(error){await rm(path);throw error;}
}
export async function checkExportFaults(page,transport,scratch) {
  const report={implementation:'real Chromium worker + loopback faults + OPFS transactional writer',
    physical_low_disk:'NOT RUN',physical_lifecycle:'NOT RUN',checks:[]};
  const id='anynote-p01-fault-'+crypto.randomUUID(),sources=[];
  let protectedNames=[];
  try{
    const source=await selectSource(page,transport,scratch,8388609);sources.push(source.path);
    for(const mode of ['corrupt','truncate']){
      await seedOutput(page,id);transport.faultNextDownload(mode,1);
      const failed=await attemptExport(page,id);
      assert.equal(failed.status,'REJECTED',mode);assert.deepEqual(failed.progress,[1]);
      if(mode==='corrupt')assert.match(failed.message,/Ciphertext integrity mismatch/);
      await unchangedOutput(page,id);
      report.checks.push({fault:mode,after_verified_parts:1,rejected:true,previous_output_preserved:true});
    }
    // The one-shot network faults must not poison a subsequent verified export.
    const repaired=await page.evaluate(async(id)=>{
      const directory=await(await navigator.storage.getDirectory()).getDirectoryHandle(id);
      const sink=await directory.getFileHandle('output.bin'),result=await physicalP01.call({kind:'export',sink});
      const actual=await sink.getFile(),readback=await physicalP01.call({kind:'reselect',source:actual});
      return {...result,saved_bytes:actual.size,readback:readback.status};
    },id);
    assert.equal(repaired.saved_bytes,8388609);assert.equal(repaired.sha256,source.expected);assert.equal(repaired.readback,'SOURCE_MATCHES');
    report.unchanged_ciphertext_retry_verified=true;
    await seedOutput(page,id);
    const gate=transport.holdNextDownload(1);let timer;
    const pending=attemptExport(page,id);
    try{
      await Promise.race([gate.arrived,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Download gate not reached')),30000);})]);
      clearTimeout(timer);await lockWorker(page);gate.release();
      const failed=await pending;
      assert.equal(failed.status,'REJECTED');assert.match(failed.message,/PAUSED_LOCKED/);assert.deepEqual(failed.progress,[1]);
      await unchangedOutput(page,id);
      report.checks.push({fault:'lock-before-late-download',after_verified_parts:1,rejected:true,previous_output_preserved:true});
    }finally{clearTimeout(timer);gate.release();await pending;}

    const small=await selectSource(page,transport,scratch,32768);sources.push(small.path);
    await seedOutput(page,id);transport.faultNextDownload('decoded-overflow');
    const expanded=await attemptExport(page,id);
    assert.equal(expanded.status,'REJECTED');assert.match(expanded.message,/Ciphertext exceeds bounded part length/);assert.deepEqual(expanded.progress,[]);
    await unchangedOutput(page,id);
    report.checks.push({fault:'gzip-decoded-overflow',encoded_length:32784,decoded_length:32785,rejected_before_write:true,previous_output_preserved:true});

    // Real exclusive OPFS lock denies a second writable stream before any export.
    const denied=await page.evaluate(async(id)=>{
      const directory=await(await navigator.storage.getDirectory()).getDirectoryHandle(id),sink=await directory.getFileHandle('output.bin');
      const owner=await sink.createWritable({mode:'exclusive'});
      try{await physicalP01.call({kind:'export',sink});return false;}catch{return true;}
      finally{await owner.abort();}
    },id);
    assert.equal(denied,true);await unchangedOutput(page,id);
    report.exclusive_sink_denial=true;

    const before=await page.evaluate(async()=>{const root=await navigator.storage.getDirectory(),names=[];for await(const [name] of root.entries())names.push(name);return names;});
    transport.faultNextDownload('corrupt');
    await assert.rejects(page.evaluate(()=>physicalP01.prepareExport()),/Ciphertext integrity mismatch/);
    const after=await page.evaluate(async()=>{const root=await navigator.storage.getDirectory(),names=[];for await(const [name] of root.entries())names.push(name);return names;});
    assert.deepEqual(after.sort(),before.sort(),'Failed share preparation must remove its owned temporary export');
    report.failed_prepare_cleaned=true;
    const prepared=await page.evaluate(()=>physicalP01.prepareExport());
    assert.equal(prepared.bytes,32768);assert.equal(prepared.sha256,small.expected);
    protectedNames=await page.evaluate(async()=>{
      const root=await navigator.storage.getDirectory(),names=[
        'anynote-p01-export-'+crypto.randomUUID().replaceAll('-',''),
        'anynote-p01-export-'+crypto.randomUUID().replaceAll('-',''),
        'anynote-p01-unrelated-'+crypto.randomUUID()];
      for(const name of names)await root.getDirectoryHandle(name,{create:true});
      const directory=await root.getDirectoryHandle(names[1]),writer=await(await directory.getFileHandle('purpose.marker',{create:true})).createWritable();
      await writer.write('different owner');await writer.close();return names;
    });
    await page.reload();await page.waitForFunction(()=>typeof physicalP01==='object');
    const missing=await attemptExport(page,id);assert.equal(missing.status,'REJECTED');assert.match(missing.message,/No live upload/);
    const cleaned=await page.evaluate(()=>physicalP01.removeOrphans());assert.equal(cleaned.removed,1);
    await page.evaluate(async({protectedNames,removed})=>{
      const root=await navigator.storage.getDirectory();
      for(const name of protectedNames)await root.getDirectoryHandle(name);
      try{await root.getDirectoryHandle(removed);}catch(error){if(error.name==='NotFoundError')return;throw error;}
      throw new Error('Owned orphan survived cleanup');
    },{protectedNames,removed:prepared.id});
    assert.equal((await page.evaluate(()=>physicalP01.removeOrphans())).removed,0);
    report.reload_requires_fresh_keys=true;report.marked_orphan_removed=true;
    report.unmarked_and_different_owner_preserved=true;report.cleanup_idempotent=true;
    console.log('PASS: real corrupt/truncated/expanded download, late-lock abort, exclusive sink and selective orphan cleanup');
    return report;
  }finally{
    await page.evaluate(async(names)=>{const root=await navigator.storage.getDirectory();for(const name of names){try{await root.removeEntry(name,{recursive:true});}catch(error){if(error.name!=='NotFoundError')throw error;}}},[id,...protectedNames]);
    for(const path of sources)await rm(path);
  }
}
