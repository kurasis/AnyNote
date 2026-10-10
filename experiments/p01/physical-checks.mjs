import assert from 'node:assert/strict';
import { createHash, randomFillSync } from 'node:crypto';
import { open, rm } from 'node:fs/promises';
import { join } from 'node:path';

export async function checkSelectedFiles(page,transport,scratch,large) {
  const report={source:'real selected browser File',sink:'explicit synthetic plaintext OPFS export test only',
    physical_iphone:'NOT RUN', ios_files:'NOT VERIFIED',cases:[]};
  await page.goto(transport.origin+'/physical/');
  await page.waitForFunction(()=>typeof physicalP01==='object');
  await page.evaluate(()=>navigator.serviceWorker.ready);
  for(const size of [0,1,8388609,...(large?[1000000000]:[])]){
    await transport.reset();
    const path=join(scratch,`selected-${size}.bin`),file=await open(path,'wx'),hash=createHash('sha256');
    try{
      for(let offset=0;offset<size;offset+=8388608){
        const bytes=Buffer.alloc(Math.min(8388608,size-offset));randomFillSync(bytes);hash.update(bytes);await file.write(bytes);
      }
    }finally{await file.close();}
    const expected=hash.digest('hex');
    await page.locator('input[type=file]').setInputFiles(path);
    const uploaded=await page.evaluate(()=>physicalP01.call({kind:'upload',source:document.querySelector('input[type=file]').files[0]}));
    assert.equal(uploaded.bytes,size);assert.equal(uploaded.sha256,expected);
    const id='anynote-p01-export-'+crypto.randomUUID().replaceAll('-','');
    try{
      const exported=await page.evaluate(async(id)=>{
        const directory=await (await navigator.storage.getDirectory()).getDirectoryHandle(id,{create:true});
        const sink=await directory.getFileHandle('explicit-synthetic-export',{create:true});
        const report=await physicalP01.call({kind:'export',sink});
        const actual=await sink.getFile();
        const readback=await physicalP01.call({kind:'reselect',source:actual});
        return {...report,saved_bytes:actual.size,readback:readback.status};
      },id);
      assert.equal(exported.saved_bytes,size);assert.equal(exported.sha256,expected);assert.equal(exported.readback,'SOURCE_MATCHES');
      await assert.rejects(page.evaluate(()=>physicalP01.call({kind:'reselect',source:new File(['changed'],'changed.bin')})));
      // Same length but changed bytes must also fail (one-byte case).
      if(size===1){await assert.rejects(page.evaluate(async()=>{
        const original=new Uint8Array(await document.querySelector('input[type=file]').files[0].arrayBuffer());
        original[0]^=1;
        return physicalP01.call({kind:'reselect',source:new File([original],'changed.bin')});
      }));}
      const transferred=size+Math.ceil(size/8388608)*16;
      assert.equal(transport.counts().uploaded_bytes,transferred);assert.equal(transport.counts().downloaded_bytes,transferred);
      report.cases.push({size,sha256:expected,status:exported.status,saved_bytes:exported.saved_bytes,uploaded_bytes:transferred,downloaded_bytes:transferred});
      await page.evaluate(()=>physicalP01.worker.postMessage({kind:'lock'}));
      await assert.rejects(page.evaluate(async(id)=>{
        const directory=await(await navigator.storage.getDirectory()).getDirectoryHandle(id);
        return physicalP01.call({kind:'export',sink:await directory.getFileHandle('explicit-synthetic-export')});
      },id));
    }finally{
      await page.evaluate(async(id)=>{await(await navigator.storage.getDirectory()).removeEntry(id,{recursive:true});},id);
      await rm(path);
    }
    console.log('PASS: selected-file bounded upload/download and explicit OPFS export',size,'bytes; not iOS Files');
  }
  const oversize=join(scratch,'oversize-selected.bin'),largeFile=await open(oversize,'wx');
  await largeFile.truncate(1000000001);await largeFile.close();
  try{
    await page.locator('input[type=file]').setInputFiles(oversize);
    await assert.rejects(page.evaluate(()=>physicalP01.call({kind:'upload',source:document.querySelector('input[type=file]').files[0]})));
  }finally{await rm(oversize);}
  report.oversize_before_read=true;report.locked_export_rejected=true;
  return report;
}
