import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile,mkdtemp,rm,mkdir,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {chromium} from 'playwright-core';
import {createHash} from 'node:crypto';
import {createReadStream} from 'node:fs';
import './package-device-kit.mjs';

const assets=resolve('dist/device-kit'),scratch=await mkdtemp(join(tmpdir(),'anynote-device-kit-'));
const record={status:'IN PROGRESS',physical_acceptance:false,os_share_mocked:true,
  limitation:'Real Chromium sandbox enabled; Share UI is an explicit mock. No physical iPhone/Files acceptance.',
  source_commit:JSON.parse(await readFile(join(assets,'BUILD.json'),'utf8')).source_commit};
let context;
const server=createServer(async(req,res)=>{
  const url=new URL(req.url,'http://localhost');
  const name=url.pathname==='/nested/anynote-p01/'?'index.html':url.pathname.slice('/nested/anynote-p01/'.length);
  if(!url.pathname.startsWith('/nested/anynote-p01/')||!/^[a-zA-Z0-9_.-]+$/.test(name)){res.writeHead(404);res.end();return;}
  if(name==='test-share-worker.js'){
    res.writeHead(200,{'Content-Type':'text/javascript','X-Content-Type-Options':'nosniff'});
    res.end(`self.onmessage=async({data})=>{try{
      const root=await navigator.storage.getDirectory(),directory=await root.getDirectoryHandle('mock-files-owned-by-hosted-test',{create:true});
      if(data.kind==='read-saved'){postMessage({file:await(await directory.getFileHandle('saved-synthetic.bin')).getFile()});return;}
      const handle=await directory.getFileHandle('saved-synthetic.bin',{create:true}),access=await handle.createSyncAccessHandle();
      try{for(let offset=0;offset<data.size;offset+=8388608){const bytes=new Uint8Array(await data.slice(offset,offset+8388608).arrayBuffer());if(access.write(bytes,{at:offset})!==bytes.length)throw new Error('Short mocked OS write');bytes.fill(0);}access.flush();}finally{access.close();}
      postMessage({file:await handle.getFile()});
    }catch(error){postMessage({error:String(error.message)});}};`);return;
  }
  try{
    const mime=name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':name.endsWith('.png')?'image/png':name.endsWith('.webmanifest')?'application/manifest+json':'text/html';
    const body=await readFile(join(assets,name));res.writeHead(200,{'Content-Type':mime,'X-Content-Type-Options':'nosniff',
      'Content-Security-Policy':"default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'none'"});res.end(body);
  }catch{res.writeHead(404);res.end();}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
try{
  context=await chromium.launchPersistentContext(join(scratch,'profile'),{executablePath:process.env.CHROMIUM_EXECUTABLE??'/usr/bin/google-chrome',headless:true,chromiumSandbox:true});
  await context.addInitScript(()=>{
    Object.defineProperty(navigator,'canShare',{value:({files})=>files?.length===1});
    Object.defineProperty(navigator,'share',{value:async({files})=>{
      if(!navigator.userActivation.isActive)throw new Error('Share invoked without real user activation');
      const worker=new Worker('./test-share-worker.js',{type:'module'});
      globalThis.mockedSharedFile=await new Promise((resolve,reject)=>{
        worker.onmessage=({data})=>{worker.terminate();data.error?reject(new Error(data.error)):resolve(data.file);};
        worker.onerror=()=>{worker.terminate();reject(new Error('Mock OS copy failed'));};worker.postMessage(files[0]);
      });
      globalThis.mockedCopyReady=true;
      if(sessionStorage.getItem('kill-after-share')==='yes')await new Promise(()=>{});
    }});
  });
  const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.goto(`http://127.0.0.1:${server.address().port}/nested/anynote-p01/`);
  await page.evaluate(()=>navigator.serviceWorker.ready);
  await page.locator('#start').click();
  await page.waitForFunction(()=>['share','report'].includes(globalThis.deviceP01?.stage),null,{timeout:240000});
  const automatic=await page.evaluate(()=>deviceP01.report);
  assert.equal(automatic.status,'PASS_AUTOMATED_LOCAL_CHECKS',JSON.stringify(automatic));
  assert.deepEqual(automatic.files.map(item=>item.bytes),[0,1,8388609,1000000000]);
  assert.equal(automatic.files.at(-1).chunks,120);
  assert.equal(automatic.checks.filter(item=>item.name.startsWith('second-part')).length,3);
  assert.equal(automatic.physical_acceptance,false);
  await page.evaluate(()=>sessionStorage.setItem('kill-after-share','yes'));
  await page.locator('#legacy-share').click();
  await page.waitForFunction(()=>globalThis.mockedCopyReady===true,null,{timeout:120000});
  // Destroy the real page while its OS-share promise is still pending: iOS-like loss of all JS state.
  await page.reload();
  await page.waitForFunction(()=>deviceP01.stage==='verify');
  const recovered=await page.evaluate(()=>deviceP01.report);
  assert.deepEqual(recovered.files,automatic.files);
  assert.equal(recovered.recovery.previous_stage,'handoff');
  assert.equal(recovered.recovery.keys_restored,false);
  assert.match(recovered.share,/OUTCOME_UNKNOWN_AFTER_RESTART/);
  const partialDownload=page.waitForEvent('download');await page.locator('#save-report').click();
  await(await partialDownload).saveAs(join(scratch,'recovered-report.json'));
  assert.deepEqual(JSON.parse(await readFile(join(scratch,'recovered-report.json'),'utf8')),recovered);
  // Saving the diagnostic report must also survive the next app reopening.
  await page.reload();await page.waitForFunction(()=>deviceP01.stage==='verify');
  // Use the real activated picker path, choose a tiny JSON, then recover and retry the same output.
  const chooserPromise=page.waitForEvent('filechooser');await page.locator('#start').click();
  await(await chooserPromise).setFiles({name:'wrong-report.json',mimeType:'application/json',buffer:Buffer.from('wrong')});
  await page.waitForFunction(()=>deviceP01.stage==='verify'&&deviceP01.report.files_destination?.status==='FAIL');
  const wrongSelection=await page.evaluate(()=>deviceP01.report);
  assert.equal(wrongSelection.files_destination.selected_bytes,5);
  assert.equal(wrongSelection.files_destination.expected_bytes,1000000000);
  assert.deepEqual(wrongSelection.files,automatic.files);
  await page.reload();await page.waitForFunction(()=>deviceP01.stage==='verify');
  assert.equal((await page.evaluate(()=>deviceP01.report)).files_destination.status,'FAIL');
  // Reject arbitrary owner/name and a purpose-marker mismatch without touching other data.
  const exportRef=await page.evaluate(()=>deviceP01.report.pending_export);
  const rejected=await page.evaluate(async(ref)=>{
    const request=data=>new Promise(resolve=>{const channel=new MessageChannel();channel.port1.onmessage=({data})=>{channel.port1.close();resolve(data);};navigator.serviceWorker.controller.postMessage({kind:'prepare-download',...data},[channel.port2]);});
    const traversal=await request({owner_id:ref.owner_id,name:'../purpose.marker'});
    const root=await navigator.storage.getDirectory(),id='anynote-p01-device-'+ 'e'.repeat(32);
    const directory=await root.getDirectoryHandle(id,{create:true});
    const writer=await(await directory.getFileHandle('purpose.marker',{create:true})).createWritable();await writer.write('not this kit');await writer.close();
    let wrongMarker;try{wrongMarker=await request({owner_id:id,name:ref.name});}finally{await root.removeEntry(id,{recursive:true});}
    return {traversal,wrongMarker};
  },exportRef);
  assert.match(rejected.traversal.error,/Invalid synthetic export/);
  assert.match(rejected.wrongMarker.error,/purpose marker mismatch/);
  // Cancel a real partial SW response; the next request must get the released trial lock.
  await page.evaluate(()=>{deviceP01.report.stream_download={status:'REQUESTED_OUTCOME_UNKNOWN',method:'SCOPED_SERVICE_WORKER_DISK_STREAM',physical_acceptance:false};});
  const cancelUrl=await page.locator('#download-sample').getAttribute('href');
  const cancellation=await page.evaluate(async(url)=>{
    const response=await fetch(url),reader=response.body.getReader();
    const first=await reader.read();await reader.cancel();
    return {status:response.status,chunk:first.value.length,cache:response.headers.get('Cache-Control')};
  },cancelUrl);
  assert.equal(cancellation.status,200);assert.equal(cancellation.cache,'no-store');
  assert.ok(cancellation.chunk>0&&cancellation.chunk<=262144);
  await page.waitForFunction(async()=>deviceP01.report.stream_download?.status==='CANCELLED'
    &&!(await navigator.locks.query()).held.some(lock=>lock.name==='anynote-p01-device-kit'));
  await page.waitForFunction(url=>document.querySelector('#download-sample').href!==url,cancelUrl);
  // Stop the real service worker after it prepared a ticket: lose all of its JS state.
  const cdp=await context.newCDPSession(page);
  await cdp.send('ServiceWorker.enable');await cdp.send('ServiceWorker.stopAllWorkers');await cdp.detach();
  // Download through the restarted actual service worker/network stack. No OS Share mock here.
  const streamPromise=page.waitForEvent('download');await page.locator('#download-sample').click();
  const streamed=await streamPromise;
  assert.match(streamed.suggestedFilename(),/^synthetic-export-[0-9a-f-]{36}\.bin$/);
  const streamedPath=join(scratch,'actual-streamed.bin');await streamed.saveAs(streamedPath);
  const digest=createHash('sha256');let total=0;
  for await(const bytes of createReadStream(streamedPath)){digest.update(bytes);total+=bytes.length;}
  assert.equal(total,1000000000);assert.equal(digest.digest('hex'),automatic.files.at(-1).sha256);
  await page.waitForFunction(()=>deviceP01.report.stream_download?.status==='STREAM_SENT_NOT_FILES_VERIFIED');
  // Download alone must not erase the prior failed selection or fabricate a Files pass.
  assert.equal((await page.evaluate(()=>deviceP01.report)).files_destination.status,'FAIL');
  const replay=await page.evaluate(async(url)=>(await fetch(url)).status,streamed.url());
  assert.equal(replay,410);
  const invalid=await page.evaluate(async()=>{
    const response=await fetch(new URL('download/'+ '0'.repeat(32),location.href));return {status:response.status,cache:response.headers.get('Cache-Control')};
  });
  assert.deepEqual(invalid,{status:410,cache:'no-store'});
  const rejectedPath=await page.evaluate(async()=>{
    const response=await fetch(new URL('download/../arbitrary-file',location.href));return response.status;
  });
  assert.equal(rejectedPath,404);
  // Real user-activated picker receives the actual browser-downloaded disk file.
  const correctChooser=page.waitForEvent('filechooser');await page.locator('#start').click();
  await(await correctChooser).setFiles(streamedPath);
  await page.waitForFunction(()=>deviceP01.stage==='report',null,{timeout:120000});
  const result=await page.evaluate(()=>deviceP01.report);
  assert.equal(result.files_destination.status,'PASS_SELECTED_OUTPUT_HASH',JSON.stringify(result));
  assert.equal(result.files_destination.sha256,result.files.at(-1).sha256);
  assert.equal(result.temporary_export_cleanup,'PASS');
  assert.equal(result.retained_export,'REOPENED_AND_HASH_VERIFIED');
  assert.equal(result.physical_acceptance,false);
  const directories=await page.evaluate(async()=>{
    const names=[];for await(const[name]of(await navigator.storage.getDirectory()).entries())names.push(name);return names;
  });
  assert.equal(directories.filter(name=>name.startsWith('anynote-p01-device-')).length,0);
  const download=page.waitForEvent('download');await page.locator('#start').click();
  const downloaded=await download;await downloaded.saveAs(join(scratch,'report.json'));
  assert.deepEqual(JSON.parse(await readFile(join(scratch,'report.json'),'utf8')),result);
  await page.reload();await page.waitForFunction(()=>deviceP01.stage==='report');
  assert.equal((await page.evaluate(()=>deviceP01.report)).files_destination.status,'PASS_SELECTED_OUTPUT_HASH');
  // Reproduce the owner's legacy 0.1.1 report-stage failure and migrate its exact known key.
  await page.evaluate((report)=>{
    const key=`anynote-p01-report-v1:${location.pathname}`;
    const old=`anynote-p01-report-v1:${new URL('../anynote-p01-v011/',location.href).pathname}`;
    localStorage.setItem(old,JSON.stringify({version:1,stage:'report',report}));localStorage.removeItem(key);
  },wrongSelection);
  await page.reload();await page.waitForFunction(()=>deviceP01.stage==='verify');
  const failed=await page.evaluate(()=>deviceP01.report);
  assert.equal(failed.files_destination.status,'FAIL');
  assert.deepEqual(failed.files,automatic.files);
  assert.equal(failed.recovery.previous_stage,'report');
  assert.equal(failed.recovery.previous_kit_path,'Documented sibling anynote-p01-v011/');
  // An interrupted automatic run has diagnostics, never an implicit 1 GB restart or unlocked resume.
  await page.evaluate(()=>{
    const key=`anynote-p01-report-v1:${location.pathname}`,value=JSON.parse(localStorage.getItem(key));
    value.stage='run';value.report.status='IN PROGRESS';value.report.files=[];localStorage.setItem(key,JSON.stringify(value));
  });
  await page.reload();await page.waitForFunction(()=>deviceP01.stage==='report');
  assert.equal((await page.evaluate(()=>deviceP01.report)).status,'INTERRUPTED');
  // Reject malformed records, then exercise an actual denied Storage write before worker work.
  await page.evaluate(()=>localStorage.setItem(`anynote-p01-report-v1:${location.pathname}`,'{bad'));
  await page.reload();await page.waitForFunction(()=>!document.querySelector('#start').disabled);
  assert.equal(await page.evaluate(()=>deviceP01.report),undefined);
  await page.evaluate(()=>{
    localStorage.removeItem(`anynote-p01-report-v1:${location.pathname}`);
    localStorage.removeItem(`anynote-p01-report-v1:${new URL('../anynote-p01-v011/',location.href).pathname}`);
  });
  await page.addInitScript(()=>{
    const original=Storage.prototype.setItem;
    Storage.prototype.setItem=function(key,value){if(key.startsWith('anynote-p01-report-v1:'))throw new DOMException('Denied','QuotaExceededError');return original.call(this,key,value);};
  });
  await page.reload();await page.locator('#start').click();
  await page.waitForFunction(()=>deviceP01.stage==='report');
  assert.equal((await page.evaluate(()=>deviceP01.report)).status,'BLOCKED');
  assert.equal((await page.evaluate(()=>deviceP01.report)).files,undefined);
  assert.equal(errors.length,0,errors.join('\n'));
  Object.assign(record,{status:'PASS',browser:context.browser().version(),automatic_and_mocked_share_result:result,
    pending_share_page_destroyed_and_report_restored:true,restored_selected_output_hash:true,
    report_download_restart_retained:true,failed_report_retained:true,interrupted_run_not_restarted:true,
    real_service_worker_stream_download:true,streamed_download_bytes:total,
    prepared_ticket_survives_actual_service_worker_stop:true,
    stream_download_selected_hash:true,unknown_download_token_rejected:true,
    cancelled_stream_releases_lock:true,arbitrary_export_path_rejected:true,unmarked_export_rejected:true,download_replay_rejected:true,
    retained_staged_export_reopened_and_hashed:true,
    wrong_json_size_recorded:true,wrong_json_retry_after_reload:true,legacy_failed_report_offers_retry:true,
    malformed_checkpoint_rejected:true,denied_checkpoint_blocks_before_work:true,
    wrong_selected_length_rejected:true,downloaded_report_matches:true,owned_export_directories_remaining:0,
    nested_path:'/nested/anynote-p01/',secure_context:'Trustworthy loopback, not a phone HTTPS origin'});
  console.log('PASS: real exact 1 GB service-worker attachment and selected hash, activated mocked share with real page destruction/reload, durable report, recovered selected-output hash, denied storage, cleanup.');
}catch(error){record.status='FAIL';record.error=String(error.stack);
  try{record.page_diagnostics=await context.pages()[0].evaluate(()=>({stage:deviceP01?.stage,report:deviceP01?.report,controller:!!navigator.serviceWorker.controller,output:document.querySelector('#status')?.textContent}));}catch{}
  throw error;}
finally{
  await mkdir('artifacts',{recursive:true});await writeFile('artifacts/device-kit-report.json',JSON.stringify(record,null,2));
  await context?.close();await new Promise(resolve=>server.close(resolve));await rm(scratch,{recursive:true,force:true});
}
