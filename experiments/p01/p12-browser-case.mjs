// Called only by the real sandboxed multi-account shipped-PWA runner.
import {randomBytes,createHash} from 'node:crypto';
import {openSync,writeSync,closeSync,createReadStream} from 'node:fs';
import {join} from 'node:path';
export async function filesCase({page,action,check,scratch,control}){
 const source=join(scratch,'P12_PUBLIC_SELECTED_FILE.bin'),fd=openSync(source,'wx'),expected=createHash('sha256');
 try{for(let left=1000000000;left>0;){const bytes=randomBytes(Math.min(left,8388608));writeSync(fd,bytes);expected.update(bytes);left-=bytes.length;}}finally{closeSync(fd);}
 await page.locator('#offline').click();await page.waitForFunction(()=>Boolean(navigator.serviceWorker?.controller),null,{timeout:30000});
 const panel=page.locator('details').filter({has:page.locator('#file-source')});await panel.locator('summary').click();await page.locator('#file-source').setInputFiles(source);await action(page,'file-upload');
 check((await page.locator('#file-state').textContent()).includes('Committed'),'P12_GIGABYTE_PROTECTED_WORKER_UPLOAD');await action(page,'file-refresh');check(await page.locator('#file-items').textContent().then(t=>t.includes('UNATTACHED')),'P12_UNATTACHED_RECOVERY_VISIBLE');
 const downloaded=page.waitForEvent('download',{timeout:120000});await page.locator('#file-items button').filter({hasText:'Export file'}).last().click();const download=await downloaded,destination=join(scratch,'explicit-p12-export.bin');await download.saveAs(destination);let bytes=0;const actual=createHash('sha256');for await(const part of createReadStream(destination)){actual.update(part);bytes+=part.length;}check(bytes===1000000000&&actual.digest('hex')===expected.digest('hex'),'P12_SERVICE_WORKER_STREAM_GIGABYTE_HASH');
 await page.waitForFunction(()=>!document.getElementById('status').dataset.busy,null,{timeout:180000});check(!(await page.locator('#status').getAttribute('data-error')),'P12_NO_FALSE_EXPORT_SUCCESS');
 await page.locator('#file-items button').filter({hasText:'Attach to this entry'}).first().click();await page.waitForFunction(()=>!document.getElementById('status').dataset.busy,null,{timeout:90000});await action(page,'save-note');await action(page,'file-refresh');check((await page.locator('#save-state').getAttribute('data-state'))==='COMMITTED','P12_FILE_AND_ENTRY_BOTH_COMMITTED');
 const inspection=control('p09-inspect',JSON.stringify({markers:['P12_PUBLIC_SELECTED_FILE.bin']}));check(inspection.status==='PASS','P12_SQL_LOG_FILENAME_INSPECTION');
 const storage=await page.evaluate(async()=>{const {IndexedVault}=await import('/auth/vault-store.js'),store=await new IndexedVault(JSON.parse(document.getElementById('profiles').value)).open();try{return await store.transaction(false,async tx=>{const rows=[];await tx.each(r=>rows.push(r));return JSON.stringify({state:await tx.get(),rows});});}finally{store.close();}});check(!storage.includes('P12_PUBLIC_SELECTED_FILE.bin'),'P12_INDEXEDDB_FILENAME_INSPECTION');
 await page.locator('#lock').click();await page.waitForFunction(()=>document.getElementById('workspace').hidden);check(await page.locator('#workspace').isHidden()&&await page.locator('#file-items').textContent()==='','P12_LIFECYCLE_MASKS_FILE_VIEW');return {gigabyte_bytes:bytes,checks:7,physical_acceptance:false,stream_completion:'actual desktop saved output hash; iPhone Files acceptance remains NOT_RUN'};
}
