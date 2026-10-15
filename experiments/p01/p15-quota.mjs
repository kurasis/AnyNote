// Actual Chromium quota-manager fault, not a mocked crypto/store implementation.
import {createHash} from 'node:crypto';
import {phrase} from '../../packages/protocol/notes/test-fixture.mjs';

export async function quotaCase({page,action,check,readyWriter,draft}){
  const origin='https://app.anynote.test:18443',storageErrors=['INSUFFICIENT_STORAGE','STORAGE_FAILURE','STORAGE_ABORTED'];
  const expected=await page.locator('#note-body').inputValue();
  const records=()=>page.evaluate(async()=>{
    const {IndexedVault}=await import('/auth/vault-store.js');
    const store=await new IndexedVault(JSON.parse(document.getElementById('profiles').value)).open();
    let rows;try{rows=await store.transaction(false,async tx=>{const found=[];await tx.each(row=>{if(row.frame?.context?.record_kind==='draft')found.push({id:row.id,encoded:JSON.stringify(row)});});return found;});}finally{store.close();}
    rows.sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
    return Promise.all(rows.map(async row=>({id:row.id,sha256:[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(row.encoded)))].map(b=>b.toString(16).padStart(2,'0')).join('')})));
  });
  const beforeRecords=await records();check(beforeRecords.length>0,'P15_QUOTA_STARTS_WITH_ACKNOWLEDGED_ENCRYPTED_DRAFT');
  const cdp=await page.context().newCDPSession(page);
  const before=await cdp.send('Storage.getUsageAndQuota',{origin});
  let overridden=false,errorCode;
  try{
    await cdp.send('Storage.overrideQuotaForOrigin',{origin,quotaSize:0});overridden=true;
    const limited=await cdp.send('Storage.getUsageAndQuota',{origin});
    check(limited.quota===0,'P15_ACTUAL_BROWSER_ORIGIN_QUOTA_IS_ZERO');
    await page.locator('#note-body').fill('PUBLIC P15 unacknowledged no-space edit.\n'.repeat(256));
    await page.locator('#save-local').click();
    await page.waitForFunction(codes=>codes.includes(document.getElementById('status').dataset.error)||(globalThis.__custodyDiagnostics??[]).some(e=>codes.includes(e.error)),storageErrors,{timeout:60000});
    const observed=await page.evaluate(codes=>({error:document.getElementById('status').dataset.error,
      diagnostic:(globalThis.__custodyDiagnostics??[]).findLast(e=>codes.includes(e.error))?.error,
      locked:document.getElementById('workspace').hidden,state:document.getElementById('save-state').dataset.state}),storageErrors);
    errorCode=storageErrors.includes(observed.error)?observed.error:observed.diagnostic;
    check(storageErrors.includes(errorCode),'P15_REAL_QUOTA_WRITE_FAILURE_REPORTED');
    check(observed.locked||!['LOCAL_SAVED','COMMITTED'].includes(observed.state),'P15_QUOTA_FAILURE_CANNOT_ACKNOWLEDGE_NEW_TEXT');
    check(JSON.stringify(await records())===JSON.stringify(beforeRecords),'P15_QUOTA_ABORT_RETAINS_EXACT_ENCRYPTED_DRAFT_BYTES');
    // Fence the unacknowledged edit before restoring space, so a normal autosave
    // after recovery cannot turn this durability assertion into a race.
    if(!await page.locator('#workspace').isHidden())await page.locator('#lock').click();
    await page.waitForFunction(()=>document.getElementById('workspace').hidden);
  }finally{
    if(overridden)await cdp.send('Storage.overrideQuotaForOrigin',{origin});
    await cdp.detach();
  }
  await page.reload();await page.waitForFunction(()=>document.getElementById('status').dataset.state==='ready');
  await readyWriter(page);await page.locator('#phrase').fill(phrase);await action(page,'unlock');
  await page.locator('#drafts li[data-id="'+draft+'"] button').click();
  await page.waitForFunction(()=>!document.getElementById('status').dataset.busy);
  check(await page.locator('#note-body').inputValue()===expected,'P15_NO_SPACE_RECOVERY_REOPENS_LAST_ACKNOWLEDGED_TEXT');
  return {status:'PASS',physical_acceptance:false,forced_origin_quota_bytes:0,
    prior_origin_usage_bytes:before.usage,prior_origin_quota_bytes:before.quota,observed_error:errorCode,
    retained_draft_records:beforeRecords.length,retained_ciphertext_sha256:createHash('sha256').update(JSON.stringify(beforeRecords)).digest('hex'),
    scope:'Actual hosted Chromium origin-quota override and real Worker/IndexedDB transaction abort after the genuine gigabyte workflow; not physical disk filling, iPhone eviction or capacity evidence'};
}
