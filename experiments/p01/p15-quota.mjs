// A real quota-manager denial in a fresh Chromium process with the same disk
// profile. A reported quota alone is not evidence that an existing writer fails.
import {createHash} from 'node:crypto';
import {phrase} from '../../packages/protocol/notes/test-fixture.mjs';

export async function quotaCase({page,action,check,readyWriter,restart,draft}){
  const origin='https://app.anynote.test:18443',quotaBytes=1;
  const storageErrors=['INSUFFICIENT_STORAGE','STORAGE_FAILURE','STORAGE_ABORTED'];
  const expected=await page.locator('#note-body').inputValue();
  const records=()=>page.evaluate(async()=>{
    const {IndexedVault}=await import('/auth/vault-store.js');
    const store=await new IndexedVault(JSON.parse(document.getElementById('profiles').value)).open();
    let rows;try{rows=await store.transaction(false,async tx=>{const found=[];await tx.each(row=>{if(row.frame?.context?.record_kind==='draft')found.push({id:row.id,encoded:JSON.stringify(row)});});return found;});}finally{store.close();}
    rows.sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
    return Promise.all(rows.map(async row=>({id:row.id,sha256:[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(row.encoded)))].map(b=>b.toString(16).padStart(2,'0')).join('')})));
  });
  const beforeRecords=await records();check(beforeRecords.length>0,'P15_QUOTA_STARTS_WITH_ACKNOWLEDGED_ENCRYPTED_DRAFT');
  const initial=await page.context().newCDPSession(page);
  const before=await initial.send('Storage.getUsageAndQuota',{origin});await initial.detach();
  await page.locator('#lock').click();await page.waitForFunction(()=>document.getElementById('workspace').hidden);
  const reopened=await restart();page=reopened.page;const cdp=reopened.cdp;
  check(reopened.previous_browser_pid!==reopened.browser_pid,'P15_QUOTA_REOPENS_SAME_DISK_PROFILE_IN_NEW_BROWSER_PROCESS');
  const state=()=>page.evaluate(codes=>({error:document.getElementById('status').dataset.error,
    diagnostic:(globalThis.__custodyDiagnostics??[]).findLast(e=>codes.includes(e.error))?.error,
    locked:document.getElementById('workspace').hidden,save_state:document.getElementById('save-state').dataset.state}),storageErrors);
  const errorOf=s=>storageErrors.includes(s.error)?s.error:s.diagnostic;
  const completed=()=>page.waitForFunction(codes=>{
    const s=document.getElementById('status');
    return (globalThis.__custodyDiagnostics??[]).some(e=>codes.includes(e.error))||(!s.dataset.busy&&(s.dataset.error||['Done','Готово'].includes(s.textContent)));
  },storageErrors,{timeout:60000});
  let overridden=false,errorCode,failedOperation='writer-admission',observed;
  try{
    // Set the limit before this new process opens the protected database. Do not
    // assume an override retroactively revokes a previous process's admission.
    await cdp.send('Storage.overrideQuotaForOrigin',{origin,quotaSize:quotaBytes});overridden=true;
    const limited=await cdp.send('Storage.getUsageAndQuota',{origin});
    check(limited.quota===quotaBytes,'P15_ACTUAL_BROWSER_ORIGIN_QUOTA_IS_ONE_BYTE');
    await page.goto(origin+'/auth/notes.html');await page.waitForFunction(()=>document.getElementById('status').dataset.state==='ready');
    await readyWriter(page);await page.locator('#phrase').fill(phrase);await page.locator('#unlock').click();await completed();
    observed=await state();errorCode=errorOf(observed);
    if(!storageErrors.includes(errorCode)){
      // Some backends may admit an equal-sized metadata replacement. In that
      // case require a genuine growing encrypted draft transaction to fail.
      if(observed.error||observed.locked)throw Error('P15_QUOTA_UNEXPECTED_ADMISSION:'+JSON.stringify(observed));
      await page.locator('#drafts li[data-id="'+draft+'"] button').click();await page.waitForFunction(()=>!document.getElementById('status').dataset.busy);
      check(await page.locator('#note-body').inputValue()===expected,'P15_QUOTA_RESTART_READS_PREVIOUS_ACKNOWLEDGED_TEXT');
      failedOperation='draft-update';
      await page.locator('#note-body').fill('PUBLIC P15 unacknowledged no-space edit.\n'.repeat(1536));
      await page.locator('#save-local').click();await completed();observed=await state();errorCode=errorOf(observed);
    }
    if(!storageErrors.includes(errorCode))throw Error('P15_QUOTA_DID_NOT_DENY_REAL_WRITE:'+JSON.stringify(observed));
    check(true,'P15_REAL_QUOTA_WRITE_FAILURE_REPORTED');
    check(observed.locked||!['LOCAL_SAVED','COMMITTED'].includes(observed.save_state),'P15_QUOTA_FAILURE_CANNOT_ACKNOWLEDGE_NEW_WORK');
  }finally{
    // Destruction fences any failed admission/editor before capacity returns.
    await page.goto('about:blank');
    if(overridden)await cdp.send('Storage.overrideQuotaForOrigin',{origin});
    await cdp.detach();
  }
  await page.goto(origin+'/auth/notes.html');await page.waitForFunction(()=>document.getElementById('status').dataset.state==='ready');
  check(JSON.stringify(await records())===JSON.stringify(beforeRecords),'P15_QUOTA_ABORT_RETAINS_EXACT_ENCRYPTED_DRAFT_BYTES');
  await readyWriter(page);await page.locator('#phrase').fill(phrase);await action(page,'unlock');
  await page.locator('#drafts li[data-id="'+draft+'"] button').click();await page.waitForFunction(()=>!document.getElementById('status').dataset.busy);
  check(await page.locator('#note-body').inputValue()===expected,'P15_NO_SPACE_RECOVERY_REOPENS_LAST_ACKNOWLEDGED_TEXT');
  return {status:'PASS',physical_acceptance:false,forced_origin_quota_bytes:quotaBytes,failed_operation:failedOperation,
    previous_browser_pid:reopened.previous_browser_pid,browser_pid:reopened.browser_pid,
    prior_origin_usage_bytes:before.usage,prior_origin_quota_bytes:before.quota,observed_error:errorCode,
    retained_draft_records:beforeRecords.length,retained_ciphertext_sha256:createHash('sha256').update(JSON.stringify(beforeRecords)).digest('hex'),
    scope:'Actual Chromium restart with the same persistent disk profile and one-byte quota before real Worker/IndexedDB write admission; no storage import/reset, crypto/store mocks or physical disk/iPhone eviction claim'};
}
