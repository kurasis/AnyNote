// Delay a genuine authenticated request so its response crosses lock/unlock.
// Never replace API data, Worker results, custody checks or generation fences.
export async function lockRace({page,action,readyWriter,phrase,check}){
 const before=await page.evaluate(()=>globalThis.__custodyDiagnostics.length);
 for(const listing of [false,true]){
  const pattern=listing?'**/api/v1/groups':'**/api/v1/groups/*';
  let release,seen;
  const held=new Promise(resolve=>release=resolve),arrived=new Promise(resolve=>seen=resolve);
  let captured=false;
  const handler=async route=>{
   if(captured||route.request().method()!=='GET'){await route.fallback();return;}
   captured=true;seen();await held;await route.fallback();
  };
  await page.route(pattern,handler);
  try{
   if(listing)await page.locator('#refresh').click();
   else await page.locator('#groups button').filter({hasText:'PUBLIC browser shared group'}).click();
   let timer;
   try{await Promise.race([arrived,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('P15_REAL_RESPONSE_NOT_HELD')),60000);})]);}
   finally{clearTimeout(timer);}
   await page.locator('#lock').click();await page.waitForFunction(()=>document.getElementById('workspace').hidden);
   check(await page.locator('#groups').textContent()==='','P15_HELD_'+(listing?'LIST':'GROUP')+'_LOCK_CLEARS_TITLES');
   await readyWriter(page);await page.locator('#phrase').fill(phrase);
   // Queue explicit unlock while the old UI task is still awaiting its response.
   const unlocked=action(page,'unlock');await page.waitForFunction(()=>Boolean(document.getElementById('status').dataset.busy));release();await unlocked;
   check(await page.locator('#workspace').isVisible(),'P15_LATE_'+(listing?'LIST':'GROUP')+'_RESPONSE_CANNOT_RELOCK_NEW_UNLOCK');
  }finally{release();await page.unroute(pattern,handler);}
 }
 const errors=await page.evaluate(before=>globalThis.__custodyDiagnostics.slice(before),before);
 check(!errors.some(e=>e.event==='custody-error'&&e.error==='VAULT_LOCKED'),'P15_STALE_NETWORK_RESPONSE_NEVER_REENTERS_LOCKED_CUSTODY');
 return {status:'PASS',scenarios:2,actual_authenticated_responses:true,physical_acceptance:false};
}
