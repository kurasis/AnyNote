import {pwaCase} from './p15-browser-case.mjs';
import {quotaCase} from './p15-quota.mjs';
import {contentCase} from './p13-browser-case.mjs';
import {filesCase} from './p12-browser-case.mjs';
// Mandatory hosted sandboxed Chromium: genuine WebAuthn through the shipped strict-CSP UI.
import {chromium} from 'playwright-core';
import https from 'node:https';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,existsSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,join} from 'node:path';
import {spawnSync} from 'node:child_process';
const root=resolve(import.meta.dirname,'../..'),scratch=mkdtempSync(join(tmpdir(),'anynote-p10-browser-'));
const report={purpose:'P10 actual multi-account shared-group UI and protected persistent storage',status:'PENDING',source_commit:spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).stdout.trim(),physical_acceptance:false,independent_review:'NOT_RUN'};
mkdirSync(root+'/artifacts/p10',{recursive:true});
rmSync(root+'/artifacts/p10/browser-report.json',{force:true});
let checks=0,context;const children=[];
const check=(value,name)=>{if(!value)throw Error(name);checks++;};
const control=(op,input)=>{const r=spawnSync('python3',['scripts/p06-stack.py','control',op],{cwd:root,encoding:'utf8',input});if(r.status!==0)throw Error('CONTROL_FAILED');return JSON.parse(r.stdout);};
// Chromium's resolver rules do not configure Node/Playwright's request client.
// Forward the original authenticated immutable request over verified TLS, then
// suppress only its response. Errors must not serialize cookies/CSRF headers.
async function commitBeforeLosingResponse(request){
  const u=new URL(request.url());if(u.origin!=='https://api.anynote.test:18443'||request.method()!=='POST')throw Error('FAULT_ROUTE_SCOPE');
  const headers={...Object.fromEntries(Object.entries(await request.allHeaders()).filter(([name])=>!name.startsWith(':'))),host:'api.anynote.test:18443'},body=request.postData();
  return new Promise((done,reject)=>{
    const req=https.request({hostname:'127.0.0.1',port:18443,servername:'api.anynote.test',ca:readFileSync(root+'/.local/p06/tls/ca.crt'),path:u.pathname,method:'POST',headers},res=>{
      let bytes=0;res.on('data',b=>{bytes+=b.length;if(bytes>1048576)req.destroy();});res.on('end',()=>res.statusCode===200?done():reject(Error('FAULT_COMMIT_DENIED')));
    });req.on('error',()=>reject(Error('FAULT_TRANSPORT_FAILED')));req.setTimeout(15000,()=>req.destroy());req.end(body);
  });
}
try{
  if(process.env.GITHUB_ACTIONS==='true'){
    // Trust the locally generated test CA with real NSS validation; never ignore certificate errors.
    const db=join(process.env.HOME,'.pki/nssdb');mkdirSync(db,{recursive:true});
    if(!existsSync(join(db,'cert9.db'))){const r=spawnSync('certutil',['-N','--empty-password','-d','sql:'+db]);if(r.status!==0)throw Error('NSS_INIT');}
    const r=spawnSync('certutil',['-A','-d','sql:'+db,'-n','AnyNote P06 disposable CA','-t','C,,','-i',root+'/.local/p06/tls/ca.crt']);if(r.status!==0)throw Error('NSS_TRUST');
  }
  try{
    context=await chromium.launchPersistentContext(join(scratch,'profile'),{executablePath:process.env.CHROMIUM_EXECUTABLE??['/usr/bin/google-chrome','/usr/bin/chromium'].find(existsSync),headless:true,chromiumSandbox:true,acceptDownloads:true,args:['--host-resolver-rules=MAP app.anynote.test 127.0.0.1,MAP api.anynote.test 127.0.0.1','--no-proxy-server']});
  }catch(e){
    if(process.env.GITHUB_ACTIONS!=='true'&&process.argv.includes('--allow-cloud-sandbox-block')&&/sandbox|namespace|Operation not permitted|Failed to move to new namespace/i.test(String(e))){report.status='BLOCKED';report.reason='Cloud Chromium sandbox unavailable; hosted mandatory browser gate remains required';writeFileSync(root+'/artifacts/p10/browser-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));process.exitCode=0;}else throw e;
  }

  if(context){
    report.browser_version=context.browser().version();
    report.runtime_platform=process.platform;
    const errors=[],url='https://app.anynote.test:18443/auth/',phrase='public synthetic purple harbor paper lantern',options={protocol:'ctap2',ctap2Version:'ctap2_1',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true,hasPrf:true};
    const launch=()=>chromium.launchPersistentContext(join(scratch,'profile-'+children.length),{executablePath:process.env.CHROMIUM_EXECUTABLE??['/usr/bin/google-chrome','/usr/bin/chromium'].find(existsSync),headless:true,chromiumSandbox:true,acceptDownloads:true,args:['--host-resolver-rules=MAP app.anynote.test 127.0.0.1,MAP api.anynote.test 127.0.0.1','--no-proxy-server']});
    async function action(p,id,expected=null){await p.locator('#'+id).click();try{await p.waitForFunction(()=>!document.getElementById('status').dataset.busy&&!!document.getElementById('status').textContent,null,{timeout:300000});await p.waitForFunction(()=>!!document.getElementById('status').dataset.error||['Done','Готово'].includes(document.getElementById('status').textContent),null,{timeout:300000});}catch{throw Error('P10_UI_WAIT:'+id+':'+JSON.stringify(await p.evaluate(()=>({locked:document.getElementById('workspace').hidden,busy:!!document.getElementById('status').dataset.busy,error:document.getElementById('status').dataset.error,phase:document.getElementById('status').dataset.phase,diagnostics:globalThis.__custodyDiagnostics}))));}const e=await p.locator('#status').getAttribute('data-error');if(expected){check((Array.isArray(expected)?expected:[expected]).includes(e),'P10_EXPECTED_UI_DENIAL:'+id+':'+e);return;}if(e)throw Error('P10_UI:'+id+':'+e+':'+await p.locator('#status').getAttribute('data-phase')+':'+JSON.stringify(await p.evaluate(()=>globalThis.__custodyDiagnostics)));}
    // Observe only closed error/operation codes and visibility, never RPC values.
    // Native Worker execution, timers, custody guards and results remain untouched.
    async function observeCustody(ctx){await ctx.addInitScript(()=>{
      globalThis.__custodyDiagnostics=[];const stamp=value=>{const out=globalThis.__custodyDiagnostics;out.push({...value,ms:Math.floor(performance.now())});if(out.length>32)out.shift();};
      document.addEventListener('visibilitychange',()=>stamp({event:'visibility',hidden:document.hidden}));addEventListener('pagehide',()=>stamp({event:'pagehide'}));
      const NativeWorker=globalThis.Worker;globalThis.Worker=class extends NativeWorker{
        constructor(...args){super(...args);this.operations=new Map();this.addEventListener('message',({data})=>{if(data?.id){const operation=this.operations.get(data.id);this.operations.delete(data.id);if(typeof data.error==='string'&&/^[A-Z_]+$/.test(data.error))stamp({event:'custody-error',operation,error:data.error,...(typeof data.lock_reason==='string'?{lock_reason:data.lock_reason}:{})});}});this.addEventListener('error',()=>stamp({event:'worker-error'}));}
        postMessage(message,...rest){if(message?.version===1&&typeof message.op==='string')this.operations.set(message.id,message.op==='notes'?'notes.'+message.args?.[1]:message.op);return super.postMessage(message,...rest);}
      };
    });}
    async function readyWriter(p){const until=Date.now()+15000;while(Date.now()<until){const ready=await p.evaluate(async()=>{const el=document.getElementById('profiles');if(!el?.value)return true;const {IndexedVault}=await import('/auth/vault-store.js'),store=await new IndexedVault(JSON.parse(el.value)).open();try{return await store.transaction(false,async tx=>{const s=await tx.get();return !s.lease||s.lease.expires<=Date.now();});}finally{store.close();}});if(ready)return;await new Promise(r=>setTimeout(r,250));}throw Error('WRITER_LEASE_REMAINING');}
    // Three automated users share one runner IP. Pace genuine requests below the
    // unchanged production per-session/IP budgets; never mock an API response.
    const requestSlots=new Map();
    async function pace(route){const u=new URL(route.request().url()),family=/\/accounts\/[^/]+\/roster$/.test(u.pathname)?'roster':/\/(?:groups|me\/group)/.test(u.pathname)?'groups':null;if(family){const now=Date.now(),next=Math.max(now,requestSlots.get(family)??now);requestSlots.set(family,next+1200);if(next>now)await new Promise(resolve=>setTimeout(resolve,next-now));}await route.continue();}
    async function setup(ctx,name){await observeCustody(ctx);const p=await ctx.newPage();await p.route('**/api/v1/**',pace);const cdp=await ctx.newCDPSession(p);p.on('pageerror',e=>errors.push(e.name));await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options});const response=await p.goto(url);check(response.status()===200&&response.headers()['content-security-policy'].includes("worker-src 'self'")&&!response.headers()['content-security-policy'].includes("'unsafe-eval'"),'REAL_TRUSTED_TLS_CSP');await p.waitForFunction(()=>document.getElementById('status').dataset.state==='ready');await p.locator('#invite').fill(control('invite').token);await p.locator('#handle').fill(name);await p.locator('#register').click();await p.locator('#pending').waitFor({state:'visible',timeout:30000});const download=p.waitForEvent('download');await p.locator('#kit').click();const kit=JSON.parse(readFileSync(await (await download).path(),'utf8')).kit;await p.locator('#saved').check();await p.locator('#verify-account').fill(kit.account_id.slice(-6));await p.locator('#verify-secret').fill(kit.recovery_secret.slice(-6));await p.locator('#local-phrase').fill(phrase);await p.locator('#finish').click();await p.waitForFunction(()=>document.getElementById('account').textContent.includes('trusted')||document.getElementById('status').dataset.error,null,{timeout:90000});check((await p.locator('#account').textContent()).includes('trusted'),'GENUINE_UV_REGISTRATION_ROOT_BOOTSTRAP');await notesPage(p);return {p,account:kit.account_id,root:kit.root_fingerprint,cdp};}
    async function notesPage(p){await p.goto(url+'notes.html');await p.waitForFunction(()=>document.getElementById('status').dataset.state==='ready');await readyWriter(p);await p.locator('#phrase').fill(phrase);await action(p,'unlock');check(await p.locator('#workspace').isVisible(),'FRESH_POSSESSION_UNLOCK');}
    const owner=await setup(context,'p10-browser-owner');const peers=[];for(const name of ['p10-browser-editor','p10-browser-reader']){const ctx=await launch();children.push(ctx);peers.push(await setup(ctx,name));}
    const p=owner.p;await p.locator('#group-kind').selectOption('shared');await p.locator('#group-title').fill('PUBLIC browser shared group');await action(p,'create-group');const group=await p.locator('#groups li').filter({hasText:'PUBLIC browser shared group'}).getAttribute('data-id');check(!!group,'SHARED_CREATE_THROUGH_SHIPPED_UI');await p.locator('#thread-title').fill('PUBLIC browser shared thread');await action(p,'create-thread');await action(p,'new-entry');await p.locator('#note-title').fill('PUBLIC full history title');await p.locator('#note-body').fill('PUBLIC pre-invitation shared body');await action(p,'save-note');
    await p.locator('#members-panel > summary').click();await p.waitForFunction(()=>!document.getElementById('status').dataset.busy);await action(p,'close-history');
    for(const [index,role]of [[0,'editor'],[1,'reader']]){
      const peer=peers[index];await p.locator('#member-account').fill(peer.account);await p.locator('#member-root').fill(peer.root);await p.locator('#member-role').selectOption(role);await p.locator('#sharing-confirm').uncheck();await action(p,'invite-member','IDENTITY_CONFIRMATION_REQUIRED');await p.locator('#sharing-confirm').check();await action(p,'invite-member');const card=await p.locator('#share-card').inputValue();check(card.length>0&&!card.includes('PUBLIC pre-invitation shared body'),'PUBLIC_CARD_HAS_NO_NOTE_PLAINTEXT');
      await peer.p.locator('#members-panel > summary').click();await peer.p.locator('#share-card').fill(card);await peer.p.locator('#member-root').fill(owner.root);await peer.p.locator('#sharing-confirm').check();await action(peer.p,'accept-invitation');check((await peer.p.locator('#membership-state').textContent()).includes('waiting'),'PENDING_GRANTS_EXPLICIT_STATE');
      await action(p,'activate-member');await action(p,'show-share-card');const activeCard=await p.locator('#share-card').inputValue();await peer.p.locator('#share-card').fill(activeCard);await action(peer.p,'import-group');
      await peer.p.locator('#groups button').filter({hasText:'PUBLIC browser shared group'}).click();await peer.p.waitForFunction(()=>!document.getElementById('status').dataset.busy);await peer.p.locator('#threads button').filter({hasText:'PUBLIC browser shared thread'}).click();await peer.p.waitForFunction(()=>!document.getElementById('status').dataset.busy);await peer.p.locator('#entries button').first().click();await peer.p.waitForFunction(()=>document.getElementById('note-body').value==='PUBLIC pre-invitation shared body');check(true,'INDEPENDENT_ACCOUNT_READS_RETAINED_ENCRYPTED_HISTORY');
    }
    const editor=peers[0].p,reader=peers[1].p;
    await action(editor,'refresh','PINNED_ACCOUNT_REQUIRED');await action(p,'show-share-card');await editor.locator('#share-card').fill(await p.locator('#share-card').inputValue());await action(editor,'import-group');check(true,'NEW_MEMBER_PIN_REQUIRES_INDEPENDENT_CARD_REFRESH');
    await action(editor,'refresh');await editor.locator('#threads button').filter({hasText:'PUBLIC browser shared thread'}).click();await editor.waitForFunction(()=>!document.getElementById('status').dataset.busy);await action(editor,'new-entry');await editor.locator('#note-title').fill('PUBLIC editor live note');await editor.locator('#note-body').fill('PUBLIC independent browser editor body');await action(editor,'save-note');check(await editor.locator('#save-state').getAttribute('data-state')==='COMMITTED','EDITOR_PUBLISHES_WITH_OWN_DEVICE_SIGNATURE');
    await action(editor,'new-entry');await editor.locator('#note-title').fill('PUBLIC revoked local draft');await editor.locator('#note-body').fill('PUBLIC revoked local work');await action(editor,'save-local');const revokedDraft=await editor.locator('#drafts li').last().getAttribute('data-id');check(!!revokedDraft,'EDITOR_UNSENT_DRAFT_PERSISTED_BEFORE_REMOVAL');
    await reader.bringToFront();
    if(await reader.locator('#workspace').isHidden()){
      const diagnostics=await reader.evaluate(()=>globalThis.__custodyDiagnostics);
      check(!diagnostics.some(d=>d.lock_reason==='worker-integrity'||['INTEGRITY_FAILURE','LOCAL_CONTEXT_MISMATCH','ROLLBACK_QUARANTINE'].includes(d.error)),'READER_PROTECTIVE_INTEGRITY_LOCK');
      await reader.locator('#phrase').fill(phrase);await action(reader,'unlock');await reader.locator('#groups button').filter({hasText:'PUBLIC browser shared group'}).click();await reader.waitForFunction(()=>!document.getElementById('status').dataset.busy);await reader.locator('#threads button').filter({hasText:'PUBLIC browser shared thread'}).click();await reader.waitForFunction(()=>!document.getElementById('status').dataset.busy);check(true,'READER_RETURNS_THROUGH_REAL_UNLOCK_AFTER_PAUSE');
    }
    await action(reader,'new-entry');await reader.locator('#note-title').fill('PUBLIC reader draft');await reader.locator('#note-body').fill('PUBLIC reader work survives denial');await action(reader,'save-local');await action(reader,'save-note','ROLE_FORBIDDEN');check(await reader.locator('#note-body').inputValue()==='PUBLIC reader work survives denial','READER_DRAFT_RETAINED');
    // Owner verifies every writer contribution before closing the immutable history.
    await action(p,'refresh');await p.locator('#threads button').filter({hasText:'PUBLIC browser shared thread'}).click();await p.waitForFunction(()=>!document.getElementById('status').dataset.busy);await p.locator('#entries button').last().click();await p.waitForFunction(()=>document.getElementById('note-body').value==='PUBLIC independent browser editor body');await action(p,'close-history');
    const member=p.locator('#members-list li').filter({has: p.locator('[data-account="'+peers[0].account+'"]')});
    await p.locator('#members-list li[data-account="'+peers[0].account+'"] button').filter({hasText:'Remove access'}).click();await p.waitForFunction(()=>!document.getElementById('status').dataset.busy);check((await p.locator('#membership-state').textContent()).includes('paused'),'REMOVAL_VISIBLE_MAINTENANCE_STATE');
    // A visible P11 poll may already have concealed the removed group before
    // Refresh runs. Both timings must clear the view and retain the actual draft.
    await action(editor,'refresh',['NOT_FOUND',null]);check(await editor.locator('#editor').isHidden()&&await editor.locator('#preview').textContent()==='','REMOVED_VIEW_MASKED_WITH_DRAFTS_PRESERVED');check(await editor.locator('#note-body').inputValue()===''&&await editor.locator('#drafts li[data-id="'+revokedDraft+'"]').count()===1,'REMOVAL_CLEARS_DOM_AND_RETAINS_ENCRYPTED_DRAFT');await editor.locator('#drafts li[data-id="'+revokedDraft+'"] button').click();await editor.waitForFunction(()=>document.getElementById('note-body').value==='PUBLIC revoked local work');check(true,'REMOVED_USER_RECOVERS_OWN_UNSENT_LOCAL_WORK');await action(editor,'refresh',['NOT_FOUND',null]);check(await editor.locator('#editor').isHidden()&&await editor.locator('#note-body').inputValue()===''&&await editor.locator('#drafts li[data-id="'+revokedDraft+'"]').count()===1,'RECOVERED_DRAFT_REMASKED_WITHOUT_LOSS');
    await action(p,'maintain-keys');await action(p,'close-history');await action(p,'refresh');await p.locator('#threads button').filter({hasText:'PUBLIC browser shared thread'}).click();await p.waitForFunction(()=>!document.getElementById('status').dataset.busy);await action(p,'new-entry');await p.locator('#note-title').fill('PUBLIC new epoch note');await p.locator('#note-body').fill('PUBLIC future browser body');await action(p,'save-note');check(await p.locator('#save-state').getAttribute('data-state')==='COMMITTED','ACTUAL_PWA_POST_REMOVAL_NEW_EPOCH');
    await p.locator('#language').selectOption('ru');check(await p.locator('#invite-member').textContent()==='Пригласить аккаунт','RUSSIAN_MEMBERSHIP_CONTROLS');await p.locator('#language').selectOption('en');
    const inspection=control('p09-inspect',JSON.stringify({markers:['PUBLIC browser shared group','PUBLIC pre-invitation shared body','PUBLIC independent browser editor body','PUBLIC reader work survives denial','PUBLIC revoked local work','PUBLIC future browser body']}));check(inspection.status==='PASS','ACTUAL_SQL_AND_LOG_NO_PLAINTEXT');
    for(const device of [owner,...peers]){const local=await device.p.evaluate(async()=>{const {IndexedVault}=await import('/auth/vault-store.js'),profile=JSON.parse(document.getElementById('profiles').value),store=await new IndexedVault(profile).open();try{return await store.transaction(false,async tx=>{const rows=[];await tx.each(r=>rows.push(r));return JSON.stringify({state:await tx.get(),rows});});}finally{store.close();}});check(!local.includes('PUBLIC revoked local work')&&!local.includes('PUBLIC reader work survives denial')&&!local.includes('PUBLIC pre-invitation shared body'),'ACTUAL_INDEPENDENT_INDEXEDDB_NO_PLAINTEXT');check(await device.p.evaluate(()=>localStorage.length===0&&sessionStorage.length===0),'NO_ORDINARY_STORAGE_CONTENT_OR_SESSION');}
    if(process.argv.includes('--p11-sync')){
      await action(p,'sync-now');check((await p.locator('#sync-state').textContent())==='Synced','P11_OWNER_FULL_STAGED_SYNC');
      await p.locator('#language').selectOption('ru');check(await p.locator('#sync-now').textContent()==='Синхронизировать','P11_RUSSIAN_SYNC_CONTROL');await p.locator('#language').selectOption('en');
      const again=await p.reload();check(again.status()===200,'P11_RELOAD_REAL_HOST');await p.waitForFunction(()=>document.getElementById('status').dataset.state==='ready');await readyWriter(p);await p.locator('#phrase').fill(phrase);await action(p,'unlock');await action(p,'sync-now');check(await p.locator('#sync-state').textContent()==='Synced','P11_INDEXEDDB_CURSOR_RESTART_AND_CATCHUP');
      report.p11_staged_sync_checks=4;
    }
    if(process.argv.includes('--p12-files'))report.p12_files=await filesCase({page:p,action,check,scratch,control});
    if(process.argv.includes('--p15-pwa')){
      if(!process.argv.includes('--p12-files'))throw Error('P15_REQUIRES_REAL_GIGABYTE_CASE');
      const passed=[];report.p15_pwa={status:'PENDING',checks:passed};
      Object.assign(report.p15_pwa,await pwaCase({page:p,action,scratch,control,readyWriter,commitBeforeLosingResponse,
        check:(value,name)=>{check(value,name);passed.push(name);}}));
      const quotaChecks=[];report.p15_storage={status:'PENDING',checks:quotaChecks};
      Object.assign(report.p15_storage,await quotaCase({page:p,action,readyWriter,draft:report.p15_pwa.retained_update_draft_id,
        check:(value,name)=>{check(value,name);quotaChecks.push(name);}}));
    }
    if(process.argv.includes('--p13-content'))report.p13_content=await contentCase({page:p,action,check,scratch,control});
    check(errors.length===0,'NO_RUNTIME_OR_CSP_ERRORS');report.status='PASS';report.checks=checks;report.custody_diagnostics=await Promise.all([owner,...peers].map(async(d,i)=>({role:['owner','editor','reader'][i],events:await d.p.evaluate(()=>globalThis.__custodyDiagnostics)})));report.chromium_sandbox=true;report.request_pacing='Genuine roster/group requests paced below unchanged production limits; no mocked API responses';report.tls_verification='Real trusted disposable CA and hostname validation';report.source_tree_dirty=!!spawnSync('git',['status','--porcelain'],{cwd:root,encoding:'utf8'}).stdout.trim();writeFileSync(root+'/artifacts/p10/browser-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
  }
}catch(e){report.status='FAIL';report.checks=checks;report.reason=String(e.message).slice(0,1000);report.custody_diagnostics=await Promise.all([context,...children].filter(Boolean).map(async ctx=>Promise.all(ctx.pages().map(p=>p.evaluate(()=>({hidden:Boolean(document.getElementById('workspace')?.hidden),events:globalThis.__custodyDiagnostics??[]})).catch(()=>({unavailable:true}))))));writeFileSync(root+'/artifacts/p10/browser-report.json',JSON.stringify(report,null,2)+'\n');throw e;}finally{for(const ctx of children)await ctx.close();await context?.close();rmSync(scratch,{recursive:true,force:true});}
