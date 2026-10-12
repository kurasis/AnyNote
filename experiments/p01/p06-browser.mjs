// Mandatory hosted sandboxed Chromium: genuine WebAuthn through the shipped strict-CSP UI.
import {chromium} from 'playwright-core';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,existsSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,join} from 'node:path';
import {spawnSync} from 'node:child_process';
const root=resolve(import.meta.dirname,'../..'),scratch=mkdtempSync(join(tmpdir(),'anynote-p06-browser-'));
const report={purpose:'P06 actual sandboxed WebAuthn account-security UI',status:'PENDING',source_commit:spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).stdout.trim(),physical_acceptance:false,independent_review:'NOT_RUN'};
mkdirSync(root+'/artifacts/p06',{recursive:true});
rmSync(root+'/artifacts/p06/browser-report.json',{force:true});
let checks=0,context;
const check=(value,name)=>{if(!value)throw Error(name);checks++;};
const control=op=>{const r=spawnSync('python3',['scripts/p06-stack.py','control',op],{cwd:root,encoding:'utf8'});if(r.status!==0)throw Error('CONTROL_FAILED');return JSON.parse(r.stdout);};
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
    if(process.env.GITHUB_ACTIONS!=='true'&&process.argv.includes('--allow-cloud-sandbox-block')&&/sandbox|namespace|Operation not permitted|Failed to move to new namespace/i.test(String(e))){report.status='BLOCKED';report.reason='Cloud Chromium sandbox unavailable; hosted mandatory browser gate remains required';writeFileSync(root+'/artifacts/p06/browser-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));process.exitCode=0;}else throw e;
  }
  if(context){
    const page=await context.newPage(),cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
    const authenticator=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
    const errors=[],bootstrapDiagnostics=[];let bootstrapped=false;
    page.on('pageerror',e=>{errors.push(e.name);if(!bootstrapped)bootstrapDiagnostics.push({runtime_error:e.name,message:e.message.slice(0,200)});});
    page.on('requestfailed',r=>{if(!bootstrapped){const u=new URL(r.url());bootstrapDiagnostics.push({path:u.pathname,failure:r.failure()?.errorText});}});
    page.on('console',m=>{if(!bootstrapped&&m.type()==='error')bootstrapDiagnostics.push({browser_error:m.text().slice(0,300)});});
    const response=await page.goto('https://app.anynote.test:18443/auth/');
    check(response.status()===200,'STATIC_TLS');const csp=response.headers()['content-security-policy'];check(csp.includes("frame-ancestors 'none'")&&!csp.includes("'unsafe-eval'")&&!csp.includes("'unsafe-inline'"),'STRICT_CSP');
    await page.waitForFunction(()=>document.getElementById('status').dataset.state, null, {timeout:15000});
    const bootstrap=await page.locator('#status').evaluate(e=>({state:e.dataset.state,error:e.dataset.error}));
    check(bootstrap.state==='ready','AUTH_BOOTSTRAP:'+JSON.stringify({bootstrap,diagnostics:bootstrapDiagnostics}));bootstrapped=true;
    const invitation=control('invite').token;await page.locator('#invite').fill(invitation);await page.locator('#handle').fill('p06-browser');await page.locator('#register').click();
    await page.locator('#pending').waitFor({state:'visible',timeout:20000});check(true,'REAL_ATTESTATION');
    const download=page.waitForEvent('download');await page.locator('#kit').click();const kitDownload=await download;const exported=JSON.parse(readFileSync(await kitDownload.path(),'utf8'));check(exported.version===1&&exported.service_url==='https://api.anynote.test:18443'&&exported.instructions.includes('Never send')&&exported.kit.recovery_secret.startsWith('anr1')&&exported.kit.recovery_secret.length===63,'COMPLETE_OFFLINE_KIT');await page.locator('#saved').check();await page.locator('#verify-account').fill(exported.kit.account_id.slice(-6));await page.locator('#verify-secret').fill(exported.kit.recovery_secret.slice(-6));exported.kit.recovery_secret='';
    await page.locator('#local-phrase').fill('public synthetic purple harbor paper lantern');await page.locator('#finish').click();await page.waitForFunction(()=>document.getElementById('account').textContent.includes('trusted')||document.getElementById('status').dataset.error,null,{timeout:20000});check((await page.locator('#account').textContent()).includes('trusted'),'REGISTRATION:'+await page.locator('#status').getAttribute('data-error'));check(true,'ROOT_PROOF_TRUSTED');
    const cookies=await context.cookies('https://api.anynote.test:18443');const session=cookies.find(c=>c.name==='__Host-vault_session');check(session&&session.domain==='api.anynote.test'&&session.secure&&session.httpOnly&&session.sameSite==='Strict'&&session.path==='/','HOST_ONLY_STRICT_COOKIE');check(!cookies.some(c=>c.name==='XSRF-TOKEN'),'NO_READABLE_CSRF_COOKIE');
    check(await page.evaluate(()=>localStorage.length===0&&sessionStorage.length===0),'NO_WEB_STORAGE_TOKENS');
    await page.locator('#add').click();await page.waitForFunction(()=>document.getElementById('status').textContent.includes('different passkey provider'),null,{timeout:20000});check(true,'EXISTING_PROVIDER_EXCLUSION');
    check((await cdp.send('WebAuthn.getCredentials',{authenticatorId:authenticator.authenticatorId})).credentials.length===1,'FIRST_RESIDENT_PROVIDER');
    // A second passkey requires another provider: the existing authenticator correctly
    // rejects excluded credential IDs. Keep production exclusion checks unchanged.
    await cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:authenticator.authenticatorId});
    const secondAuthenticator=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
    await page.locator('#add').click();await page.waitForFunction(()=>document.querySelectorAll('#passkeys li').length===2,null,{timeout:20000});check(true,'MULTIPLE_REAL_PASSKEYS');
    await page.locator('#codes').click();await page.locator('#recovery').waitFor({state:'visible'});check((await page.locator('#recovery').textContent()).split('\n').length===11,'AUTH_ONLY_RECOVERY_CODES');
    await page.locator('#logout').click();await page.waitForFunction(()=>document.getElementById('account').textContent==='Signed out');
    await page.locator('#login').click();await page.waitForFunction(()=>document.getElementById('account').textContent.includes('restricted'),null,{timeout:20000});check(true,'REAL_ASSERTION_RESTRICTED');
    const csrfDenial=await page.evaluate(async()=>{const r=await fetch('https://api.anynote.test:18443/api/v1/auth/logout',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({version:1})});return r.status;});check(csrfDenial===400,'REAL_BROWSER_CSRF_DENIAL');
    const publicState=await page.evaluate(async()=>{const {AuthClient}=await import('/auth/client.js');const c=new AuthClient('https://api.anynote.test:18443');const me=await c.call('/me',null,'me-result');return {state:me.session.state,content:me.content_access};});check(publicState.state==='restricted'&&!publicState.content,'NO_CONTENT_AFTER_LOGIN');
    check((await cdp.send('WebAuthn.getCredentials',{authenticatorId:secondAuthenticator.authenticatorId})).credentials.length===1,'SECOND_RESIDENT_PROVIDER');
    check(errors.length===0,'NO_RUNTIME_OR_CSP_ERRORS');report.status='PASS';report.checks=checks;report.tls_verification='NSS trusted disposable test CA, no bypass';report.chromium_sandbox=true;report.synthetic_authenticator='two independent CDP ctap2 resident UV providers';
    writeFileSync(root+'/artifacts/p06/browser-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
  }
}catch(e){report.status='FAIL';report.checks=checks;report.reason=String(e.message).slice(0,2000);writeFileSync(root+'/artifacts/p06/browser-report.json',JSON.stringify(report,null,2)+'\n');throw e;}finally{await context?.close();rmSync(scratch,{recursive:true,force:true});}
