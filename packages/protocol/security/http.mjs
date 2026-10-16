// Only the separately marked P17 target; genuine TLS, WebAuthn, Laravel and SQL.
import assert from 'node:assert/strict';
import https from 'node:https';
import http from 'node:http';
import {readFileSync,mkdirSync,writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {authenticator} from '../p16-authenticator.mjs';
import {initialRoot,registrationRequest} from '../auth-client.mjs';
import {VaultEngine} from '../vault/engine.mjs';
import {Store,phrase} from '../notes/test-fixture.mjs';
import {readOwnedSecrets} from '../notes/test-fixture.mjs';
import {privateGroup,publish,edit,content,uploadFile,downloadFile,notes} from '../p16-fixture.mjs';
import {b64} from '../adapters/primitives.mjs';
const ident=()=>randomBytes(16).toString('base64url'),control=(op,x)=>JSON.parse(execFileSync('python3',['scripts/p17-stack.py','control',op],{input:x?JSON.stringify(x):undefined,encoding:'utf8'}));
const fixtures=[],times=[],operations=[];let checks=0,transientRetries=0;const check=v=>{assert(v);checks++;},same=(a,b)=>{assert.deepEqual(a,b);checks++;};
class Browser {
 port=20443;origin='https://app.anynote.test:20443';ca=readFileSync('.local/p06/tls/ca.crt');cookie;csrf;
 async call(path,body,method=body?'POST':'GET',extra={}){
  const text=extra.raw??(body===undefined?undefined:JSON.stringify(body)),started=performance.now();
  const result=await new Promise((done,reject)=>{const r=https.request({hostname:'127.0.0.1',port:this.port,servername:'api.anynote.test',ca:this.ca,path:'/api/v1'+path,method,headers:{Host:'api.anynote.test:'+this.port,Origin:this.origin,...(this.cookie?{Cookie:this.cookie}:{}),...(this.csrf?{'X-CSRF-TOKEN':this.csrf}:{}),...(text?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(text)}:{}),...extra.headers}},response=>{const chunks=[];let bytes=0;response.on('data',b=>{if(extra.lose){response.destroy();r.destroy();reject(Error('SYNTHETIC_RESPONSE_LOSS'));return;}bytes+=b.length;if(bytes>4194304)r.destroy(Error('BOUNDED_HTTP'));else chunks.push(b);});response.on('error',reject);response.on('end',()=>{let json;try{json=JSON.parse(Buffer.concat(chunks));}catch{}done({status:response.statusCode,json,headers:response.headers});});});r.setTimeout(30000,()=>r.destroy(Error('HTTP_TIMEOUT')));r.on('error',reject);r.end(text);});
  times.push(performance.now()-started);if(result.headers['set-cookie'])this.cookie=result.headers['set-cookie'].filter(c=>c.startsWith('__Host-vault_session=')).map(c=>c.split(';')[0]).join('; ');if(result.json?.csrf_token)this.csrf=result.json.csrf_token;return result;
 }
}
async function ok(browser,path,body,method){const r=await browser.call(path,body,method);if(r.status!==200)throw Error('P17_HTTP:'+path.split('?')[0]+':'+r.status+':'+r.json?.error?.code);checks++;return r.json;}
async function committed(browser,path,body){
 const immutable=JSON.stringify(body);
 for(let attempt=0;attempt<4;attempt++){
  same(JSON.stringify(body),immutable);const r=await browser.call(path,body);
  if(r.status===200){checks++;return r.json;}
  same(r.status,503);same(r.json?.error?.code,'TEMPORARY_UNAVAILABLE');transientRetries++;
  const delay=Number(r.headers['retry-after']);check(Number.isFinite(delay)&&delay>=1&&delay<=2);
  await new Promise(resolve=>setTimeout(resolve,delay*1000));
 }
 throw Error('Bounded immutable publication retries exhausted');
}
async function account(){
 const browser=new Browser();await ok(browser,'/auth/csrf');const o=await ok(browser,'/auth/passkeys/options',{version:1,ceremony:'register',invitation:control('invite').token,handle:'p17-'+randomBytes(12).toString('hex')}),passkey=authenticator(o.account_id),registered=await ok(browser,'/auth/passkeys/verify',{version:1,challenge_id:o.challenge_id,credential:passkey.create(o.publicKey,{clientOrigin:browser.origin})});
 const capabilities=await ok(browser,'/capabilities'),initial=await initialRoot(capabilities.service_id,o.account_id),pins={service_id:capabilities.service_id,account_id:o.account_id,root_fingerprint:initial.fingerprint},profile={service_id:pins.service_id,account_id:pins.account_id,device_id:initial.device.device_id,profile_id:ident()},store=new Store(profile),engine=new VaultEngine(store);
 const challenge=await ok(browser,'/accounts/registration-challenge',{version:1,registration_id:registered.registration_id,identity:initial.identity,device:initial.device}),request=registrationRequest(registered.registration_id,initial,challenge.challenge);
 await engine.initialize(phrase,{device_signing_secret:b64(initial.keys.signing.privateKey),device_encryption_secret:b64(initial.keys.encryption.privateKey),group_keys:[]},pins,request);await ok(browser,'/accounts/register',request);
 const f={browser,initial,pins,profile,store,engine,cap:(await engine.unlock(phrase)).capability};fixtures.push(f);const s=await ok(browser,'/accounts/'+pins.account_id+'/roster');await engine.devices(f.cap,'snapshotStart',[s.identity,s.head,s.generation]);await engine.devices(f.cap,'snapshotPage',[s.events]);await engine.devices(f.cap,'snapshotFinish');const settings=await engine.devices(f.cap,'genesis');await ok(browser,'/me/settings-genesis',settings.request);await engine.devices(f.cap,'finishRegistration');return f;
}
if(process.argv.includes('--ready')){
 let ready=false;for(let n=0;n<30;n++){try{const r=await new Browser().call('/auth/csrf');if(r.status===200&&typeof r.json.csrf_token==='string'&&r.headers['set-cookie']?.some(c=>c.startsWith('__Host-vault_session=')&&/; secure/i.test(c)&&/; httponly/i.test(c)&&!/; domain=/i.test(c))){ready=true;break;}}catch{}await new Promise(resolve=>setTimeout(resolve,500));}
 assert(ready,'Actual P17 trusted HTTPS/SQL/session readiness failed');console.log('PASS: isolated P17 trusted HTTPS, SQL and secure session readiness');process.exit(0);
}
const canary='P17_SYNTHETIC_CONTENT_'+randomBytes(24).toString('hex'),filename='P17_SYNTHETIC_NAME_'+randomBytes(24).toString('hex')+'.bin';
let outbound=0;const trap=http.createServer((_q,r)=>{outbound++;r.end('synthetic SSRF canary');});await new Promise(r=>trap.listen(0,'127.0.0.1',r));
try{
 const a=await account(),b=await account(),c=await account(),groups=[];
 for(const f of [a,b,c])groups.push(await privateGroup(f));
 const thread=await publish(a,edit(groups[0].group_id,'thread',null,null,content(canary))),version=thread.request.bundle.envelope.header.context.revision_id;
 await publish(a,edit(groups[0].group_id,'entry',null,thread.object_id,content(canary,canary)));
 // Every foreign session attacks the exact known private IDs, including snapshot leases.
 const snapshot=await ok(a.browser,'/snapshots',{version:1,operation_id:ident(),purpose:'resync',group_id:groups[0].group_id}),sid=snapshot.descriptor.snapshot_id;
 for(const f of [b,c])for(const path of ['/groups/'+groups[0].group_id,'/objects/'+thread.object_id,'/objects/'+thread.object_id+'/revisions/'+version,'/snapshots/'+sid+'/catalog','/snapshots/'+sid+'/pages?index=0','/snapshots/'+sid+'/revisions/'+version])same((await f.browser.call(path)).status,404);
 // Malformed raw controls traverse the actual HTTP boundary and must never be 500/200.
 for(const raw of ['{"version":1,"version":1}','{"version":1,"\\u0076ersion":1}','{"a":"\\ud800"}','{"a":1e9999}','{"a":'.repeat(33)+'{}'+'}'.repeat(33)]){
  const r=await a.browser.call('/groups',undefined,'POST',{raw});same(r.status,400);same(r.json.error.code,'INVALID_REQUEST');
 }
 for(const headers of [{Origin:'https://hostile.anynote.test:20443'},{'X-CSRF-TOKEN':'synthetic-wrong-csrf'}])check((await a.browser.call('/groups',{version:1},'POST',{headers})).status!==200);
 // Unsupported push is closed at routing. A listening local endpoint proves no outbound hit.
 for(const endpoint of ['http://127.0.0.1:'+trap.address().port,'https://169.254.169.254/latest/meta-data/','https://[::1]/','https://push.example.invalid/redirect'])same((await a.browser.call('/me/notification-subscriptions',{endpoint})).status,404);
 same(outbound,0);
 // Read some committed response bytes then destroy the TLS request before consuming a receipt.
 const saved=await notes(a,'save',[edit(groups[0].group_id,'thread',null,null,content(canary+' lost'))]),queued=await notes(a,'queue',[saved.draft_id]),sent=await notes(a,'send',[queued.attempt_id]),path='/groups/'+groups[0].group_id+'/threads';
 await assert.rejects(()=>a.browser.call(path,sent.request,'POST',{lose:true}),/SYNTHETIC_RESPONSE_LOSS/);checks++;
 const retries=await Promise.all(Array.from({length:8},()=>committed(a.browser,path,sent.request)));for(const r of retries)same(r,retries[0]);await notes(a,'ack',[queued.attempt_id,retries[0]]);operations.push(sent.request.bundle.envelope.header.context.operation_id);
 // Genuine simultaneous publications across independent accounts and immutable attempts.
 const pending=[];for(let n=0;n<24;n++){const f=fixtures[n%3],g=groups[n%3],d=await notes(f,'save',[edit(g.group_id,'thread',null,null,content(canary+' '+n))]),q=await notes(f,'queue',[d.draft_id]),s=await notes(f,'send',[q.attempt_id]);pending.push({f,g,q,s});}
 const began=performance.now();for(let n=0;n<pending.length;n+=8)await Promise.all(pending.slice(n,n+8).map(async({f,g,q,s})=>{const receipt=await committed(f.browser,'/groups/'+g.group_id+'/threads',s.request);await notes(f,'ack',[q.attempt_id,receipt]);operations.push(s.request.bundle.envelope.header.context.operation_id);}));const concurrentMs=performance.now()-began;
 const plaintext=randomBytes(1048577),source=new Blob([plaintext]),receipt=await uploadFile(a,groups[0].group_id,source,filename),download=await downloadFile(a,groups[0].group_id,receipt.file_version_id);same(download.bytes,plaintext.length);same(download.sha256,createHash('sha256').update(plaintext).digest('hex'));
 for(const f of [b,c])for(const suffix of ['/manifest','/chunks/0'])same((await f.browser.call('/files/'+receipt.file_version_id+suffix)).status,404);
 const secrets=await readOwnedSecrets({store:a.store,scope:a.profile}),needles=[Buffer.from(canary),Buffer.from(filename),Buffer.from(a.initial.kit.recovery_secret),Buffer.from(b64(a.initial.keys.signing.privateKey)),Buffer.from(a.initial.keys.signing.privateKey),Buffer.from(b64(a.initial.keys.encryption.privateKey)),Buffer.from(a.initial.keys.encryption.privateKey),...secrets.group_keys.flatMap(g=>[Buffer.from(g.group_secret),Buffer.from(g.group_secret,'base64url')])];
 const serialized=JSON.stringify({state:a.store.state,rows:[...a.store.rows]});for(const needle of needles)check(!Buffer.from(serialized).includes(needle));
 const inspected=control('inspect',{needles:needles.map(b=>b.toString('base64')),operations});same(inspected.status,'PASS');check(inspected.tables>=78&&inspected.rows>100&&inspected.files>=2);same(inspected.operation_revision_counts,Array(operations.length).fill(1));
 // Public output is scanned before publication; secret/canary values are never recorded.
 const git=(...args)=>execFileSync('git',args,{encoding:'utf8'}).trim(),sorted=times.toSorted((a,b)=>a-b),report={purpose:'P17 isolated genuine multi-account HTTPS/SQL adversarial and store inspection',status:'PASS',source_commit:git('rev-parse','HEAD'),source_tree_dirty:git('status','--porcelain')!=='',checks,accounts:3,foreign_routes_checked:16,concurrent_publications:24,max_inflight:8,concurrent_elapsed_ms:concurrentMs,typed_transient_retries:transientRetries,discarded_response_retries:8,exactly_once_operations:operations.length,actual_file_bytes:plaintext.length,full_file_hash_verified:true,disabled_push_outbound_requests:outbound,inspection:inspected,http_requests:times.length,http_latency_ms:{p50:sorted[Math.floor(sorted.length*.5)],p95:sorted[Math.floor(sorted.length*.95)],max:sorted.at(-1)},physical_acceptance:false,independent_review:'NOT_RUN',limitations:['Synthetic authenticator; genuine maintained verifier, not physical UV','Bounded three-account concurrency and 1MiB+1 file; inherited gates retain separate full1GB and shared-device tests','Canary inspection only of owned P17 SQL/blob/logs and protected local fixture; no forensic completeness claim']};
 const raw=JSON.stringify(report,null,2)+'\n';for(const needle of needles)check(!Buffer.from(raw).includes(needle));mkdirSync('artifacts/p17',{recursive:true});writeFileSync('artifacts/p17/http-report.json',raw);console.log(raw);
}finally{await new Promise(r=>trap.close(r));for(const f of fixtures){f.initial.dispose();await f.engine.close();}}
