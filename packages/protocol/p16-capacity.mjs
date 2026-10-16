// O06 measured registered-account/device and retained signed SQL fixture.
import assert from 'node:assert/strict';
import {account,enroll,privateGroup,publish,edit,content,notes,ident} from './p16-fixture.mjs';
import {readOwnedSecrets} from './notes/test-fixture.mjs';
import {sealObject,openObject} from './adapters/core.mjs';
import {sodium,un64} from './adapters/primitives.mjs';
import {wire} from './adapters/codecs/identity-codec.mjs';
import {digest} from './adapters/codecs/protocol-codec.mjs';
import {execFileSync,spawn} from 'node:child_process';
import {once} from 'node:events';
import {cpus,totalmem,platform,arch} from 'node:os';
import {mkdirSync,writeFileSync} from 'node:fs';
const action=(name)=>JSON.parse(execFileSync('python3',['scripts/p16-drill.py','action',name],{encoding:'utf8',maxBuffer:1048576}));
const started=Date.now(),configuration=action('capacity-prepare'),fixtures=[];let peak=process.memoryUsage().rss,secret;
const timer=setInterval(()=>peak=Math.max(peak,process.memoryUsage().rss),50);
try{
 const accounts=10,activeDevices=[];
 for(let i=0;i<accounts;i++){const f=await account(configuration);fixtures.push(f);activeDevices.push(f.profile.device_id);for(let n=0;n<4;n++)activeDevices.push(await enroll(f));console.log('PASS: actual registered capacity accounts/devices '+fixtures.length+'/'+activeDevices.length);}
 assert.equal(new Set(activeDevices).size,50);
 const f=fixtures[0],g=await privateGroup(f),thread=await publish(f,edit(g.group_id,'thread',null,null,content('P16 capacity thread'))),entry=await publish(f,edit(g.group_id,'entry',null,thread.object_id,content('P16 capacity fixture','Public synthetic capacity content. '.repeat(24)))),sample=(await notes(f,'open',[{group_id:g.group_id,object_id:entry.object_id,revision_id:entry.receipt.receipt.revision_id,object_kind:'entry',thread_id:thread.object_id,bundle:entry.request.bundle}])).payload;
 const owned=await readOwnedSecrets(f);secret=un64(owned.group_keys.find(k=>k.group_id===g.group_id).group_secret);for(const k of owned.group_keys)k.group_secret='';owned.device_signing_secret='';owned.device_encryption_secret='';
 const child=spawn('python3',['scripts/p16-drill.py','action','capacity-load'],{stdio:['pipe','pipe','pipe']});let output='',error='',streamError;child.stdin.on('error',e=>{streamError=e;});child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>error+=b);let previous=entry.receipt.heads[0];
 const send=async value=>{if(streamError){await completion;throw streamError;}try{if(!child.stdin.write(JSON.stringify(value)+'\n'))await once(child.stdin,'drain');}catch(e){await completion;throw e;}};
 const completion=new Promise((ok,no)=>{child.on('error',no);child.on('close',code=>code===0?ok(output):no(Error('CAPACITY_LOAD_FAILED:'+error.slice(-2000))));});completion.catch(()=>{});
 await send({account_id:f.pins.account_id,device_id:f.profile.device_id,group_id:g.group_id,object_id:entry.object_id,count:100000,parent:previous});
 const generationStarted=Date.now();
 for(let i=0;i<100000;i++){const payload=structuredClone(sample);payload.context={...payload.context,operation_id:ident(),revision_id:ident(),action:'update',parents:[previous]};const bundle=sealObject(wire(payload),secret,f.initial.keys.signing.privateKey);const verified=openObject(wire(bundle),secret,f.initial.keys.signing.publicKey,wire(payload.context));assert.equal(verified.markdown,payload.markdown);await send(bundle);previous={revision_id:payload.context.revision_id,envelope_digest:digest('envelope',wire(bundle.envelope))};if(i%25000===0)console.log('Signed/verified/enqueued retained capacity revisions '+(i+1)+'/100000');}
 child.stdin.end();const installed=JSON.parse(await completion),loadedAt=Date.now();assert.equal(installed.status,'PASS');assert.equal(installed.retained_signed_revisions_inserted,100000);assert(installed.quota_journal_consistent);
 const latency=[];let after=null,pages=0,observed=0;
 do{const before=performance.now(),response=await f.browser.call('/objects/'+entry.object_id+'/revisions'+(after?'?after='+after:''));latency.push(performance.now()-before);assert.equal(response.status,200);assert(response.json.revisions.length<=100);pages++;observed+=response.json.revisions.length;after=response.json.next;await new Promise(r=>setTimeout(r,550));}while(after!==null&&pages<=1002);
 assert.equal(observed,100001);const metrics=action('capacity-metrics');assert.equal(metrics.database_counts.users,10);assert.equal(metrics.database_counts.devices,50);assert(metrics.database_counts.object_revisions>=100000);latency.sort((a,b)=>a-b);
 const report={status:'PASS',purpose:'P16 O06 actual capacity fixture, distinct from 100 GB physical acceptance',source_commit:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),source_tree_dirty:!!execFileSync('git',['status','--porcelain'],{encoding:'utf8'}).trim(),reference_host:{platform:platform(),arch:arch(),logical_cpus:cpus().length,cpu:cpus()[0]?.model,total_memory_bytes:totalmem()},request_spacing_ms:550,memory_scope:'sampled Node main process; PHP allocated peak separately; container snapshots are not process peaks',accounts:10,active_devices:50,retained_signed_revisions_inserted:100000,every_client_record_encrypted_signed_and_opened:true,every_server_bundle_signature_verified:true,bulk_fixture_installed:installed,http_publication_requests_for_bulk:0,actual_authenticated_http_history_pages:pages,actual_history_rows_read:observed,http_page_latency_ms:{p50:latency[Math.floor(latency.length*.5)],p95:latency[Math.floor(latency.length*.95)],max:latency.at(-1)},generation_and_load_ms:loadedAt-generationStarted,history_read_elapsed_ms:Date.now()-loadedAt,maximum_observed_node_rss_bytes:peak,metrics,logical_100gb_inventory:'NOT_RUN',physical_100gb_fixture:'NOT_RUN',reason:'The runner has less than 100 GB free before backup/working reserves; no sparse files, fabricated quota rows or production-disk fill substitute for real ciphertext.',elapsed_ms:Date.now()-started,physical_acceptance:false};
 mkdirSync('artifacts/p16',{recursive:true});writeFileSync('artifacts/p16/capacity-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}finally{clearInterval(timer);if(secret)sodium.memzero(secret);for(const f of fixtures){await f.engine.globalLock();f.initial.dispose();}}
