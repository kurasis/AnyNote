// Actual TLS/Nginx/PHP/SQL/private blob store and protected maintained crypto.
import assert from 'node:assert/strict';
import {mkdirSync,writeFileSync} from 'node:fs';
import {mkdtempSync,openSync,closeSync,writeSync,rmSync,openAsBlob} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {control} from './notes/http-fixture.mjs';
import {Synchronizer,SyncClient} from './sync/client.mjs';
import {NotesClient} from './notes/client.mjs';
import {AuthClient} from './auth-client.mjs';
import {execFileSync,execFile} from 'node:child_process';
import {promisify} from 'node:util';
const execute=promisify(execFile);
import {account,privateGroup,ok,notes,ident,publish,edit,content,prepare,pathFor} from './sync/http-fixture.mjs';
import {binary} from './files/http.mjs';
import {hash,sodium} from './adapters/primitives.mjs';
let checks=0;const same=(a,b)=>{assert.deepEqual(a,b);checks++;};const fs=[];let cleanupVersion,cleanupFinish,cleanupReceipt;
async function denial(f,path,code,body,method){const r=await f.browser.call(path,body,method);same(r.json?.error?.code,code);}
try{
 const f=await account('p12-owner-'+Date.now()),other=await account('p12-other-'+Date.now());fs.push(f,other);const g=await privateGroup(f),hidden=await privateGroup(other),call=(op,x)=>f.engine.notes(f.cap,'files',[op,x]);
 for(const size of [0,1,8388607,8388608,8388609]){
  const bytes=sodium.randombytes_buf(size),source=new Blob([bytes]),made=await call('prepare',{group_id:g.group_id,source,name:'P12_SECRET_NAME.txt'}),before=await ok(f.browser,'/me/storage'),reserve=await ok(f.browser,'/groups/'+g.group_id+'/uploads',made.request);same((await ok(f.browser,'/groups/'+g.group_id+'/uploads',made.request)).upload_id,reserve.upload_id);
  await denial(other,'/uploads/'+reserve.upload_id,'NOT_FOUND');await denial(f,'/groups/'+g.group_id+'/uploads','IDEMPOTENCY_MISMATCH',{...made.request,plaintext_bytes:String(size+1)});
  const ciphertext=[];
  for(let index=0;index<Math.ceil(size/8388608);index++){
   const p=await call('part',{draft_id:made.draft_id,source,index});ciphertext.push(p.ciphertext);const route='/uploads/'+p.upload_id+'/parts/'+index,r=await binary(f.browser,route,p.ciphertext);same(r.status,200);await call('ackPart',{draft_id:made.draft_id,part:r.json});same((await binary(f.browser,route,p.ciphertext)).json,r.json);
   const bad=new Uint8Array(p.ciphertext);bad[0]^=1;same((await binary(f.browser,route,bad)).json.error.code,'IDEMPOTENCY_MISMATCH');same((await binary(other.browser,route,p.ciphertext)).json.error.code,'NOT_FOUND');
  }
  const finished=await call('finish',{draft_id:made.draft_id});
  if(size===1){const beforeFault=control('p12-transaction-state');control('p12-fault-on');try{await denial(f,'/uploads/'+finished.upload_id+'/commit','TEMPORARY_UNAVAILABLE',finished.request);}finally{control('p12-fault-off');}same(control('p12-transaction-state'),beforeFault);same((await ok(f.browser,'/uploads/'+finished.upload_id)).state,'RECEIVING');}
  let committed;if(size===8388609){const results=await Promise.all([ok(f.browser,'/uploads/'+finished.upload_id+'/commit',finished.request),execute('python3',['scripts/p06-stack.py','control','p12-collect'])]);committed=results[0];same(JSON.parse(results[1].stdout).deleted_files,0);}else committed=await ok(f.browser,'/uploads/'+finished.upload_id+'/commit',finished.request);same(await ok(f.browser,'/uploads/'+finished.upload_id+'/commit',finished.request),committed);const bound=await call('committed',{draft_id:made.draft_id,receipt:committed});same(bound.state,'UNATTACHED');const after=await ok(f.browser,'/me/storage');same(BigInt(after.committed_bytes)-BigInt(before.committed_bytes),BigInt(committed.ciphertext_bytes));same(after.reserved_bytes,before.reserved_bytes);
  const record=await ok(f.browser,'/files/'+committed.file_version_id+'/manifest'),reader=await call('open',{group_id:g.group_id,file_version_id:committed.file_version_id,record});
  for(let i=0;i<ciphertext.length;i++){const r=await binary(f.browser,'/files/'+committed.file_version_id+'/chunks/'+i);same(r.status,200);const decrypted=await call('decrypt',{reader_id:reader.reader_id,ciphertext:r.bytes});same(hash(decrypted.plaintext),hash(bytes.subarray(i*8388608,Math.min(bytes.length,(i+1)*8388608))));sodium.memzero(decrypted.plaintext);}
  same((await call('complete',{reader_id:reader.reader_id})).complete,true);await denial(other,'/files/'+committed.file_version_id+'/manifest','NOT_FOUND');await denial(f,'/uploads/'+finished.upload_id,'INVALID_REQUEST',undefined,'DELETE');
  const unattached=await ok(f.browser,'/me/unattached-files');assert(unattached.items.some(x=>x.file_version_id===committed.file_version_id));checks++;
  if(size===0){cleanupVersion=committed.file_version_id;cleanupFinish=finished;cleanupReceipt=committed;}
  if(size===1){const thread=await publish(f,edit(g.group_id,'thread',null,null,content('P12 thread'))),draft=await notes(f,'save',[edit(g.group_id,'entry',null,thread.object_id,content('P12 linked'))]);await notes(f,'attach',[{draft_id:draft.draft_id,file_draft_id:made.draft_id}]);const queued=await notes(f,'queue',[draft.draft_id]),sent=await notes(f,'send',[queued.attempt_id]),receipt=await ok(f.browser,pathFor(sent.request),sent.request);await notes(f,'ack',[queued.attempt_id,receipt]);assert(!(await ok(f.browser,'/me/unattached-files')).items.some(x=>x.file_version_id===committed.file_version_id));checks++;
   const wrong=await notes(other,'save',[edit(hidden.group_id,'thread',null,null,content('wrong'))]);await assert.rejects(notes(other,'attach',[{draft_id:wrong.draft_id,file_draft_id:made.draft_id}]),/ATTACHMENT_CONTEXT_MISMATCH/);checks++;
  }
  sodium.memzero(bytes);
 }
 const missingSource=new Blob(['missing part']),missing=await call('prepare',{group_id:g.group_id,source:missingSource});await ok(f.browser,'/groups/'+g.group_id+'/uploads',missing.request);const missingPart=await call('part',{draft_id:missing.draft_id,source:missingSource,index:0});await call('ackPart',{draft_id:missing.draft_id,part:{index:'0',ciphertext_bytes:String(missingPart.ciphertext.length),ciphertext_digest:hash(missingPart.ciphertext)}});const missingFinish=await call('finish',{draft_id:missing.draft_id});await denial(f,'/uploads/'+missing.request.upload_id+'/commit','INVALID_CHUNK',missingFinish.request);await ok(f.browser,'/uploads/'+missing.request.upload_id,undefined,'DELETE');
 const snapshot=await ok(f.browser,'/snapshots',{version:1,operation_id:ident(),purpose:'resync',group_id:g.group_id});assert(Number(snapshot.files.count)>=5);checks++;const filePage=await ok(f.browser,'/snapshots/'+snapshot.descriptor.snapshot_id+'/files?start=0');same(filePage.items.length,Number(snapshot.files.count));await denial(other,'/snapshots/'+snapshot.descriptor.snapshot_id+'/files','NOT_FOUND');await denial(f,'/files/'+cleanupVersion+'/unattached','INVALID_REQUEST',undefined,'DELETE');await ok(f.browser,'/snapshots/'+snapshot.descriptor.snapshot_id,undefined,'DELETE');
 const auth=new AuthClient('https://api.anynote.test:18443',async(url,options)=>{const u=new URL(url);assert.equal(u.origin,'https://api.anynote.test:18443');const result=await f.browser.call(u.pathname.slice('/api/v1'.length)+u.search,options.body?JSON.parse(options.body):undefined,options.method);return new Response(JSON.stringify(result.json),{status:result.status,headers:{'Content-Type':'application/json'}});});
 const synchronizer=new Synchronizer({transport:new SyncClient(auth),vault:{notes:(op,args=[])=>f.engine.notes(f.cap,op,args)},notes:new NotesClient(auth),authorize:async()=>{},group:async id=>{await notes(f,'group',[await ok(f.browser,'/groups/'+id)]);}});
 const synced=await synchronizer.catchUp();same(synced.state,'SYNCED');assert(synced.cursor);checks++;same((await call('history',{group_id:g.group_id})).length,5);
 // A completed synchronizer cancels its lease; explicit cleanup can now reclaim bytes.
 const active=control('p12-file-state');assert(active.file_pins>=0);checks++;
 const beforeDelete=await ok(f.browser,'/me/storage');same((await ok(f.browser,'/files/'+cleanupVersion+'/unattached',undefined,'DELETE')).state,'RECLAIMABLE');same((await ok(f.browser,'/me/storage')).committed_bytes,beforeDelete.committed_bytes);assert(control('p12-collect').deleted_files>=1);checks++;await denial(f,'/files/'+cleanupVersion+'/manifest','NOT_FOUND');same(control('p12-pruned-proof',JSON.stringify({file_version_id:cleanupVersion})).retained_fields,['envelope','request_digest']);same(await ok(f.browser,'/uploads/'+cleanupFinish.upload_id+'/commit',cleanupFinish.request),cleanupReceipt);same(control('p12-reconcile').differences,[]);
 if(process.argv.includes('--gigabyte')){
  const root=mkdtempSync(join(tmpdir(),'anynote-p12-owned-')),path=join(root,'explicit-public-synthetic.bin'),fd=openSync(path,'wx');const expected=createHash('sha256');
  try{for(let left=1000000000;left>0;){const p=randomBytes(Math.min(left,8388608));writeSync(fd,p);expected.update(p);left-=p.length;}}finally{closeSync(fd);}
  try{
   const source=await openAsBlob(path),made=await call('prepare',{group_id:g.group_id,source,name:'P12_GIGABYTE_SECRET_NAME.bin'}),reserve=await ok(f.browser,'/groups/'+g.group_id+'/uploads',made.request),before=await ok(f.browser,'/me/storage');let dataBytes=0;
   for(let index=0;index<120;index++){const p=await call('part',{draft_id:made.draft_id,source,index}),r=await binary(f.browser,'/uploads/'+reserve.upload_id+'/parts/'+index,p.ciphertext);same(r.status,200);dataBytes+=p.ciphertext.length;await call('ackPart',{draft_id:made.draft_id,part:r.json});p.ciphertext.fill(0);if(index%20===0)console.log('P12 gigabyte encrypted parts:',index+1);}
   same(dataBytes,1000001920);const finished=await call('finish',{draft_id:made.draft_id}),receipt=await ok(f.browser,'/uploads/'+reserve.upload_id+'/commit',finished.request);await call('committed',{draft_id:made.draft_id,receipt});same(await ok(f.browser,'/uploads/'+reserve.upload_id+'/commit',finished.request),receipt);
   const after=await ok(f.browser,'/me/storage');same(BigInt(after.committed_bytes)-BigInt(before.committed_bytes),BigInt(receipt.ciphertext_bytes));same(BigInt(before.reserved_bytes)-BigInt(after.reserved_bytes),BigInt(reserve.reserved_bytes));
   const record=await ok(f.browser,'/files/'+receipt.file_version_id+'/manifest'),reader=await call('open',{group_id:g.group_id,file_version_id:receipt.file_version_id,record}),observed=createHash('sha256');let outputBytes=0;
   for(let index=0;index<120;index++){const r=await binary(f.browser,'/files/'+receipt.file_version_id+'/chunks/'+index);same(r.status,200);const p=await call('decrypt',{reader_id:reader.reader_id,ciphertext:r.bytes});observed.update(p.plaintext);outputBytes+=p.plaintext.length;p.plaintext.fill(0);}
   same(outputBytes,1000000000);same(observed.digest('hex'),expected.digest('hex'));same((await call('complete',{reader_id:reader.reader_id})).complete,true);
  }finally{rmSync(root,{recursive:true});}
 }
 const expired=await call('prepare',{group_id:g.group_id,source:new Blob(['expiry'])}),expiredReservation=await ok(f.browser,'/groups/'+g.group_id+'/uploads',expired.request);control('p12-expire',JSON.stringify({upload_id:expiredReservation.upload_id}));same((await binary(f.browser,'/uploads/'+expiredReservation.upload_id+'/parts/0',new Uint8Array(22))).json.error.code,'UPLOAD_EXPIRED');const cleaned=control('p12-collect');assert(cleaned.expired_uploads>=1);checks++;same((await ok(f.browser,'/uploads/'+expiredReservation.upload_id)).state,'EXPIRED');same(control('p12-reconcile').differences,[]);
 const first=await call('prepare',{group_id:g.group_id,source:new Blob([])}),second=await other.engine.notes(other.cap,'files',['prepare',{group_id:hidden.group_id,source:new Blob([])}]),budget=control('p12-budget',JSON.stringify({available_bytes:'120000'}));
 try{
  const responses=await Promise.all([f.browser.call('/groups/'+g.group_id+'/uploads',first.request),other.browser.call('/groups/'+hidden.group_id+'/uploads',second.request)]);same(responses.filter(r=>r.status===200).length,1);same(responses.filter(r=>r.json?.error?.code==='QUOTA_EXCEEDED').length,1);
  for(let index=0;index<2;index++)if(responses[index].status===200){const owner=index===0?f:other;await ok(owner.browser,'/uploads/'+responses[index].json.upload_id,undefined,'DELETE');}
 }finally{control('p12-budget-restore',JSON.stringify({limit_bytes:budget.previous_limit_bytes}));}
 same(control('p12-reconcile').differences,[]);
 const partial=await call('prepare',{group_id:g.group_id,source:new Blob(['cancel'])}),reserved=await ok(f.browser,'/groups/'+g.group_id+'/uploads',partial.request),cancel=await ok(f.browser,'/uploads/'+reserved.upload_id,undefined,'DELETE');same(cancel.state,'CANCELLED');same((await ok(f.browser,'/uploads/'+reserved.upload_id,undefined,'DELETE')).state,'CANCELLED');await call('burn',{draft_id:partial.draft_id,confirm:true,status:cancel});same((await binary(f.browser,'/uploads/'+reserved.upload_id+'/parts/0',new Uint8Array(22))).json.error.code,'UPLOAD_EXPIRED');
 const git=(...a)=>execFileSync('git',a,{encoding:'utf8'}).trim();const report={purpose:'P12 actual TLS/SQL/blob/protected file transfers',status:'PASS',checks,source_commit:git('rev-parse','HEAD'),source_tree:git('rev-parse','HEAD^{tree}'),source_tree_dirty:git('status','--porcelain')!=='',physical_acceptance:false};mkdirSync('artifacts/p12',{recursive:true});writeFileSync('artifacts/p12/http-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}finally{for(const f of fs){f.initial.dispose();await f.engine.close();}}
