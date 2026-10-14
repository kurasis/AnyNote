import {PortableReader} from './content/portable.mjs';
// Actual synthetic HTTPS/SQL export acceptance; no owner device or production work.
import assert from 'node:assert/strict';
import {mkdirSync,writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {account,privateGroup,ident,ok,publish,edit,content,notes} from './sync/http-fixture.mjs';
import {fixtureCheckCount,control} from './notes/http-fixture.mjs';
import {snapshotCommitment,pageReceipt} from './sync/codec.mjs';
let checks=0;const check=v=>{assert(v);checks++;},same=(a,b)=>{assert.deepEqual(a,b);checks++;};
const fixtures=[];async function user(label){let f;f=await account(label+'-'+Date.now(),{portableTransport:()=>({get:path=>ok(f.browser,path),close(){}})});fixtures.push(f);return f;}
async function denied(f,path,code,body,method){const result=await f.browser.call(path,body,method);same(result.json?.error?.code,code);check(result.status!==200);}
try{
 const f=await user('p13-owner'),other=await user('p13-other'),g=await privateGroup(f);
 const thread=await publish(f,edit(g.group_id,'thread',null,null,content('P13 PUBLIC thread')));
 const first=await publish(f,edit(g.group_id,'entry',null,thread.object_id,content('P13 PRIVATE first','P13 PRIVATE body')));
 const second=await publish(f,edit(g.group_id,'entry',first.object_id,thread.object_id,content('P13 PRIVATE second','P13 PRIVATE changed'),first.receipt.heads));
 const request={version:1,operation_id:ident(),group_ids:[g.group_id],include_history:false,include_trash:false};
 const result=await ok(f.browser,'/exports',request),id=result.descriptor.snapshot_id,path='/exports/'+id;
 same(result.descriptor.snapshot_purpose,'export');same(result.scope.account_id,f.pins.account_id);same(result.selection,request);same(await ok(f.browser,'/exports',request),result);
 await denied(f,'/exports','IDEMPOTENCY_MISMATCH',{...request,include_history:true});
 await denied(f,'/exports','RESOURCE_LIMIT',{...request,operation_id:ident()});
 await denied(other,path,'NOT_FOUND');await denied(other,path+'/catalog','NOT_FOUND');await denied(other,path+'/pages','NOT_FOUND');
 await denied(f,path+'/renew','INVALID_REQUEST',{version:1});
 const catalog=await ok(f.browser,path+'/catalog');same(catalog.groups.length,1);same(catalog.groups[0].group_id,g.group_id);
 const page=await ok(f.browser,path+'/pages');check(page.page.items.some(x=>x.revision_id===second.receipt.receipt.revision_id));check(!page.page.items.some(x=>x.revision_id===first.receipt.receipt.revision_id));
 same(snapshotCommitment([pageReceipt(page.page)]),result.descriptor.inventory_digest);
 const captured=await ok(f.browser,path+'/records/'+second.receipt.receipt.revision_id);same(captured.record,second.request.bundle);
 const progressed=await ok(f.browser,path);check(BigInt(progressed.served_bytes)>0n);await ok(f.browser,path+'/records/'+second.receipt.receipt.revision_id);same((await ok(f.browser,path)).served_bytes,progressed.served_bytes);
 const renewed=await ok(f.browser,path+'/renew',{version:1});same(renewed.descriptor,result.descriptor);check(BigInt(renewed.maximum_expires_at_ms)-BigInt(result.descriptor.created_at)<=86401000n);
 await denied(f,path+'/renew','INVALID_REQUEST',{version:1});
 const later=await publish(f,edit(g.group_id,'entry',first.object_id,thread.object_id,content('P13 later live body'),second.receipt.heads));
 same((await ok(f.browser,path+'/pages')).page,page.page);same((await ok(f.browser,path+'/records/'+second.receipt.receipt.revision_id)).record,second.request.bundle);
 await denied(f,path+'/records/'+later.receipt.receipt.revision_id,'NOT_FOUND');
 same((await ok(f.browser,path,undefined,'DELETE')).state,'CANCELLED');await denied(f,path,'SYNC_CURSOR_EXPIRED');
 const full=await ok(f.browser,'/exports',{...request,operation_id:ident(),include_history:true});const history=await ok(f.browser,'/exports/'+full.descriptor.snapshot_id+'/pages');check(history.page.items.some(x=>x.revision_id===first.receipt.receipt.revision_id));await ok(f.browser,'/exports/'+full.descriptor.snapshot_id,undefined,'DELETE');
 const reportOnly=control('p13-retain',JSON.stringify({group_id:g.group_id})),ancestor=reportOnly.items.find(r=>r.eligible)?.revision_id;check(ancestor);
 const before=control('p13-payload-state',JSON.stringify({revision_id:ancestor}));same(before.payload_status,'retained');
 same(control('p13-payload-state',JSON.stringify({revision_id:ancestor})),before);
 const pinned=await ok(f.browser,'/exports',{...request,operation_id:ident(),include_history:true});
 const blocked=control('p13-retain',JSON.stringify({group_id:g.group_id,apply:true}));check(blocked.items.find(r=>r.revision_id===ancestor).reasons.includes('active-snapshot-or-export'));same(control('p13-payload-state',JSON.stringify({revision_id:ancestor})),before);
 await ok(f.browser,'/exports/'+pinned.descriptor.snapshot_id,undefined,'DELETE');
 const compacted=control('p13-retain',JSON.stringify({group_id:g.group_id,apply:true}));check(BigInt(compacted.released_ciphertext_bytes)>0n);same(control('p13-payload-state',JSON.stringify({revision_id:ancestor})),{payload_status:'pruned',has_ciphertext:false,has_signature:true,attachments:0});
 const afterPrune=await ok(f.browser,'/exports',{...request,operation_id:ident(),include_history:true}),prunedPage=await ok(f.browser,'/exports/'+afterPrune.descriptor.snapshot_id+'/pages');check(prunedPage.page.items.some(r=>r.revision_id===ancestor&&r.payload_status==='pruned'));const compactProof=await ok(f.browser,'/exports/'+afterPrune.descriptor.snapshot_id+'/records/'+ancestor);same(compactProof.record.payload_status,'pruned');check(!('ciphertext' in compactProof.record));await ok(f.browser,'/exports/'+afterPrune.descriptor.snapshot_id,undefined,'DELETE');same(control('p12-reconcile').differences,[]);
 const resync=await ok(f.browser,'/snapshots',{version:1,operation_id:ident(),purpose:'resync',group_id:g.group_id}),resyncPath='/snapshots/'+resync.descriptor.snapshot_id;
 await notes(f,'sync',['snapshotStart',resync]);await notes(f,'sync',['catalog',await ok(f.browser,resyncPath+'/catalog')]);const resyncPage=await ok(f.browser,resyncPath+'/pages?index=0');await notes(f,'sync',['snapshotPage',resyncPage]);
 for(const item of resyncPage.page.items){const response=await ok(f.browser,resyncPath+'/revisions/'+item.revision_id);await notes(f,'sync',['snapshotItem',response]);}
 same((await notes(f,'sync',['snapshotFinish',{}])).cursor,resync.descriptor.watermark);await denied(f,'/objects/'+first.object_id+'/revisions/'+ancestor,'NOT_FOUND');await ok(f.browser,resyncPath,undefined,'DELETE');
 await assert.rejects(()=>notes(f,'cached',[ancestor]),/PAYLOAD_UNAVAILABLE/);checks++;
 const portableLease=await ok(f.browser,'/exports',{...request,operation_id:ident(),include_history:true});const begin=await notes(f,'portable',['begin',{confirm:true,result:portableLease}]);check(begin.recipient.startsWith('age1'));check(!('kit' in begin));const encrypted=[];let final;
 for(let n=0;n<10000;n++){const frame=await notes(f,'portable',['next',{}]);if(frame.done){final=frame;break;}check(frame.ciphertext instanceof Uint8Array);encrypted.push(Buffer.from(frame.ciphertext));check(!('object_dek' in frame)&&!('group_secret' in frame));}
 check(final?.kit);const blob=new Blob(encrypted),offline=new PortableReader(()=>blob.stream(),final.kit);const recovered=await offline.validate();same(recovered.status,'VERIFIED_OFFLINE');check(recovered.notes.some(n=>n.payload_status==='pruned'));const latest=await offline.note(later.receipt.receipt.revision_id);same(latest.payload.title,'P13 later live body');offline.close();await ok(f.browser,'/exports/'+portableLease.descriptor.snapshot_id,undefined,'DELETE');
 const report={purpose:'P13 actual export HTTPS/SQL development checks',status:'PASS',checks:checks+fixtureCheckCount(),source_commit:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),source_tree_dirty:Boolean(execFileSync('git',['status','--porcelain'],{encoding:'utf8'}).trim()),physical_acceptance:false,scope:'Captured export leases, current authorization, reference-safe retention and quota, and pruned-payload full resync; full P13 acceptance remains required'};
 mkdirSync('artifacts/p13',{recursive:true});writeFileSync('artifacts/p13/http-development-report.json',JSON.stringify(report,null,2)+'\n');console.log(report);
}finally{for(const f of fixtures){await f.engine?.globalLock();f.initial?.dispose();}}
