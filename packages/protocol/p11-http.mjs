// Actual maintained WebAuthn, TLS, Laravel, SQL and protected encryption; no physical claim.
import assert from 'node:assert/strict';
import {mkdirSync,writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {account,privateGroup,ident,ok,notes,publish,edit,content} from './sync/http-fixture.mjs';
import {control,fixtureCheckCount} from './notes/http-fixture.mjs';
import {checkedSnapshot,checkedDelta} from './sync/codec.mjs';
let checks=0;const check=(v)=>{assert(v);checks++;},same=(a,b)=>{assert.deepEqual(a,b);checks++;};
const fixtures=[];async function owner(name){const f=await account(name+'-'+Date.now());fixtures.push(f);return f;}
async function denied(f,path,code,body,method){const r=await f.browser.call(path,body,method);same(r.json?.error?.code,code);check(r.status!==200);}
const initialPins=control('p11-state').pins;
try{
 const f=await owner('p11-owner'),other=await owner('p11-other'),third=await owner('p11-third'),g=await privateGroup(f),hidden=await privateGroup(other),scope={...f.pins,group_id:g.group_id},thread=await publish(f,edit(g.group_id,'thread',null,null,content('P11 PUBLIC thread'))),entry=await publish(f,edit(g.group_id,'entry',null,thread.object_id,content('P11 PRIVATE TEST','P11 PRIVATE BODY TEST'))),request={version:1,operation_id:ident(),purpose:'resync',group_id:g.group_id};
 const r=checkedSnapshot(await ok(f.browser,'/snapshots',request),f.pins,f.profile.device_id,g.group_id),d=r.descriptor,path='/snapshots/'+d.snapshot_id;same(r.scope,scope);same(await ok(f.browser,'/snapshots',request),r);
 await denied(f,'/snapshots','IDEMPOTENCY_MISMATCH',{...request,group_id:null});for(const caller of [other,third])for(const route of [path+'/catalog',path+'/pages?index=0',path+'/revisions/'+entry.receipt.receipt.revision_id])await denied(caller,route,'NOT_FOUND');
 await notes(f,'sync',['snapshotStart',r]);const catalog=await ok(f.browser,path+'/catalog');await notes(f,'sync',['catalog',catalog]);const page=await ok(f.browser,path+'/pages?index=0');await notes(f,'sync',['snapshotPage',page]);same(page.page.items.length,3);
 control('p11-hidden-burst',JSON.stringify({account_id:other.pins.account_id,count:2001}));
 // Commit after the materialized snapshot: captured heads and ciphertext stay immutable.
 const newer=await publish(f,edit(g.group_id,'entry',entry.object_id,thread.object_id,content('P11 newer','P11 newer body'),entry.receipt.heads));
 for(const item of page.page.items){const b=await ok(f.browser,path+'/revisions/'+item.revision_id);same(b.item,item);if(item.object_id===entry.object_id)same(b.reference.heads,entry.receipt.heads);await notes(f,'sync',['snapshotItem',b]);}
 same((await notes(f,'sync',['status',{}])).cursor,null);same((await notes(f,'sync',['snapshotFinish',{}])).cursor,d.watermark);
 // Hidden rows are scanned, and an explicitly captured watermark excludes later writes.
 await publish(other,edit(hidden.group_id,'thread',null,null,content('P11 hidden')));let scanned=d.watermark;for(let n=0;n<2;n++){const empty=checkedDelta(await ok(f.browser,'/sync?generation='+scanned.generation+'&sequence='+scanned.sequence+'&group='+g.group_id+'&limit=1'),scanned,f.pins,g.group_id);same(empty.events.length,0);same(empty.scanned_count,'1000');check(!empty.complete);scanned=empty.next_cursor;}const first=checkedDelta(await ok(f.browser,'/sync?generation='+scanned.generation+'&sequence='+scanned.sequence+'&group='+g.group_id+'&limit=1'),scanned,f.pins,g.group_id);check(first.events.some(e=>e.revision_id===newer.receipt.receipt.revision_id));
 const later=await publish(f,edit(g.group_id,'entry',entry.object_id,thread.object_id,content('P11 later','P11 later body'),newer.receipt.heads));let c=first.next_cursor;
 while(c.sequence!==first.watermark.sequence){const p=checkedDelta(await ok(f.browser,'/sync?generation='+c.generation+'&sequence='+c.sequence+'&watermark='+first.watermark.sequence+'&group='+g.group_id),c,f.pins,g.group_id);check(!p.events.some(e=>e.revision_id===later.receipt.receipt.revision_id));c=p.next_cursor;}
 const after=checkedDelta(await ok(f.browser,'/sync?generation='+c.generation+'&sequence='+c.sequence+'&group='+g.group_id),c,f.pins,g.group_id);check(after.events.some(e=>e.revision_id===later.receipt.receipt.revision_id));
 for(const suffix of ['&unexpected=1','&limit=0','&bytes=1023','&sequence=0','&watermark=9223372036854775807'])await denied(f,'/sync?generation='+c.generation+'&sequence='+c.sequence+suffix,suffix.startsWith('&watermark')?'SYNC_CURSOR_EXPIRED':'INVALID_REQUEST');
 await denied(f,'/sync?generation='+ident()+'&sequence=0','SYNC_CURSOR_EXPIRED');await denied(other,'/sync?generation='+c.generation+'&sequence='+c.sequence+'&group='+g.group_id,'NOT_FOUND');
 same((await ok(f.browser,path+'/renew',{version:1})).descriptor,d);await ok(f.browser,'/sync/ack',{version:1,cursor:c,group_id:g.group_id});await denied(f,'/sync/ack','SYNC_CURSOR_EXPIRED',{version:1,cursor:{...c,sequence:'0'},group_id:g.group_id});
 const before=control('p11-state');control('p11-fault-on');try{await denied(f,'/snapshots','TEMPORARY_UNAVAILABLE',{...request,operation_id:ident()});}finally{control('p11-fault-off');}same(control('p11-state'),before);
 same((await ok(f.browser,path,undefined,'DELETE')).state,'CANCELLED');await denied(f,path+'/pages?index=0','SYNC_CURSOR_EXPIRED');await denied(f,'/snapshots','SYNC_CURSOR_EXPIRED',request);
 const expired=await ok(f.browser,'/snapshots',{...request,operation_id:ident()});control('p11-expire',JSON.stringify({id:expired.descriptor.snapshot_id}));await denied(f,'/snapshots/'+expired.descriptor.snapshot_id+'/catalog','SYNC_CURSOR_EXPIRED');
 const fresh=await ok(f.browser,'/snapshots',{...request,operation_id:ident()});await ok(f.browser,'/snapshots/'+fresh.descriptor.snapshot_id,undefined,'DELETE');same(control('p11-state').pins,initialPins);
 const git=(...a)=>execFileSync('git',a,{encoding:'utf8'}).trim(),report={purpose:'P11 actual TLS/SQL filtered transport and protected staged snapshot',status:'PASS',checks:checks+fixtureCheckCount(),source_commit:git('rev-parse','HEAD'),source_tree:git('rev-parse','HEAD^{tree}'),source_tree_dirty:git('status','--porcelain')!=='',physical_acceptance:false,independent_review:'NOT_RUN'};
 mkdirSync('artifacts/p11',{recursive:true});writeFileSync('artifacts/p11/http-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}finally{control('p11-fault-off');for(const f of fixtures){f.initial.dispose();await f.engine.close();}}
