// One synthetic owner continues into the actual P16 backup/root-reset/restore.
// No alternate authentication, crypto or authorization route is installed.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {account,enroll,notes,edit,content,publish,uploadFile,downloadFile} from './p16-fixture.mjs';
import {genesisPin} from './shared/proof.mjs';

export async function releaseJourney(owner){
 const peer=await account();
 const slots=new Map();
 const ok=async(f,path,body)=>{if(body===undefined){const family=/\/roster(?:\?|$)/.test(path)?'roster':/\/journal$/.test(path)?'journal':null;if(family){const at=Math.max(Date.now(),slots.get(family)??0);slots.set(family,at+1200);if(at>Date.now())await new Promise(resolve=>setTimeout(resolve,at-Date.now()));}}const r=await f.browser.call(path,body);assert.equal(r.status,200,path+':'+r.json?.error?.code);return r.json;};
 const shared=async(f,op,arg)=>{try{return await notes(f,'shared',[op,structuredClone(arg)]);}catch(error){throw new Error('P18_SHARED:'+op+':'+error.message,{cause:error});}};
 const snapshot=async f=>{const v=await ok(f,'/accounts/'+f.pins.account_id+'/roster?root='+f.pins.root_fingerprint);assert.equal(v.next,null);return {identity:v.identity,events:v.events,head:v.head,generation:v.generation};};
 const accountProof=async f=>({pins:f.pins,snapshot:await snapshot(f)});
 let proof;const events=[];
 const observe=(stage,evidence)=>{events.push({stage,evidence});console.log('PASS: P18 linked '+stage);};
 const refresh=async()=>{proof={...proof,journal:await ok(owner,'/groups/'+proof.pin.group_id+'/journal'),accounts:await Promise.all(proof.accounts.map(async a=>({...a,snapshot:await snapshot({browser:owner.browser,pins:a.pins})})))};await shared(owner,'adopt',proof);await notes(owner,'group',[await ok(owner,'/groups/'+proof.pin.group_id)]);};
 const transmit=async f=>{const g=proof.pin.group_id,a=await shared(f,'retry',{group_id:g});let result;if(a.family==='epoch'){await ok(f,'/groups/'+g+'/epoch/begin',a.body);for(const page of a.pages)await ok(f,'/groups/'+g+'/epoch/page',{version:1,page});result=await ok(f,'/groups/'+g+'/epoch/commit',{version:1,commit:a.commit});}else result=await ok(f,'/groups/'+g+'/'+({invite:'invites',consent:'owner-consent'}[a.family]??a.family),a.body);await shared(f,'complete',{group_id:g,result});return result;};
 try{
  const enrolled=await enroll(owner);owner.snapshot=await ok(owner,'/accounts/'+owner.pins.account_id+'/roster');
  assert(owner.snapshot.events.length>1);observe('enroll',{device_id:enrolled,roster:owner.snapshot.head});
  const made=await notes(owner,'prepareShared'),status=await ok(owner,'/groups',made.request),g=status.group_id;await notes(owner,'group',[status]);
  proof={pin:genesisPin(status.genesis),journal:await ok(owner,'/groups/'+g+'/journal'),accounts:[await accountProof(owner)]};await shared(owner,'adopt',proof);
  await shared(owner,'history',{group_id:g});await transmit(owner);await refresh();
  const ap=await accountProof(peer),inv=await shared(owner,'invite',{group_id:g,account:ap,expected_root:ap.pins.root_fingerprint,role:'reader',confirm:true});await transmit(owner);proof.accounts.push(ap);await refresh();
  await shared(peer,'adopt',await shared(owner,'card',{group_id:g}));await shared(peer,'accept',{group_id:g,invitation:inv.body.invitation,confirm:true});await transmit(peer);await refresh();
  assert.equal((await peer.browser.call('/groups/'+g)).json.error.code,'NOT_FOUND');
  await shared(owner,'epoch',{group_id:g,reason:'admission',confirm:true});await transmit(owner);await refresh();
  const card=await shared(owner,'card',{group_id:g});for(const f of [owner,peer]){await shared(f,'adopt',card);if(f===owner)proof=card;await notes(f,'group',[await ok(f,'/groups/'+g)]);await shared(f,'keys',{group_id:g});}
  observe('share',{group_id:g,owner_account_id:owner.pins.account_id,recipient_account_id:peer.pins.account_id,role:'reader',accepted_without_grants_denied:true});
  const source=new Blob(['PUBLIC P18 linked release journey: Привет • Hello • مرحبا']),hash=createHash('sha256').update(Buffer.from(await source.arrayBuffer())).digest('hex'),file=await uploadFile(owner,g,source,'P18 multilingual • файл.bin'),thread=await publish(owner,edit(g,'thread',null,null,content('P18 linked sharing journey')));
  await publish(owner,{...edit(g,'entry',null,thread.object_id,content('P18 shared attachment')),attachments:[{file_id:file.file_id,file_version_id:file.file_version_id,envelope_digest:file.envelope_digest}]});
  const received=await downloadFile(peer,g,file.file_version_id);assert.equal(received.sha256,hash);assert.equal(received.bytes,source.size);
  observe('upload',{file_version_id:file.file_version_id,plaintext_bytes:source.size,plaintext_sha256:hash,independent_recipient_hash:received.sha256});
  // Close writer-observed history before revocation, then rotate actual grants.
  await shared(owner,'history',{group_id:g});await transmit(owner);await refresh();
  await shared(owner,'policy',{group_id:g,action:'remove',target_account_id:peer.pins.account_id,confirm:true});await transmit(owner);
  for(const path of ['/groups/'+g,'/files/'+file.file_version_id+'/manifest'])assert.equal((await peer.browser.call(path)).json.error.code,'NOT_FOUND');
  await refresh();const rotated=await shared(owner,'epoch',{group_id:g,reason:'member-removal',confirm:true});assert(rotated.pages.every(p=>p.records.every(r=>r.body.context.recipient.account_id!==peer.pins.account_id)));await transmit(owner);await refresh();
  await shared(owner,'history',{group_id:g});await transmit(owner);await refresh();
  await publish(owner,edit(g,'entry',null,thread.object_id,content('P18 future epoch after removal')));
  observe('revoke',{recipient_account_id:peer.pins.account_id,manifest_denied:true,group_denied:true,removed_recipient_excluded:true,fresh_epoch_publication:true,previously_downloaded_copies_remain_readable:true});
  return {status:'PASS',owner_account_id:owner.pins.account_id,events,recovery_scope:'The same owner subsequently backs up and independently recovers its private epoch-zero file. Shared content requires the separate P13 portable export kit; no root-kit authority over the removed peer is asserted.'};
 }finally{await peer.engine.globalLock();peer.initial.dispose();}
}
