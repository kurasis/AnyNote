// Real verified HTTPS / maintained WebAuthn / MariaDB / native SQLite, synthetic data only.
import {Browser,authenticator,options,verify,login,control,check,request,fixtureCheckCount} from './notes/http-fixture.mjs';
import {initialRoot,registrationRequest} from './auth-client.mjs';
import {wire} from './adapters/codecs/identity-codec.mjs';
import {sodium,b64,un64} from './adapters/primitives.mjs';
import {VaultEngine} from './vault/engine.mjs';
import {readOwnedSecrets} from './notes/test-fixture.mjs';
import {sealObject} from './adapters/core.mjs';
import {Store,phrase} from './notes/test-fixture.mjs';
import {noteValue} from './notes/client.mjs';
import {stateDigest} from './adapters/codecs/state-codec.mjs';
import {verifiedSnapshot} from './devices/client.mjs';
import {responseForEvaluation,approvalForEvaluation} from './devices/enrollment.mjs';
import {pairingQr,scannedChannelForEvaluation,sealPairingFrame,openPairingFrame,closePairingChannel} from './devices/pairing-channel.mjs';
import {nativeHarness} from './devices/native-harness.mjs';
import {readFileSync,mkdirSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
const startedCommit=spawnSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).stdout.trim(),startedDirty=!!spawnSync('git',['status','--porcelain'],{encoding:'utf8'}).stdout.trim();
const root=resolve(import.meta.dirname,'../..'),ident=()=>b64(sodium.randombytes_buf(16));
const raw=b=>JSON.parse(new TextDecoder().decode(b));
const ok=async(browser,path,body,shape)=>{const r=await browser.call(path,body);check(r.status===200,'P09_HTTP:'+path+':'+r.status+':'+r.json?.error?.code);if(shape)noteValue(shape,r.json);return r.json;};
const denied=async(browser,path,body,codes)=>{const r=await browser.call(path,body);check(r.status>=400&&codes.includes(r.json?.error?.code),'P09_DENIAL:'+path+':'+r.status+':'+r.json?.error?.code);return r;};
async function snapshot(browser,initial){const v=await ok(browser,'/accounts/'+initial.identity.body.account_id+'/roster');check(v.next===null,'SMALL_COMPLETE_ROSTER');return {identity:v.identity,events:v.events,head:v.head,generation:v.generation};}
async function sync(f,s){await f.engine.devices(f.cap,'snapshotStart',[s.identity,s.head,s.generation]);for(let n=0;n<s.events.length;n+=20)await f.engine.devices(f.cap,'snapshotPage',[s.events.slice(n,n+20)]);return f.engine.devices(f.cap,'snapshotFinish');}
const notes=(f,op,args=[])=>f.engine.notes(f.cap,op,structuredClone(args));
async function account(handle){
 const browser=new Browser();await browser.start();const o=await options(browser,'register',{invitation:control('invite').token,handle}),passkey=authenticator(o.account_id),att=await verify(browser,o,passkey.create(o.publicKey));check(att.status===200,'MAINTAINED_WEBAUTHN_ACCEPTANCE');
 const capabilities=await request('/capabilities'),initial=await initialRoot(capabilities.json.service_id,o.account_id),pins={service_id:initial.identity.body.service_id,account_id:o.account_id,root_fingerprint:initial.fingerprint},profile={service_id:pins.service_id,account_id:pins.account_id,device_id:initial.device.device_id,profile_id:ident()},store=new Store(profile),engine=new VaultEngine(store);
 const prep=await ok(browser,'/accounts/registration-challenge',{version:1,registration_id:att.json.registration_id,identity:initial.identity,device:initial.device}),registration=registrationRequest(att.json.registration_id,initial,prep.challenge);
 await engine.initialize(phrase,{device_signing_secret:b64(initial.keys.signing.privateKey),device_encryption_secret:b64(initial.keys.encryption.privateKey),group_keys:[]},pins,registration);
 await ok(browser,'/accounts/register',registration);const f={browser,passkey,initial,pins,profile,store,engine,cap:(await engine.unlock(phrase)).capability};await sync(f,await snapshot(browser,initial));
 const settings=await engine.devices(f.cap,'genesis'),accepted=await ok(browser,'/me/settings-genesis',settings.request);await engine.devices(f.cap,'finishRegistration');f.settings=accepted;return f;
}
const content=(title='',markdown='',metadata_kind='content')=>({title,markdown,metadata_kind,tags:[],checklist:[],summary_entry_id:null,preferences:[]});
const edit=(group,kind,object_id=null,thread_id=null,c=content(),parents=[],action=parents.length?'update':'create')=>({draft_id:null,group_id:group,object_id,object_kind:kind,thread_id,action,parents,archived:false,content:c});
async function prepared(f,e){const d=await notes(f,'save',[e]),a=await notes(f,'queue',[d.draft_id]),s=await notes(f,'send',[a.attempt_id]);return {...d,...a,request:s.request};}
function pathFor(r){const c=r.bundle.envelope.header.context;return c.action==='soft-delete'?'/objects/'+c.object_id+'/tombstone':c.action==='restore'?'/objects/'+c.object_id+'/restore':c.action==='create'&&c.object_kind==='thread'?'/groups/'+c.group_id+'/threads':c.action==='create'&&c.object_kind==='entry'?'/threads/'+c.thread_id+'/entries':'/objects/'+c.object_id+'/revisions';}
async function publish(f,e){const p=await prepared(f,e),receipt=await ok(f.browser,pathFor(p.request),p.request,'receipt-result');await notes(f,'ack',[p.attempt_id,receipt]);return {...p,receipt};}
async function open(f,id){const state=await ok(f.browser,'/objects/'+id,undefined,'object-state'),head=state.object.heads[0],bundle=await ok(f.browser,'/objects/'+id+'/revisions/'+head.revision_id,undefined,'bundle-result');const opened=await notes(f,'open',[{group_id:state.group_id,object_id:id,revision_id:head.revision_id,object_kind:state.object.object_kind,thread_id:state.object.thread_id,bundle:bundle.bundle}]);check(opened.envelope_digest===head.envelope_digest,'CURRENT_HEAD_DIGEST');return {...opened,...state};}
async function enrollNative(f){
 const browser=new Browser(),session=await login(browser,f.passkey),scope={service_id:f.pins.service_id,account_id:f.pins.account_id,device_id:ident(),profile_id:ident()},native=await nativeHarness({scope,pins:f.pins,phrase});
 const current=await snapshot(f.browser,f.initial),proof=verifiedSnapshot(current,f.pins);await native.call({operation:'device-snapshot',snapshot:current});
 const offer=await native.call({operation:'device-offer',session_id:session.session.id,invitation:null}),op=offer.body.operation_id,qr=await native.call({operation:'pairing-qr',record:offer,mode:'new-device-offer'}),channel=scannedChannelForEvaluation(wire(qr.qr),'approver');
 try{
  await ok(browser,'/me/enrollments',{version:1,mode:'new-device-offer',record:offer});
  const response=responseForEvaluation(proof.roster,wire(offer),f.initial.device.device_id,f.initial.keys.signing.privateKey,null,BigInt(Date.now())),frame=sealPairingFrame(channel,'approver-response',response.response,stateDigest('offer',wire(offer)));
  await ok(f.browser,'/me/enrollments/'+op+'/relay',{version:1,frame:raw(frame),offer:null});const got=await native.call({operation:'pairing-frame',handle:qr.handle,message:'approver-response',value:raw(frame),anchor:stateDigest('offer',wire(offer)),seal:false});check(!got.error,'NATIVE_QR_CHANNEL');
  const approval=approvalForEvaluation(proof.roster,response.transcript,f.initial.keys.signing.privateKey,BigInt(Date.now())),af=sealPairingFrame(channel,'approver-approval',approval,stateDigest('transcript',response.transcript));
  await ok(f.browser,'/me/enrollments/'+op+'/approve',{version:1,transcript:raw(response.transcript),approval:raw(approval),frame:raw(af)});
  const event=await native.call({operation:'device-confirmation',transcript:raw(response.transcript),approval:raw(approval),session_id:session.session.id,confirmed:true});check(!event.error,'NATIVE_BOTH_KEY_PROOF');
  const result=await ok(browser,'/me/enrollments/'+op+'/confirm',{version:1,event});check(result.session.device_id===scope.device_id&&result.session.state==='trusted','NATIVE_FRESH_SESSION_TRUST');
  const s=await snapshot(f.browser,f.initial);await sync(f,s);await native.call({operation:'device-snapshot',snapshot:s});
  return {native,browser,scope};
 }catch(e){await native.close();throw e;}finally{closePairingChannel(channel);}
}
const f=await account('p09-http'),others=[],nativePeers=[];
try{
 const features=(await request('/capabilities')).json.features;check(features.content_storage===true&&features.sync===false&&features.file_transfer===false&&features.production_ready===false,'PRIVATE_CONTENT_CAPABILITY_HAS_EXPLICIT_LATER_PHASE_BOUNDARIES');
 const made=await notes(f,'prepareGroup'),g=await ok(f.browser,'/groups',made.request,'group-status');await notes(f,'group',[g]);check(g.kind==='private'&&!g.settings,'REAL_PRIVATE_GROUP');
 const groupBefore=control('p09-state');const repeated=await ok(f.browser,'/groups',made.request,'group-status');check(JSON.stringify(repeated)===JSON.stringify(g)&&JSON.stringify(control('p09-state'))===JSON.stringify(groupBefore),'GENESIS_ONE_RESULT');
 const metadata=await publish(f,edit(g.group_id,'group-metadata',g.group_id,null,content('PUBLIC synthetic private group title')));
 const thread=await publish(f,edit(g.group_id,'thread',null,null,content('PUBLIC synthetic private thread title')));
 const body='PUBLIC synthetic confidential body for SQL inspection';
 const entry=await publish(f,edit(g.group_id,'entry',null,thread.object_id,content('PUBLIC synthetic private entry title',body)));
 check((await open(f,entry.object_id)).payload.markdown===body,'REAL_ENCRYPTED_NOTE_READ');
 const page=await ok(f.browser,'/threads/'+thread.object_id+'/entries',undefined,'objects-page');check(page.objects.length===1&&page.objects[0].created_sequence===entry.receipt.receipt.cursor.sequence,'ACTUAL_COMMIT_ORDER');
 const stateBefore=control('p09-state'),again=await ok(f.browser,pathFor(entry.request),entry.request,'receipt-result');check(JSON.stringify(again)===JSON.stringify(entry.receipt)&&JSON.stringify(control('p09-state'))===JSON.stringify(stateBefore),'NO_DUPLICATE_ROWS_QUOTA_OR_EVENT');
 const changed=structuredClone(entry.request);changed.bundle.ciphertext=changed.bundle.ciphertext.slice(0,-1)+(changed.bundle.ciphertext.endsWith('A')?'Q':'A');await denied(f.browser,pathFor(changed),changed,['MALFORMED_ENVELOPE','INVALID_REQUEST']);
 const fault=await prepared(f,edit(g.group_id,'entry',null,thread.object_id,content('PUBLIC fault title','PUBLIC fault body'))),beforeFault=control('p09-state');control('p09-fault-on');
 try{await denied(f.browser,pathFor(fault.request),fault.request,['TEMPORARY_UNAVAILABLE']);}finally{control('p09-fault-off');}
 check(JSON.stringify(control('p09-state'))===JSON.stringify(beforeFault),'SQL_FAILURE_AT_RECEIPT_ROLLS_BACK_CIPHER_HEADS_QUOTA_AND_COUNTER');
 const retry=await ok(f.browser,pathFor(fault.request),fault.request,'receipt-result');await notes(f,'ack',[fault.attempt_id,retry]);
 const quota=await prepared(f,edit(g.group_id,'entry',null,thread.object_id,content('PUBLIC quota draft','PUBLIC quota body')));control('p09-quota-on');
 try{const q=control('p09-state');await denied(f.browser,pathFor(quota.request),quota.request,['QUOTA_EXCEEDED']);check(JSON.stringify(control('p09-state'))===JSON.stringify(q),'QUOTA_DENIAL_NO_PARTIAL_COMMIT');}finally{control('p09-quota-off');}
 check((await notes(f,'draft',[quota.draft_id])).payload.markdown==='PUBLIC quota body','QUOTA_PRESERVES_DRAFT');await notes(f,'ack',[quota.attempt_id,await ok(f.browser,pathFor(quota.request),quota.request,'receipt-result')]);
 const other=await account('p09-other');others.push(other);await denied(other.browser,'/objects/'+entry.object_id,undefined,['NOT_FOUND']);await denied(other.browser,'/objects/'+entry.object_id+'/revisions/'+entry.request.bundle.envelope.header.context.revision_id,undefined,['NOT_FOUND']);await denied(other.browser,pathFor(entry.request),entry.request,['NOT_FOUND']);
 check((await ok(other.browser,'/groups',undefined,'groups-page')).groups.every(x=>x.owner_account_id===other.pins.account_id),'PRIVATE_ACCOUNT_ISOLATION');
 const peer=await enrollNative(f);nativePeers.push(peer);const nativeCall=async(action,args={})=>{const r=await peer.native.call({operation:'notes',request:{action,...args}});check(!r.error,'NATIVE_NOTES:'+action+':'+r.error);return r;};
 const nativeGroup=await nativeCall('prepare-group'),ng=await ok(peer.browser,'/groups',nativeGroup.request,'group-status');await nativeCall('group',{status:ng});await notes(f,'group',[ng]);await f.engine.devices(f.cap,'acceptKeys',[ng.genesis,ng.genesis.pages[0].records]);
 const ns=await nativeCall('save',{edit:edit(ng.group_id,'thread',null,null,content('PUBLIC native to PWA title'))}),nq=await nativeCall('queue',{draft_id:ns.draft_id}),nSend=await nativeCall('send',{attempt_id:nq.attempt_id}),nr=await ok(peer.browser,pathFor(nSend.request),nSend.request,'receipt-result');await nativeCall('ack',{attempt_id:nq.attempt_id,result:nr});
 check((await open(f,ns.object_id)).payload.title==='PUBLIC native to PWA title','ACTUAL_NATIVE_SQLITE_TO_PWA_ADAPTER');
 const nodeEntry=await publish(f,edit(ng.group_id,'entry',null,ns.object_id,content('PUBLIC PWA to native title','PUBLIC PWA to native body'))),c=nodeEntry.request.bundle.envelope.header.context;
 const nativeRead=await nativeCall('open',{request:{group_id:ng.group_id,object_id:c.object_id,revision_id:c.revision_id,object_kind:'entry',thread_id:ns.object_id,bundle:nodeEntry.request.bundle}});check(nativeRead.payload.markdown==='PUBLIC PWA to native body','PWA_ADAPTER_TO_ACTUAL_NATIVE_SQLITE');
 const disk=await peer.native.call({operation:'test-inspect-ciphertext'});check(!JSON.stringify(disk).includes('PUBLIC PWA to native body')&&!JSON.stringify(disk).includes('PUBLIC native to PWA title'),'ACTUAL_NATIVE_INSPECTOR');

 // Eight identical real requests commit one immutable result, one quota charge and one event.
 const repeatedAttempt=await prepared(f,edit(ng.group_id,'entry',null,ns.object_id,content('PUBLIC repeated race','PUBLIC repeated body'))),beforeRepeated=control('p09-state');
 const repeatedResults=await Promise.all(Array.from({length:8},()=>f.browser.call(pathFor(repeatedAttempt.request),repeatedAttempt.request)));
 check(repeatedResults.every(r=>r.status===200),'EIGHT_IDENTICAL_REQUESTS_SUCCEED');
 check(repeatedResults.every(r=>JSON.stringify(r.json)===JSON.stringify(repeatedResults[0].json)),'EIGHT_IDENTICAL_RECEIPTS');
 const afterRepeated=control('p09-state');check(afterRepeated.counts.object_revisions===beforeRepeated.counts.object_revisions+1&&afterRepeated.counts.mutation_receipts===beforeRepeated.counts.mutation_receipts+1&&BigInt(afterRepeated.counter)===BigInt(beforeRepeated.counter)+1n,'IDENTICAL_RACE_ONE_DURABLE_EFFECT');
 await notes(f,'ack',[repeatedAttempt.attempt_id,repeatedResults[0].json]);
 // Distinct signed edits from one base: exactly one winner; every rejected local draft remains.
 const base=await open(f,nodeEntry.object_id),racing=[];
 for(let k=0;k<8;k++)racing.push(await prepared(f,edit(ng.group_id,'entry',nodeEntry.object_id,ns.object_id,content('PUBLIC concurrent edit '+k,'PUBLIC preserved concurrent text '+k),base.object.heads)));
 const raceBefore=control('p09-state'),results=await Promise.all(racing.map(a=>f.browser.call(pathFor(a.request),a.request))),winner=results.findIndex(r=>r.status===200);
 check(winner>=0&&results.filter(r=>r.status===200).length===1&&results.filter(r=>r.json?.error?.code==='STALE_REVISION').length===7,'EIGHT_DISTINCT_SAME_BASE_ONE_WINNER');
 const raceAfter=control('p09-state');check(raceAfter.counts.object_revisions===raceBefore.counts.object_revisions+1&&BigInt(raceAfter.counter)===BigInt(raceBefore.counter)+1n,'CAS_RACE_ONE_EVENT_AND_REVISION');
 for(let k=0;k<racing.length;k++){if(k===winner)await notes(f,'ack',[racing[k].attempt_id,results[k].json]);else{await notes(f,'reject',[racing[k].attempt_id,'STALE_REVISION']);check((await notes(f,'draft',[racing[k].draft_id])).payload.markdown==='PUBLIC preserved concurrent text '+k,'REJECTED_CONCURRENT_EDIT_PRESERVED');}}
 const latest=await open(f,nodeEntry.object_id),loser=racing.find((_,k)=>k!==winner),oldDraft=await notes(f,'draft',[loser.draft_id]);
 const resolved=edit(ng.group_id,'entry',nodeEntry.object_id,ns.object_id,{title:oldDraft.payload.title,markdown:oldDraft.payload.markdown,metadata_kind:'content',tags:[],checklist:[],summary_entry_id:null,preferences:[]},latest.object.heads);
 resolved.draft_id=loser.draft_id;const resolvedAttempt=await prepared(f,resolved),resolvedResult=await ok(f.browser,pathFor(resolvedAttempt.request),resolvedAttempt.request,'receipt-result');await notes(f,'ack',[resolvedAttempt.attempt_id,resolvedResult]);
 check((await open(f,nodeEntry.object_id)).payload.markdown===oldDraft.payload.markdown,'EXPLICIT_CONFLICT_REBASE_NEW_REVISION');
 // A correctly encrypted/resigned body still cannot reuse an old immutable operation ID.
 const secrets=await readOwnedSecrets({store:f.store}),storedKey=secrets.group_keys.find(k=>k.group_id===ng.group_id),changedPayload=structuredClone(base.payload);
 changedPayload.context.operation_id=nodeEntry.request.bundle.envelope.header.context.operation_id;changedPayload.context.revision_id=ident();changedPayload.context.parents=[];changedPayload.context.action='create';changedPayload.markdown='PUBLIC changed signed body under old operation';
 const changedBundle=sealObject(wire(changedPayload),un64(storedKey.group_secret),f.initial.keys.signing.privateKey),sameId={group_id:ng.group_id,object_id:changedPayload.context.object_id,object_kind:'entry',thread_id:ns.object_id,action:'create',bundle:changedBundle},sameBefore=control('p09-state');
 await denied(f.browser,pathFor(sameId),sameId,['IDEMPOTENCY_MISMATCH']);check(JSON.stringify(control('p09-state'))===JSON.stringify(sameBefore),'SIGNED_BODY_CHANGE_NO_SIDE_EFFECT');
 // Tombstone and explicit restore retain exact immutable ancestry and original content.
 const deleting=await publish(f,edit(ng.group_id,'entry',nodeEntry.object_id,ns.object_id,content(),resolvedResult.heads,'soft-delete')),trash=await ok(f.browser,'/groups/'+ng.group_id+'/trash',undefined,'objects-page');check(trash.objects.some(o=>o.object_id===nodeEntry.object_id),'REAL_SIGNED_TOMBSTONE');
 const deletedState=control('p09-state');await ok(f.browser,pathFor(resolvedAttempt.request),resolvedAttempt.request,'receipt-result');check(JSON.stringify(control('p09-state'))===JSON.stringify(deletedState),'EXACT_OLD_RECEIPT_RETRY_DOES_NOT_RESURRECT');
 const staleAfterDelete=await prepared(f,edit(ng.group_id,'entry',nodeEntry.object_id,ns.object_id,content('PUBLIC stale resurrection','PUBLIC stale body'),resolvedResult.heads));await denied(f.browser,pathFor(staleAfterDelete.request),staleAfterDelete.request,['STALE_REVISION']);check(JSON.stringify(control('p09-state'))===JSON.stringify(deletedState),'STALE_EDIT_CANNOT_IMPLICITLY_RESTORE');await notes(f,'reject',[staleAfterDelete.attempt_id,'STALE_REVISION']);
 const tomb=await open(f,nodeEntry.object_id);check(tomb.payload.context.action==='soft-delete'&&tomb.payload.markdown==='','EMPTY_TYPED_TOMBSTONE_PAYLOAD');
 const parent=tomb.payload.context.parents[0],parentBundle=await ok(f.browser,'/objects/'+nodeEntry.object_id+'/revisions/'+parent.revision_id,undefined,'bundle-result'),prior=await notes(f,'open',[{group_id:ng.group_id,object_id:nodeEntry.object_id,revision_id:parent.revision_id,object_kind:'entry',thread_id:ns.object_id,bundle:parentBundle.bundle}]);
 check(prior.envelope_digest===parent.envelope_digest,'EXACT_PRE_DELETE_PARENT_VERIFIED');
 const restored=await publish(f,edit(ng.group_id,'entry',nodeEntry.object_id,ns.object_id,{title:prior.payload.title,markdown:prior.payload.markdown,metadata_kind:'content',tags:[],checklist:[],summary_entry_id:null,preferences:[]},deleting.receipt.heads,'restore'));
 check(restored.request.bundle.envelope.header.context.revision_id!==parent.revision_id&&(await open(f,nodeEntry.object_id)).payload.markdown===prior.payload.markdown,'EXPLICIT_RESTORE_FRESH_IMMUTABLE_REVISION');
 // A real encrypted note above the old edge's 256 KiB ceiling must round-trip.
 const largeText='PUBLIC bounded large note '+ 'x'.repeat(400000),large=await publish(f,edit(ng.group_id,'entry',null,ns.object_id,content('PUBLIC large note',largeText)));
 check((await open(f,large.object_id)).payload.markdown===largeText,'REAL_LARGE_CONTROL_CIPHERTEXT_ROUND_TRIP');
 const oversized=await request('/groups',{body:{padding:'x'.repeat(4194304)},cookie:f.browser.cookie,csrf:f.browser.csrf});check(oversized.status===413&&oversized.json?.error?.code==='REQUEST_TOO_LARGE','REAL_EDGE_OVERSIZE_CLOSED_ERROR');
 const inspection=control('p09-inspect',JSON.stringify({markers:['PUBLIC synthetic private group title','PUBLIC synthetic private thread title','PUBLIC synthetic private entry title',body,'PUBLIC native to PWA title','PUBLIC PWA to native body',b64(f.initial.keys.signing.privateKey),f.initial.kit.recovery_secret]}));check(inspection.status==='PASS','SQL_AND_LOG_PLAINTEXT_PRIVATE_KEY_ABSENCE');
 mkdirSync(root+'/artifacts/p09',{recursive:true});const report={purpose:'P09 actual verified HTTPS/SQL/native private-note vertical slice',status:'PASS',checks:fixtureCheckCount(),source_commit:startedCommit,source_tree_dirty:startedDirty||!!spawnSync('git',['status','--porcelain'],{cwd:root,encoding:'utf8'}).stdout.trim()||spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).stdout.trim()!==startedCommit,physical_acceptance:false,independent_review:'NOT_RUN',native_storage:'Actual protected SQLite and main-window IPC',node_storage:'Transactional model; actual IndexedDB covered by hosted UI job'};
 writeFileSync(root+'/artifacts/p09/http-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}finally{for(const p of nativePeers)await p.native.close();for(const p of [f,...others]){p.initial.dispose();await p.engine.close();}}
