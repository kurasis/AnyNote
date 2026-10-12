// Real verified HTTPS / maintained WebAuthn / MariaDB / native SQLite, synthetic data only.
import {Browser,authenticator,options,verify,login,control,check,request,fixtureCheckCount} from './notes/http-fixture.mjs';
import {initialRoot,registrationRequest} from './auth-client.mjs';
import {wire} from './adapters/codecs/identity-codec.mjs';
import {sodium,b64,un64} from './adapters/primitives.mjs';
import {VaultEngine} from './vault/engine.mjs';
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
 const inspection=control('p09-inspect',JSON.stringify({markers:['PUBLIC synthetic private group title','PUBLIC synthetic private thread title','PUBLIC synthetic private entry title',body,'PUBLIC native to PWA title','PUBLIC PWA to native body',b64(f.initial.keys.signing.privateKey),f.initial.kit.recovery_secret]}));check(inspection.status==='PASS','SQL_AND_LOG_PLAINTEXT_PRIVATE_KEY_ABSENCE');
 mkdirSync(root+'/artifacts/p09',{recursive:true});const report={purpose:'P09 actual verified HTTPS/SQL/native private-note vertical slice',status:'PASS',checks:fixtureCheckCount(),source_commit:spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).stdout.trim(),source_tree_dirty:!!spawnSync('git',['status','--porcelain'],{cwd:root,encoding:'utf8'}).stdout.trim(),physical_acceptance:false,independent_review:'NOT_RUN',native_storage:'Actual protected SQLite and main-window IPC',node_storage:'Transactional model; actual IndexedDB covered by hosted UI job'};
 writeFileSync(root+'/artifacts/p09/http-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}finally{for(const p of nativePeers)await p.native.close();for(const p of [f,...others]){p.initial.dispose();await p.engine.close();}}
