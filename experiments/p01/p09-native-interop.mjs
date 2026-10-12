// Actual native process (Windows/MSVC in CI) and the unchanged maintained PWA adapter.
import {fixture,run,sync,readOwnedSecrets} from '../../packages/protocol/notes/test-fixture.mjs';
import {nativeHarness} from '../../packages/protocol/devices/native-harness.mjs';
import {sodium,b64} from '../../packages/protocol/adapters/primitives.mjs';
import {wire} from '../../packages/protocol/adapters/codecs/identity-codec.mjs';
import {verifiedSnapshot} from '../../packages/protocol/devices/client.mjs';
import {responseForEvaluation,approvalForEvaluation} from '../../packages/protocol/devices/enrollment.mjs';
import {stateDigest} from '../../packages/protocol/adapters/codecs/state-codec.mjs';
import {groupCodecForProfile} from '../../packages/protocol/adapters/codecs/group-codec.mjs';
import {scannedChannelForEvaluation,sealPairingFrame,closePairingChannel} from '../../packages/protocol/devices/pairing-channel.mjs';
import {mkdirSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
const root=resolve(import.meta.dirname,'../..'),f=await fixture(),id=()=>b64(sodium.randombytes_buf(16)),phrase='public synthetic purple harbor paper lantern',g=groupCodecForProfile('p02-group-c2');let checks=0;
const check=(v,k)=>{if(!v)throw Error(k);checks++;};
const scope={service_id:f.pins.service_id,account_id:f.pins.account_id,device_id:id(),profile_id:id()},native=await nativeHarness({scope,pins:f.pins,phrase}),session=id();
const n=async(action,args={})=>{const out=await native.call({operation:'notes',request:{action,...args}});check(!out.error,'NATIVE_NOTES:'+action+':'+out.error);return out;};
const note=(action,args=[])=>f.old.engine.notes(f.old.cap,action,structuredClone(args));
try{
 await native.call({operation:'device-snapshot',snapshot:f.snapshot});
 const offer=await native.call({operation:'device-offer',session_id:session,invitation:null}),qr=await native.call({operation:'pairing-qr',record:offer,mode:'new-device-offer'}),channel=scannedChannelForEvaluation(wire(qr.qr),'approver'),proof=verifiedSnapshot(f.snapshot,f.pins);
 try{
  const response=responseForEvaluation(proof.roster,wire(offer),f.old.scope.device_id,f.initial.keys.signing.privateKey,null,BigInt(Date.now())),frame=sealPairingFrame(channel,'approver-response',response.response,stateDigest('offer',wire(offer)));
  const decoded=await native.call({operation:'pairing-frame',handle:qr.handle,message:'approver-response',value:JSON.parse(new TextDecoder().decode(frame)),anchor:stateDigest('offer',wire(offer)),seal:false});check(!decoded.error,'ACTUAL_NATIVE_CHANNEL');
  const approval=approvalForEvaluation(proof.roster,response.transcript,f.initial.keys.signing.privateKey,BigInt(Date.now())),event=await native.call({operation:'device-confirmation',transcript:JSON.parse(new TextDecoder().decode(response.transcript)),approval:JSON.parse(new TextDecoder().decode(approval)),session_id:session,confirmed:true});check(!event.error,'NATIVE_BOTH_KEY_CONFIRMATION');
  const current={...f.snapshot,events:[...f.snapshot.events,event],head:{version:event.body.version,digest:stateDigest('event',wire(event))},generation:event.body.generation};await sync(f.old,current);await native.call({operation:'device-snapshot',snapshot:current});
 }finally{closePairingChannel(channel);}
 const made=await n('prepare-group'),commit=made.request.commit,group=made.group_id,status={version:1,group_id:group,kind:'private',owner_account_id:f.pins.account_id,state:'active',membership:commit.body.intent.body.membership,key_epoch:'0',epoch_digest:g.groupDigest('epoch-intent',wire(commit.body.intent)),history_checkpoint_digest:null,rekey_required:false,history_closure_required:false,restore_quarantined:false,settings:false,genesis:{version:1,group_id:group,...made.request}};
 await n('group',{status});await note('group',[status]);await run(f.old,'acceptKeys',[made.request,made.request.pages[0].records]);check(true,'PRIVATE_GROUP_AND_INDEPENDENT_RECIPIENT_COVERAGE');
 const content=title=>({title,markdown:'',metadata_kind:'content',tags:[],checklist:[],summary_entry_id:null,preferences:[]}),edit=title=>({draft_id:null,group_id:group,object_id:null,object_kind:'thread',thread_id:null,action:'create',parents:[],archived:false,content:content(title)});
 const title='PUBLIC native → PWA · русский · 😀',saved=await n('save',{edit:edit(title)}),queued=await n('queue',{draft_id:saved.draft_id}),sent=await n('send',{attempt_id:queued.attempt_id}),c=sent.request.bundle.envelope.header.context;
 const opened=await note('open',[{group_id:group,object_id:c.object_id,revision_id:c.revision_id,object_kind:'thread',thread_id:null,bundle:sent.request.bundle}]);check(opened.payload.title===title,'WINDOWS_NATIVE_TO_MAINTAINED_PWA_ADAPTER');
 const jsTitle='PUBLIC PWA → native · кириллица · 📝',jsSaved=await note('save',[edit(jsTitle)]),jsQueue=await note('queue',[jsSaved.draft_id]),jsSent=await note('send',[jsQueue.attempt_id]),jc=jsSent.request.bundle.envelope.header.context;
 const nativeOpened=await n('open',{request:{group_id:group,object_id:jc.object_id,revision_id:jc.revision_id,object_kind:'thread',thread_id:null,bundle:jsSent.request.bundle}});check(nativeOpened.payload.title===jsTitle,'MAINTAINED_PWA_ADAPTER_TO_WINDOWS_NATIVE');
 const bad=structuredClone(jsSent.request.bundle);bad.envelope.header.context.object_id=id();const refused=await native.call({operation:'notes',request:{action:'open',request:{group_id:group,object_id:jc.object_id,revision_id:jc.revision_id,object_kind:'thread',thread_id:null,bundle:bad}}});check(!!refused.error,'ACTUAL_NATIVE_CONTEXT_DENIAL');
 const disk=await native.call({operation:'test-inspect-ciphertext'});check(!JSON.stringify(disk).includes(title)&&!JSON.stringify(disk).includes(jsTitle),'ACTUAL_NATIVE_CIPHERTEXT_INSPECTOR');
 await native.call({operation:'lock'});const denied=await native.call({operation:'notes',request:{action:'summary'}});check(!!denied.error,'NATIVE_LOCK_INVALIDATES_IPC');await native.call({operation:'unlock-phrase'});const again=await n('send',{attempt_id:queued.attempt_id});check(JSON.stringify(again.request)===JSON.stringify(sent.request),'UNKNOWN_ATTEMPT_RETAINED_AFTER_NATIVE_LOCK');
 const report={purpose:'P09 actual native SQLite and maintained PWA adapter interoperation',status:'PASS',checks,platform:process.platform,source_commit:spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).stdout.trim(),source_tree_dirty:!!spawnSync('git',['status','--porcelain'],{cwd:root,encoding:'utf8'}).stdout.trim(),physical_acceptance:false,independent_review:'NOT_RUN',browser_scope:'Portable PWA crypto/custody adapter; actual sandboxed UI is a separate required job'};
 mkdirSync(root+'/artifacts/p09',{recursive:true});writeFileSync(root+'/artifacts/p09/native-interop-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}finally{await native.close();f.initial.dispose();await f.old.engine.close();await f.fresh.engine.close();sodium.memzero(f.keys.signing.privateKey);sodium.memzero(f.keys.encryption.privateKey);}
