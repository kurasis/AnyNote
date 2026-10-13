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

const shared=async(f,op,x)=>notes(f,'shared',[op,structuredClone(x)]);
const nativePeers=[];
const f=await account('p10-owner'),editor=await account('p10-editor'),reader=await account('p10-reader'),outsider=await account('p10-outsider'),members=[f,editor,reader];
async function accountProof(f){return {pins:f.pins,snapshot:await snapshot(f.browser,f.initial)};}
async function adopt(f,proof){await shared(f,'adopt',proof);return proof;}
async function refreshGroup(f,group,known){const journal=await ok(f.browser,'/groups/'+group+'/journal'),proof={...known,journal,accounts:await Promise.all(known.accounts.map(async a=>{const v=await ok(f.browser,'/accounts/'+a.pins.account_id+'/roster?root='+a.pins.root_fingerprint);return {...a,snapshot:{identity:v.identity,events:v.events,head:v.head,generation:v.generation}};}))};await adopt(f,proof);await notes(f,'group',[await ok(f.browser,'/groups/'+group)]);return proof;}
async function transmit(f,group){const a=await shared(f,'retry',{group_id:group}),held=a.body.invitation??a.body.acceptance??a.body.policy??a.body.intent??a.body.commit??a.body.history,op=held?.body.operation_id??a.body.operation_id,receipt=await f.browser.call('/me/group-receipts/'+op+'?family='+(a.family==='epoch'?'commit':a.family));check(receipt.status===200||receipt.status===404,'CURRENT_SCOPED_SECURITY_RECEIPT_QUERY');if(receipt.status===200){await shared(f,'complete',{group_id:group,result:receipt.json});return receipt.json;}let result;
 if(a.family==='epoch'){await ok(f.browser,'/groups/'+group+'/epoch/begin',a.body);for(const page of a.pages)await ok(f.browser,'/groups/'+group+'/epoch/page',{version:1,page});result=await ok(f.browser,'/groups/'+group+'/epoch/commit',{version:1,commit:a.commit});}
 else result=await ok(f.browser,'/groups/'+group+'/'+({invite:'invites',consent:'owner-consent'}[a.family]??a.family),a.body);
 await shared(f,'complete',{group_id:group,result});return result;
}
let proof;
try{
 const closeBody=(a)=>({version:1,account_id:a.pins.account_id,root_fingerprint:a.pins.root_fingerprint,operation_id:ident(),confirmation:'CLOSE_ACCOUNT'});
 const made=await notes(f,'prepareShared'),status=await ok(f.browser,'/groups',made.request,'group-status'),group=status.group_id;await notes(f,'group',[status]);
 proof={pin:(await import('./shared/proof.mjs')).genesisPin(status.genesis),journal:await ok(f.browser,'/groups/'+group+'/journal'),accounts:[await accountProof(f)]};await adopt(f,proof);
 await shared(f,'history',{group_id:group});await transmit(f,group);proof=await refreshGroup(f,group,proof);await denied(f.browser,'/me/close-account',closeBody(f),['ROLE_FORBIDDEN']);check((await ok(f.browser,'/groups/'+group)).owner_account_id===f.pins.account_id,'OWNER_ACCOUNT_CANNOT_BE_CLOSED_OR_ORPHANED');
 const title=await publish(f,edit(group,'group-metadata',group,null,content('PUBLIC P10 shared title'))),thread=await publish(f,edit(group,'thread',null,null,content('PUBLIC P10 shared thread'))),entry=await publish(f,edit(group,'entry',null,thread.object_id,content('PUBLIC retained history','PUBLIC retained pre-admission body')));
 const trashed=await publish(f,edit(group,'entry',null,thread.object_id,content('PUBLIC retained trash','PUBLIC retained trash body'))),tomb=await publish(f,edit(group,'entry',trashed.object_id,thread.object_id,content(),trashed.receipt.heads,'soft-delete'));
 await shared(f,'history',{group_id:group});await transmit(f,group);proof=await refreshGroup(f,group,proof);
 for(const [target,role]of [[editor,'editor'],[reader,'reader']]){
  const ap=await accountProof(target);
  await assertReject(()=>shared(f,'invite',{group_id:group,account:ap,expected_root:b64(sodium.randombytes_buf(32)),role,confirm:true}),'IDENTITY_CONFIRMATION_REQUIRED');
  const inv=await shared(f,'invite',{group_id:group,account:ap,expected_root:ap.pins.root_fingerprint,role,confirm:true});await transmit(f,group);
  proof={...proof,accounts:[...proof.accounts,ap]};proof=await refreshGroup(f,group,proof);
  await denied(target.browser,'/groups/'+group,undefined,['NOT_FOUND']);await denied(target.browser,'/groups/'+group+'/journal',undefined,['NOT_FOUND']);
  const invites=await ok(target.browser,'/me/group-invitations');check(invites.invitations.some(i=>i.body.operation_id===inv.body.invitation.body.operation_id),'TARGET_DISCOVERS_PENDING_INVITATION');
  const card=await shared(f,'card',{group_id:group});await adopt(target,card);
  await shared(target,'accept',{group_id:group,invitation:inv.body.invitation,confirm:true});await transmit(target,group);
  await denied(target.browser,'/groups/'+group,undefined,['NOT_FOUND']);check(true,'ACCEPTED_WITHOUT_GRANTS_HAS_NO_CONTENT_ACCESS');
  proof=await refreshGroup(f,group,proof);const maintenance=await shared(f,'epoch',{group_id:group,reason:'admission',confirm:true});
  await ok(f.browser,'/groups/'+group+'/epoch/begin',maintenance.body);
  await denied(target.browser,'/objects/'+entry.object_id,undefined,['NOT_FOUND']);
  // Interrupted staging: exact page retransmission and final commit are durable/idempotent.
  for(const page of maintenance.pages){const r=await ok(f.browser,'/groups/'+group+'/epoch/page',{version:1,page});const again=await ok(f.browser,'/groups/'+group+'/epoch/page',{version:1,page});check(JSON.stringify(r)===JSON.stringify(again),'STAGED_PAGE_IDEMPOTENT');}
  const result=await ok(f.browser,'/groups/'+group+'/epoch/commit',{version:1,commit:maintenance.commit});const again=await ok(f.browser,'/groups/'+group+'/epoch/commit',{version:1,commit:maintenance.commit});check(JSON.stringify(result)===JSON.stringify(again),'EPOCH_LOST_RESPONSE_RECONCILES_EXACT_RECEIPT');await shared(f,'complete',{group_id:group,result});
  proof=await refreshGroup(f,group,proof);
  for(const active of [f,target]){const card=await shared(f,'card',{group_id:group});await adopt(active,card);if(active===f)proof=card;await notes(active,'group',[await ok(active.browser,'/groups/'+group)]);await shared(active,'keys',{group_id:group});}
  check((await open(target,entry.object_id)).payload.markdown==='PUBLIC retained pre-admission body','FULL_HISTORY_KEYS_AND_SIGNED_CHECKPOINT_READ');const trashPage=await ok(target.browser,'/groups/'+group+'/trash');check(trashPage.objects.some(o=>o.object_id===trashed.object_id),'INVITATION_INCLUDES_RETAINED_TRASH');const prior=await ok(target.browser,'/objects/'+trashed.object_id+'/revisions/'+trashed.request.bundle.envelope.header.context.revision_id);const old=await notes(target,'open',[{group_id:group,object_id:trashed.object_id,revision_id:prior.revision_id,object_kind:'entry',thread_id:thread.object_id,bundle:prior.bundle}]);check(old.payload.markdown==='PUBLIC retained trash body','NEW_MEMBER_DECRYPTS_RETAINED_TRASH_VERSION');
 }
 // All members refresh verified policy, account rosters and current epochs.
 proof=await refreshGroup(f,group,proof);const card=await shared(f,'card',{group_id:group});for(const m of members){await adopt(m,card);await notes(m,'group',[await ok(m.browser,'/groups/'+group)]);await shared(m,'keys',{group_id:group});}
 const edited=await publish(editor,edit(group,'entry',null,thread.object_id,content('PUBLIC editor contribution','PUBLIC independent editor body')));
 check((await open(reader,edited.object_id)).payload.markdown==='PUBLIC independent editor body','READER_OPENS_AUTHORIZED_CURRENT_WRITER');
 const privateDraft=await notes(reader,'save',[edit(group,'entry',null,thread.object_id,content('PUBLIC reader local draft','PUBLIC preserved forbidden text'))]);await assertReject(()=>notes(reader,'queue',[privateDraft.draft_id]),'ROLE_FORBIDDEN');
 // A malicious reader with actual group keys and signing keys is still rejected by the real backend.
 const secrets=await readOwnedSecrets({store:reader.store}),gk=secrets.group_keys.find(k=>k.group_id===group&&k.key_epoch===card.journal.events.findLast(e=>e.kind==='epoch').commit.body.intent.body.next_epoch),draft=await notes(reader,'draft',[privateDraft.draft_id]),evil=sealObject(wire(draft.payload),un64(gk.group_secret),reader.initial.keys.signing.privateKey),evilReq={group_id:group,object_id:draft.payload.context.object_id,object_kind:'entry',thread_id:thread.object_id,action:'create',bundle:evil};
 await denied(reader.browser,pathFor(evilReq),evilReq,['ROLE_FORBIDDEN']);await denied(outsider.browser,'/groups/'+group+'/journal',undefined,['NOT_FOUND']);
 await assertReject(()=>shared(reader,'policy',{group_id:group,action:'role',target_account_id:editor.pins.account_id,role:'reader',confirm:true}),'OWNER_REQUIRED');
 // Close writer-observed history before role loss; other members must supply real witnessed contributions.
 await open(f,edited.object_id);await shared(f,'history',{group_id:group});await transmit(f,group);proof=await refreshGroup(f,group,proof);
 const beforeLoss=await prepared(editor,edit(group,'entry',null,thread.object_id,content('PUBLIC offline editor','PUBLIC retain after downgrade')));
 await shared(f,'policy',{group_id:group,action:'role',target_account_id:editor.pins.account_id,role:'reader',confirm:true});await transmit(f,group);await denied(editor.browser,pathFor(beforeLoss.request),beforeLoss.request,['ROLE_FORBIDDEN']);await notes(editor,'reject',[beforeLoss.attempt_id,'ROLE_FORBIDDEN']);check((await notes(editor,'draft',[beforeLoss.draft_id])).payload.markdown==='PUBLIC retain after downgrade','DOWNGRADED_OFFLINE_WORK_RETAINED');
 proof=await refreshGroup(f,group,proof);await shared(f,'history',{group_id:group});await transmit(f,group);proof=await refreshGroup(f,group,proof);
 await shared(f,'policy',{group_id:group,action:'remove',target_account_id:editor.pins.account_id,confirm:true});await transmit(f,group);await denied(editor.browser,'/groups/'+group,undefined,['NOT_FOUND']);await denied(editor.browser,'/objects/'+entry.object_id,undefined,['NOT_FOUND']);
 proof=await refreshGroup(f,group,proof);await assertReject(()=>prepared(f,edit(group,'entry',null,thread.object_id,content('PUBLIC block','PUBLIC old epoch write'))),'REKEY_REQUIRED');
 const removal=await shared(f,'epoch',{group_id:group,reason:'member-removal',confirm:true});check(removal.pages.every(p=>p.records.every(r=>r.body.context.recipient.account_id!==editor.pins.account_id)),'REMOVED_ACCOUNT_RECEIVES_NO_FUTURE_OR_RETAINED_GRANT');await transmit(f,group);proof=await refreshGroup(f,group,proof);await shared(f,'history',{group_id:group});await transmit(f,group);proof=await refreshGroup(f,group,proof);
 const future=await publish(f,edit(group,'entry',null,thread.object_id,content('PUBLIC post-removal','PUBLIC fresh epoch future body')));check(future.request.bundle.envelope.header.context.policy.key_epoch!=='0','POST_REMOVAL_FRESH_EPOCH_PUBLICATION');
 // Private-to-shared copy is an explicit, fresh object/DEK/epoch operation.
 const privateMade=await notes(f,'prepareGroup'),privateStatus=await ok(f.browser,'/groups',privateMade.request,'group-status');await notes(f,'group',[privateStatus]);const privateThread=await publish(f,edit(privateStatus.group_id,'thread',null,null,content('PUBLIC private copy thread'))),privateEntry=await publish(f,edit(privateStatus.group_id,'entry',null,privateThread.object_id,content('PUBLIC selected private title','PUBLIC selected private body')));
 const copyArgs={source_group:privateStatus.group_id,destination_group:group,destination_thread:thread.object_id,revision_id:privateEntry.request.bundle.envelope.header.context.revision_id},copyPreview=await notes(f,'copyPreview',[copyArgs]);
 check(copyPreview.preview.destination_audience.every(m=>m.account_id!==editor.pins.account_id)&&copyPreview.preview.source_audience.length===1,'COPY_SHOWS_EXACT_SOURCE_DESTINATION_AUDIENCE');await assertReject(()=>notes(f,'copy',[{...copyArgs,preview_digest:copyPreview.digest,confirm:false}]),'COPY_CONFIRMATION_REQUIRED');
 const copied=await notes(f,'copy',[{...copyArgs,preview_digest:copyPreview.digest,confirm:true}]),copyQueued=await notes(f,'queue',[copied.draft_id]),copySent=await notes(f,'send',[copyQueued.attempt_id]),copyResult=await ok(f.browser,pathFor(copySent.request),copySent.request,'receipt-result');await notes(f,'ack',[copyQueued.attempt_id,copyResult]);
 check(copySent.request.object_id!==privateEntry.object_id&&copySent.request.bundle.ciphertext!==privateEntry.request.bundle.ciphertext&&copySent.request.bundle.wrap.nonce!==privateEntry.request.bundle.wrap.nonce,'COPY_FRESH_IDS_DEK_WRAP_AND_CONTEXT');check((await open(f,copied.object_id)).payload.markdown==='PUBLIC selected private body'&&(await open(f,privateEntry.object_id)).payload.markdown==='PUBLIC selected private body','COPY_ORIGINAL_AND_HISTORY_REMAIN_PRIVATE');
 // Former writers cannot invent backdated retained history, even with genuine old keys/signatures.
 const oldDraft=await notes(editor,'draft',[beforeLoss.draft_id]),oldSecrets=await readOwnedSecrets({store:editor.store}),oldPolicy=beforeLoss.request.bundle.envelope.header.context.policy,oldKey=oldSecrets.group_keys.find(k=>k.group_id===group&&k.key_epoch===oldPolicy.key_epoch),forged=structuredClone(oldDraft.payload);forged.context=structuredClone(beforeLoss.request.bundle.envelope.header.context);forged.context.operation_id=ident();forged.context.revision_id=ident();forged.markdown='PUBLIC revoked backdated forged text';const forgedBundle=sealObject(wire(forged),un64(oldKey.group_secret),editor.initial.keys.signing.privateKey);
 await assertReject(()=>notes(f,'open',[{group_id:group,object_id:forged.context.object_id,revision_id:forged.context.revision_id,object_kind:'entry',thread_id:thread.object_id,bundle:forgedBundle}]),'UNANCHORED_HISTORY');
 // Two owners explicitly consent after current authentication; neither signature is optional.
 await open(f,future.object_id);await open(f,copied.object_id);await shared(f,'history',{group_id:group});await transmit(f,group);proof=await refreshGroup(f,group,proof);
 const currentCard=await shared(f,'card',{group_id:group});await adopt(reader,currentCard);await notes(reader,'group',[await ok(reader.browser,'/groups/'+group)]);await shared(reader,'keys',{group_id:group});
 const proposal=await shared(f,'transferProposal',{group_id:group,account_id:reader.pins.account_id,device_id:reader.initial.device.device_id,confirm:true});const missing=structuredClone(proposal);await denied(f.browser,'/groups/'+group+'/policy',{version:1,policy:missing},['ROLE_FORBIDDEN','INVALID_SIGNATURE']);
 const consent=await shared(reader,'cosign',{group_id:group,policy:proposal,confirm:true});await transmit(reader,group);await shared(f,'transfer',{group_id:group,policy:consent.body.policy,confirm:true});await transmit(f,group);proof=await refreshGroup(f,group,proof);check((await ok(f.browser,'/groups/'+group)).owner_account_id===reader.pins.account_id,'CO_SIGNED_OWNER_TRANSFER_EXACTLY_ONE_OWNER');await assertReject(()=>shared(f,'policy',{group_id:group,action:'archive',confirm:true}),'OWNER_REQUIRED');
 const ownerCard=await shared(f,'card',{group_id:group});await adopt(reader,ownerCard);await notes(reader,'group',[await ok(reader.browser,'/groups/'+group)]);
 await shared(reader,'policy',{group_id:group,action:'archive',confirm:true});await transmit(reader,group);const archived=await ok(reader.browser,'/groups/'+group);check(archived.state==='archived','ARCHIVE_OWNER_POLICY');let readerProof=await refreshGroup(reader,group,ownerCard);await assertReject(()=>prepared(reader,edit(group,'entry',null,thread.object_id,content('PUBLIC archived','PUBLIC preserve archived'))),'ARCHIVED');
 await shared(reader,'policy',{group_id:group,action:'unarchive',confirm:true});await transmit(reader,group);readerProof=await refreshGroup(reader,group,readerProof);check((await ok(reader.browser,'/groups/'+group)).state==='active','OWNER_UNARCHIVE');
 const faultAttempt=await shared(reader,'policy',{group_id:group,action:'archive',confirm:true}),beforeFault=control('p10-state');control('p10-fault-on');try{await denied(reader.browser,'/groups/'+group+'/policy',faultAttempt.body,['TEMPORARY_UNAVAILABLE']);}finally{control('p10-fault-off');}check(JSON.stringify(control('p10-state'))===JSON.stringify(beforeFault),'SECURITY_RECEIPT_FAILURE_ROLLS_BACK_POLICY_JOURNAL_PROJECTIONS_QUOTA_AND_EVENT');await transmit(reader,group);readerProof=await refreshGroup(reader,group,readerProof);await shared(reader,'policy',{group_id:group,action:'unarchive',confirm:true});await transmit(reader,group);readerProof=await refreshGroup(reader,group,readerProof);
 // Own-account new-device grants and narrow reader roster maintenance use independently enrolled keys.
 const peer=await enrollNative(f);nativePeers.push(peer);proof=await refreshGroup(f,group,proof);const extension=await shared(f,'ownGrants',{group_id:group,device_id:peer.scope.device_id});await ok(f.browser,'/me/device-envelopes',extension);
 const ownCard=await shared(f,'card',{group_id:group});let nativeResult=await peer.native.call({operation:'notes',request:{action:'shared',request:{action:'adopt',proof:ownCard}}});check(!nativeResult.error,'REAL_NATIVE_ADOPTS_SHARED_POLICY');nativeResult=await peer.native.call({operation:'notes',request:{action:'shared',request:{action:'own-keys',group_id:group,records:extension.records}}});check(!nativeResult.error,'REAL_NATIVE_RECEIVES_ALL_RETAINED_EPOCHS_ON_NEW_OWN_DEVICE');
 const maintenanceCard=await shared(f,'card',{group_id:group});await adopt(reader,maintenanceCard);await notes(reader,'group',[await ok(reader.browser,'/groups/'+group)]);await shared(reader,'keys',{group_id:group}).catch(e=>{check(e.message==='ROSTER_CHANGED','OLD_CURRENT_GRANTS_REFUSED_AFTER_NEW_ROSTER');});
 await shared(reader,'policy',{group_id:group,action:'role',target_account_id:f.pins.account_id,role:'reader',confirm:true});await transmit(reader,group);proof=await refreshGroup(f,group,proof);
 // The former owner is now a reader; mandatory roster maintenance grants no writer authority.
 const rotation=await shared(f,'epoch',{group_id:group,reason:'roster-maintenance',confirm:true});await ok(f.browser,'/groups/'+group+'/epoch/begin',rotation.body);
 const tamperedPage=structuredClone(rotation.pages[0]);tamperedPage.records.pop();await ok(f.browser,'/groups/'+group+'/epoch/page',{version:1,page:tamperedPage});await denied(f.browser,'/groups/'+group+'/epoch/commit',{version:1,commit:rotation.commit},['KEYS_PENDING','INVALID_SIGNATURE']);
 check((await ok(f.browser,'/groups/'+group)).key_epoch!==rotation.body.intent.body.next_epoch,'PARTIAL_RECIPIENT_COVERAGE_NEVER_ACTIVATES');
 // Explicit cancellation burns this exposed key; retain and reconcile its frozen attempt.
 const cancellation=await ok(f.browser,'/groups/'+group+'/cancel',{version:1,operation_id:rotation.body.intent.body.operation_id});await shared(f,'finishCancel',{group_id:group,result:cancellation});
 const priorReceipt=await ok(f.browser,'/groups/'+group+'/epoch/begin',rotation.body);check(priorReceipt.state==='STAGING'&&(await ok(f.browser,'/groups/'+group+'/journal')).pending===null,'OLD_BEGIN_RECEIPT_DOES_NOT_REACTIVATE_CANCELLED_TRANSITION');
 const nextIntent=structuredClone(rotation.body.intent);nextIntent.body.operation_id=ident();nextIntent.signature=b64(sodium.crypto_sign_detached((await import('./shared/proof.mjs')).groupCodec.groupSigningInput('epoch-intent-body',wire(nextIntent.body)),f.initial.keys.signing.privateKey));await denied(f.browser,'/groups/'+group+'/epoch/begin',{version:1,intent:nextIntent,policy:null},['INVALID_SIGNATURE']);
 proof=await refreshGroup(f,group,proof);const replacement=await shared(f,'epoch',{group_id:group,reason:'roster-maintenance',confirm:true});check(replacement.body.intent.body.key_commitment!==rotation.body.intent.body.key_commitment,'CANCELLED_EXPOSED_KEY_NEVER_REUSED');await transmit(f,group);proof=await refreshGroup(f,group,proof);await assertReject(()=>shared(f,'history',{group_id:group}),'WRITER_REQUIRED');const closedCard=await shared(f,'card',{group_id:group});await adopt(reader,closedCard);await shared(reader,'keys',{group_id:group});await shared(reader,'history',{group_id:group});await transmit(reader,group);readerProof=await refreshGroup(reader,group,closedCard);check((await ok(reader.browser,'/groups/'+group)).rekey_required===false,'READER_EXECUTES_EXACT_ROSTER_REKEY_WITHOUT_WRITING_CONTENT');

 const closed=await ok(outsider.browser,'/me/close-account',closeBody(outsider));check(closed.state==='PENDING_RETENTION','SELF_ACCOUNT_CLOSURE_PRESERVES_CONTENT_RETENTION_QUEUE');await denied(outsider.browser,'/groups',undefined,['SESSION_EXPIRED','AUTH_REQUIRED']);
 const inspect=control('p09-inspect',JSON.stringify({markers:['PUBLIC P10 shared title','PUBLIC retained pre-admission body','PUBLIC independent editor body','PUBLIC fresh epoch future body',b64(f.initial.keys.signing.privateKey)]}));check(inspect.status==='PASS','SQL_LOGS_HAVE_NO_PLAINTEXT_OR_PRIVATE_KEYS');
 mkdirSync(root+'/artifacts/p10',{recursive:true});const report={purpose:'P10 actual HTTPS/SQL signed shared-group integration',status:'PASS',checks:fixtureCheckCount(),source_commit:startedCommit,source_tree_dirty:startedDirty,physical_acceptance:false,independent_review:'NOT_RUN'};writeFileSync(root+'/artifacts/p10/http-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}finally{for(const peer of nativePeers)await peer.native.close();for(const m of [...members,outsider]){m.initial.dispose();await m.engine.close();}}
async function assertReject(fn,code){let error;try{await fn();}catch(e){error=e;}check(error?.message===code,'EXPECTED_REJECTION:'+code+':'+error?.message);}
