import {syncValue,checkedScope,checkedSnapshot,checkedDelta,checkedBundle,pageReceipt,snapshotCommitment,catalogCommitment,itemOrder,syncHash} from '../sync/codec.mjs';
import {replayGroup,genesisPin,groupApi,groupBuilders,groupCodec} from '../shared/proof.mjs';
import {sharedValue} from '../shared/client.mjs';
import {senderForCertificate,sealGroupKeyForEvaluation} from '../devices/proofs.mjs';
import {decode as fileDecode,inventoryCommitment,signingInput as fileSigningInput,envelopeDigest as fileSigningDigest} from '../adapters/codecs/codec.mjs';
// Protected Worker workflow. Signing/encryption is subordinate to verified private-group authority.
import {sodium,b64,un64,hash} from '../adapters/primitives.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {canonicalBytes,sealObject,openObject} from '../adapters/core.mjs';
import {common,decode,digest,signingInput} from '../adapters/codecs/protocol-codec.mjs';
import {verifiedSnapshot,historicalSnapshot} from '../devices/client.mjs';
import {privateGenesis,verifyGenesis} from '../devices/genesis.mjs';
import {activeCertificateForEvaluation,rosterDetails} from '../devices/roster.mjs';
import {certificateDetails} from '../devices/proofs.mjs';
import {stateDigest} from '../adapters/codecs/state-codec.mjs';
import {noteValue} from './client.mjs';
import {FileWorkflow} from '../files/workflow.mjs';
import {ContentWorkflow} from '../content/workflow.mjs';
import {ProtectedImport} from '../content/import.mjs';
import {fileValue} from '../files/codec.mjs';
import {imageBounds} from '../../content-browser/preview-bounds.mjs';
import {ProtectedExport} from '../content/protected-export.mjs';
import {contentValue} from '../content/client.mjs';
import {FileReader} from '../adapters/files.mjs';
import {aad} from '../adapters/codecs/protocol-codec.mjs';
import {fileAad,decode as portableFileDecode} from '../adapters/codecs/codec.mjs';
import {ensure,id} from '../vault/store.mjs';
const random=()=>b64(sodium.randombytes_buf(16));
const valueHash=v=>hash(canonicalBytes(wire(v)));
const requestFor=b=>{const c=b.envelope.header.context;return noteValue('commit-request',{group_id:c.group_id,object_id:c.object_id,object_kind:c.object_kind,action:c.action,thread_id:c.thread_id,bundle:b});};
function wipe(v){if(v instanceof Uint8Array)sodium.memzero(v);else if(v&&typeof v==='object')for(const k of Object.keys(v)){wipe(v[k]);if(typeof v[k]==='string')v[k]='';}}
export class NotesWorkflow {
 #defer;#state;#proof;#snapshot;#keys;#copyAudience;#files;#contents;#portable;#portableFile;#import;#importTag;#importGroupTag;
 constructor({scope,pins,keys,load,read,persist,devices,secrets,files,content,portableTransport}){this.scope=scope;this.pins=pins;this.#keys=keys;this.load=load;this.read=read;this.persist=persist;this.devices=devices;this.secrets=secrets;this.files=files;this.content=content;this.portableTransport=portableTransport;}
 close(){this.#import?.close();this.#import=undefined;this.#portable?.close();this.#portable=undefined;this.#portableFile?.close();this.#portableFile=undefined;this.#fileCatalogIds.clear();this.#contents?.close();this.#contents=undefined;this.#files?.close();this.#files=undefined;this.#state=this.#proof=this.#snapshot=undefined;}
 async #ready(){
  if(!this.#state)this.#state=(await this.load())??{purpose:'p09-private-control',version:1,groups:[],drafts:[],attempts:[],witnesses:[]};
  noteValue('local-control',this.#state);
  const saved=await this.devices();ensure(saved.control?.head,'ROSTER_PROOF_REQUIRED');
  const c=saved.control;this.#snapshot={identity:c.identity,head:c.head,generation:c.generation,events:saved.pages.flat()};this.#proof=verifiedSnapshot(this.#snapshot,this.pins,c.head);
 }
 #own(proof=this.#proof){
  const own=proof.details.devices.find(d=>d.device_id===this.scope.device_id);ensure(own?.status==='ACTIVE'&&own.generation===proof.details.generation,own?.status==='REVOKED'?'DEVICE_REVOKED':'DEVICE_NOT_TRUSTED');
  const cert=activeCertificateForEvaluation(proof.roster,this.scope.device_id,'sign-content'),b=certificateDetails(cert).body;
  ensure(b.device_signing_key===b64(this.#keys.signing.publicKey)&&b.device_encryption_key===b64(this.#keys.encryption.publicKey),'DEVICE_KEY_MISMATCH');return b;
 }
 #author(localOnly=false){
  let proof=this.#proof;
  if(localOnly&&!proof.details.devices.some(d=>d.device_id===this.scope.device_id&&d.status==='ACTIVE')){
   const e=this.#snapshot.events.findLast(e=>e.body.payload?.certificate?.body.device_id===this.scope.device_id);
   ensure(e,'DEVICE_REVOKED');proof=historicalSnapshot(this.#snapshot,this.pins,{version:e.body.version,digest:stateDigest('event',wire(e))});
  }
  const b=this.#own(proof);return {account_id:this.scope.account_id,device_id:this.scope.device_id,root_fingerprint:this.pins.root_fingerprint,recovery_generation:b.recovery_generation,roster:structuredClone(proof.details.head)};
 }
 async #info(group){
  const ref=this.#state.groups.find(g=>g.group_id===group);ensure(ref,'KEYS_PENDING');
  const data=await this.read(ref.record_id,'group-evidence');noteValue('local-evidence',data);
  if(data.purpose==='p10-group-proof'){const proof=structuredClone(data.proof);const own=proof.accounts.find(a=>a.pins.account_id===this.scope.account_id);ensure(own,'ROOT_PIN_MISMATCH');own.snapshot=structuredClone(this.#snapshot);const witnesses=await this.#historyRecords(group);const verified=replayGroup(proof,{ownPins:this.pins,known:data.proof,witnesses,localGenesis:data.proof.pin.owner_account_id===this.scope.account_id&&data.proof.journal.events.length===0});return {ref,evidence:proof.journal.genesis,data,verified,info:{group_id:group,membership:verified.details.policy,epoch_digest:verified.policy.epoch_digest,policy:verified.policy,epochs:verified.details.epochs,rekey_required:verified.details.write_state==='REKEY_REQUIRED',write_state:verified.details.write_state,members:verified.details.members}};}
  const evidence=data.evidence,signer=evidence.commit.body.policy.body.signer;
  const historical=historicalSnapshot(this.#snapshot,this.pins,signer.roster_head),info=verifyGenesis(evidence,historical.roster,historical.identity);
  ensure(info.group_id===group&&evidence.commit.body.policy.body.members[0].account_id===this.scope.account_id,'POLICY_CHANGED');
  // Rekey need is derived from the verified signed history, never just an
  // unsigned flag a hostile service can clear. P09 supports genesis epoch only.
  const epochRoster=evidence.commit.body.intent.body.rosters[0].roster;
  info.rekey_required=this.#snapshot.events.some(e=>BigInt(e.body.version)>BigInt(epochRoster.version)&&['revoke','reset'].includes(e.body.kind));
  return {ref,evidence,info};
 }
 #policy(info){if(info.policy)return structuredClone(info.policy);return {membership:info.membership,key_epoch:'0',epoch_digest:info.epoch_digest,history_checkpoint_digest:null};}
 #writable(group,info){
  ensure(this.#state.sync?.state!=='RESTORE_QUARANTINE','RESTORE_QUARANTINE');this.#own();if(info.policy){ensure(info.write_state==='WRITABLE',info.write_state);const member=info.members?.find(m=>m.account_id===this.scope.account_id);ensure(member&&member.role!=='reader','ROLE_FORBIDDEN');}
  ensure(group.state==='COMMITTED'&&group.status,'GROUP_NOT_COMMITTED');const s=group.status;
  ensure(!info.rekey_required,'REKEY_REQUIRED');
  ensure(s.state==='active','ROLE_FORBIDDEN');ensure(!s.restore_quarantined,'RESTORE_QUARANTINE');ensure(!s.rekey_required,'REKEY_REQUIRED');ensure(!s.history_closure_required,'HISTORY_CLOSURE_REQUIRED');
  ensure(same(s.membership,info.membership)&&s.key_epoch===(info.policy?.key_epoch??'0')&&s.epoch_digest===info.epoch_digest&&s.history_checkpoint_digest===(info.policy?.history_checkpoint_digest??null),'POLICY_CHANGED');
 }
 async #key(group,info,epoch=info.policy?.key_epoch??'0'){
  const data=await this.secrets();try{const k=data.group_keys.find(k=>k.service_id===this.pins.service_id&&k.group_id===group&&k.key_epoch===epoch&&k.epoch_digest===(info.epochs?.find(e=>e.key_epoch===epoch)?.epoch_digest??info.epoch_digest));ensure(k,'KEYS_PENDING');return un64(k.group_secret);}finally{wipe(data);}
 }
 async #fileAuthority(group,write,envelope){
  const {ref,info,verified}=await this.#info(group);
  if(write){this.#writable(ref,info);const key=await this.#key(group,info);if(verified){const epoch=verified.details.epochs.find(e=>e.key_epoch===info.policy.key_epoch);if(!epoch||groupCodec.groupKeyCommitment(verified.details.scope,key)!==epoch.key_commitment){wipe(key);throw Error('KEY_REPAIR_REQUIRED');}}return {author:this.#author(),policy:this.#policy(info),members:structuredClone(info.members??[{account_id:this.scope.account_id,root_fingerprint:this.pins.root_fingerprint,role:'owner'}]),key,signing:new Uint8Array(this.#keys.signing.privateKey)};}
  const c=envelope.header.context;ensure(c.service_id===this.scope.service_id&&c.group_id===group,'CONTEXT_MISMATCH');let certificate;
  if(verified){let authority;try{authority=groupApi.checkHistoricalFileForEvaluation(verified.token,wire(envelope),groupApi.groupSenderForEvaluation(verified.token,this.scope.account_id,this.scope.device_id,'receive-group-key'));}catch(e){if(e.message!=='UNANCHORED_HISTORY'||!same(c.policy,info.policy))throw e;authority=groupApi.checkCurrentFileForEvaluation(verified.token,wire(envelope));groupApi.observeAcceptedFileForEvaluation(verified.token,wire(envelope));}certificate=authority.certificate;}
  else{ensure(c.author.account_id===this.scope.account_id&&c.author.root_fingerprint===this.pins.root_fingerprint&&same(c.policy,this.#policy(info)),'CONTEXT_MISMATCH');const historical=historicalSnapshot(this.#snapshot,this.pins,c.author.roster);certificate=activeCertificateForEvaluation(historical.roster,c.author.device_id,'sign-content');const files=await this.files.readControl(),known=files?.witnesses?.some(w=>w.file_version_id===c.file_version_id&&w.envelope_digest===fileSigningDigest(wire(envelope)));ensure(this.#proof.details.devices.some(d=>d.device_id===c.author.device_id&&d.status==='ACTIVE')||known,'UNANCHORED_HISTORY');}
  const author=certificateDetails(certificate).body;ensure(author.recovery_generation===c.author.recovery_generation,'CONTEXT_MISMATCH');const key=await this.#key(group,info,c.policy.key_epoch);if(verified){const epoch=verified.details.epochs.find(e=>e.key_epoch===c.policy.key_epoch);if(!epoch||groupCodec.groupKeyCommitment(verified.details.scope,key)!==epoch.key_commitment){wipe(key);throw Error('KEY_REPAIR_REQUIRED');}}return {key,publicKey:un64(author.device_signing_key)};
 }
 async #draft(id){const ref=this.#state.drafts.find(d=>d.draft_id===id);ensure(ref,'DRAFT_NOT_FOUND');const data=decode('draft',wire(await this.read(ref.record_id,'draft')));ensure(data.draft_id===ref.draft_id&&valueHash(data)===ref.saved_digest,'INTEGRITY_FAILURE');return {ref,data};}
 async #attempt(id){const ref=this.#state.attempts.find(a=>a.attempt_id===id);ensure(ref,'ATTEMPT_NOT_FOUND');const data=decode('outbox',wire(await this.read(ref.record_id,'outbox')));ensure(data.attempt_id===ref.attempt_id&&data.draft_id===ref.draft_id&&data.state===ref.state,'INTEGRITY_FAILURE');return {ref,data};}
 async #commit(extra={}){noteValue('local-control',this.#state);if(this.#defer){this.#defer.push(extra);return;}await this.persist(this.#state,extra);}
 async command(op,args=[]){
  await this.#ready();
  if(op==='thumbnail'){ensure(args.length===2,'INVALID_CONTENT_COMMAND');return this.#thumbnailCommand(args[0],args[1]);}
  if(op==='import'){ensure(args.length===2,'INVALID_CONTENT_COMMAND');return this.#importCommand(args[0],args[1]);}
  if(op==='portable'){ensure(args.length===2&&this.portableTransport,'INVALID_CONTENT_COMMAND');return this.#portableCommand(args[0],args[1]);}
  if(op==='content'){
   ensure(args.length===2&&this.content,'INVALID_CONTENT_COMMAND');
   return this.#contentWorkflow().command(args[0],args[1]);
  }
  if(op==='files'){
   ensure(args.length===2&&this.files,'INVALID_FILE_COMMAND');
   this.#files??=new FileWorkflow({scope:this.scope,...this.files,authority:(g,w,e)=>this.#fileAuthority(g,w,e)});
   const result=await this.#files.command(args[0],args[1]);
   if(this.content&&['open','observe'].includes(args[0])&&args[1].record){try{await this.#contentWorkflow().rememberFile(args[1].record);result.search_index_status='metadata-local-saved';}catch(e){if(!['INSUFFICIENT_STORAGE','STORAGE_FAILURE','STORAGE_ABORTED','RESOURCE_LIMIT'].includes(e.message))throw e;result.search_index_status='pending';}}
   return result;
  }
  if(op==='attach'){
   ensure(args.length===1&&id(args[0]?.draft_id)&&id(args[0]?.file_draft_id),'INVALID_REQUEST');const {ref,data}=await this.#draft(args[0].draft_id);
   ensure(data.context.object_kind==='entry'&&data.context.action!=='soft-delete','ATTACHMENT_CONTEXT_MISMATCH');
   const transfers=await this.command('files',['list',{}]),file=transfers.find(f=>f.draft_id===args[0].file_draft_id);ensure(file&&file.group_id===ref.group_id,'ATTACHMENT_CONTEXT_MISMATCH');
   const attachment=await this.command('files',['attachment',{draft_id:file.draft_id}]);
   const attachments=[...data.context.attachments.filter(a=>a.file_id!==attachment.file_id),attachment];
   // Frozen ordering is bytewise, not locale-dependent.
   attachments.sort((a,b)=>{const x=a.file_id+'/'+a.file_version_id,y=b.file_id+'/'+b.file_version_id;return x<y?-1:x>y?1:0;});
   ensure(attachments.length<=32,'RESOURCE_LIMIT');data.context.attachments=attachments;data.payload.context=structuredClone(data.context);decode('draft',wire(data));ref.saved_digest=valueHash(data);await this.#commit({records:[{id:ref.record_id,kind:'draft',data}]});return {draft_id:ref.draft_id,state:'LOCAL_SAVED',attachment};
  }
  if(op==='sync')return this.#syncCommand(args);
  if(op==='summary')return {groups:this.#state.groups.map(g=>({group_id:g.group_id,state:g.state,status:g.status})),drafts:this.#state.drafts.map(d=>{const a=this.#state.attempts.findLast(a=>a.draft_id===d.draft_id);return {...d,attempt_id:a?.attempt_id??null,state:a?(a.state==='COMMITTED'&&a.source_digest!==d.saved_digest?'LOCAL_SAVED':a.state):'LOCAL_SAVED'};}),witnessed:this.#state.witnesses.length,witnesses:structuredClone(this.#state.witnesses)};
  if(op==='prepareShared'){
   ensure(this.#state.sync?.state!=='RESTORE_QUARANTINE','RESTORE_QUARANTINE');ensure(args.length===0&&this.#state.groups.length<100,'RESOURCE_LIMIT');this.#own();const made=privateGenesis(this.#proof.roster,this.#proof.identity,this.scope.device_id,this.#keys.signing.privateKey,'shared'),group=made.request.commit.body.group_id,record_id=random(),evidence={version:1,group_id:group,...made.request};
   const proof={pin:genesisPin(evidence),journal:{version:1,group_id:group,genesis:evidence,events:[],pending:null},accounts:[{pins:this.pins,snapshot:this.#snapshot}]};replayGroup(proof,{ownPins:this.pins,localGenesis:true});this.#state.groups.push({group_id:group,record_id,state:'GENESIS_PENDING',status:null});try{await this.#commit({records:[{id:record_id,kind:'group-evidence',data:{purpose:'p10-group-proof',version:1,proof,attempt:null}}],addKeys:[made.secret]});return {group_id:group,request:made.request};}finally{wipe(made.secret);}
  }
  if(op==='copyPreview'||op==='copy'){
   ensure(args.length===1,'INVALID_REQUEST');const x=args[0];ensure(id(x.source_group)&&id(x.destination_group)&&id(x.revision_id),'INVALID_REQUEST');const source=await this.#info(x.source_group),destination=await this.#info(x.destination_group);ensure(source.ref.status?.kind==='private'&&source.ref.status?.settings!==true&&destination.ref.status?.kind==='shared','COPY_AUDIENCE_REQUIRED');this.#writable(destination.ref,destination.info);const opened=await this.command('cached',[x.revision_id]),p=opened.payload;ensure(p.context.group_id===x.source_group&&p.context.object_kind==='entry'&&p.metadata_kind==='content'&&p.context.action!=='soft-delete'&&p.context.attachments.length===0,'COPY_SCOPE_MISMATCH');const preview={source_group:x.source_group,destination_group:x.destination_group,revision_id:x.revision_id,source_audience:[this.scope.account_id],destination_audience:destination.info.members.map(m=>({account_id:m.account_id,root_fingerprint:m.root_fingerprint,role:m.role})),policy:this.#policy(destination.info),scope:'selected-current-entry-only',title:p.title};const digest=valueHash(preview);if(op==='copyPreview')return {preview,digest};ensure(x.confirm===true&&x.preview_digest===digest&&id(x.destination_thread),'COPY_CONFIRMATION_REQUIRED');this.#copyAudience=valueHash(destination.info.members);try{return await this.command('save',[{draft_id:null,group_id:x.destination_group,object_id:null,object_kind:'entry',thread_id:x.destination_thread,action:'create',parents:[],archived:false,content:{title:p.title,markdown:p.markdown,metadata_kind:'content',tags:p.tags,checklist:p.checklist,summary_entry_id:null,preferences:[]}}]);}finally{this.#copyAudience=undefined;}
  }
  if(op==='shared')return this.#sharedCommand(args);
  if(op==='recoverDraft'){
   ensure(args.length===1&&args[0]?.confirm===true&&Object.keys(args[0]).sort().join(',')==='confirm,destination_group,destination_thread,draft_id','CONFIRMATION_REQUIRED');const x=args[0];ensure(id(x.draft_id)&&id(x.destination_group)&&id(x.destination_thread),'INVALID_REQUEST');
   const old=await this.#draft(x.draft_id),destination=await this.#info(x.destination_group),p=old.data.payload;
   ensure(destination.ref.status?.kind==='private'&&!destination.ref.status.settings&&destination.ref.status.owner_account_id===this.scope.account_id,'PRIVATE_NAMESPACE_REQUIRED');ensure(p.context.object_kind==='entry'&&p.metadata_kind==='content'&&p.context.attachments.length===0,'COPY_SCOPE_MISMATCH');
   ensure(this.#state.witnesses.some(w=>w.group_id===x.destination_group&&w.object_kind==='thread'&&w.object_id===x.destination_thread&&w.action!=='soft-delete'),'UNANCHORED_HISTORY');
   const saved=await this.command('save',[{draft_id:null,group_id:x.destination_group,object_id:null,object_kind:'entry',thread_id:x.destination_thread,action:'create',parents:[],archived:false,content:{title:p.title,markdown:p.markdown,metadata_kind:'content',tags:p.tags,checklist:p.checklist,summary_entry_id:null,preferences:[]}}]);return {...saved,source_draft_retained:true,scope:'owned-private-local-copy'};
  }
  if(op==='prepareGroup'){
   ensure(this.#state.sync?.state!=='RESTORE_QUARANTINE','RESTORE_QUARANTINE');ensure(args.length===0&&this.#state.groups.length<100,'RESOURCE_LIMIT');this.#own();const made=privateGenesis(this.#proof.roster,this.#proof.identity,this.scope.device_id,this.#keys.signing.privateKey),group=made.request.commit.body.group_id,record_id=random();
   this.#state.groups.push({group_id:group,record_id,state:'GENESIS_PENDING',status:null,...this.#importGroupTag});
   const evidence={version:1,group_id:group,...made.request};
   try{await this.#commit({records:[{id:record_id,kind:'group-evidence',data:{purpose:'p09-private-genesis',version:1,evidence}}],addKeys:[made.secret]});return {group_id:group,request:made.request};}finally{wipe(made.secret);}
  }
  if(op==='groupEvidence'){ensure(args.length===1&&id(args[0]),'INVALID_REQUEST');return (await this.#info(args[0])).evidence;}
  if(op==='retryGroup'){ensure(args.length===1&&id(args[0]),'INVALID_REQUEST');const {ref,evidence}=await this.#info(args[0]);ensure(ref.state==='GENESIS_PENDING','GROUP_NOT_PENDING');const {version,commit,pages}=evidence;return {group_id:ref.group_id,request:{version,commit,pages}};}
  if(op==='group'){
   ensure(args.length===1,'INVALID_REQUEST');const s=noteValue('group-status',args[0]);if(s.kind==='shared'||s.key_epoch!=='0'||(this.#state.groups.some(g=>g.group_id===s.group_id)&&((await this.read(this.#state.groups.find(g=>g.group_id===s.group_id).record_id,'group-evidence')).purpose==='p10-group-proof'))){const found=await this.#info(s.group_id);ensure(found.data,'GROUP_PROOF_REQUIRED');ensure(same(s.membership,found.info.membership)&&s.key_epoch===found.info.policy.key_epoch&&s.epoch_digest===found.info.epoch_digest&&s.history_checkpoint_digest===found.info.policy.history_checkpoint_digest,'POLICY_CHANGED');const {genesis,...summary}=s;found.ref.status=structuredClone(summary);found.ref.state='COMMITTED';await this.#commit();return {group_id:s.group_id,state:'group-local-saved'};}ensure(s.owner_account_id===this.scope.account_id&&s.genesis.group_id===s.group_id,'POLICY_CHANGED');
   const signer=s.genesis.commit.body.policy.body.signer,historical=historicalSnapshot(this.#snapshot,this.pins,signer.roster_head),info=verifyGenesis(s.genesis,historical.roster,historical.identity);ensure(info.group_id===s.group_id,'CONTEXT_MISMATCH');
   let ref=this.#state.groups.find(g=>g.group_id===s.group_id);const known=ref?await this.#info(s.group_id):null;
   if(known)ensure(same(known.evidence,s.genesis),'ROLLBACK_QUARANTINE');
   else{ensure(this.#proof.details.devices.some(d=>d.device_id===signer.device_id&&d.status==='ACTIVE'&&d.certificate_digest===signer.certificate_digest),'UNANCHORED_HISTORY');ensure(this.#state.groups.length<100,'RESOURCE_LIMIT');ref={group_id:s.group_id,record_id:random(),state:'COMMITTED',status:null};this.#state.groups.push(ref);}
   ensure(same(s.membership,info.membership)&&s.key_epoch==='0'&&s.epoch_digest===info.epoch_digest,'POLICY_CHANGED');ref.state='COMMITTED';const {genesis,...summary}=s;ref.status=structuredClone(summary);
   await this.#commit({records:[{id:ref.record_id,kind:'group-evidence',data:{purpose:'p09-private-genesis',version:1,evidence:s.genesis}}]});return {group_id:s.group_id,state:'group-local-saved'};
  }
  if(op==='save'){
   ensure(args.length===1,'INVALID_REQUEST');const edit=noteValue('edit-request',args[0]),{ref:group,info}=await this.#info(edit.group_id);const old=edit.draft_id?this.#state.drafts.find(d=>d.draft_id===edit.draft_id):null;
   ensure(!edit.draft_id||old,'DRAFT_NOT_FOUND');ensure(!old||(old.group_id===edit.group_id&&old.object_kind===edit.object_kind&&old.thread_id===edit.thread_id&&(edit.object_id===null||old.object_id===edit.object_id)),'LOCAL_CONTEXT_MISMATCH');
   const object_id=old?.object_id??(edit.object_kind==='group-metadata'?edit.group_id:edit.object_id??random());ensure(edit.object_kind!=='group-metadata'||object_id===edit.group_id,'CONTEXT_MISMATCH');
   ensure(edit.content.metadata_kind!=='account-preferences'||(group.status?.settings===true&&edit.object_kind==='group-metadata'),'PRIVATE_NAMESPACE_REQUIRED');
   ensure(group.status?.settings!==true||edit.content.metadata_kind==='account-preferences','PRIVATE_NAMESPACE_REQUIRED');
   if(edit.content.summary_entry_id!==null)ensure(edit.object_kind==='thread'&&this.#state.witnesses.some(w=>w.group_id===edit.group_id&&w.object_kind==='entry'&&w.thread_id===object_id&&w.object_id===edit.content.summary_entry_id&&w.action!=='soft-delete'),'CONTEXT_MISMATCH');
   for(const p of edit.parents)ensure(this.#state.witnesses.some(w=>w.group_id===edit.group_id&&w.object_id===object_id&&w.revision_id===p.revision_id&&w.envelope_digest===p.envelope_digest),'UNANCHORED_HISTORY');
   const context={...common('object-context'),service_id:this.scope.service_id,group_id:edit.group_id,object_kind:edit.object_kind,object_id,revision_id:random(),operation_id:random(),thread_id:edit.thread_id,action:edit.action,author:this.#author(true),policy:this.#policy(info),parents:edit.parents,attachments:edit.attachments??(old?(await this.#draft(old.draft_id)).data.context.attachments:[]),payload_schema:1,archived:edit.archived};
   if(context.attachments.length){const files=await this.files.readControl();for(const a of context.attachments){const w=files?.witnesses?.find(w=>w.group_id===edit.group_id&&w.file_version_id===a.file_version_id&&w.envelope_digest===a.envelope_digest);ensure(w,'UNANCHORED_HISTORY');const e=await this.files.readRecord(w.record_id,'file-evidence');ensure(e.envelope.header.context.file_id===a.file_id,'ATTACHMENT_CONTEXT_MISMATCH');}}
   const payload=decode('payload',wire({...common('object-plaintext'),context,...edit.content})),draft_id=old?.draft_id??random(),data=decode('draft',wire({draft_id,context,payload}));
   const ref=old??{draft_id,record_id:random(),group_id:edit.group_id,object_id,object_kind:edit.object_kind,thread_id:edit.thread_id,saved_digest:valueHash(data)};ref.saved_digest=valueHash(data);if(this.#importTag)Object.assign(ref,this.#importTag);if(this.#copyAudience)ref.copy_audience_digest=this.#copyAudience;
   if(!old){ensure(this.#state.drafts.length<10000,'RESOURCE_LIMIT');this.#state.drafts.push(ref);}
   await this.#commit({records:[{id:ref.record_id,kind:'draft',data}]});return {draft_id,object_id,state:'LOCAL_SAVED'};
  }
  if(op==='draft'){ensure(args.length===1&&id(args[0]),'INVALID_REQUEST');const {ref,data}=await this.#draft(args[0]);return {draft_id:ref.draft_id,payload:data.payload};}
  if(op==='queue'){
   ensure(args.length===1&&id(args[0]),'INVALID_REQUEST');const {ref,data}=await this.#draft(args[0]),{ref:group,info}=await this.#info(ref.group_id);this.#writable(group,info);if(ref.copy_audience_digest)ensure(ref.copy_audience_digest===valueHash(info.members),'COPY_CONFIRMATION_REQUIRED');
   const live=this.#state.attempts.findLast(a=>a.draft_id===ref.draft_id&&['QUEUED','SENT_UNKNOWN'].includes(a.state));if(live){ensure(live.source_digest===ref.saved_digest,'PUBLICATION_PENDING');const {data:out}=await this.#attempt(live.attempt_id);return {attempt_id:out.attempt_id,state:out.state};}
   ensure(this.#state.attempts.length<10000,'RESOURCE_LIMIT');data.context.author=this.#author();data.context.policy=this.#policy(info);data.context.operation_id=random();data.context.revision_id=random();data.payload.context=structuredClone(data.context);decode('draft',wire(data));ref.saved_digest=valueHash(data);
   if(info.policy&&data.context.object_kind==='group-metadata')ensure(info.members.some(m=>m.account_id===this.scope.account_id&&m.role==='owner'),'OWNER_REQUIRED');const key=await this.#key(ref.group_id,info);let bundle;try{bundle=sealObject(wire(data.payload),key,this.#keys.signing.privateKey);}finally{wipe(key);}
   const attempt_id=bundle.envelope.header.context.operation_id,out=decode('outbox',wire({draft_id:ref.draft_id,attempt_id,revision_id:bundle.envelope.header.context.revision_id,state:'QUEUED',bundle,attempt_digest:digest('bundle',wire(bundle)),receipt:null})),attempt={attempt_id,record_id:random(),draft_id:ref.draft_id,source_digest:ref.saved_digest,state:'QUEUED'};
   if(ref.import_id)Object.assign(attempt,{import_id:ref.import_id,source_revision_id:ref.source_revision_id,archive_sha256:ref.archive_sha256});
   this.#state.attempts.push(attempt);await this.#commit({records:[{id:ref.record_id,kind:'draft',data},{id:attempt.record_id,kind:'outbox',data:out}]});return {attempt_id,state:'QUEUED'};
  }
  if(op==='send'){
   ensure(args.length===1&&id(args[0]),'INVALID_REQUEST');const {ref,data}=await this.#attempt(args[0]);ensure(['QUEUED','SENT_UNKNOWN'].includes(data.state),'INVALID_OUTBOX_TRANSITION');const {ref:group,info}=await this.#info(data.bundle.envelope.header.context.group_id);this.#writable(group,info);const draftRef=this.#state.drafts.find(d=>d.draft_id===data.draft_id);if(draftRef?.copy_audience_digest)ensure(draftRef.copy_audience_digest===valueHash(info.members),'COPY_CONFIRMATION_REQUIRED');
   data.state=ref.state='SENT_UNKNOWN';await this.#commit({records:[{id:ref.record_id,kind:'outbox',data}]});return {attempt_id:ref.attempt_id,request:requestFor(data.bundle),state:'SENT_UNKNOWN'};
  }
  if(op==='reject'){
   ensure(args.length===2&&id(args[0])&&['STALE_REVISION','REKEY_REQUIRED','HISTORY_CLOSURE_REQUIRED','POLICY_CHANGED','ROSTER_CHANGED','DEVICE_REVOKED','DEVICE_NOT_TRUSTED','ROLE_FORBIDDEN','NOT_FOUND','ACCESS_REVOKED'].includes(args[1]),'INVALID_REQUEST');const {ref,data}=await this.#attempt(args[0]);ensure(['QUEUED','SENT_UNKNOWN'].includes(data.state),'INVALID_OUTBOX_TRANSITION');
   data.state=ref.state=args[1]==='STALE_REVISION'?'CONFLICT':['REKEY_REQUIRED','HISTORY_CLOSURE_REQUIRED','POLICY_CHANGED','ROSTER_CHANGED'].includes(args[1])?'REKEY_REQUIRED':'ACCESS_LOST';await this.#commit({records:[{id:ref.record_id,kind:'outbox',data}]});return {state:data.state,draft_id:data.draft_id};
  }
  if(op==='ack'){
   ensure(args.length===2&&id(args[0]),'INVALID_REQUEST');const result=noteValue('receipt-result',args[1]),{ref,data}=await this.#attempt(args[0]);ensure(['SENT_UNKNOWN','COMMITTED'].includes(data.state),'INVALID_OUTBOX_TRANSITION');
   const previouslyCommitted=data.state==='COMMITTED';if(previouslyCommitted)ensure(same(data.receipt,result.receipt),'IDEMPOTENCY_MISMATCH');
   const c=data.bundle.envelope.header.context,ed=digest('envelope',wire(data.bundle.envelope));ensure(result.receipt.operation_id===c.operation_id&&result.receipt.revision_id===c.revision_id&&result.receipt.envelope_digest===ed&&same(result.heads,[{revision_id:c.revision_id,envelope_digest:ed}]),'RECEIPT_CONTEXT_MISMATCH');
   data.state=ref.state='COMMITTED';data.receipt=result.receipt;decode('outbox',wire(data));const cached=this.#cache(data.bundle);
   const records=[{id:ref.record_id,kind:'outbox',data},cached],draftRef=this.#state.drafts.find(d=>d.draft_id===data.draft_id),local=draftRef?await this.#draft(data.draft_id):null;ensure(local||previouslyCommitted,'INTEGRITY_FAILURE');let retired=!local;const retireDrafts=[];
   if(local&&local.ref.saved_digest===ref.source_digest){this.#state.drafts=this.#state.drafts.filter(d=>d.draft_id!==data.draft_id);retireDrafts.push(local.ref.record_id);retired=true;}

   if(local&&!retired&&local.ref.saved_digest!==ref.source_digest&&['create','update'].includes(c.action)&&local.data.context.action===c.action&&same(local.data.context.parents,c.parents)){
    local.data.context.action='update';local.data.context.parents=structuredClone(result.heads);local.data.context.operation_id=random();local.data.context.revision_id=random();local.data.payload.context=structuredClone(local.data.context);decode('draft',wire(local.data));local.ref.saved_digest=valueHash(local.data);records.push({id:local.ref.record_id,kind:'draft',data:local.data});
   }
   await this.#commit({records,retireDrafts});if(c.attachments.length){await this.command('files',['list',{}]);await this.#files.markReferences(c.group_id,c.attachments);}return {state:'COMMITTED',draft_id:data.draft_id,revision_id:c.revision_id,draft_retired:retired};
  }
  if(op==='open'){
   ensure(args.length===1,'INVALID_REQUEST');const x=noteValue('open-request',args[0]),b=decode('bundle',wire(x.bundle)),c=b.envelope.header.context,{info}=await this.#info(x.group_id);
   if(info.policy){const shared=await this.#info(x.group_id);ensure(c.service_id===this.scope.service_id&&c.group_id===x.group_id&&c.object_id===x.object_id&&c.revision_id===x.revision_id&&c.object_kind===x.object_kind&&c.thread_id===x.thread_id,'CONTEXT_MISMATCH');let authority;try{authority=groupApi.checkHistoricalObjectForEvaluation(shared.verified.token,wire(b.envelope),groupApi.groupSenderForEvaluation(shared.verified.token,this.scope.account_id,this.scope.device_id,'receive-group-key'));}catch(e){if(e.message!=='UNANCHORED_HISTORY'||!same(c.policy,info.policy))throw e;authority=groupApi.checkCurrentObjectForEvaluation(shared.verified.token,wire(b.envelope));groupApi.observeAcceptedObjectForEvaluation(shared.verified.token,wire(b.envelope));}const key=await this.#key(x.group_id,info,c.policy.key_epoch);let payload;try{payload=openObject(wire(b),key,un64(certificateDetails(authority.certificate).body.device_signing_key),wire(c));}finally{wipe(key);}ensure(payload.metadata_kind!=='account-preferences','PRIVATE_NAMESPACE_REQUIRED');const cached=this.#cache(b);await this.#commit({records:[cached]});return {payload,envelope_digest:digest('envelope',wire(b.envelope)),state:'verified'};}
   ensure(c.service_id===this.scope.service_id&&c.group_id===x.group_id&&c.object_id===x.object_id&&c.revision_id===x.revision_id&&c.object_kind===x.object_kind&&c.thread_id===x.thread_id&&c.author.account_id===this.scope.account_id&&c.author.root_fingerprint===this.pins.root_fingerprint&&same(c.policy,this.#policy(info)),'CONTEXT_MISMATCH');
   const historical=historicalSnapshot(this.#snapshot,this.pins,c.author.roster),cert=activeCertificateForEvaluation(historical.roster,c.author.device_id,'sign-content'),author=certificateDetails(cert).body;ensure(author.recovery_generation===c.author.recovery_generation,'CONTEXT_MISMATCH');
   const ed=digest('envelope',wire(b.envelope)),current=this.#proof.details.devices.some(d=>d.device_id===c.author.device_id&&d.status==='ACTIVE'&&d.generation===c.author.recovery_generation),known=this.#state.witnesses.some(w=>w.group_id===x.group_id&&w.object_id===x.object_id&&w.revision_id===x.revision_id&&w.envelope_digest===ed);
   ensure(current||known,'UNANCHORED_HISTORY');const key=await this.#key(x.group_id,info);let payload;try{payload=openObject(wire(b),key,un64(author.device_signing_key),wire(c));}finally{wipe(key);}
   const cached=this.#cache(b);await this.#commit({records:[cached]});return {payload,envelope_digest:ed};
  }
  if(op==='cached'){
   ensure(args.length===1&&id(args[0]),'INVALID_REQUEST');const w=this.#state.witnesses.find(w=>w.revision_id===args[0]);ensure(w,'RECORD_NOT_FOUND');const data=await this.read(w.cache_id,'cache');ensure(data.purpose!=='p11-header-evidence','PAYLOAD_UNAVAILABLE');const cache=decode('cache',wire(data)),b=decode('bundle',un64(cache.record_bytes));ensure(digest('envelope',wire(b.envelope))===w.envelope_digest,'INTEGRITY_FAILURE');return this.command('open',[{group_id:w.group_id,object_id:w.object_id,revision_id:w.revision_id,object_kind:b.envelope.header.context.object_kind,thread_id:b.envelope.header.context.thread_id,bundle:b}]);
  }
  ensure(false,'INVALID_NOTE_COMMAND');
 }
 async #exportHeader(item,envelope){
  const c=envelope.header.context,file=item.object_kind==='file-manifest';
  ensure(c.service_id===this.scope.service_id&&c.group_id===item.group_id&&(file?c.file_id:c.object_id)===item.object_id&&(file?c.file_version_id:c.revision_id)===item.revision_id&&(file?fileSigningDigest(wire(envelope)):digest('envelope',wire(envelope)))===item.envelope_digest,'CONTEXT_MISMATCH');
  const info=await this.#info(c.group_id);let certificate;
  if(info.verified){const reader=groupApi.groupSenderForEvaluation(info.verified.token,this.scope.account_id,this.scope.device_id,'receive-group-key');let authority;
   try{authority=file?groupApi.checkHistoricalFileForEvaluation(info.verified.token,wire(envelope),reader):groupApi.checkHistoricalObjectForEvaluation(info.verified.token,wire(envelope),reader);}
   catch(e){if(e.message!=='UNANCHORED_HISTORY'||!same(c.policy,info.info.policy))throw e;authority=file?groupApi.checkCurrentFileForEvaluation(info.verified.token,wire(envelope)):groupApi.checkCurrentObjectForEvaluation(info.verified.token,wire(envelope));}
   certificate=authority.certificate;
  }else{ensure(c.author.account_id===this.scope.account_id&&c.author.root_fingerprint===this.pins.root_fingerprint&&same(c.policy,this.#policy(info.info)),'CONTEXT_MISMATCH');const past=historicalSnapshot(this.#snapshot,this.pins,c.author.roster);certificate=activeCertificateForEvaluation(past.roster,c.author.device_id,'sign-content');ensure(certificateDetails(certificate).body.recovery_generation===c.author.recovery_generation,'CONTEXT_MISMATCH');const known=file?(await this.files?.readControl())?.witnesses?.some(w=>w.file_version_id===c.file_version_id&&w.envelope_digest===item.envelope_digest):this.#state.witnesses.some(w=>w.revision_id===c.revision_id&&w.envelope_digest===item.envelope_digest);ensure(this.#proof.details.devices.some(d=>d.device_id===c.author.device_id&&d.status==='ACTIVE'&&d.generation===c.author.recovery_generation)||known,'UNANCHORED_HISTORY');}
  const publicKey=un64(certificateDetails(certificate).body.device_signing_key);ensure(sodium.crypto_sign_verify_detached(un64(envelope.signature),file?fileSigningInput('header',wire(envelope.header)):signingInput('header',wire(envelope.header)),publicKey),'INVALID_SIGNATURE');return {info,publicKey};
 }
 async #exportKey(item,record){
  const c=record.envelope.header.context,file=item.object_kind==='file-manifest',verified=await this.#exportHeader(item,record.envelope),group=await this.#key(c.group_id,verified.info.info,c.policy.key_epoch);let dek,plain;
  try{
   if(file){const reader=new FileReader(wire(record),group,verified.publicKey,wire(c));if(record.envelope.header.framing.chunk_count==='0')reader.finish();else reader.close();dek=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,un64(record.wrap.ciphertext),fileAad(wire(record.envelope.header),'wrap-aad'),un64(record.wrap.nonce),group);plain=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,un64(record.manifest_ciphertext),fileAad(wire(record.envelope.header),'manifest-aad'),un64(record.envelope.header.manifest_nonce),dek);const manifest=portableFileDecode('manifest',plain);return {...common('export-selected-key'),service_id:c.service_id,group_id:c.group_id,object_id:c.file_id,revision_id:c.file_version_id,key_kind:'manifest-and-file-deks',object_dek:b64(dek),file_data_dek:manifest.file_data_key};}
   const payload=openObject(wire(record),group,verified.publicKey,wire(c));wipe(payload);dek=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,un64(record.wrap.ciphertext),aad('object-key-wrap',{context:c}),un64(record.wrap.nonce),group);return {...common('export-selected-key'),service_id:c.service_id,group_id:c.group_id,object_id:c.object_id,revision_id:c.revision_id,key_kind:'object-dek',object_dek:b64(dek),file_data_dek:null};
  }finally{wipe(group);wipe(dek);wipe(plain);}
 }
 async #exportProofs(groups,headers){
  const proofs=new Map(),accounts=new Map([[this.pins.account_id,{pins:structuredClone(this.pins),snapshot:structuredClone(this.#snapshot)}]]),privateTokens=new Map();
  for(const status of groups){const local=await this.#info(status.group_id);ensure(same(status.membership,local.info.membership)&&status.key_epoch===(local.info.policy?.key_epoch??'0')&&status.epoch_digest===local.info.epoch_digest,'POLICY_CHANGED');
   let proof;if(local.verified){proof=structuredClone(local.data.proof);const own=proof.accounts.find(a=>a.pins.account_id===this.scope.account_id);own.snapshot=structuredClone(this.#snapshot);}
   else{proof={pin:genesisPin(local.evidence),journal:{version:1,group_id:status.group_id,genesis:local.evidence,events:[],pending:null},accounts:[{pins:structuredClone(this.pins),snapshot:structuredClone(this.#snapshot)}]};const token=replayGroup(proof,{ownPins:this.pins,localGenesis:true}).token;groupApi.custodyWitnesses(token,await this.#historyRecords(status.group_id));privateTokens.set(status.group_id,token);}
   proof.journal.pending=null;proofs.set(status.group_id,proof);for(const a of proof.accounts){const old=accounts.get(a.pins.account_id);if(old)ensure(same(old.pins,a.pins),'ROOT_PIN_MISMATCH');accounts.set(a.pins.account_id,structuredClone(a));}
  }
  for(const row of headers)await this.#exportHeader(row.item,row.envelope);
  const pending=headers.filter(row=>privateTokens.has(row.item.group_id)),knownByGroup=new Map([...privateTokens].map(([id,token])=>[id,new Map(groupApi.observedHistoryRecordsForEvaluation(token).map(r=>[r.revision_id,r]))])),waiting=new Map(),counts=new Map(),ready=[];
  for(const row of pending){const c=row.envelope.header.context,known=knownByGroup.get(row.item.group_id);let missing=0;for(const p of c.parents)if(known.get(p.revision_id)?.envelope_digest!==p.envelope_digest){missing++;const key=row.item.group_id+'/'+p.revision_id;const children=waiting.get(key)??[];children.push(row);waiting.set(key,children);}counts.set(row,missing);if(!missing)ready.push(row);}
  let accepted=0;while(ready.length){const row=ready.pop(),token=privateTokens.get(row.item.group_id),c=row.envelope.header.context,known=knownByGroup.get(row.item.group_id);ensure(c.parents.every(p=>known.get(p.revision_id)?.envelope_digest===p.envelope_digest),'MISSING_SOURCE_ANCESTRY');if(row.item.object_kind==='file-manifest')groupApi.observeAcceptedFileForEvaluation(token,wire(row.envelope));else groupApi.observeAcceptedObjectForEvaluation(token,wire(row.envelope));known.set(row.item.revision_id,{envelope_digest:row.item.envelope_digest});accepted++;for(const child of waiting.get(row.item.group_id+'/'+row.item.revision_id)??[]){counts.set(child,counts.get(child)-1);if(counts.get(child)===0)ready.push(child);}}
  ensure(accepted===pending.length,'MISSING_SOURCE_ANCESTRY');
  const pins=[];
  for(const [group_id,proof]of proofs){let verified;
   const token=privateTokens.get(group_id);if(token){const records=groupApi.observedHistoryRecordsForEvaluation(token),pages=[];let batch=[];const page=items=>({purpose:'history-inventory-page',contract:'p02-file-c1',version:1,service_id:this.scope.service_id,group_id,page_index:String(pages.length),records:items});for(const record of records){if(batch.length&&(batch.length===500||wire(page([...batch,record])).length>1048576)){pages.push(page(batch));batch=[];}batch.push(record);}if(batch.length)pages.push(page(batch));
    const history=JSON.parse(new TextDecoder().decode(groupBuilders.historyForEvaluation(token,groupApi.groupSenderForEvaluation(token,this.scope.account_id,this.scope.device_id),this.#keys.signing.privateKey,pages.map(wire))));groupApi.endorseGroupHistoryForEvaluation(token,wire(history),pages.map(wire),groupApi.independentHistoryWitnessForEvaluation(token));const head={version:history.body.sequence,digest:groupCodec.groupDigest('history',wire(history))};proof.pin.history=head;proof.journal.events.push({kind:'history',history,pages});verified=groupApi.groupDetails(token);
   }else{verified=replayGroup(proof,{ownPins:this.pins,known:proof}).details;proof.pin.history=structuredClone(verified.history);}
   pins.push({group_id,genesis_digest:proof.pin.genesis_digest,policy:verified.policy,epoch:verified.epoch,history:verified.history});sharedValue('adopt-request',proof);
  }
  const document=contentValue('portable-evidence',{profile:'p13-public-proof-v1',version:1,accounts:[...accounts.values()],groups:[...proofs.values()]});ensure(wire(document).length<=16777216,'RESOURCE_LIMIT');return {document,pins};
 }
 async #portableCommand(op,x){
  if(op==='cancel'){this.#portable?.close();this.#portable=undefined;this.#portableFile?.close();this.#portableFile=undefined;return {cancelled:true};}
  if(op==='begin'){
   ensure(x.confirm===true&&!this.#portable,'CONFIRMATION_REQUIRED');this.#own();const signer=this.#author();
   this.#portable=new ProtectedExport({transport:this.portableTransport(),scope:this.scope,pins:this.pins,signer,sign:bytes=>sodium.crypto_sign_detached(bytes,this.#keys.signing.privateKey),authorize:async()=>{await this.#ready();this.#own();},proofs:(groups,headers)=>this.#exportProofs(groups,headers),selected:(item,record)=>this.#exportKey(item,record),verifyChunk:async(item,record,index,cipher)=>{
    if(index===0){this.#portableFile?.close();const a=await this.#fileAuthority(item.group_id,false,record.envelope);try{this.#portableFile=new FileReader(wire(record),a.key,a.publicKey,wire(record.envelope.header.context));}finally{wipe(a.key);}}
    ensure(this.#portableFile,'INCOMPLETE_FILE');const bytes=this.#portableFile.decryptNext(cipher);wipe(bytes);if(index===Number(record.envelope.header.framing.chunk_count)-1){this.#portableFile.finish();this.#portableFile=undefined;}
   }});
   try{return await this.#portable.begin(x.result);}catch(e){this.#portable.close();this.#portable=undefined;throw e;}
  }
  ensure(op==='next'&&Object.keys(x).length===0&&this.#portable,'INVALID_CONTENT_COMMAND');try{const result=await this.#portable.next();if(result.done)this.#portable=undefined;return result;}catch(e){this.#portable.close();this.#portable=undefined;this.#portableFile?.close();this.#portableFile=undefined;throw e;}
 }
 async #importDestination(group_id){if(!group_id){this.#own();return {mode:'new-private',group_id:null,members:[{account_id:this.scope.account_id,root_fingerprint:this.pins.root_fingerprint,role:'owner'}]};}const {ref,info}=await this.#info(group_id);this.#writable(ref,info);return {group_id,policy:structuredClone(this.#policy(info)),members:structuredClone(info.members??[{account_id:this.scope.account_id,root_fingerprint:this.pins.root_fingerprint,role:'owner'}])};}
 async #importPublish(state,alias,edit){
  const tag={import_id:state.import_id,source_revision_id:alias.source_revision_id,archive_sha256:state.archive_sha256};
  const existing=this.#state.attempts.find(a=>a.import_id===tag.import_id&&a.source_revision_id===tag.source_revision_id&&a.archive_sha256===tag.archive_sha256);
  if(existing){const {data}=await this.#attempt(existing.attempt_id);alias.object_id=data.bundle.envelope.header.context.object_id;alias.attempt_id=existing.attempt_id;
   if(existing.state==='COMMITTED'){alias.committed=true;alias.receipt=data.receipt;return null;}
   ensure(['QUEUED','SENT_UNKNOWN'].includes(existing.state),'RECONCILIATION_REQUIRED');const sent=await this.command('send',[existing.attempt_id]);return {kind:'note-publish',source_revision_id:tag.source_revision_id,attempt_id:existing.attempt_id,request:{kind:'note',method:'POST',path:this.#publicationPath(sent.request),body:sent.request}};
  }
  let draft=this.#state.drafts.find(d=>d.import_id===tag.import_id&&d.source_revision_id===tag.source_revision_id&&d.archive_sha256===tag.archive_sha256);
  if(!draft){this.#importTag=tag;try{const saved=await this.command('save',[edit]);draft=this.#state.drafts.find(d=>d.draft_id===saved.draft_id);}finally{this.#importTag=undefined;}}
  ensure(draft,'INTEGRITY_FAILURE');alias.draft_id=draft.draft_id;alias.object_id=draft.object_id;
  const queued=await this.command('queue',[draft.draft_id]);alias.attempt_id=queued.attempt_id;const sent=await this.command('send',[queued.attempt_id]);return {kind:'note-publish',source_revision_id:tag.source_revision_id,attempt_id:queued.attempt_id,request:{kind:'note',method:'POST',path:this.#publicationPath(sent.request),body:sent.request}};
 }
 #publicationPath(request){const c=request.bundle.envelope.header.context;return c.action==='create'&&c.object_kind==='thread'?'/groups/'+c.group_id+'/threads':c.action==='create'&&c.object_kind==='entry'?'/threads/'+c.thread_id+'/entries':'/objects/'+c.object_id+'/revisions';}
 async #importApply(op,{state,event,reader,pending,response}){
  this.#files??=new FileWorkflow({scope:this.scope,...this.files,authority:(g,w,e)=>this.#fileAuthority(g,w,e)});
  if(op==='destination'){
   let made=state.new_group;const known=this.#state.groups.find(g=>g.import_id===state.import_id&&g.archive_sha256===state.archive_sha256);
   if(!made&&known){const retried=await this.command('retryGroup',[known.group_id]);made={group_id:known.group_id,request:retried.request};}
   if(!made){this.#importGroupTag={import_id:state.import_id,archive_sha256:state.archive_sha256};try{made=await this.command('prepareGroup',[]);}finally{this.#importGroupTag=undefined;}}
   state.new_group=made;return {kind:'group-create',request:{kind:'group',method:'POST',path:'/groups',body:made.request}};
  }
  if(op==='response'){
   if(pending.kind==='group-create'){noteValue('group-status',response);ensure(response.group_id===state.new_group.group_id&&response.kind==='private'&&response.owner_account_id===this.scope.account_id,'CONTEXT_MISMATCH');await this.command('group',[response]);const resolved=await this.#importDestination(response.group_id);ensure(resolved.members.length===1&&resolved.members[0].account_id===this.scope.account_id,'COPY_CONFIRMATION_REQUIRED');state.destination=resolved;state.pending=null;return;}
   if(pending.kind==='note-publish'){noteValue('receipt-result',response);await this.command('ack',[pending.attempt_id,response]);const alias=[...state.notes,...state.threads].find(n=>n.source_revision_id===pending.source_revision_id);ensure(alias,'INTEGRITY_FAILURE');if(!alias.committed)state.published++;alias.committed=true;alias.receipt=response.receipt;state.pending=null;return;}
   const file=state.files.find(f=>f.source_revision_id===pending.source_revision_id);ensure(file,'INTEGRITY_FAILURE');
   if(pending.kind==='file-reserve'){fileValue('upload-status',response);ensure(response.upload_id===file.request.upload_id&&['RESERVED','RECEIVING','READY','COMMITTED'].includes(response.state),'INVALID_TRANSFER_STATE');if(response.state==='COMMITTED'){const result=await this.#files.command('committed',{draft_id:file.draft_id,receipt:response.receipt});file.attachment=result.attachment;}file.ready_to_commit=response.state==='READY'||response.state==='COMMITTED';file.reserved=true;}
   else if(pending.kind==='file-part'){ensure(same(response,pending.part),'CIPHERTEXT_MISMATCH');await this.#files.command('ackPart',{draft_id:file.draft_id,part:response});}
   else if(pending.kind==='file-commit'){fileValue('receipt',response);const result=await this.#files.command('committed',{draft_id:file.draft_id,receipt:response});file.attachment=result.attachment;file.receipt=response;}
   else throw Error('INVALID_CONTENT_COMMAND');state.pending=null;return;
  }
  if(op==='finish'){
   if(!state.files.length)return;ensure(state.files.every(f=>f.attachment),'FILE_NOT_COMMITTED');
   const key=(kind,index)=>b64(un64(hash(canonicalBytes(wire({purpose:'AnyNote/P13/import-container',import_id:state.import_id,kind,index})))).subarray(0,16));
   let thread=state.threads.find(t=>t.source_revision_id===key('thread',0));if(!thread){thread={source_revision_id:key('thread',0),source_thread:key('thread',0),source_group:state.destination.group_id};state.threads.push(thread);}
   const fields=(title,markdown)=>({title,markdown,metadata_kind:'content',tags:[],checklist:[],summary_entry_id:null,preferences:[]});
   if(!thread.committed){const result=await this.#importPublish(state,thread,{draft_id:null,group_id:state.destination.group_id,object_id:null,object_kind:'thread',thread_id:null,action:'create',parents:[],archived:false,content:fields('Recovered files','')});if(result)return result;}
   for(let n=0;n<state.files.length;n+=32){const source_revision_id=key('files',n);let alias=state.notes.find(a=>a.source_revision_id===source_revision_id);if(!alias){alias={source_revision_id,source_kind:'file-container'};state.notes.push(alias);}if(alias.committed)continue;const attachments=state.files.slice(n,n+32).map(f=>f.attachment).sort((a,b)=>a.file_id+'/'+a.file_version_id<b.file_id+'/'+b.file_version_id?-1:1);const result=await this.#importPublish(state,alias,{draft_id:null,group_id:state.destination.group_id,object_id:null,object_kind:'entry',thread_id:thread.object_id,action:'create',parents:[],archived:false,content:fields('Recovered files '+(n/32+1),'Files recovered from encrypted export '+state.export_id+'. Original signed provenance remains in the source archive.'),attachments});if(result)return result;}
   return;
  }
  if(event.kind==='file-start'){
   let file=state.files.find(f=>f.source_revision_id===event.revision);if(file?.attachment)return;
   const made=await this.#files.recoveredPrepare({group_id:state.destination.group_id,identityProof:reader.fileSource(event.revision),import_id:state.import_id,source_revision_id:event.revision,archive_sha256:state.archive_sha256,name:event.metadata.name,audience_digest:hash(canonicalBytes(wire({policy:state.destination.policy,members:state.destination.members})))});
   if(!file){file={source_revision_id:event.revision,source_file_id:event.context.file_id,draft_id:made.draft_id,request:made.request};state.files.push(file);}ensure(file.draft_id===made.draft_id,'IDEMPOTENCY_MISMATCH');
   return {kind:'file-reserve',source_revision_id:event.revision,request:{kind:'reserve-file',method:'POST',path:'/groups/'+state.destination.group_id+'/uploads',body:made.request}};
  }
  if(event.kind==='file-part'){
   const file=state.files.find(f=>f.source_revision_id===event.revision);ensure(file,'INTEGRITY_FAILURE');if(file.attachment||file.ready_to_commit)return;
   const part=await this.#files.recoveredPart(file.draft_id,event.index,event.bytes);return {kind:'file-part',source_revision_id:event.revision,upload_id:part.upload_id,index:part.index,part:{index:part.index,ciphertext_bytes:String(part.ciphertext.length),ciphertext_digest:hash(part.ciphertext)},request:{kind:'file-part',method:'PUT',path:'/uploads/'+part.upload_id+'/parts/'+part.index,ciphertext:part.ciphertext}};
  }
  if(event.kind==='file-finish'){
   const file=state.files.find(f=>f.source_revision_id===event.revision);ensure(file,'INTEGRITY_FAILURE');if(file.attachment)return;
   const completed=await this.#files.command('finish',{draft_id:file.draft_id});return {kind:'file-commit',source_revision_id:event.revision,request:{kind:'commit-file',method:'POST',path:'/uploads/'+completed.upload_id+'/commit',body:completed.request}};
  }
  ensure(event.kind==='note','INVALID_CONTENT_COMMAND');const p=event.payload,c=p.context;
  if(p.metadata_kind==='account-preferences'){state.skipped_preferences=(state.skipped_preferences??0)+1;return;}
  let alias=state.notes.find(n=>n.source_revision_id===event.revision);if(!alias){alias={source_revision_id:event.revision,source_object_id:c.object_id,source_kind:c.object_kind};state.notes.push(alias);}if(alias.committed)return;
  let thread=state.threads.find(t=>t.source_group===c.group_id&&t.source_thread===(c.thread_id??c.object_id));
  if(!thread){thread={source_group:c.group_id,source_thread:c.thread_id??c.object_id,source_revision_id:b64(un64(hash(canonicalBytes(wire({purpose:'AnyNote/P13/import-thread',import_id:state.import_id,source_group:c.group_id,source_thread:c.thread_id??c.object_id})))).subarray(0,16))};state.threads.push(thread);}
  if(!thread.committed){const result=await this.#importPublish(state,thread,{draft_id:null,group_id:state.destination.group_id,object_id:null,object_kind:'thread',thread_id:null,action:'create',parents:[],archived:false,content:{title:'Recovered '+thread.source_thread.slice(-8),markdown:'',metadata_kind:'content',tags:[],checklist:[],summary_entry_id:null,preferences:[]}});if(result)return {...result,repeat:true};}
  const attachments=c.attachments.map(a=>{const file=state.files.find(f=>f.source_revision_id===a.file_version_id);ensure(file?.attachment,'FILE_NOT_COMMITTED');return file.attachment;}).sort((a,b)=>a.file_id+'/'+a.file_version_id<b.file_id+'/'+b.file_version_id?-1:1);
  const provenance='\n\nRecovered copy from export '+state.export_id+'; source revision '+event.revision+'. Original signed history remains in the encrypted source archive.';
  const content={title:p.title,markdown:p.markdown+provenance,metadata_kind:'content',tags:structuredClone(p.tags),checklist:structuredClone(p.checklist),summary_entry_id:null,preferences:[]};
  return this.#importPublish(state,alias,{draft_id:null,group_id:state.destination.group_id,object_id:null,object_kind:'entry',thread_id:thread.object_id,action:'create',parents:[],archived:false,content,attachments});
 }
 async #importCommand(op,x){
  if(op==='begin'){ensure(!this.#import&&(x.destination_group===undefined||id(x.destination_group)),'INVALID_CONTENT_COMMAND');this.#import=new ProtectedImport({scope:this.scope,jobs:this.#contentWorkflow(),destination:id=>this.#importDestination(id===undefined?x.destination_group:id),apply:(op,value)=>this.#importApply(op,value)});try{return await this.#import.begin(x);}catch(e){this.#import.close();this.#import=undefined;throw e;}}
  ensure(this.#import,'IMPORT_NOT_STARTED');if(op==='confirm')return this.#import.confirm(x.audience_digest);if(op==='cancel'){const report=await this.#import.cancel();this.#import=undefined;return report;}ensure(op==='next','INVALID_CONTENT_COMMAND');const result=await this.#import.next(x.response);if(result.state==='COMPLETE'){this.#import.close();this.#import=undefined;}return result;
 }
 async #thumbnailCommand(op,x){
  this.#files??=new FileWorkflow({scope:this.scope,...this.files,authority:(g,w,e)=>this.#fileAuthority(g,w,e)});
  if(op==='prepare'){
   ensure(x.bytes instanceof Uint8Array&&x.bytes.length<=262144&&id(x.source_version_id),'PREVIEW_RESOURCE_LIMIT');const dimensions=imageBounds(x.bytes);ensure(dimensions.mime==='image/png'&&dimensions.width<=256&&dimensions.height<=256,'PREVIEW_RESOURCE_LIMIT');
   const source=x.source_record,c=source.envelope.header.context;ensure(c.file_version_id===x.source_version_id&&c.group_id===x.group_id,'CONTEXT_MISMATCH');await this.#files.command('observe',{group_id:x.group_id,file_version_id:x.source_version_id,record:source});const writer=await this.#fileAuthority(x.group_id,true);wipe(writer);
   const job_id=random(),job={purpose:'p13-thumbnail-intent',version:1,job_id,source_version_id:x.source_version_id,source_envelope_digest:fileSigningDigest(wire(source.envelope)),group_id:x.group_id,source_record:structuredClone(source),width:dimensions.width,height:dimensions.height};await this.#contentWorkflow().saveJob(job_id,'preview-state',job);
   const made=await this.#files.command('prepare',{group_id:x.group_id,source:new Blob([x.bytes]),name:'thumbnail.png',media:'image/png'});job.draft_id=made.draft_id;job.derived_version_id=made.request.context.file_version_id;await this.#contentWorkflow().saveJob(job_id,'preview-state',job);return {job_id,draft_id:made.draft_id,request:made.request};
  }
  if(op==='ack'){contentValue('thumbnail-result',x.result);const job=await this.#contentWorkflow().job(x.job_id,'preview-state'),b=job.link?.body;ensure(b&&x.result.group_id===b.group_id&&x.result.source_version_id===b.source_version_id&&x.result.derived_version_id===b.derived_version_id&&x.result.operation_id===b.operation_id&&x.result.digest===hash(new Uint8Array([...new TextEncoder().encode('AnyNote/P13/thumbnail-link\0'),...canonicalBytes(wire(job.link))])),'CONTEXT_MISMATCH');job.state='LINKED';await this.#contentWorkflow().saveJob(x.job_id,'preview-state',job);return {state:'LINKED'};}
  ensure(op==='link'&&id(x.job_id),'INVALID_CONTENT_COMMAND');const job=await this.#contentWorkflow().job(x.job_id,'preview-state');ensure(job.purpose==='p13-thumbnail-intent'&&job.version===1,'INTEGRITY_FAILURE');
  const derived=x.derived_record,c=derived.envelope.header.context;ensure(c.group_id===job.group_id&&c.file_version_id===job.derived_version_id&&Number(derived.envelope.header.framing.plaintext_bytes)<=262144,'CONTEXT_MISMATCH');await this.#files.command('observe',{group_id:job.group_id,file_version_id:c.file_version_id,record:derived});const auth=await this.#fileAuthority(job.group_id,true);
  try{ensure(same(c.policy,auth.policy)&&same(c.author,auth.author),'POLICY_CHANGED');const body=contentValue('thumbnail-body',{purpose:'derived-thumbnail-link',version:1,service_id:this.scope.service_id,group_id:job.group_id,operation_id:job.operation_id??random(),author:auth.author,policy:auth.policy,source_version_id:job.source_version_id,source_envelope_digest:job.source_envelope_digest,derived_version_id:c.file_version_id,derived_envelope_digest:fileSigningDigest(wire(derived.envelope)),kind:'png-256'});
   job.operation_id=body.operation_id;job.link=contentValue('thumbnail-link',{body,signature:b64(sodium.crypto_sign_detached(new Uint8Array([...new TextEncoder().encode('AnyNote/p13-content/sign/derived-thumbnail-link\0'),...canonicalBytes(wire(body))]),auth.signing))});await this.#contentWorkflow().saveJob(x.job_id,'preview-state',job);return {request:structuredClone(job.link)};
  }finally{wipe(auth);}
 }
 async #contentAccessible(){this.#own();const result=new Set();for(const group of this.#state.groups){const {info}=await this.#info(group.group_id);if(!info.policy||info.members.some(m=>m.account_id===this.scope.account_id&&m.status!=='removed'))result.add(group.group_id);}return result;}
 #contentWorkflow(){ensure(this.content,'INVALID_CONTENT_COMMAND');return this.#contents??=new ContentWorkflow({...this.content,accessible:()=>this.#contentAccessible(),catalog:()=>this.#contentCatalog(),open:revision=>this.#readVerifiedCached(revision)});}
 #fileCatalogIds=new Map();
 async #contentCatalog(){
  const heads=new Map((this.#state.sync?.projection??[]).map(p=>[p.reference.object_id,new Set(p.reference.heads.map(h=>h.revision_id))]));
  const result=this.#state.witnesses.map(w=>({...w,payload_status:'retained',current:heads.has(w.object_id)?heads.get(w.object_id).has(w.revision_id):null}));
  const files=await this.files?.readControl(),known=new Map((this.#contents?.fileReferences()??[]).map(f=>[f.file_version_id,f]));
  for(const w of files?.witnesses??[]){let ref=known.get(w.file_version_id)??this.#fileCatalogIds.get(w.file_version_id);
   if(!ref||ref.envelope_digest!==w.envelope_digest){const evidence=await this.files.readRecord(w.record_id,'file-evidence'),c=evidence.envelope.header.context;ensure(fileSigningDigest(wire(evidence.envelope))===w.envelope_digest&&c.group_id===w.group_id&&c.file_version_id===w.file_version_id,'INTEGRITY_FAILURE');ref={file_id:c.file_id,envelope_digest:w.envelope_digest};this.#fileCatalogIds.set(w.file_version_id,ref);}
   result.push({...w,object_id:ref.file_id,revision_id:w.file_version_id,object_kind:'file-manifest',thread_id:null,payload_status:'retained',current:null});
  }return result;
 }
 async #readVerifiedCached(selector){
  ensure(!this.#defer,'PUBLICATION_PENDING');const revision=typeof selector==='string'?selector:selector.revision_id;
  if(selector.object_kind==='file-manifest'){
   const record=await this.#contentWorkflow().fileRecord(revision),context=record.envelope.header.context;
   ensure(context.group_id===selector.group_id&&context.file_id===selector.object_id&&context.file_version_id===revision,'CONTEXT_MISMATCH');
   this.#files??=new FileWorkflow({scope:this.scope,...this.files,authority:(g,w,e)=>this.#fileAuthority(g,w,e)});
   const metadata=await this.#files.command('observe',{group_id:context.group_id,file_version_id:revision,record});
   return {state:'verified',envelope_digest:metadata.envelope_digest,payload:{context:{group_id:context.group_id,object_id:context.file_id,revision_id:revision,object_kind:'file-manifest',thread_id:null,action:'create'},title:metadata.name,markdown:'',tags:[],checklist:[]}};
  }
  const original=this.#state;this.#state=structuredClone(original);this.#defer=[];try{const opened=await this.command('cached',[revision]);return {...opened,state:'verified'};}finally{this.#state=original;this.#defer=undefined;}
 }
 async #historyRecords(group){const out=[];for(const w of this.#state.witnesses.filter(w=>w.group_id===group)){const data=await this.read(w.cache_id,'cache'),envelope=data.purpose==='p11-header-evidence'?syncValue('header-evidence',data).envelope:decode('bundle',un64(decode('cache',wire(data)).record_bytes)).envelope,b=envelope.header.context;ensure(digest('envelope',wire(envelope))===w.envelope_digest,'INTEGRITY_FAILURE');out.push({object_kind:b.object_kind,object_id:b.object_id,revision_id:b.revision_id,envelope_digest:w.envelope_digest,parents:b.parents,payload_status:'retained'});}if(this.files){const files=await this.files.readControl(),ids=(files?.witnesses??[]).filter(w=>w.group_id===group);for(const w of ids){const evidence=await this.files.readRecord(w.record_id,'file-evidence'),c=evidence.envelope.header.context;ensure(fileDecode('envelope',wire(evidence.envelope))&&w.envelope_digest===fileSigningDigest(wire(evidence.envelope)),'INTEGRITY_FAILURE');out.push({object_kind:'file-manifest',object_id:c.file_id,revision_id:c.file_version_id,envelope_digest:w.envelope_digest,parents:c.parents,payload_status:'retained'});}}return out.sort((a,b)=>a.revision_id<b.revision_id?-1:1);}
 async #syncVerify(item,bundle,reference,previous=[]){
  checkedBundle(item,bundle);noteValue('object-ref',reference);const c=bundle.envelope.header.context;
  ensure(reference.object_id===item.object_id&&reference.object_kind===item.object_kind&&reference.thread_id===c.thread_id,'CONTEXT_MISMATCH');
  const original=this.#state;this.#state=structuredClone(original);this.#defer=[];
  for(const x of previous)if(!this.#state.witnesses.some(w=>w.revision_id===x.witness.revision_id))this.#state.witnesses.push(structuredClone(x.witness));
  try{
   if(item.payload_status==='pruned'){
    const {info}=await this.#info(item.group_id);let cert;
    if(info.policy){const shared=await this.#info(item.group_id);cert=groupApi.checkHistoricalObjectForEvaluation(shared.verified.token,wire(bundle.envelope),groupApi.groupSenderForEvaluation(shared.verified.token,this.scope.account_id,this.scope.device_id,'receive-group-key')).certificate;}
    else{ensure(c.service_id===this.scope.service_id&&c.author.account_id===this.scope.account_id&&c.author.root_fingerprint===this.pins.root_fingerprint&&same(c.policy,this.#policy(info)),'CONTEXT_MISMATCH');const past=historicalSnapshot(this.#snapshot,this.pins,c.author.roster);cert=activeCertificateForEvaluation(past.roster,c.author.device_id,'sign-content');ensure(certificateDetails(cert).body.recovery_generation===c.author.recovery_generation,'CONTEXT_MISMATCH');ensure(this.#proof.details.devices.some(d=>d.device_id===c.author.device_id&&d.status==='ACTIVE'&&d.generation===c.author.recovery_generation)||this.#state.witnesses.some(w=>w.revision_id===item.revision_id&&w.envelope_digest===item.envelope_digest),'UNANCHORED_HISTORY');}
    ensure(sodium.crypto_sign_verify_detached(un64(bundle.envelope.signature),signingInput('header',wire(bundle.envelope.header)),un64(certificateDetails(cert).body.device_signing_key)),'INVALID_SIGNATURE');
    const old=this.#state.witnesses.find(w=>w.revision_id===item.revision_id);if(old)ensure(old.envelope_digest===item.envelope_digest&&old.group_id===item.group_id&&old.object_id===item.object_id,'ROLLBACK_QUARANTINE');
    const witness=old??{group_id:c.group_id,object_id:c.object_id,revision_id:c.revision_id,envelope_digest:item.envelope_digest,object_kind:c.object_kind,thread_id:c.thread_id,archived:c.archived,action:c.action,cache_id:random()};
    const record={id:witness.cache_id,kind:'cache',data:syncValue('header-evidence',{purpose:'p11-header-evidence',version:1,envelope:bundle.envelope})};return {value:{item:structuredClone(item),cache_id:witness.cache_id,witness:structuredClone(witness),reference:structuredClone(reference)},record};
   }
   const opened=await this.command('open',[{group_id:item.group_id,object_id:item.object_id,revision_id:item.revision_id,object_kind:item.object_kind,thread_id:c.thread_id,bundle}]);wipe(opened);
   const witness=structuredClone(this.#state.witnesses.find(w=>w.revision_id===item.revision_id)),record=this.#defer.flatMap(e=>e.records??[]).find(r=>r.id===witness.cache_id);
   ensure(record,'INTEGRITY_FAILURE');return {value:{item:structuredClone(item),cache_id:witness.cache_id,witness,reference:structuredClone(reference)},record};
  }finally{this.#state=original;this.#defer=undefined;}
 }
 async #syncCommand(args){
  ensure(args.length===2&&typeof args[0]==='string'&&args[1]&&typeof args[1]==='object','INVALID_REQUEST');const [op,x]=args;
  const scope={...this.pins,group_id:null};let s=this.#state.sync;
  if(!s){s={purpose:'p11-sync-control',version:1,scope,cursor:null,watermark:null,stage:null,groups:[],pending:null,retry:[],projection:[],state:'NEW',quarantine:null};this.#state.sync=s;}
  syncValue('sync-control',s);
  const output=()=>structuredClone({scope:s.scope,cursor:s.cursor,watermark:s.watermark,state:s.state,quarantine:s.quarantine,stage:s.stage?{result:s.stage.result,catalog_next:s.stage.catalog_next,pages:s.stage.pages.length,items:s.stage.items.length}:null,pending:s.pending?.page??null,projection:s.projection});
  if(op==='status')return output();
  ensure(s.state!=='RESTORE_QUARANTINE'||['offline','quarantine','snapshotCancel','deltaCancel','snapshotStart'].includes(op),'RESTORE_QUARANTINE');
  if(op==='offline'){ensure(Object.keys(x).length===0,'INVALID_REQUEST');if(!['QUARANTINED','RESTORE_QUARANTINE'].includes(s.state))s.state='OFFLINE';await this.#commit();return output();}
  if(op==='quarantine'){ensure(typeof x.digest==='string'&&['QUARANTINED','RESTORE_QUARANTINE'].includes(x.state),'INVALID_REQUEST');ensure(s.state!=='RESTORE_QUARANTINE'||x.state==='RESTORE_QUARANTINE','RESTORE_QUARANTINE');s.state=x.state;s.quarantine=x.digest;await this.#commit();return output();}
  if(op==='compact'){
   ensure(Object.keys(x).length===1&&Number.isSafeInteger(x.limit)&&x.limit>=1&&x.limit<=16,'INVALID_REQUEST');ensure(s.cursor&&!s.stage&&!s.pending,'SYNC_GAP');
   const keep=new Set(s.projection.flatMap(p=>p.reference.heads.map(h=>h.revision_id)));
   for(const d of this.#state.drafts){const data=(await this.#draft(d.draft_id)).data;for(const p of data.context.parents)keep.add(p.revision_id);}
   for(const a of this.#state.attempts){const data=(await this.#attempt(a.attempt_id)).data;if(data.state!=='COMMITTED')for(const p of data.bundle.envelope.header.context.parents)keep.add(p.revision_id);}
   const records=[];for(const w of this.#state.witnesses){if(s.scope.group_id!==null&&w.group_id!==s.scope.group_id)continue;if(keep.has(w.revision_id))continue;const data=await this.read(w.cache_id,'cache');if(data.purpose==='p11-header-evidence')continue;const b=decode('bundle',un64(decode('cache',wire(data)).record_bytes));ensure(digest('envelope',wire(b.envelope))===w.envelope_digest,'INTEGRITY_FAILURE');records.push({id:w.cache_id,kind:'cache',data:syncValue('header-evidence',{purpose:'p11-header-evidence',version:1,envelope:b.envelope})});if(records.length===x.limit)break;}
   if(records.length)await this.#commit({records});return {compacted:records.length,scope:'superseded-ciphertext-only',signed_headers_retained:true,drafts_retained:true};
  }
  if(op==='snapshotStart'){
   const r=checkedSnapshot(x,this.pins,this.scope.device_id,x.scope.group_id);ensure(!s.pending,'PUBLICATION_PENDING');
   ensure(!s.cursor||same(s.scope,r.scope),'LOCAL_CONTEXT_MISMATCH');
   if(s.cursor&&(s.cursor.generation!==r.descriptor.watermark.generation||BigInt(s.cursor.sequence)>BigInt(r.descriptor.watermark.sequence))){s.state='RESTORE_QUARANTINE';s.quarantine=syncHash(r);await this.#commit();return output();}
   ensure(s.state!=='RESTORE_QUARANTINE','RESTORE_QUARANTINE');s.scope=structuredClone(r.scope);s.stage={result:structuredClone(r),catalog:[],catalog_next:'0',pages:[],items:[],inventory:[],last:null,all_items:'0'};s.state='STAGING';await this.#commit();return output();
  }
  if(op==='snapshotCancel'){ensure(Object.keys(x).length===0,'INVALID_REQUEST');s.stage=null;if(s.state!=='RESTORE_QUARANTINE')s.state=s.cursor?'SYNCED':'NEW';await this.#commit();return output();}
  if(op==='catalog'){
   syncValue('catalog-page',x);const t=s.stage;ensure(t&&x.snapshot_id===t.result.descriptor.snapshot_id&&x.start===t.catalog_next,'SYNC_GAP');
   const count=t.catalog.length+x.groups.length;ensure(count<=Number(t.result.catalog_count)&&x.next===(count<Number(t.result.catalog_count)?String(count):null)&&(x.groups.length>0||count===Number(t.result.catalog_count)),'SYNC_GAP');
   for(const g of x.groups){ensure((s.scope.group_id===null||s.scope.group_id===g.group_id)&&(!t.catalog.length||t.catalog.at(-1).group_id<g.group_id),'CONTEXT_MISMATCH');await this.command('group',[g]);t.catalog.push(structuredClone(g));}
   t.catalog_next=String(count);if(x.next===null)ensure(catalogCommitment(t.catalog)===t.result.catalog_digest,'CIPHERTEXT_MISMATCH');await this.#commit();return output();
  }
  if(op==='snapshotPage'){
   syncValue('snapshot-page-result',x);checkedScope(x.scope,this.pins,s.scope.group_id);const t=s.stage,p=x.page;
   ensure(t&&t.catalog_next===t.result.catalog_count&&p.snapshot_id===t.result.descriptor.snapshot_id&&p.page_index===String(t.pages.length)&&t.pages.length<Number(t.result.descriptor.page_count)&&p.items.length>0,'SYNC_GAP');
   for(const item of p.items){const order=itemOrder(item);ensure((t.last===null||t.last<order)&&t.catalog.some(g=>g.group_id===item.group_id),'SYNC_GAP');t.last=order;t.inventory.push(structuredClone(item));}
   t.all_items=String(t.inventory.length);ensure(BigInt(t.all_items)<=BigInt(t.result.descriptor.item_count),'SYNC_GAP');t.pages.push(pageReceipt(p));await this.#commit();return output();
  }
  if(op==='snapshotItem'){
   syncValue('snapshot-bundle',x);const t=s.stage;ensure(t&&x.snapshot_id===t.result.descriptor.snapshot_id&&t.inventory.some(i=>same(i,x.item)),'CONTEXT_MISMATCH');
   const old=t.items.find(i=>i.item.revision_id===x.item.revision_id);if(old){ensure(same(old.item,x.item)&&same(old.reference,x.reference),'ROLLBACK_QUARANTINE');return output();}
   const verified=await this.#syncVerify(x.item,x.bundle,x.reference,t.items);t.items.push(verified.value);await this.#commit({records:[verified.record]});return output();
  }
  if(op==='snapshotFiles'){const t=s.stage;ensure(t&&t.result.files&&Array.isArray(x.inventory)&&String(x.inventory.length)===t.result.files.count,'SYNC_GAP');const files=await this.files.readControl();for(const item of x.inventory){const w=files?.witnesses?.find(w=>w.group_id===item.group_id&&w.file_version_id===item.file_version_id&&w.envelope_digest===item.envelope_digest);ensure(w,'UNANCHORED_HISTORY');const e=await this.files.readRecord(w.record_id,'file-evidence');ensure(e.envelope.header.context.file_id===item.file_id,'CONTEXT_MISMATCH');}const digest=hash(new Uint8Array([...new TextEncoder().encode('AnyNote/P12/snapshot-files\0'),...canonicalBytes(wire(x.inventory))]));ensure(digest===t.result.files.digest,'INTEGRITY_FAILURE');t.files_verified=true;await this.#commit();return output();}
  if(op==='snapshotFinish'){
   ensure(Object.keys(x).length===0,'INVALID_REQUEST');const t=s.stage;ensure(t&&t.catalog_next===t.result.catalog_count&&t.pages.length===Number(t.result.descriptor.page_count)&&t.all_items===t.result.descriptor.item_count&&t.items.length===t.inventory.length&&(!t.result.files||t.files_verified===true)&&snapshotCommitment(t.pages)===t.result.descriptor.inventory_digest,'SYNC_GAP');
   await this.#syncPublish(t.items,true);s.cursor=structuredClone(t.result.descriptor.watermark);s.watermark=structuredClone(s.cursor);s.stage=null;s.state='SYNCED';s.quarantine=null;await this.#commit();return output();
  }
  if(op==='deltaCancel'){ensure(Object.keys(x).length===0,'INVALID_REQUEST');s.pending=null;if(s.state!=='RESTORE_QUARANTINE')s.state=s.cursor?'SYNCED':'NEW';await this.#commit();return output();}
  if(op==='deltaStart'){
   ensure(s.cursor&&!s.stage,'SYNC_CURSOR_EXPIRED');ensure(!s.pending||same(s.pending.page,x),'PUBLICATION_PENDING');checkedDelta(x,s.cursor,this.pins,s.scope.group_id);
   if(!s.pending)s.pending={page:structuredClone(x),items:[]};s.state='STAGING';await this.#commit();return output();
  }
  if(op==='deltaItem'){
   syncValue('delta-bundle',x);const p=s.pending;ensure(p&&p.page.events.some(e=>e.revision_id===x.item.revision_id&&e.object_id===x.item.object_id&&e.group_id===x.item.group_id&&e.digest===x.item.envelope_digest),'CONTEXT_MISMATCH');
   const old=p.items.find(i=>i.item.revision_id===x.item.revision_id);if(old){ensure(same(old.item,x.item),'ROLLBACK_QUARANTINE');return output();}
   const verified=await this.#syncVerify(x.item,x.bundle,x.reference,p.items);p.items.push(verified.value);await this.#commit({records:[verified.record]});return output();
  }
  if(op==='deltaFinish'){
   ensure(Object.keys(x).length===0,'INVALID_REQUEST');const p=s.pending;ensure(p&&p.page.events.every(e=>e.revision_id!==null&&p.items.some(i=>i.item.revision_id===e.revision_id)),'SYNC_GAP');
   await this.#syncPublish(p.items,false);s.cursor=structuredClone(p.page.next_cursor);s.watermark=structuredClone(p.page.watermark);s.pending=null;s.state='SYNCED';await this.#commit();return output();
  }
  throw Error('INVALID_SYNC_COMMAND');
 }
 async #syncPublish(items,snapshot){
  const s=this.#state.sync,merged=new Map(this.#state.witnesses.map(w=>[w.revision_id,w]));
  for(const v of items){const old=merged.get(v.witness.revision_id);if(old){const {cache_id:oldCache,...oldProof}=old,{cache_id:newCache,...newProof}=v.witness;ensure(same(oldProof,newProof),'ROLLBACK_QUARANTINE');}merged.set(v.witness.revision_id,structuredClone(v.witness));}
  for(const v of items){const data=await this.read(v.cache_id,'cache'),envelope=data.purpose==='p11-header-evidence'?syncValue('header-evidence',data).envelope:decode('bundle',un64(decode('cache',wire(data)).record_bytes)).envelope;ensure(digest('envelope',wire(envelope))===v.item.envelope_digest,'INTEGRITY_FAILURE');for(const parent of envelope.header.context.parents){const w=merged.get(parent.revision_id);ensure(w&&w.group_id===v.item.group_id&&w.object_id===v.item.object_id&&w.envelope_digest===parent.envelope_digest,'UNANCHORED_HISTORY');}}
  const refs=new Map(snapshot?s.projection.filter(p=>s.scope.group_id!==null&&p.group_id!==s.scope.group_id).map(p=>[p.group_id+'/'+p.reference.object_id,p]):s.projection.map(p=>[p.group_id+'/'+p.reference.object_id,p]));
  for(const v of items){for(const h of v.reference.heads){const w=merged.get(h.revision_id);ensure(w&&w.group_id===v.item.group_id&&w.object_id===v.item.object_id&&w.envelope_digest===h.envelope_digest,'UNANCHORED_HISTORY');}refs.set(v.item.group_id+'/'+v.item.object_id,{group_id:v.item.group_id,reference:structuredClone(v.reference)});}
  this.#state.witnesses=[...merged.values()];s.projection=[...refs.values()].sort((a,b)=>a.group_id+'/'+a.reference.object_id<b.group_id+'/'+b.reference.object_id?-1:1);
 }
 async #sharedCommand(args){
  ensure(args.length===2&&typeof args[0]==='string'&&args[1]&&typeof args[1]==='object','INVALID_REQUEST');const [op,x]=args;
  this.#own();ensure(this.#state.sync?.state!=='RESTORE_QUARANTINE'||['proof','details','card','adopt','keys','ownKeys','finishCancel','complete'].includes(op),'RESTORE_QUARANTINE');
  if(op==='upgradePrivate'){ensure(args.length===2&&id(x.group_id),'INVALID_REQUEST');const old=await this.#info(x.group_id);ensure(!old.data,'GROUP_PROOF_REQUIRED');const proof={pin:genesisPin(old.evidence),journal:{version:1,group_id:x.group_id,genesis:old.evidence,events:[],pending:null},accounts:[{pins:this.pins,snapshot:this.#snapshot}]};replayGroup(proof,{ownPins:this.pins,localGenesis:true,witnesses:await this.#historyRecords(x.group_id)});await this.#commit({records:[{id:old.ref.record_id,kind:'group-evidence',data:{purpose:'p10-group-proof',version:1,proof,attempt:null}}]});return proof;}
  if(op==='adopt'){
   sharedValue('adopt-request',x);ensure(x.pin.service_id===this.scope.service_id,'CONTEXT_MISMATCH');const group=x.pin.group_id;let ref=this.#state.groups.find(g=>g.group_id===group),old=ref?await this.read(ref.record_id,'group-evidence'):null;
   ensure(!old||old.purpose==='p10-group-proof','GROUP_PROOF_REQUIRED');const witnesses=await this.#historyRecords(group);const result=replayGroup(x,{ownPins:this.pins,known:old?.proof,witnesses,localGenesis:old?.proof.pin.owner_account_id===this.scope.account_id&&old?.proof.journal.events.length===0});
   if(!ref){ensure(this.#state.groups.length<100,'RESOURCE_LIMIT');ref={group_id:group,record_id:random(),state:'COMMITTED',status:null};this.#state.groups.push(ref);}
   const data={purpose:'p10-group-proof',version:1,proof:structuredClone(x),attempt:old?.attempt??null,pending_key:old?.pending_key??null};await this.#commit({records:[{id:ref.record_id,kind:'group-evidence',data}]});return {group_id:group,members:result.details.members,write_state:result.details.write_state};
  }
  ensure(id(x.group_id),'INVALID_REQUEST');const {ref,data,verified,info}=await this.#info(x.group_id);ensure(data,'GROUP_PROOF_REQUIRED');const token=verified.token,signer=groupApi.groupSenderForEvaluation(token,this.scope.account_id,this.scope.device_id),now=BigInt(Date.now()),key=this.#keys.signing.privateKey;
  const persist=async(attempt,addKeys=[])=>{sharedValue('attempt',attempt);ensure(!data.attempt||['COMMITTED','CANCELLED'].includes(data.attempt.state),'PUBLICATION_PENDING');data.attempt=attempt;await this.#commit({records:[{id:ref.record_id,kind:'group-evidence',data}],addKeys});return structuredClone(attempt);};
  const attempt=(family,body,pages=[],commit=null)=>({family,body,pages,commit,state:'PREPARED'});
  if(op==='proof')return structuredClone(data.proof);
  if(op==='details')return {...verified.details,policy:verified.policy};
  if(op==='card'){const proof=structuredClone(data.proof),history=proof.journal.events.findLast(e=>e.kind==='history');ensure(history,'INDEPENDENT_HISTORY_REQUIRED');proof.pin.history={version:history.history.body.sequence,digest:groupCodec.groupDigest('history',wire(history.history))};return proof;}
  if(op==='cancelAttempt'){ensure(x.confirm===true&&data.attempt&&!['COMMITTED','CANCELLED'].includes(data.attempt.state),'CONFIRMATION_REQUIRED');const a=data.attempt,r=a.body.invitation??a.body.acceptance??a.body.policy??a.body.intent??a.body.commit??a.body.history;return {version:1,operation_id:r?.body.operation_id??a.body.operation_id};}
  if(op==='finishCancel'){const a=data.attempt;ensure(a&&x.result,'INVALID_REQUEST');sharedValue('result',x.result);const r=a.body.invitation??a.body.acceptance??a.body.policy??a.body.intent??a.body.commit??a.body.history,body={version:1,operation_id:r?.body.operation_id??a.body.operation_id};ensure(x.result.group_id===x.group_id&&x.result.operation_id===body.operation_id&&x.result.state==='CANCELLED'&&x.result.digest===valueHash(body),'RECEIPT_CONTEXT_MISMATCH');a.state='CANCELLED';wipe(data.pending_key);data.pending_key=null;await this.#commit({records:[{id:ref.record_id,kind:'group-evidence',data}]});return {state:'CANCELLED'};}
  if(op==='retry'){ensure(data.attempt&&data.attempt.state!=='COMMITTED','RECORD_NOT_FOUND');data.attempt.state='SENT_UNKNOWN';await this.#commit({records:[{id:ref.record_id,kind:'group-evidence',data}]});return structuredClone(data.attempt);}
  if(op==='complete'){ensure(data.attempt&&x.result,'INVALID_REQUEST');sharedValue('result',x.result);const a=data.attempt,r=a.body.invitation??a.body.acceptance??a.body.policy??a.body.intent??a.body.commit??a.body.history;ensure(x.result.group_id===x.group_id&&x.result.operation_id===(r?.body.operation_id??a.body.operation_id),'RECEIPT_CONTEXT_MISMATCH');const finalBody=a.family==='epoch'?{version:1,commit:a.commit}:a.body;ensure(x.result.digest===valueHash(finalBody)&&x.result.state===({invite:'INVITED',accept:'ACCEPTED_PENDING_GRANTS',policy:'POLICY_COMMITTED',consent:'OWNER_CONSENT',epoch:'ACTIVATED',history:'HISTORY_CLOSED',cancel:'CANCELLED'}[a.family]),'RECEIPT_CONTEXT_MISMATCH');const addKeys=[];if(a.family==='epoch'&&a.state!=='COMMITTED'){ensure(data.pending_key&&data.pending_key.group_id===x.group_id&&data.pending_key.key_epoch===a.commit.body.intent.body.next_epoch&&data.pending_key.epoch_digest===groupCodec.groupDigest('epoch-intent',wire(a.commit.body.intent))&&groupCodec.groupKeyCommitment(verified.details.scope,un64(data.pending_key.group_secret))===a.commit.body.intent.body.key_commitment,'KEY_REPAIR_REQUIRED');addKeys.push(structuredClone(data.pending_key));}data.attempt.state='COMMITTED';wipe(data.pending_key);data.pending_key=null;try{await this.#commit({records:[{id:ref.record_id,kind:'group-evidence',data}],addKeys});return {state:'COMMITTED'};}finally{wipe(addKeys);}}
  if(op==='invite'){
   ensure(x.confirm===true&&['reader','editor'].includes(x.role)&&x.account?.pins.root_fingerprint===x.expected_root,'IDENTITY_CONFIRMATION_REQUIRED');const account=sharedValue('account-proof',x.account),target=verifiedSnapshot(account.snapshot,account.pins);groupApi.custodyAccount(token,target);const invitation=JSON.parse(new TextDecoder().decode(groupBuilders.invitationForGroupEvaluation(token,signer,account.pins,x.role,key,now)));groupApi.stageInvitationForEvaluation(token,wire(invitation),now);const old=data.proof.accounts.find(a=>a.pins.account_id===account.pins.account_id);if(old)ensure(same(old.pins,account.pins),'ROOT_PIN_MISMATCH');else data.proof.accounts.push(structuredClone(account));return persist(attempt('invite',{version:1,invitation}));
  }
  if(op==='accept'){
   const inv=groupCodec.groupDecode('invitation',wire(x.invitation));ensure(x.confirm===true&&inv.body.target_account_id===this.scope.account_id&&inv.body.target_root_fingerprint===this.pins.root_fingerprint,'IDENTITY_CONFIRMATION_REQUIRED');groupApi.stageInvitationForEvaluation(token,wire(inv),now);const acceptance=JSON.parse(new TextDecoder().decode(groupBuilders.acceptanceForGroupEvaluation(wire(inv),signer,key)));groupApi.acceptInvitationForEvaluation(token,wire(acceptance),now);return persist(attempt('accept',{version:1,acceptance}));
  }
  if(op==='policy'){
   ensure(x.confirm===true&&['role','remove','archive','unarchive'].includes(x.action),'CONFIRMATION_REQUIRED');const payload=['role','remove'].includes(x.action)?{target_account_id:x.target_account_id,...(x.action==='role'?{role:x.role}:{})}:{};const policy=JSON.parse(new TextDecoder().decode(groupBuilders.policyForEvaluation(token,x.action,signer,key,payload)));groupApi.applyGroupPolicyForEvaluation(token,wire(policy),now);return persist(attempt('policy',{version:1,policy}));
  }
  if(op==='transferProposal'){ensure(x.confirm===true,'CONFIRMATION_REQUIRED');const incoming=groupApi.groupSenderForEvaluation(token,x.account_id,x.device_id);ensure(incoming.account_id!==this.scope.account_id&&verified.details.members.some(m=>m.account_id===this.scope.account_id&&m.role==='owner'),'OWNER_REQUIRED');return JSON.parse(new TextDecoder().decode(groupBuilders.policyForEvaluation(token,'transfer',signer,key,{incoming_signer:incoming})));}
  if(op==='cosign'){
   ensure(x.confirm===true,'CONFIRMATION_REQUIRED');const policy=groupCodec.groupDecode('policy',wire(x.policy)),incoming=policy.body.payload.incoming_signer;ensure(policy.body.action==='transfer'&&same(incoming,signer),'INCOMING_OWNER_REQUIRED');policy.cosignature=b64(sodium.crypto_sign_detached(groupCodec.groupSigningInput('policy-body',wire(policy.body)),key));groupApi.applyGroupPolicyForEvaluation(token,wire(policy),now);return persist(attempt('consent',{version:1,policy}));
  }
  if(op==='transfer'){ensure(x.confirm===true,'CONFIRMATION_REQUIRED');const policy=groupCodec.groupDecode('policy',wire(x.policy));ensure(policy.body.action==='transfer'&&same(policy.body.signer,signer),'OWNER_REQUIRED');groupApi.applyGroupPolicyForEvaluation(token,wire(policy),now);return persist(attempt('policy',{version:1,policy}));}
  if(op==='history'){
   const rows=groupApi.observedHistoryRecordsForEvaluation(token),pages=[];let batch=[];const make=records=>({purpose:'history-inventory-page',contract:'p02-file-c1',version:1,service_id:this.scope.service_id,group_id:x.group_id,page_index:String(pages.length),records});for(const r of rows){if(batch.length&&(batch.length===500||wire(make([...batch,r])).length>1048576)){pages.push(make(batch));batch=[];}batch.push(r);}if(batch.length)pages.push(make(batch));const history=JSON.parse(new TextDecoder().decode(groupBuilders.historyForEvaluation(token,signer,key,pages.map(wire))));groupApi.endorseGroupHistoryForEvaluation(token,wire(history),pages.map(wire),groupApi.independentHistoryWitnessForEvaluation(token));return persist(attempt('history',{version:1,history,pages}));
  }
  if(op==='epoch'){
   ensure(x.confirm===true,'CONFIRMATION_REQUIRED');let policy=null;const pending=data.proof.journal.pending;
   if(x.reason==='admission'){ensure(pending?.acceptance&&pending.invitation,'ACCEPTED_INVITATION_REQUIRED');groupApi.stageInvitationForEvaluation(token,wire(pending.invitation),now);groupApi.acceptInvitationForEvaluation(token,wire(pending.acceptance),now);policy=groupBuilders.admissionPolicyForEvaluation(token,signer,key);}
   const fresh=sodium.randombytes_buf(32),secrets=await this.secrets();let keys;try{keys=new Map(secrets.group_keys.filter(k=>k.group_id===x.group_id).map(k=>[k.key_epoch,un64(k.group_secret)]));const rosters=groupApi.groupRostersForEvaluation(token,policy,now),intent=groupBuilders.epochIntentForEvaluation(token,x.reason,signer,key,fresh,rosters,now,policy),parsed=groupCodec.groupDecode('epoch-intent',intent);keys.set(parsed.body.next_epoch,fresh);groupApi.beginGroupEpochForEvaluation(token,intent,policy,now);const pages=groupBuilders.grantPagesForEvaluation(token,intent,keys,key,this.#proof.roster,now,policy),commit=groupBuilders.epochCommitForEvaluation(token,intent,pages,key,policy);for(const p of pages)groupApi.stageGroupGrantPageForEvaluation(token,p,now);groupApi.finalizeGroupEpochForEvaluation(token,commit,now);const add={service_id:this.scope.service_id,group_id:x.group_id,key_epoch:parsed.body.next_epoch,epoch_digest:groupCodec.groupDigest('epoch-intent',intent),group_secret:b64(fresh)};data.pending_key=add;return await persist(attempt('epoch',{version:1,intent:parsed,policy:policy?groupCodec.groupDecode('policy',policy):null},pages.map(p=>groupCodec.groupDecode('grant-page',p)),groupCodec.groupDecode('epoch-commit',commit)));}finally{wipe(secrets);if(keys)for(const k of keys.values())wipe(k);wipe(fresh);}
  }
  if(op==='ownGrants'){
   ensure(verified.details.members.some(m=>m.account_id===this.scope.account_id),'ACCESS_REVOKED');const recipients=this.#proof.details.devices.filter(d=>d.status==='ACTIVE'&&d.device_id===x.device_id);ensure(recipients.length===1,'DEVICE_NOT_TRUSTED');const cert=activeCertificateForEvaluation(this.#proof.roster,this.scope.device_id,'distribute-group-key'),target=(await import('../devices/roster.mjs')).activeRecipientForRosterEvaluation(this.#proof.roster,x.device_id),publicKey=certificateDetails(activeCertificateForEvaluation(this.#proof.roster,x.device_id,'receive-group-key')).body.device_encryption_key,records=[];
   for(const e of verified.details.epochs){const k=await this.#key(x.group_id,info,e.key_epoch);try{ensure(groupCodec.groupKeyCommitment(verified.details.scope,k)===e.key_commitment,'KEY_REPAIR_REQUIRED');records.push(JSON.parse(new TextDecoder().decode(sealGroupKeyForEvaluation(wire({purpose:'group-key-distribution',contract:'p02-identity-c1',protocol:'anynote',protocol_version:1,service_id:this.scope.service_id,group_id:x.group_id,key_epoch:e.key_epoch,epoch_digest:e.epoch_digest,membership_head:verified.details.policy,operation_id:random(),issuer:signer,recipient:target}),k,un64(publicKey),key,cert))));}finally{wipe(k);}}return {version:1,records};
  }
  if(op==='ownKeys'){
   ensure(verified.details.members.some(m=>m.account_id===this.scope.account_id),'ACCESS_REVOKED');ensure(Array.isArray(x.records)&&x.records.length<=60,'RESOURCE_LIMIT');const add=[];
   try{for(const r of x.records){const c=r.body.context;ensure(c.service_id===this.scope.service_id&&c.group_id===x.group_id&&same(c.membership_head,verified.details.policy)&&c.issuer.account_id===this.scope.account_id&&c.recipient.account_id===this.scope.account_id&&c.recipient.kind==='device'&&c.recipient.device_id===this.scope.device_id,'RECIPIENT_ACCESS_MISMATCH');const epoch=verified.details.epochs.find(e=>e.key_epoch===c.key_epoch&&e.epoch_digest===c.epoch_digest);ensure(epoch,'EPOCH_INVENTORY_MISMATCH');const cert=activeCertificateForEvaluation(this.#proof.roster,c.issuer.device_id,'distribute-group-key');ensure(same(c.issuer,senderForCertificate(cert,this.#proof.details.head)),'ROSTER_CHANGED');const expected=(await import('../devices/roster.mjs')).activeRecipientForRosterEvaluation(this.#proof.roster,this.scope.device_id);ensure(same(expected,c.recipient),'ROSTER_CHANGED');const k=(await import('../devices/proofs.mjs')).openGroupKeyForEvaluation(wire(r),wire(c),cert,this.#keys.encryption.publicKey,this.#keys.encryption.privateKey);try{ensure(groupCodec.groupKeyCommitment(verified.details.scope,k)===epoch.key_commitment,'KEY_REPAIR_REQUIRED');add.push({service_id:this.scope.service_id,group_id:x.group_id,key_epoch:c.key_epoch,epoch_digest:c.epoch_digest,group_secret:b64(k)});}finally{wipe(k);}}await this.#commit({addKeys:add});return {state:'keys-local-saved',epochs:add.length};}finally{wipe(add);}
  }
  if(op==='keys'){
   const reader=groupApi.groupSenderForEvaluation(token,this.scope.account_id,this.scope.device_id,'receive-group-key'),add=[];
   try{for(const raw of groupApi.groupGrantRecordsForEvaluation(token)){const r=JSON.parse(new TextDecoder().decode(raw)),recipient=r.body.context.recipient;if(recipient.kind!=='device'||recipient.account_id!==this.scope.account_id||recipient.device_id!==this.scope.device_id)continue;const k=groupApi.openAuthorizedGroupKeyForEvaluation(token,raw,reader,this.#keys.encryption.publicKey,this.#keys.encryption.privateKey);try{add.push({service_id:this.scope.service_id,group_id:x.group_id,key_epoch:r.body.context.key_epoch,epoch_digest:r.body.context.epoch_digest,group_secret:b64(k)});}finally{wipe(k);}}ensure(add.length===verified.details.epochs.length,'KEY_REPAIR_REQUIRED');await this.#commit({addKeys:add});return {state:'keys-local-saved',epochs:add.length};}finally{wipe(add);}
  }
  throw Error('INVALID_SHARED_COMMAND');
 }
 #cache(bundle){
  const c=bundle.envelope.header.context,ed=digest('envelope',wire(bundle.envelope));let w=this.#state.witnesses.find(w=>w.revision_id===c.revision_id);
  if(w)ensure(w.group_id===c.group_id&&w.object_id===c.object_id&&w.envelope_digest===ed,'ROLLBACK_QUARANTINE');
  else{ensure(this.#state.witnesses.length<10000,'RESOURCE_LIMIT');w={group_id:c.group_id,object_id:c.object_id,revision_id:c.revision_id,envelope_digest:ed,object_kind:c.object_kind,thread_id:c.thread_id,archived:c.archived,action:c.action,cache_id:random()};this.#state.witnesses.push(w);}
  return {id:w.cache_id,kind:'cache',data:decode('cache',wire({cached_kind:'object-bundle',record_bytes:b64(wire(bundle))}))};
 }
}
