// Protected Worker workflow. Signing/encryption is subordinate to verified private-group authority.
import {sodium,b64,un64,hash} from '../adapters/primitives.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {canonicalBytes,sealObject,openObject} from '../adapters/core.mjs';
import {common,decode,digest} from '../adapters/codecs/protocol-codec.mjs';
import {verifiedSnapshot,historicalSnapshot} from '../devices/client.mjs';
import {privateGenesis,verifyGenesis} from '../devices/genesis.mjs';
import {activeCertificateForEvaluation,rosterDetails} from '../devices/roster.mjs';
import {certificateDetails} from '../devices/proofs.mjs';
import {stateDigest} from '../adapters/codecs/state-codec.mjs';
import {noteValue} from './client.mjs';
import {ensure,id} from '../vault/store.mjs';
const random=()=>b64(sodium.randombytes_buf(16));
const valueHash=v=>hash(canonicalBytes(wire(v)));
const requestFor=b=>{const c=b.envelope.header.context;return noteValue('commit-request',{group_id:c.group_id,object_id:c.object_id,object_kind:c.object_kind,action:c.action,thread_id:c.thread_id,bundle:b});};
function wipe(v){if(v instanceof Uint8Array)sodium.memzero(v);else if(v&&typeof v==='object')for(const k of Object.keys(v)){wipe(v[k]);if(typeof v[k]==='string')v[k]='';}}
export class NotesWorkflow {
 #state;#proof;#snapshot;#keys;
 constructor({scope,pins,keys,load,read,persist,devices,secrets}){this.scope=scope;this.pins=pins;this.#keys=keys;this.load=load;this.read=read;this.persist=persist;this.devices=devices;this.secrets=secrets;}
 close(){this.#state=this.#proof=this.#snapshot=undefined;}
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
  const b=this.#own(proof);return {account_id:this.scope.account_id,device_id:this.scope.device_id,root_fingerprint:this.pins.root_fingerprint,recovery_generation:b.recovery_generation,roster:proof.details.head};
 }
 async #info(group){
  const ref=this.#state.groups.find(g=>g.group_id===group);ensure(ref,'KEYS_PENDING');
  const data=await this.read(ref.record_id,'group-evidence');noteValue('local-evidence',data);
  const evidence=data.evidence,signer=evidence.commit.body.policy.body.signer;
  const historical=historicalSnapshot(this.#snapshot,this.pins,signer.roster_head),info=verifyGenesis(evidence,historical.roster,historical.identity);
  ensure(info.group_id===group&&evidence.commit.body.policy.body.members[0].account_id===this.scope.account_id,'POLICY_CHANGED');
  return {ref,evidence,info};
 }
 #policy(info){return {membership:info.membership,key_epoch:'0',epoch_digest:info.epoch_digest,history_checkpoint_digest:null};}
 #writable(group,info){
  this.#own();ensure(group.state==='COMMITTED'&&group.status,'GROUP_NOT_COMMITTED');const s=group.status;
  ensure(s.state==='active','ROLE_FORBIDDEN');ensure(!s.restore_quarantined,'RESTORE_QUARANTINE');ensure(!s.rekey_required,'REKEY_REQUIRED');ensure(!s.history_closure_required,'HISTORY_CLOSURE_REQUIRED');
  ensure(same(s.membership,info.membership)&&s.key_epoch==='0'&&s.epoch_digest===info.epoch_digest&&s.history_checkpoint_digest===null,'POLICY_CHANGED');
 }
 async #key(group,info){
  const data=await this.secrets();try{const k=data.group_keys.find(k=>k.service_id===this.pins.service_id&&k.group_id===group&&k.key_epoch==='0'&&k.epoch_digest===info.epoch_digest);ensure(k,'KEYS_PENDING');return un64(k.group_secret);}finally{wipe(data);}
 }
 async #draft(id){const ref=this.#state.drafts.find(d=>d.draft_id===id);ensure(ref,'DRAFT_NOT_FOUND');const data=decode('draft',wire(await this.read(ref.record_id,'draft')));ensure(data.draft_id===ref.draft_id&&valueHash(data)===ref.saved_digest,'INTEGRITY_FAILURE');return {ref,data};}
 async #attempt(id){const ref=this.#state.attempts.find(a=>a.attempt_id===id);ensure(ref,'ATTEMPT_NOT_FOUND');const data=decode('outbox',wire(await this.read(ref.record_id,'outbox')));ensure(data.attempt_id===ref.attempt_id&&data.draft_id===ref.draft_id&&data.state===ref.state,'INTEGRITY_FAILURE');return {ref,data};}
 async #commit(extra={}){noteValue('local-control',this.#state);await this.persist(this.#state,extra);}
 async command(op,args=[]){
  await this.#ready();
  if(op==='summary')return {groups:this.#state.groups.map(g=>({group_id:g.group_id,state:g.state,status:g.status})),drafts:this.#state.drafts.map(d=>{const a=this.#state.attempts.findLast(a=>a.draft_id===d.draft_id);return {...d,attempt_id:a?.attempt_id??null,state:a?(a.state==='COMMITTED'&&a.source_digest!==d.saved_digest?'LOCAL_SAVED':a.state):'LOCAL_SAVED'};}),witnessed:this.#state.witnesses.length,witnesses:structuredClone(this.#state.witnesses)};
  if(op==='prepareGroup'){
   ensure(args.length===0&&this.#state.groups.length<100,'RESOURCE_LIMIT');this.#own();const made=privateGenesis(this.#proof.roster,this.#proof.identity,this.scope.device_id,this.#keys.signing.privateKey),group=made.request.commit.body.group_id,record_id=random();
   this.#state.groups.push({group_id:group,record_id,state:'GENESIS_PENDING',status:null});
   const evidence={version:1,group_id:group,...made.request};
   try{await this.#commit({records:[{id:record_id,kind:'group-evidence',data:{purpose:'p09-private-genesis',version:1,evidence}}],addKeys:[made.secret]});return {group_id:group,request:made.request};}finally{wipe(made.secret);}
  }
  if(op==='groupEvidence'){ensure(args.length===1&&id(args[0]),'INVALID_REQUEST');return (await this.#info(args[0])).evidence;}
  if(op==='retryGroup'){ensure(args.length===1&&id(args[0]),'INVALID_REQUEST');const {ref,evidence}=await this.#info(args[0]);ensure(ref.state==='GENESIS_PENDING','GROUP_NOT_PENDING');const {version,commit,pages}=evidence;return {group_id:ref.group_id,request:{version,commit,pages}};}
  if(op==='group'){
   ensure(args.length===1,'INVALID_REQUEST');const s=noteValue('group-status',args[0]);ensure(s.owner_account_id===this.scope.account_id&&s.genesis.group_id===s.group_id,'POLICY_CHANGED');
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
   for(const p of edit.parents)ensure(this.#state.witnesses.some(w=>w.group_id===edit.group_id&&w.object_id===object_id&&w.revision_id===p.revision_id&&w.envelope_digest===p.envelope_digest),'UNANCHORED_HISTORY');
   const context={...common('object-context'),service_id:this.scope.service_id,group_id:edit.group_id,object_kind:edit.object_kind,object_id,revision_id:random(),operation_id:random(),thread_id:edit.thread_id,action:edit.action,author:this.#author(true),policy:this.#policy(info),parents:edit.parents,attachments:[],payload_schema:1,archived:edit.archived};
   const payload=decode('payload',wire({...common('object-plaintext'),context,...edit.content})),draft_id=old?.draft_id??random(),data=decode('draft',wire({draft_id,context,payload}));
   const ref=old??{draft_id,record_id:random(),group_id:edit.group_id,object_id,object_kind:edit.object_kind,thread_id:edit.thread_id,saved_digest:valueHash(data)};ref.saved_digest=valueHash(data);
   if(!old){ensure(this.#state.drafts.length<512,'RESOURCE_LIMIT');this.#state.drafts.push(ref);}
   await this.#commit({records:[{id:ref.record_id,kind:'draft',data}]});return {draft_id,object_id,state:'LOCAL_SAVED'};
  }
  if(op==='draft'){ensure(args.length===1&&id(args[0]),'INVALID_REQUEST');const {ref,data}=await this.#draft(args[0]);return {draft_id:ref.draft_id,payload:data.payload};}
  if(op==='queue'){
   ensure(args.length===1&&id(args[0]),'INVALID_REQUEST');const {ref,data}=await this.#draft(args[0]),{ref:group,info}=await this.#info(ref.group_id);this.#writable(group,info);
   const live=this.#state.attempts.findLast(a=>a.draft_id===ref.draft_id&&['QUEUED','SENT_UNKNOWN'].includes(a.state));if(live){ensure(live.source_digest===ref.saved_digest,'PUBLICATION_PENDING');const {data:out}=await this.#attempt(live.attempt_id);return {attempt_id:out.attempt_id,state:out.state};}
   ensure(this.#state.attempts.length<512,'RESOURCE_LIMIT');data.context.author=this.#author();data.context.policy=this.#policy(info);data.context.operation_id=random();data.context.revision_id=random();data.payload.context=structuredClone(data.context);decode('draft',wire(data));ref.saved_digest=valueHash(data);
   const key=await this.#key(ref.group_id,info);let bundle;try{bundle=sealObject(wire(data.payload),key,this.#keys.signing.privateKey);}finally{wipe(key);}
   const attempt_id=bundle.envelope.header.context.operation_id,out=decode('outbox',wire({draft_id:ref.draft_id,attempt_id,revision_id:bundle.envelope.header.context.revision_id,state:'QUEUED',bundle,attempt_digest:digest('bundle',wire(bundle)),receipt:null})),attempt={attempt_id,record_id:random(),draft_id:ref.draft_id,source_digest:ref.saved_digest,state:'QUEUED'};
   this.#state.attempts.push(attempt);await this.#commit({records:[{id:ref.record_id,kind:'draft',data},{id:attempt.record_id,kind:'outbox',data:out}]});return {attempt_id,state:'QUEUED'};
  }
  if(op==='send'){
   ensure(args.length===1&&id(args[0]),'INVALID_REQUEST');const {ref,data}=await this.#attempt(args[0]);ensure(['QUEUED','SENT_UNKNOWN'].includes(data.state),'INVALID_OUTBOX_TRANSITION');const {ref:group,info}=await this.#info(data.bundle.envelope.header.context.group_id);this.#writable(group,info);
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
   await this.#commit({records,retireDrafts});return {state:'COMMITTED',draft_id:data.draft_id,revision_id:c.revision_id,draft_retired:retired};
  }
  if(op==='open'){
   ensure(args.length===1,'INVALID_REQUEST');const x=noteValue('open-request',args[0]),b=decode('bundle',wire(x.bundle)),c=b.envelope.header.context,{info}=await this.#info(x.group_id);
   ensure(c.service_id===this.scope.service_id&&c.group_id===x.group_id&&c.object_id===x.object_id&&c.revision_id===x.revision_id&&c.object_kind===x.object_kind&&c.thread_id===x.thread_id&&c.author.account_id===this.scope.account_id&&c.author.root_fingerprint===this.pins.root_fingerprint&&same(c.policy,this.#policy(info)),'CONTEXT_MISMATCH');
   const historical=historicalSnapshot(this.#snapshot,this.pins,c.author.roster),cert=activeCertificateForEvaluation(historical.roster,c.author.device_id,'sign-content'),author=certificateDetails(cert).body;ensure(author.recovery_generation===c.author.recovery_generation,'CONTEXT_MISMATCH');
   const ed=digest('envelope',wire(b.envelope)),current=this.#proof.details.devices.some(d=>d.device_id===c.author.device_id&&d.status==='ACTIVE'&&d.generation===c.author.recovery_generation),known=this.#state.witnesses.some(w=>w.group_id===x.group_id&&w.object_id===x.object_id&&w.revision_id===x.revision_id&&w.envelope_digest===ed);
   ensure(current||known,'UNANCHORED_HISTORY');const key=await this.#key(x.group_id,info);let payload;try{payload=openObject(wire(b),key,un64(author.device_signing_key),wire(c));}finally{wipe(key);}
   const cached=this.#cache(b);await this.#commit({records:[cached]});return {payload,envelope_digest:ed};
  }
  if(op==='cached'){
   ensure(args.length===1&&id(args[0]),'INVALID_REQUEST');const w=this.#state.witnesses.find(w=>w.revision_id===args[0]);ensure(w,'RECORD_NOT_FOUND');const cache=decode('cache',wire(await this.read(w.cache_id,'cache'))),b=decode('bundle',un64(cache.record_bytes));ensure(digest('envelope',wire(b.envelope))===w.envelope_digest,'INTEGRITY_FAILURE');return this.command('open',[{group_id:w.group_id,object_id:w.object_id,revision_id:w.revision_id,object_kind:b.envelope.header.context.object_kind,thread_id:b.envelope.header.context.thread_id,bundle:b}]);
  }
  ensure(false,'INVALID_NOTE_COMMAND');
 }
 #cache(bundle){
  const c=bundle.envelope.header.context,ed=digest('envelope',wire(bundle.envelope));let w=this.#state.witnesses.find(w=>w.revision_id===c.revision_id);
  if(w)ensure(w.group_id===c.group_id&&w.object_id===c.object_id&&w.envelope_digest===ed,'ROLLBACK_QUARANTINE');
  else{ensure(this.#state.witnesses.length<512,'RESOURCE_LIMIT');w={group_id:c.group_id,object_id:c.object_id,revision_id:c.revision_id,envelope_digest:ed,object_kind:c.object_kind,thread_id:c.thread_id,archived:c.archived,action:c.action,cache_id:random()};this.#state.witnesses.push(w);}
  return {id:w.cache_id,kind:'cache',data:decode('cache',wire({cached_kind:'object-bundle',record_bytes:b64(wire(bundle))}))};
 }
}
