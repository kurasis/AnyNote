import {contentFrame,contentManifest,prepareContent,readContent,rotateContent,contentControlId,CONTENT_PROFILE} from '../content/local.mjs';
import {contentState,contentIds} from '../content/workflow.mjs';
import {syncValue} from '../sync/codec.mjs';
import {canonicalBytes} from '../adapters/core.mjs';
import {pagedFrame,publicPartIds,preparePaged,readPaged,openManifest,sealManifest,rotatePagedFrame} from '../sync/paged-local.mjs';
import {bootstrapControl} from '../devices/bootstrap.mjs';
import {NotesWorkflow} from '../notes/workflow.mjs';
import {noteControlId,sealNoteLocal,openNoteLocal,noteFrameHash} from '../notes/local.mjs';
import {noteValue} from '../notes/client.mjs';
import {fileControlId,fileIds} from '../files/workflow.mjs';
import {fileValue} from '../files/codec.mjs';
import {sealLifecycle,openLifecycle,lifecycleHash} from '../devices/local.mjs';
import {strictJson} from '../src/strict-json.mjs';
import {DeviceWorkflow,controlId} from '../devices/workflow.mjs';
// Long-lived keys stay in the dedicated worker. No command returns L or device secrets.
import {sodium,b64,un64,randomKey,hash,Buffer} from '../adapters/primitives.mjs';
import {phraseKek,prfKek,wrapLocalKey,unwrapLocalKey,sealLocal,openLocal} from '../adapters/local.mjs';
import {decode,common,encode,digest} from '../adapters/codecs/protocol-codec.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {signManifest,verifyManifest} from './manifest.mjs';
import {possession} from '../auth-client.mjs';
import {ensure,id,scope,record,metadata,same} from './store.mjs';
const kinds=new Set(['cache','search','draft','outbox','transfer']);
const bounded=data=>{const bytes=wire(data);ensure(bytes.length<=4194304,'RESOURCE_LIMIT');return bytes;};
function wipe(v){if(v instanceof Uint8Array)sodium.memzero(v);else if(v&&typeof v==='object'){for(const k of Object.keys(v)){wipe(v[k]);if(typeof v[k]==='string')v[k]='';}}}
const frameHash=f=>f?.contract===CONTENT_PROFILE?hash(canonicalBytes(wire(contentFrame(f)))):f?.contract==='p11-local-v1'?hash(canonicalBytes(wire(pagedFrame(f)))):f?.contract==='p09-local-v1'?noteFrameHash(f):f?.contract==='p08-local-v1'?lifecycleHash(f):hash(encode('local-envelope',wire(f)));
const descriptor=w=>{const {nonce,ciphertext,...d}=w;return d;};
export class VaultEngine {
  #notesTail=Promise.resolve();#notes;#notesHash;#notesFence;#workflow;#workflowHash;#workflowFence;#deviceAnchor;#key;#keys;#cap;#epoch;#last=0;#revision=0;#anchors=new Map();#busy=false;
  constructor(store){this.store=store;this.scope=scope(store.scope);this.owner=b64(sodium.randombytes_buf(16));this.vaultId=b64(sodium.randombytes_buf(16));}
  context(kind,record_id){ensure(id(record_id),'INVALID_RECORD');return {...common('local-record'),...this.scope,record_id,record_kind:kind,local_schema:1};}
  #lockReason='explicit';
  get lockReason(){return this.#key?null:this.#lockReason;}
  #authorize(cap){
    if(!this.#key||cap!==this.#cap){const e=Object.assign(Error('VAULT_LOCKED'),{code:'VAULT_LOCKED'});e.lockReason=this.#key?'capability-mismatch':this.#lockReason;throw e;}
    const now=Date.now();if(now-this.#last>300000||now<this.#last){const reason=now<this.#last?'clock-regression':'idle-expired';this.lock(reason);const e=Object.assign(Error('VAULT_LOCKED'),{code:'VAULT_LOCKED'});e.lockReason=reason;throw e;}this.#last=now;
  }
  async #state(tx,cap){this.#authorize(cap);const s=metadata(await tx.get(),this.scope);verifyManifest(s,this.#keys.signing.publicKey);ensure(s.epoch===this.#epoch,'STALE_CAPABILITY');ensure(s.revision>=this.#revision,'ROLLBACK_QUARANTINE');this.#revision=s.revision;return s;}
  #load(frame,key){const p=openLocal(wire(frame),key,wire(frame.context));decode(frame.context.record_kind,bounded(p.data));return p;}
  async initialize(phrase,secrets,pins,registration){
    ensure(!this.#key,'VAULT_ALREADY_OPEN');decode('vault-secrets',bounded(secrets));ensure(secrets.group_keys.length===0,'INITIAL_GROUP_KEYS_FORBIDDEN');
    const key=randomKey(),context={...common('local-unlock'),...this.scope,wrapper_id:b64(sodium.randombytes_buf(16)),method:'argon2id13'},parameters={algorithm:'argon2id13',salt:b64(sodium.randombytes_buf(16)),opslimit:3,memlimit:67108864};
    let kek;
    try{
      kek=await phraseKek(phrase,wire(parameters));const wrapper=decode('phrase-wrapper',wrapLocalKey('phrase-wrapper',wire({context,parameters}),key,kek));
      const c=this.context('vault-secrets',this.vaultId),frame=decode('local-envelope',sealLocal(wire({...common('local-record-plaintext'),context:c,data:secrets}),key));
      const state={manifest:signManifest(this.scope,pins,this.vaultId,un64(secrets.device_signing_secret)),schema:1,scope:this.scope,epoch:1,revision:1,lease:null,rotation:null,wrappers:[wrapper],pins,vault_id:this.vaultId};metadata(state,this.scope);
      await this.store.transaction(true,async tx=>{ensure(!await tx.get(),'PROFILE_EXISTS');ensure(await tx.count()===0,'INTEGRITY_FAILURE');await tx.put({id:this.vaultId,frame});if(registration){const signing=un64(secrets.device_signing_secret),encryption=un64(secrets.device_encryption_secret);try{const device={device_id:this.scope.device_id,signing_key:b64(sodium.crypto_sign_ed25519_sk_to_pk(signing)),encryption_key:b64(sodium.crypto_scalarmult_base(encryption))},control=bootstrapControl(registration,pins,device),record_id=controlId(this.scope);await tx.put({id:record_id,frame:sealLifecycle(this.scope,pins,record_id,'device-control',control,key)});}finally{wipe(signing);wipe(encryption);}}await tx.set(state);});
      return {profile:this.scope,state:'locked'};
    }finally{wipe(key);wipe(kek);wipe(secrets);}
  }
  async info(){return this.store.transaction(false,async tx=>{const v=await tx.get();if(!v)return {state:'enrollment-required',profile:this.scope};const s=metadata(v,this.scope);return {state:this.#key?'unlocked':'locked',profile:this.scope,wrappers:s.wrappers.map(w=>({id:w.context.wrapper_id,method:w.context.method,credential_id:w.credential_id})),pins:s.pins};});}
  async unlock(phrase){
    ensure(!this.#busy,'VAULT_BUSY');this.#busy=true;const start=this.#epoch;let key,kek;
    try{
      const s=await this.store.transaction(false,async tx=>metadata(await tx.get(),this.scope)),w=s.wrappers.find(w=>w.context.method==='argon2id13');ensure(w,'PHRASE_UNAVAILABLE');
      kek=await phraseKek(phrase,wire(w.parameters));key=unwrapLocalKey('phrase-wrapper',wire(w),wire(descriptor(w)),kek);
      ensure(this.#epoch===start,'STALE_CAPABILITY');return await this.#activate(s,key);
    }finally{wipe(key);wipe(kek);this.#busy=false;}
  }
  async #activate(snapshot,key){
    let secret;
    try{
      const loaded=await this.store.transaction(false,async tx=>{const s=metadata(await tx.get(),this.scope);ensure(s.epoch===snapshot.epoch,'STALE_CAPABILITY');ensure(s.revision>=this.#revision,'ROLLBACK_QUARANTINE');const vault=await tx.read(s.vault_id);ensure(vault&&record(this.scope,vault.frame).context.record_kind==='vault-secrets'&&vault.frame.context.record_id===s.vault_id,'INTEGRITY_FAILURE');return {s,vault,secret:await this.#secretData(tx,s,key)};});
      secret=loaded.secret;
      const signingSecret=un64(secret.device_signing_secret),encryptionSecret=un64(secret.device_encryption_secret);
      verifyManifest(loaded.s,sodium.crypto_sign_ed25519_sk_to_pk(signingSecret));
      this.lock();this.#key=Uint8Array.from(key);this.#keys={signing:{privateKey:signingSecret,publicKey:sodium.crypto_sign_ed25519_sk_to_pk(signingSecret)},encryption:{privateKey:encryptionSecret,publicKey:sodium.crypto_scalarmult_base(encryptionSecret)}};
      this.#epoch=loaded.s.epoch;this.#revision=loaded.s.revision;this.#cap=b64(sodium.randombytes_buf(32));this.#last=Date.now();return {capability:this.#cap,epoch:String(this.#epoch),state:'unlocked'};
    }finally{wipe(secret);}
  }
  lock(reason='explicit'){this.#lockReason=reason;this.#notes?.close();this.#notes=undefined;this.#workflow?.close();this.#workflow=undefined;wipe(this.#key);wipe(this.#keys);this.#key=this.#keys=this.#cap=undefined;this.#epoch=(this.#epoch??0)+1;this.#last=0;}
  async globalLock(){this.lock();await this.store.transaction(true,async tx=>{const value=await tx.get();if(!value)return;const s=metadata(value,this.scope);s.epoch++;s.revision++;s.lease=null;await tx.set(s);});}
  async lease(cap){return this.store.transaction(true,async tx=>{const s=await this.#state(tx,cap),now=Date.now(),l=s.lease;if(l&&!(now>=l.issued&&(l.owner===this.owner||l.expires<=now))){const error=Error('WRITER_BUSY');error.vaultReason=now<l.issued?'clock-regression':'other-owner';error.vaultRemaining=Math.min(10000,Math.max(0,l.expires-now));throw error;}const fence=(l?.fence??0)+1;ensure(Number.isSafeInteger(fence),'RESOURCE_LIMIT');s.lease={owner:this.owner,fence,issued:now,expires:now+10000};s.revision++;await tx.set(s);this.#revision=s.revision;return String(fence);});}
  #fence(s,fence){const l=s.lease;ensure(l&&l.owner===this.owner&&String(l.fence)===fence&&Date.now()>=l.issued&&Date.now()<l.expires,'STALE_WRITER');}
  async save(cap,fence,values){
    this.#authorize(cap);ensure(Array.isArray(values)&&values.length>0&&values.length<=16,'RESOURCE_LIMIT');const frames=[];
    try{for(const v of values){ensure(v&&Object.keys(v).sort().join(',')==='data,id,kind'&&kinds.has(v.kind),'INVALID_RECORD');decode(v.kind,bounded(v.data));const context=this.context(v.kind,v.id);frames.push({id:v.id,frame:decode('local-envelope',sealLocal(wire({...common('local-record-plaintext'),context,data:v.data}),this.#key)),data:v.data});}
      ensure(new Set(frames.map(f=>f.id)).size===frames.length,'DUPLICATE_RECORD');
      await this.store.transaction(true,async tx=>{const s=await this.#state(tx,cap);this.#fence(s,fence);const count=await tx.count();let added=0;
        for(const f of frames){ensure(f.id!==s.vault_id&&!await this.#reserved(tx,f.id),'RESERVED_RECORD');const old=await tx.read(f.id);if(!old)added++;else{record(this.scope,old.frame);ensure(old.frame.context.record_kind===f.frame.context.record_kind,'LOCAL_CONTEXT_MISMATCH');const observed=this.#anchors.get(f.id);ensure(!observed||frameHash(old.frame)===observed,'ROLLBACK_QUARANTINE');if(f.frame.context.record_kind==='outbox'){const p=this.#load(old.frame,this.#key);try{ensure(p.data.attempt_id===f.data.attempt_id&&p.data.revision_id===f.data.revision_id&&p.data.attempt_digest===f.data.attempt_digest&&digest('bundle',wire(p.data.bundle))===digest('bundle',wire(f.data.bundle)),'IMMUTABLE_ATTEMPT');const transitions={QUEUED:['QUEUED','SENT_UNKNOWN','CONFLICT','REKEY_REQUIRED','ACCESS_LOST'],SENT_UNKNOWN:['SENT_UNKNOWN','COMMITTED','CONFLICT','REKEY_REQUIRED','ACCESS_LOST'],CONFLICT:['CONFLICT'],REKEY_REQUIRED:['REKEY_REQUIRED'],ACCESS_LOST:['ACCESS_LOST'],COMMITTED:['COMMITTED']};ensure(transitions[p.data.state].includes(f.data.state),'INVALID_OUTBOX_TRANSITION');}finally{wipe(p);}}}
          ensure(count+added<=100000,'RESOURCE_LIMIT');await tx.put({id:f.id,frame:f.frame});}
        this.#authorize(cap);this.#fence(s,fence);s.revision++;await tx.set(s);this.#revision=s.revision;});
      this.#authorize(cap);for(const f of frames)this.#anchors.set(f.id,frameHash(f.frame));return {state:'local-saved',records:frames.map(f=>f.id)};
    }finally{frames.forEach(f=>wipe(f.data));wipe(values);}
  }
  async read(cap,recordId,kind){
    ensure(kinds.has(kind),'SECRET_EXPORT_FORBIDDEN');return this.store.transaction(false,async tx=>{await this.#state(tx,cap);const row=await tx.read(recordId);ensure(row,'RECORD_NOT_FOUND');const f=record(this.scope,row.frame);ensure(f.context.record_id===recordId&&f.context.record_kind===kind,'LOCAL_CONTEXT_MISMATCH');const h=frameHash(f),known=this.#anchors.get(recordId);ensure(!known||known===h,'ROLLBACK_QUARANTINE');const p=this.#load(f,this.#key);this.#authorize(cap);this.#anchors.set(recordId,h);return p.data;});
  }
  async proof(cap,challenge,session_id){this.#authorize(cap);const s=await this.store.transaction(false,tx=>this.#state(tx,cap));ensure(challenge.context.device.device_id===this.scope.device_id&&challenge.context.intent==='device-proof','CHALLENGE_CONTEXT_MISMATCH');const p=possession(challenge,this.#keys,{...s.pins,session_id});this.#authorize(cap);return p;}
  async preparePrf(cap,credential_id){this.#authorize(cap);await this.store.transaction(false,tx=>this.#state(tx,cap));ensure(credential_id===null||(typeof credential_id==='string'&&credential_id.length>0&&credential_id.length<=1366&&b64(un64(credential_id))===credential_id),'PRF_UNAVAILABLE');const context={...common('local-unlock'),...this.scope,wrapper_id:b64(sodium.randombytes_buf(16)),method:'webauthn-prf'},d={context,credential_id,prf_salt:b64(sodium.randombytes_buf(32))},publicValue={id:context.wrapper_id,credential_id,salt:d.prf_salt,scope:this.scope};return publicValue;}
  async addPrf(cap,credential_id,prf,prepared){
    this.#authorize(cap);ensure(typeof credential_id==='string'&&credential_id.length<=1366&&prf instanceof Uint8Array&&prf.length===32,'PRF_UNAVAILABLE');
    ensure(prepared&&Object.keys(prepared).sort().join(',')==='credential_id,id,salt,scope'&&id(prepared.id)&&(prepared.credential_id===null||prepared.credential_id===credential_id)&&un64(prepared.salt).length===32&&b64(un64(prepared.salt))===prepared.salt&&same(prepared.scope,this.scope),'PRF_UNAVAILABLE');const context={...common('local-unlock'),...this.scope,wrapper_id:prepared.id,method:'webauthn-prf'},d={context,credential_id,prf_salt:prepared.salt};let kek;
    try{kek=await prfKek(wire(context),credential_id,un64(d.prf_salt),prf);const w=decode('prf-wrapper',wrapLocalKey('prf-wrapper',wire(d),this.#key,kek));await this.store.transaction(true,async tx=>{const s=await this.#state(tx,cap);ensure(s.wrappers.length<20&&!s.wrappers.some(x=>x.credential_id===credential_id),'WRAPPER_EXISTS');s.wrappers.push(w);s.revision++;await tx.set(s);this.#revision=s.revision;});return {wrapper_id:context.wrapper_id};}finally{wipe(prf);wipe(kek);}
  }
  async prfOptions(wrapper_id){return this.store.transaction(false,async tx=>{const s=metadata(await tx.get(),this.scope),w=s.wrappers.find(x=>x.context.wrapper_id===wrapper_id&&x.context.method==='webauthn-prf');ensure(w,'PRF_UNAVAILABLE');return {credential_id:w.credential_id,salt:w.prf_salt};});}
  async unlockPrf(wrapper_id,credential_id,prf){let key,kek;try{const s=await this.store.transaction(false,async tx=>metadata(await tx.get(),this.scope)),w=s.wrappers.find(x=>x.context.wrapper_id===wrapper_id&&x.context.method==='webauthn-prf');ensure(w&&w.credential_id===credential_id&&prf instanceof Uint8Array&&prf.length===32,'PRF_UNAVAILABLE');kek=await prfKek(wire(w.context),credential_id,un64(w.prf_salt),prf);key=unwrapLocalKey('prf-wrapper',wire(w),wire(descriptor(w)),kek);return await this.#activate(s,key);}finally{wipe(key);wipe(kek);wipe(prf);}}
  async removeWrapper(cap,wrapper_id,phrase){
    this.#authorize(cap);const snapshot=await this.store.transaction(false,tx=>this.#state(tx,cap));ensure(snapshot.wrappers.some(w=>w.context.wrapper_id===wrapper_id&&w.context.method==='webauthn-prf'),'PHRASE_FALLBACK_REQUIRED');
    const parameters={algorithm:'argon2id13',salt:b64(sodium.randombytes_buf(16)),opslimit:3,memlimit:67108864},context={...common('local-unlock'),...this.scope,wrapper_id:b64(sodium.randombytes_buf(16)),method:'argon2id13'},key=randomKey();let kek;
    try{kek=await phraseKek(phrase,wire(parameters));const wrapper=decode('phrase-wrapper',wrapLocalKey('phrase-wrapper',wire({context,parameters}),key,kek));
      await this.store.transaction(true,async tx=>{const s=await this.#state(tx,cap);ensure(s.revision===snapshot.revision,'STALE_WRITER');await tx.each(async row=>{const f=record(this.scope,row.frame);ensure(f.context.record_id===row.id,'LOCAL_CONTEXT_MISMATCH');let p;try{if(f.contract===CONTENT_PROFILE){await tx.put({id:row.id,frame:rotateContent(f,this.scope,s.pins,row.id,this.#key,key)});return;}const paged=f.contract==='p11-local-v1',note=f.contract==='p09-local-v1',additive=f.contract==='p08-local-v1';if(paged){await tx.put({id:row.id,frame:rotatePagedFrame(f,this.scope,s.pins,row.id,this.#key,key)});return;}p=note?openNoteLocal(f,this.scope,s.pins,row.id,f.context.record_kind,this.#key):additive?openLifecycle(f,this.scope,s.pins,row.id,f.context.record_kind,this.#key):this.#load(f,this.#key);const frame=note?sealNoteLocal(this.scope,s.pins,row.id,f.context.record_kind,p,key):additive?sealLifecycle(this.scope,s.pins,row.id,f.context.record_kind,p,key):decode('local-envelope',sealLocal(wire(p),key));await tx.put({id:row.id,frame});}finally{wipe(p);}});this.#authorize(cap);s.wrappers=[wrapper];s.epoch++;s.revision++;s.lease=null;await tx.set(s);this.#revision=s.revision;});this.#anchors.clear();this.lock();return {state:'locked',protection:'phrase-only',removed:'all-prf-wrappers'};
    }finally{wipe(key);wipe(kek);}
  }

  async #secretData(tx,s,key=this.#key){const row=await tx.read(s.vault_id);ensure(row,'INTEGRITY_FAILURE');return row.frame.contract==='p11-local-v1'?syncValue('secrets',await readPaged(row.frame,this.scope,s.pins,s.vault_id,'vault-secrets',key,id=>tx.read(id))):this.#load(row.frame,key).data;}
  async #addGroupKeys(tx,s,keys){const data=await this.#secretData(tx,s);try{for(const value of keys){const old=data.group_keys.find(k=>k.group_id===value.group_id&&k.key_epoch===value.key_epoch);ensure(value.service_id===this.scope.service_id&&(!old||(old.epoch_digest===value.epoch_digest&&old.group_secret===value.group_secret)),'INTEGRITY_FAILURE');if(!old)data.group_keys.push(structuredClone(value));}data.group_keys.sort((a,b)=>{const x=a.group_id+'/'+a.key_epoch.padStart(19,'0'),y=b.group_id+'/'+b.key_epoch.padStart(19,'0');return x<y?-1:x>y?1:0;});syncValue('secrets',data);const old=await tx.read(s.vault_id),frame=await this.#storePaged(tx,s.pins,s.vault_id,'vault-secrets',data,old.frame);await tx.put({id:s.vault_id,frame});}finally{wipe(data);}}
  async #publicControl(tx){const row=await tx.read(controlId(this.scope));if(!row)return null;const s=metadata(await tx.get(),this.scope);return openLifecycle(row.frame,this.scope,s.pins,controlId(this.scope),'device-control',this.#key);}
  async #reserved(tx,recordId){if(recordId===contentControlId(this.scope)||(await tx.read(recordId))?.frame.contract===CONTENT_PROFILE)return true;if(recordId===controlId(this.scope)||recordId===noteControlId(this.scope)||recordId===fileControlId(this.scope))return true;const files=await this.#fileControl(tx);if(files){for(const [id,kind]of fileIds(files)){if(id===recordId)return true;const row=await tx.read(id);if(row&&publicPartIds(row.frame,this.scope,(await tx.get()).pins,id,kind,this.#key).includes(recordId))return true;}}const c=await this.#publicControl(tx);if(c&&(c.pages.includes(recordId)||(c.staging?.pages??[]).includes(recordId)))return true;const n=await this.#noteControl(tx);return !!n&&this.#noteIds(n).has(recordId)||await this.#criticalPart(tx,recordId);}
  async #loadDevices(cap,includeSecrets=false){
    return this.store.transaction(false,async tx=>{const s=await this.#state(tx,cap),control=await this.#publicControl(tx),pages=[];let bytes=0;
      for(const pageId of control?.pages??[]){const row=await tx.read(pageId);ensure(row,'INTEGRITY_FAILURE');const page=openLifecycle(row.frame,this.scope,s.pins,pageId,'roster-page',this.#key);bytes+=wire(page.events).length;ensure(bytes<=33554432,'RESOURCE_LIMIT');pages.push(page.events);}
      const secrets=includeSecrets?await this.#secretData(tx,s):null;return {control,pages,secrets};});
  }
  async #persistDevices(cap,control,extra){
    ensure(control.pages.length<=1000&&(control.staging?.pages??[]).length<=1000&&wire(control).length<=262144,'RESOURCE_LIMIT');
    const committed=await this.store.transaction(true,async tx=>{const s=await this.#state(tx,cap);this.#fence(s,this.#workflowFence);const oldControl=await tx.read(controlId(this.scope));ensure((oldControl?frameHash(oldControl.frame):null)===this.#workflowHash,'STALE_WRITER');let controlHash;const put=async(recordId,data,kind)=>{const frame=sealLifecycle(this.scope,s.pins,recordId,kind,data,this.#key);await tx.put({id:recordId,frame});if(recordId===controlId(this.scope))controlHash=frameHash(frame);};
      if(extra.page){ensure(id(extra.page.id)&&extra.page.id!==s.vault_id&&extra.page.id!==controlId(this.scope)&&!await tx.read(extra.page.id),'RESERVED_RECORD');await put(extra.page.id,{purpose:'p08-roster-page',version:1,events:extra.page.events},'roster-page');}
      if(extra.addKeys)await this.#addGroupKeys(tx,s,extra.addKeys);
      for(const recordId of extra.deletePages??[]){ensure(id(recordId)&&recordId!==s.vault_id&&recordId!==controlId(this.scope)&&!control.pages.includes(recordId)&&!(control.staging?.pages??[]).includes(recordId),'RESERVED_RECORD');const row=await tx.read(recordId);if(row){openLifecycle(row.frame,this.scope,s.pins,recordId,'roster-page',this.#key);await tx.remove(recordId);}}
      ensure(await tx.count()<100000,'RESOURCE_LIMIT');await put(controlId(this.scope),control,'device-control');this.#fence(s,this.#workflowFence);s.revision++;await tx.set(s);return {revision:s.revision,controlHash};});this.#revision=committed.revision;this.#workflowHash=committed.controlHash;return {state:'local-saved'};
  }
  async devices(cap,operation,args){
    this.#authorize(cap);const {s,currentHash}=await this.store.transaction(false,async tx=>{const s=await this.#state(tx,cap),row=await tx.read(controlId(this.scope));return {s,currentHash:row?frameHash(row.frame):null};});
    if(this.#workflow&&currentHash!==this.#workflowHash){this.#workflow.close();this.#workflow=undefined;}this.#workflowHash=currentHash;this.#workflowFence=await this.lease(cap);
    this.#workflow??=new DeviceWorkflow({scope:this.scope,pins:s.pins,keys:this.#keys,anchor:this.#deviceAnchor,load:includeSecrets=>this.#loadDevices(cap,includeSecrets),persist:(control,extra)=>this.#persistDevices(cap,control,extra)});
    try{const result=await this.#workflow.command(operation,args);this.#authorize(cap);await this.store.transaction(false,tx=>this.#state(tx,cap));if(result?.head)this.#deviceAnchor=structuredClone(result.head);return result;}catch(e){this.#workflow?.close();this.#workflow=undefined;throw e;}
  }
  async #storePaged(tx,pins,id,kind,data,old){
    const prior=old?.contract==='p11-local-v1'?openManifest(old,this.scope,pins,id,kind,this.#key):null,prepared=preparePaged(this.scope,pins,id,kind,data,this.#key);
    try{for(const row of prepared.records){ensure(!await tx.read(row.id),'RESERVED_RECORD');await tx.put(row);}
    if(prior)for(const part of prior.parts)await tx.remove(part.record_id);
    return prepared.frame;}finally{if(prior?.private)prior.private.pending_key.group_secret='';}
  }
  async #criticalPart(tx,id){
    const s=metadata(await tx.get(),this.scope),root=await tx.read(noteControlId(this.scope));
    if(root?.frame.contract==='p11-local-v1'&&openManifest(root.frame,this.scope,s.pins,noteControlId(this.scope),'note-control',this.#key).parts.some(p=>p.record_id===id))return true;
    const vault=await tx.read(s.vault_id);if(vault?.frame.contract==='p11-local-v1'&&publicPartIds(vault.frame,this.scope,s.pins,s.vault_id,'vault-secrets',this.#key).includes(id))return true;
    const control=await this.#noteControl(tx);for(const ref of [...(control?.groups??[]),...[...this.#noteIds(control??{groups:[],drafts:[],attempts:[],witnesses:[]})].filter(([,kind])=>kind==='cache').map(([record_id])=>({record_id}))]){const row=await tx.read(ref.record_id);if(row?.frame.contract==='p11-local-v1'&&publicPartIds(row.frame,this.scope,s.pins,ref.record_id,row.frame.context.record_kind,this.#key).includes(id))return true;}
    return false;
  }
  async #noteControl(tx){
    const row=await tx.read(noteControlId(this.scope));if(!row)return null;const s=metadata(await tx.get(),this.scope);
    return row.frame.contract==='p11-local-v1'?noteValue('local-control',await readPaged(row.frame,this.scope,s.pins,noteControlId(this.scope),'note-control',this.#key,id=>tx.read(id))):openNoteLocal(row.frame,this.scope,s.pins,noteControlId(this.scope),'note-control',this.#key);
  }
  #noteIds(c){
    const refs=[...c.groups.map(x=>[x.record_id,'group-evidence']),...c.drafts.map(x=>[x.record_id,'draft']),...c.attempts.map(x=>[x.record_id,'outbox']),...c.witnesses.map(x=>[x.cache_id,'cache'])];
    for(const x of [...(c.sync?.stage?.items??[]),...(c.sync?.pending?.items??[])])refs.push([x.cache_id,'cache']);const map=new Map();for(const [id,kind]of refs){ensure(!map.has(id)||kind==='cache'&&map.get(id)==='cache','DUPLICATE_RECORD');map.set(id,kind);}return map;
  }
  async #noteRead(cap,id,kind){
    return this.store.transaction(false,async tx=>{const s=await this.#state(tx,cap),control=await this.#noteControl(tx);ensure(control&&this.#noteIds(control).get(id)===kind,'RESERVED_RECORD');const row=await tx.read(id);ensure(row,'RECORD_NOT_FOUND');const f=record(this.scope,row.frame);ensure(f.context.record_id===id&&f.context.record_kind===kind,'LOCAL_CONTEXT_MISMATCH');
      if(kind==='cache'&&f.contract==='p11-local-v1')return syncValue('header-evidence',await readPaged(f,this.scope,s.pins,id,kind,this.#key,p=>tx.read(p)));
      return kind==='group-evidence'?(f.contract==='p11-local-v1'?noteValue('local-evidence',await readPaged(f,this.scope,s.pins,id,kind,this.#key,p=>tx.read(p))):openNoteLocal(f,this.scope,s.pins,id,kind,this.#key)):this.#load(f,this.#key).data;
    });
  }
  async #persistNotes(cap,control,extra){
    noteValue('local-control',control);ensure(wire(control).length<=33554432,'RESOURCE_LIMIT');const ids=this.#noteIds(control);
    const committed=await this.store.transaction(true,async tx=>{
      const s=await this.#state(tx,cap);this.#fence(s,this.#notesFence);const old=await tx.read(noteControlId(this.scope));ensure((old?frameHash(old.frame):null)===this.#notesHash,'STALE_WRITER');
      const device=await this.#publicControl(tx),deviceIds=new Set([s.vault_id,controlId(this.scope),noteControlId(this.scope),...(device?.pages??[]),...(device?.staging?.pages??[])]);
      for(const [id]of ids)ensure(!deviceIds.has(id),'RESERVED_RECORD');
      const before=await this.#noteControl(tx),oldIds=before?this.#noteIds(before):new Map();
      const values=extra.records??[];ensure(values.length<=16&&new Set(values.map(v=>v.id)).size===values.length,'RESOURCE_LIMIT');
      for(const v of values){
        ensure(ids.get(v.id)===v.kind,'RESERVED_RECORD');const oldRow=await tx.read(v.id);ensure(!oldRow||oldIds.get(v.id)===v.kind,'RESERVED_RECORD');
        if(v.kind==='outbox'&&oldRow){const p=this.#load(oldRow.frame,this.#key);try{ensure(p.data.attempt_id===v.data.attempt_id&&p.data.revision_id===v.data.revision_id&&p.data.attempt_digest===v.data.attempt_digest&&digest('bundle',wire(p.data.bundle))===digest('bundle',wire(v.data.bundle)),'IMMUTABLE_ATTEMPT');const transitions={QUEUED:['QUEUED','SENT_UNKNOWN','CONFLICT','REKEY_REQUIRED','ACCESS_LOST'],SENT_UNKNOWN:['SENT_UNKNOWN','COMMITTED','CONFLICT','REKEY_REQUIRED','ACCESS_LOST'],CONFLICT:['CONFLICT'],REKEY_REQUIRED:['REKEY_REQUIRED'],ACCESS_LOST:['ACCESS_LOST'],COMMITTED:['COMMITTED']};ensure(transitions[p.data.state].includes(v.data.state),'INVALID_OUTBOX_TRANSITION');}finally{wipe(p);}}
        let frame;if(v.kind==='cache'&&v.data.purpose==='p11-header-evidence'){syncValue('header-evidence',v.data);frame=await this.#storePaged(tx,s.pins,v.id,v.kind,v.data,oldRow?.frame);}
        else if(v.kind==='group-evidence'){noteValue('local-evidence',v.data);frame=await this.#storePaged(tx,s.pins,v.id,v.kind,v.data,oldRow?.frame);}
        else{if(oldRow?.frame.contract==='p11-local-v1'){const prior=openManifest(oldRow.frame,this.scope,s.pins,v.id,v.kind,this.#key);for(const part of prior.parts)await tx.remove(part.record_id);}decode(v.kind,bounded(v.data));frame=decode('local-envelope',sealLocal(wire({...common('local-record-plaintext'),context:this.context(v.kind,v.id),data:v.data}),this.#key));}
        await tx.put({id:v.id,frame});
      }
      if(extra.addKeys)await this.#addGroupKeys(tx,s,extra.addKeys);
      for(const id of extra.retireDrafts??[]){ensure(oldIds.get(id)==='draft'&&!ids.has(id),'UNSYNCED_WORK_PROTECTED');const ref=before.drafts.find(d=>d.record_id===id),attempt=control.attempts.find(a=>a.draft_id===ref.draft_id&&a.state==='COMMITTED'&&a.source_digest===ref.saved_digest);ensure(attempt&&values.some(v=>v.kind==='outbox'&&v.data.attempt_id===attempt.attempt_id&&v.data.state==='COMMITTED'),'UNSYNCED_WORK_PROTECTED');const old=await tx.read(id);ensure(old,'RECORD_NOT_FOUND');decode('draft',bounded(this.#load(old.frame,this.#key).data));await tx.remove(id);}
      for(const [id,kind]of oldIds)if(kind==='cache'&&!ids.has(id)){const row=await tx.read(id);ensure(row&&row.frame.context.record_kind==='cache','INTEGRITY_FAILURE');if(row.frame.contract==='p11-local-v1')for(const part of openManifest(row.frame,this.scope,s.pins,id,'cache',this.#key).parts)await tx.remove(part.record_id);await tx.remove(id);}
      const frame=await this.#storePaged(tx,s.pins,noteControlId(this.scope),'note-control',control,old?.frame);await tx.put({id:noteControlId(this.scope),frame});ensure(await tx.count()<=100000,'RESOURCE_LIMIT');this.#authorize(cap);this.#fence(s,this.#notesFence);s.revision++;await tx.set(s);return {revision:s.revision,hash:frameHash(frame)};
    });this.#revision=committed.revision;this.#notesHash=committed.hash;return {state:'local-saved'};
  }
  notes(cap,operation,args=[]){
    let copied;
    if(operation==='files'&&args[1]?.source instanceof Blob){const {source,...control}=args[1];copied=[args[0],{...structuredClone(control),source}];}
    else copied=structuredClone(args);
    const run=this.#notesTail.then(()=>this.#notesCommand(cap,operation,copied));this.#notesTail=run.catch(()=>{});return run;
  }
  async #fileControl(tx){
    const id=fileControlId(this.scope),row=await tx.read(id);if(!row)return null;const s=metadata(await tx.get(),this.scope);const control=fileValue('file-control',await readPaged(row.frame,this.scope,s.pins,id,'file-control',this.#key,p=>tx.read(p)));ensure(control.id===id,'INTEGRITY_FAILURE');return control;
  }
  #fileHash;
  #filesAdapter(cap){return {
    readControl:()=>this.store.transaction(false,async tx=>{await this.#state(tx,cap);return this.#fileControl(tx);}),
    load:()=>this.store.transaction(false,async tx=>{await this.#state(tx,cap);const row=await tx.read(fileControlId(this.scope));this.#fileHash=row?frameHash(row.frame):null;return this.#fileControl(tx);}),
    readRecord:(id,kind)=>this.store.transaction(false,async tx=>{const s=await this.#state(tx,cap),c=await this.#fileControl(tx);ensure(c&&fileIds(c).get(id)===kind,'RESERVED_RECORD');const row=await tx.read(id);ensure(row,'RECORD_NOT_FOUND');return fileValue(kind,await readPaged(row.frame,this.scope,s.pins,id,kind,this.#key,p=>tx.read(p)));}),
    persist:async(control,values)=>{
      const fence=await this.lease(cap);const result=await this.store.transaction(true,async tx=>{const s=await this.#state(tx,cap);this.#fence(s,fence);const id=fileControlId(this.scope),old=await tx.read(id);ensure((old?frameHash(old.frame):null)===this.#fileHash,'STALE_WRITER');fileValue('file-control',control);ensure(control.id===id,'INTEGRITY_FAILURE');const before=await this.#fileControl(tx),allowed=fileIds(control),prior=before?fileIds(before):new Map();
       for(const v of values){fileValue(v.kind,v.data);ensure(allowed.get(v.id)===v.kind&&['file-transfer','file-evidence'].includes(v.kind)&&v.data.purpose==='p12-'+v.kind&&wire(v.data).length<=262144,'INVALID_FILE_DTO');const row=await tx.read(v.id);ensure(!row||prior.get(v.id)===v.kind,'RESERVED_RECORD');await tx.put({id:v.id,frame:await this.#storePaged(tx,s.pins,v.id,v.kind,v.data,row?.frame)});}
       const frame=await this.#storePaged(tx,s.pins,id,'file-control',control,old?.frame);await tx.put({id,frame});s.file_profile='p12-files-v1';s.manifest=signManifest(this.scope,s.pins,s.vault_id,this.#keys.signing.privateKey,s.file_profile,s.content_profile);s.revision++;await tx.set(s);this.#authorize(cap);this.#fence(s,fence);return {revision:s.revision,hash:frameHash(frame)};
      });this.#revision=result.revision;this.#fileHash=result.hash;
    },
  };}
  #contentHash;
  async #contentControl(tx) {
    const id=contentControlId(this.scope),row=await tx.read(id);if(!row)return null;
    const state=metadata(await tx.get(),this.scope);ensure(state.content_profile===CONTENT_PROFILE,'INTEGRITY_FAILURE');
    return contentState(await readContent(row.frame,this.scope,state.pins,id,'content-control',this.#key,p=>tx.read(p)));
  }
  async #storeContent(tx,pins,id,kind,data,old) {
    const previous=old?contentManifest(old,this.scope,pins,id,kind,this.#key):null;
    const prepared=prepareContent(this.scope,pins,id,kind,data,this.#key);
    for(const row of prepared.records){ensure(!await tx.read(row.id),'RESERVED_RECORD');await tx.put(row);}
    if(previous)for(const part of previous.parts)await tx.remove(part.record_id);
    return prepared.frame;
  }
  #contentAdapter(cap) {return {
    load:()=>this.store.transaction(false,async tx=>{
      await this.#state(tx,cap);const row=await tx.read(contentControlId(this.scope));this.#contentHash=row?frameHash(row.frame):null;
      const value=await this.#contentControl(tx);return value?{...value,source_stale:value.source_note_hash!==this.#notesHash}:null;
    }),
    read:(id,kind)=>this.store.transaction(false,async tx=>{
      const state=await this.#state(tx,cap),control=await this.#contentControl(tx);
      ensure(control&&contentIds(control).get(id)===kind,'RESERVED_RECORD');const row=await tx.read(id);ensure(row,'RECORD_NOT_FOUND');
      return readContent(row.frame,this.scope,state.pins,id,kind,this.#key,p=>tx.read(p));
    }),
    persist:async(control,records=[],remove=[])=>{
      const value=structuredClone(contentState(control));delete value.source_stale;value.source_note_hash=this.#notesHash;
      const ids=contentIds(value),fence=this.#notesFence;
      const result=await this.store.transaction(true,async tx=>{
        const state=await this.#state(tx,cap);this.#fence(state,fence);
        const root=contentControlId(this.scope),old=await tx.read(root);ensure((old?frameHash(old.frame):null)===this.#contentHash,'STALE_WRITER');
        const prior=await this.#contentControl(tx),before=prior?contentIds(prior):new Map();
        ensure(records.length<=32&&new Set(records.map(r=>r.id)).size===records.length,'RESOURCE_LIMIT');
        for(const row of records){
          ensure(ids.get(row.id)===row.kind&&row.id!==state.vault_id&&![root,controlId(this.scope),noteControlId(this.scope),fileControlId(this.scope)].includes(row.id),'RESERVED_RECORD');
          const existing=await tx.read(row.id);ensure(!existing||before.get(row.id)===row.kind,'RESERVED_RECORD');
          const frame=await this.#storeContent(tx,state.pins,row.id,row.kind,row.data,existing?.frame);await tx.put({id:row.id,frame});
        }
        for(const id of remove){
          ensure(before.get(id)==='search-page'&&!ids.has(id),'UNSYNCED_WORK_PROTECTED');const row=await tx.read(id);ensure(row,'RECORD_NOT_FOUND');
          for(const part of contentManifest(row.frame,this.scope,state.pins,id,'search-page',this.#key).parts)await tx.remove(part.record_id);await tx.remove(id);
        }
        const frame=await this.#storeContent(tx,state.pins,root,'content-control',value,old?.frame);await tx.put({id:root,frame});
        state.content_profile=CONTENT_PROFILE;state.manifest=signManifest(this.scope,state.pins,state.vault_id,this.#keys.signing.privateKey,state.file_profile,state.content_profile);
        ensure(await tx.count()<=100000,'RESOURCE_LIMIT');this.#authorize(cap);this.#fence(state,fence);state.revision++;await tx.set(state);
        return {revision:state.revision,hash:frameHash(frame)};
      });this.#revision=result.revision;this.#contentHash=result.hash;
    },
  };}
  async #notesCommand(cap,operation,args=[]){
    this.#authorize(cap);ensure(typeof operation==='string'&&Array.isArray(args)&&args.length<=3&&(operation==='files'?args.length===2:wire(args).length<=4194304),'RESOURCE_LIMIT');
    const {s,currentHash}=await this.store.transaction(false,async tx=>{const s=await this.#state(tx,cap),row=await tx.read(noteControlId(this.scope));return {s,currentHash:row?frameHash(row.frame):null};});
    if(this.#notes&&currentHash!==this.#notesHash){this.#notes.close();this.#notes=undefined;}this.#notesHash=currentHash;this.#notesFence=await this.lease(cap);
    this.#notes??=new NotesWorkflow({scope:this.scope,pins:s.pins,keys:this.#keys,load:()=>this.store.transaction(false,async tx=>{await this.#state(tx,cap);return this.#noteControl(tx);}),read:(id,kind)=>this.#noteRead(cap,id,kind),persist:(c,e)=>this.#persistNotes(cap,c,e),devices:()=>this.#loadDevices(cap,false),secrets:async()=>{const loaded=await this.#loadDevices(cap,true);return loaded.secrets;},files:this.#filesAdapter(cap),content:this.#contentAdapter(cap)});
    try{const result=structuredClone(await this.#notes.command(operation,args));this.#authorize(cap);await this.store.transaction(false,tx=>this.#state(tx,cap));return result;}catch(e){this.#notes?.close();this.#notes=undefined;throw e;}
  }
  async evict(cap,fence,recordId){return this.store.transaction(true,async tx=>{const s=await this.#state(tx,cap);this.#fence(s,fence);ensure(recordId!==s.vault_id&&!await this.#reserved(tx,recordId),'RESERVED_RECORD');const r=await tx.read(recordId);ensure(r,'RECORD_NOT_FOUND');ensure(record(this.scope,r.frame).context.record_kind==='cache','UNSYNCED_WORK_PROTECTED');await tx.remove(recordId);s.revision++;await tx.set(s);this.#revision=s.revision;this.#anchors.delete(recordId);return {state:'cache-evicted'};});}
  async close(){this.lock();this.store.close();}
}
