// Long-lived keys stay in the dedicated worker. No command returns L or device secrets.
import {sodium,b64,un64,randomKey,hash,Buffer} from '../adapters/primitives.mjs';
import {phraseKek,prfKek,wrapLocalKey,unwrapLocalKey,sealLocal,openLocal} from '../adapters/local.mjs';
import {decode,common,encode,digest} from '../adapters/codecs/protocol-codec.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {signManifest,verifyManifest} from './manifest.mjs';
import {possession} from '../auth-client.mjs';
import {ensure,fail,id,scope,record,metadata,same} from './store.mjs';
const kinds=new Set(['cache','search','draft','outbox','transfer']);
const bounded=data=>{const bytes=wire(data);ensure(bytes.length<=4194304,'RESOURCE_LIMIT');return bytes;};
function wipe(v){if(v instanceof Uint8Array)sodium.memzero(v);else if(v&&typeof v==='object'){for(const k of Object.keys(v)){wipe(v[k]);if(typeof v[k]==='string')v[k]='';}}}
const frameHash=f=>hash(encode('local-envelope',wire(f)));
const descriptor=w=>{const {nonce,ciphertext,...d}=w;return d;};
export class VaultEngine {
  #key;#keys;#cap;#epoch;#last=0;#revision=0;#anchors=new Map();#busy=false;
  constructor(store){this.store=store;this.scope=scope(store.scope);this.owner=b64(sodium.randombytes_buf(16));this.vaultId=b64(sodium.randombytes_buf(16));}
  context(kind,record_id){ensure(id(record_id),'INVALID_RECORD');return {...common('local-record'),...this.scope,record_id,record_kind:kind,local_schema:1};}
  #authorize(cap){ensure(this.#key&&cap===this.#cap,'VAULT_LOCKED');if(Date.now()-this.#last>300000||Date.now()<this.#last){this.lock();fail('VAULT_LOCKED');}this.#last=Date.now();}
  async #state(tx,cap){this.#authorize(cap);const s=metadata(await tx.get(),this.scope);verifyManifest(s,this.#keys.signing.publicKey);ensure(s.epoch===this.#epoch,'STALE_CAPABILITY');ensure(s.revision>=this.#revision,'ROLLBACK_QUARANTINE');this.#revision=s.revision;return s;}
  #load(frame,key){const p=openLocal(wire(frame),key,wire(frame.context));decode(frame.context.record_kind,bounded(p.data));return p;}
  async initialize(phrase,secrets,pins){
    ensure(!this.#key,'VAULT_ALREADY_OPEN');decode('vault-secrets',bounded(secrets));ensure(secrets.group_keys.length===0,'INITIAL_GROUP_KEYS_FORBIDDEN');
    const key=randomKey(),context={...common('local-unlock'),...this.scope,wrapper_id:b64(sodium.randombytes_buf(16)),method:'argon2id13'},parameters={algorithm:'argon2id13',salt:b64(sodium.randombytes_buf(16)),opslimit:3,memlimit:67108864};
    let kek;
    try{
      kek=await phraseKek(phrase,wire(parameters));const wrapper=decode('phrase-wrapper',wrapLocalKey('phrase-wrapper',wire({context,parameters}),key,kek));
      const c=this.context('vault-secrets',this.vaultId),frame=decode('local-envelope',sealLocal(wire({...common('local-record-plaintext'),context:c,data:secrets}),key));
      const state={manifest:signManifest(this.scope,pins,this.vaultId,un64(secrets.device_signing_secret)),schema:1,scope:this.scope,epoch:1,revision:1,lease:null,rotation:null,wrappers:[wrapper],pins,vault_id:this.vaultId};metadata(state,this.scope);
      await this.store.transaction(true,async tx=>{ensure(!await tx.get(),'PROFILE_EXISTS');ensure(await tx.count()===0,'INTEGRITY_FAILURE');await tx.put({id:this.vaultId,frame});await tx.set(state);});
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
      const loaded=await this.store.transaction(false,async tx=>{const s=metadata(await tx.get(),this.scope);ensure(s.epoch===snapshot.epoch,'STALE_CAPABILITY');ensure(s.revision>=this.#revision,'ROLLBACK_QUARANTINE');const vault=await tx.read(s.vault_id);ensure(vault&&record(this.scope,vault.frame).context.record_kind==='vault-secrets'&&vault.frame.context.record_id===s.vault_id,'INTEGRITY_FAILURE');return {s,vault};});
      secret=this.#load(loaded.vault.frame,key).data;
      const signingSecret=un64(secret.device_signing_secret),encryptionSecret=un64(secret.device_encryption_secret);
      verifyManifest(loaded.s,sodium.crypto_sign_ed25519_sk_to_pk(signingSecret));
      this.lock();this.#key=Uint8Array.from(key);this.#keys={signing:{privateKey:signingSecret,publicKey:sodium.crypto_sign_ed25519_sk_to_pk(signingSecret)},encryption:{privateKey:encryptionSecret,publicKey:sodium.crypto_scalarmult_base(encryptionSecret)}};
      this.#epoch=loaded.s.epoch;this.#revision=loaded.s.revision;this.#cap=b64(sodium.randombytes_buf(32));this.#last=Date.now();return {capability:this.#cap,epoch:String(this.#epoch),state:'unlocked'};
    }finally{wipe(secret);}
  }
  lock(){wipe(this.#key);wipe(this.#keys);this.#key=this.#keys=this.#cap=undefined;this.#epoch=(this.#epoch??0)+1;this.#last=0;}
  async globalLock(){this.lock();await this.store.transaction(true,async tx=>{const value=await tx.get();if(!value)return;const s=metadata(value,this.scope);s.epoch++;s.revision++;s.lease=null;await tx.set(s);});}
  async lease(cap){return this.store.transaction(true,async tx=>{const s=await this.#state(tx,cap),now=Date.now(),l=s.lease;ensure(!l||(now>=l.issued&&(l.owner===this.owner||l.expires<=now)),'WRITER_BUSY');const fence=(l?.fence??0)+1;ensure(Number.isSafeInteger(fence),'RESOURCE_LIMIT');s.lease={owner:this.owner,fence,issued:now,expires:now+10000};s.revision++;await tx.set(s);this.#revision=s.revision;return String(fence);});}
  #fence(s,fence){const l=s.lease;ensure(l&&l.owner===this.owner&&String(l.fence)===fence&&Date.now()>=l.issued&&Date.now()<l.expires,'STALE_WRITER');}
  async save(cap,fence,values){
    this.#authorize(cap);ensure(Array.isArray(values)&&values.length>0&&values.length<=16,'RESOURCE_LIMIT');const frames=[];
    try{for(const v of values){ensure(v&&Object.keys(v).sort().join(',')==='data,id,kind'&&kinds.has(v.kind),'INVALID_RECORD');decode(v.kind,bounded(v.data));const context=this.context(v.kind,v.id);frames.push({id:v.id,frame:decode('local-envelope',sealLocal(wire({...common('local-record-plaintext'),context,data:v.data}),this.#key)),data:v.data});}
      ensure(new Set(frames.map(f=>f.id)).size===frames.length,'DUPLICATE_RECORD');
      await this.store.transaction(true,async tx=>{const s=await this.#state(tx,cap);this.#fence(s,fence);const count=await tx.count();let added=0;
        for(const f of frames){ensure(f.id!==s.vault_id,'RESERVED_RECORD');const old=await tx.read(f.id);if(!old)added++;else{record(this.scope,old.frame);ensure(old.frame.context.record_kind===f.frame.context.record_kind,'LOCAL_CONTEXT_MISMATCH');const observed=this.#anchors.get(f.id);ensure(!observed||frameHash(old.frame)===observed,'ROLLBACK_QUARANTINE');if(f.frame.context.record_kind==='outbox'){const p=this.#load(old.frame,this.#key);try{ensure(p.data.attempt_id===f.data.attempt_id&&p.data.revision_id===f.data.revision_id&&p.data.attempt_digest===f.data.attempt_digest&&digest('bundle',wire(p.data.bundle))===digest('bundle',wire(f.data.bundle)),'IMMUTABLE_ATTEMPT');const transitions={QUEUED:['QUEUED','SENT_UNKNOWN','CONFLICT','REKEY_REQUIRED','ACCESS_LOST'],SENT_UNKNOWN:['SENT_UNKNOWN','COMMITTED','CONFLICT','REKEY_REQUIRED','ACCESS_LOST'],CONFLICT:['CONFLICT'],REKEY_REQUIRED:['REKEY_REQUIRED'],ACCESS_LOST:['ACCESS_LOST'],COMMITTED:['COMMITTED']};ensure(transitions[p.data.state].includes(f.data.state),'INVALID_OUTBOX_TRANSITION');}finally{wipe(p);}}}
          ensure(count+added<=100000,'RESOURCE_LIMIT');await tx.put({id:f.id,frame:f.frame});}
        this.#authorize(cap);this.#fence(s,fence);s.revision++;await tx.set(s);this.#revision=s.revision;});
      this.#authorize(cap);for(const f of frames)this.#anchors.set(f.id,frameHash(f.frame));return {state:'local-saved',records:frames.map(f=>f.id)};
    }finally{frames.forEach(f=>wipe(f.data));wipe(values);}
  }
  async read(cap,recordId,kind){
    ensure(kinds.has(kind),'SECRET_EXPORT_FORBIDDEN');return this.store.transaction(false,async tx=>{await this.#state(tx,cap);const row=await tx.read(recordId);ensure(row,'RECORD_NOT_FOUND');const f=record(this.scope,row.frame);ensure(f.context.record_id===recordId&&f.context.record_kind===kind,'LOCAL_CONTEXT_MISMATCH');const h=frameHash(f),known=this.#anchors.get(recordId);ensure(!known||known===h,'ROLLBACK_QUARANTINE');const p=this.#load(f,this.#key);this.#authorize(cap);this.#anchors.set(recordId,h);return p.data;});
  }
  async proof(cap,challenge,session_id){this.#authorize(cap);const s=await this.store.transaction(false,tx=>this.#state(tx,cap));ensure(challenge.context.device.device_id===this.scope.device_id&&challenge.context.intent==='device-proof','CHALLENGE_CONTEXT_MISMATCH');const p=possession(challenge,this.#keys,{...s.pins,session_id});this.#authorize(cap);return p;}
  async preparePrf(cap,credential_id){this.#authorize(cap);await this.store.transaction(false,tx=>this.#state(tx,cap));ensure(typeof credential_id==='string'&&credential_id.length>0&&credential_id.length<=1366&&b64(un64(credential_id))===credential_id,'PRF_UNAVAILABLE');const context={...common('local-unlock'),...this.scope,wrapper_id:b64(sodium.randombytes_buf(16)),method:'webauthn-prf'},d={context,credential_id,prf_salt:b64(sodium.randombytes_buf(32))},publicValue={id:context.wrapper_id,credential_id,salt:d.prf_salt,scope:this.scope};return publicValue;}
  async addPrf(cap,credential_id,prf,prepared){
    this.#authorize(cap);ensure(typeof credential_id==='string'&&credential_id.length<=1366&&prf instanceof Uint8Array&&prf.length===32,'PRF_UNAVAILABLE');
    ensure(prepared&&Object.keys(prepared).sort().join(',')==='credential_id,id,salt,scope'&&id(prepared.id)&&prepared.credential_id===credential_id&&un64(prepared.salt).length===32&&b64(un64(prepared.salt))===prepared.salt&&same(prepared.scope,this.scope),'PRF_UNAVAILABLE');const context={...common('local-unlock'),...this.scope,wrapper_id:prepared.id,method:'webauthn-prf'},d={context,credential_id,prf_salt:prepared.salt};let kek;
    try{kek=await prfKek(wire(context),credential_id,un64(d.prf_salt),prf);const w=decode('prf-wrapper',wrapLocalKey('prf-wrapper',wire(d),this.#key,kek));await this.store.transaction(true,async tx=>{const s=await this.#state(tx,cap);ensure(s.wrappers.length<20&&!s.wrappers.some(x=>x.credential_id===credential_id),'WRAPPER_EXISTS');s.wrappers.push(w);s.revision++;await tx.set(s);this.#revision=s.revision;});return {wrapper_id:context.wrapper_id};}finally{wipe(prf);wipe(kek);}
  }
  async prfOptions(wrapper_id){return this.store.transaction(false,async tx=>{const s=metadata(await tx.get(),this.scope),w=s.wrappers.find(x=>x.context.wrapper_id===wrapper_id&&x.context.method==='webauthn-prf');ensure(w,'PRF_UNAVAILABLE');return {credential_id:w.credential_id,salt:w.prf_salt};});}
  async unlockPrf(wrapper_id,credential_id,prf){let key,kek;try{const s=await this.store.transaction(false,async tx=>metadata(await tx.get(),this.scope)),w=s.wrappers.find(x=>x.context.wrapper_id===wrapper_id&&x.context.method==='webauthn-prf');ensure(w&&w.credential_id===credential_id&&prf instanceof Uint8Array&&prf.length===32,'PRF_UNAVAILABLE');kek=await prfKek(wire(w.context),credential_id,un64(w.prf_salt),prf);key=unwrapLocalKey('prf-wrapper',wire(w),wire(descriptor(w)),kek);return await this.#activate(s,key);}finally{wipe(key);wipe(kek);wipe(prf);}}
  async removeWrapper(cap,wrapper_id,phrase){
    this.#authorize(cap);const snapshot=await this.store.transaction(false,tx=>this.#state(tx,cap));ensure(snapshot.wrappers.some(w=>w.context.wrapper_id===wrapper_id&&w.context.method==='webauthn-prf'),'PHRASE_FALLBACK_REQUIRED');
    const parameters={algorithm:'argon2id13',salt:b64(sodium.randombytes_buf(16)),opslimit:3,memlimit:67108864},context={...common('local-unlock'),...this.scope,wrapper_id:b64(sodium.randombytes_buf(16)),method:'argon2id13'},key=randomKey();let kek;
    try{kek=await phraseKek(phrase,wire(parameters));const wrapper=decode('phrase-wrapper',wrapLocalKey('phrase-wrapper',wire({context,parameters}),key,kek));
      await this.store.transaction(true,async tx=>{const s=await this.#state(tx,cap);ensure(s.revision===snapshot.revision,'STALE_WRITER');await tx.each(async row=>{const f=record(this.scope,row.frame);ensure(f.context.record_id===row.id,'LOCAL_CONTEXT_MISMATCH');let p;try{p=this.#load(f,this.#key);const frame=decode('local-envelope',sealLocal(wire(p),key));await tx.put({id:row.id,frame});}finally{wipe(p);}});this.#authorize(cap);s.wrappers=[wrapper];s.epoch++;s.revision++;s.lease=null;await tx.set(s);this.#revision=s.revision;});this.#anchors.clear();this.lock();return {state:'locked',protection:'phrase-only',removed:'all-prf-wrappers'};
    }finally{wipe(key);wipe(kek);}
  }
  async evict(cap,fence,recordId){return this.store.transaction(true,async tx=>{const s=await this.#state(tx,cap);this.#fence(s,fence);ensure(recordId!==s.vault_id,'RESERVED_RECORD');const r=await tx.read(recordId);ensure(r,'RECORD_NOT_FOUND');ensure(record(this.scope,r.frame).context.record_kind==='cache','UNSYNCED_WORK_PROTECTED');await tx.remove(recordId);s.revision++;await tx.set(s);this.#revision=s.revision;this.#anchors.delete(recordId);return {state:'cache-evicted'};});}
  async close(){this.lock();this.store.close();}
}
