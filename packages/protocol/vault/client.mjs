import {releaseKdf} from './kdf.mjs';
import {IndexedVault,metadata,ensure,name,scope} from './store.mjs';
// UI receives only an opaque capability and display data. Lock masks synchronously,
// fences every pending result and broadcasts before waiting for encrypted durability.
export class LocalVault {
  #worker;#pending=new Map();#id=0;#generation=0;#cap;#ready;#bus;#profile;#timer;#closed=false;#client;#needsOpen=false;#initReject;#initTimer;#epoch;
  constructor(url,mask=()=>{}){
    this.mask=mask;this.url=url;this.#spawn();
    this.hide=()=>{if(document.hidden)this.lock().catch(()=>{});};this.pagehide=()=>{this.lock().finally(()=>this.close()).catch(()=>{});};
    document.addEventListener('visibilitychange',this.hide);addEventListener('pagehide',this.pagehide);
  }
  #spawn(){
    this.#client=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
    this.#worker=new Worker(this.url,{type:'module'});this.#ready=new Promise((resolve,reject)=>{this.#initReject=reject;this.#initTimer=setTimeout(()=>{reject(Error('WORKER_INIT_TIMEOUT'));this.close();},30000);
      this.#worker.onmessage=async({data:r})=>{if(r?.version!==1)return;if(r.status==='READY'){clearTimeout(this.#initTimer);resolve();return;}const p=this.#pending.get(r.id);if(!p)return;this.#pending.delete(r.id);clearTimeout(p.timer);try{ensure(r.generation===this.#generation,'STALE_CAPABILITY');if(r.error)throw Error(r.error);if(this.#cap&&this.#epoch&&this.#profile&&['read','proof','save','addPrf'].includes(p.op)){const store=await new IndexedVault(this.#profile).open();try{const e=await store.transaction(false,async tx=>metadata(await tx.get(),this.#profile).epoch);ensure(String(e)===this.#epoch&&r.generation===this.#generation,'STALE_CAPABILITY');}finally{store.close();}}p.resolve(r.result);}catch(e){p.reject(e);}};
      this.#worker.onerror=()=>{reject(Error('WORKER_FAILED'));this.close();};});this.#ready.catch(()=>{});
  }
  #disposeWorker(){clearTimeout(this.#initTimer);this.#initReject?.(Error('STALE_CAPABILITY'));this.#worker?.terminate();this.#worker=null;this.#ready=null;this.#needsOpen=!!this.#profile;}
  async call(op,args=[]){
    ensure(!this.#closed,'WORKER_CLOSED');if(!this.#worker)this.#spawn();await this.#ready;if(this.#needsOpen&&this.#profile&&op!=='open'){this.#needsOpen=false;await this.call('open',[this.#profile]);}ensure(!this.#closed,'WORKER_CLOSED');ensure(this.#pending.size<20,'RESOURCE_LIMIT');return new Promise((resolve,reject)=>{const id=++this.#id,generation=this.#generation,timer=setTimeout(()=>{this.#pending.delete(id);reject(Error('WORKER_TIMEOUT'));this.close();},120000);this.#pending.set(id,{resolve,reject,timer,op});try{this.#worker.postMessage({version:1,id,generation,op,args,client:this.#client});}catch{clearTimeout(timer);this.#pending.delete(id);reject(Error('INVALID_VAULT_COMMAND'));}});
  }
  async open(profile){this.#profile=scope(profile);this.#bus?.close();this.#bus=typeof BroadcastChannel==='function'?new BroadcastChannel(name(this.#profile)):null;this.#bus&&(this.#bus.onmessage=({data})=>{if(data?.version===1&&data.event==='lock'&&data.profile===name(this.#profile)){this.#invalidate();const client=this.#client;this.#disposeWorker();releaseKdf(client).catch(()=>{});}});this.#cap=undefined;this.#epoch=undefined;this.#needsOpen=false;return this.call('open',[this.#profile]);}
  #invalidate(){this.#cap=undefined;this.#epoch=undefined;this.#generation++;this.mask();clearTimeout(this.#timer);for(const p of this.#pending.values()){clearTimeout(p.timer);p.reject(Error('STALE_CAPABILITY'));}this.#pending.clear();}
  #touch(){clearTimeout(this.#timer);this.#timer=setTimeout(()=>this.lock().catch(()=>{}),300000);}
  async unlock(phrase){ensure(!document.hidden,'RESUME_REQUIRED');const r=await this.call('unlock',[phrase]);ensure(!document.hidden,'RESUME_REQUIRED');this.#cap=r.capability;this.#epoch=r.epoch;this.#touch();return {state:'unlocked'};}
  async unlockPrf(wrapper,credential,prf){ensure(!document.hidden,'RESUME_REQUIRED');const r=await this.call('unlockPrf',[wrapper,credential,prf]);this.#cap=r.capability;this.#epoch=r.epoch;this.#touch();return {state:'unlocked'};}
  async lock(){this.#invalidate();const client=this.#client,profile=this.#profile;this.#disposeWorker();this.#bus?.postMessage({version:1,event:'lock',profile:profile?name(profile):null});await releaseKdf(client);if(profile){const store=await new IndexedVault(profile).open();try{await store.transaction(true,async tx=>{const v=await tx.get();if(!v)return;const s=metadata(v,profile);s.epoch++;s.revision++;s.lease=null;await tx.set(s);});}finally{store.close();}}return {state:'locked'};}
  async saveAndLock(values){await this.save(values);return this.lock();}
  async save(values){this.#touch();const fence=await this.call('lease',[this.#cap]);return this.call('save',[this.#cap,fence,values]);}
  read(id,kind){this.#touch();return this.call('read',[this.#cap,id,kind]);}
  proof(challenge,session){this.#touch();return this.call('proof',[this.#cap,challenge,session]);}
  preparePrf(credential){return this.call('preparePrf',[this.#cap,credential]);}
  addPrf(credential,prf,prepared){return this.call('addPrf',[this.#cap,credential,prf,prepared]);}
  async removeWrapper(id,phrase){const r=await this.call('removeWrapper',[this.#cap,id,phrase]);await this.lock();return r;}
  close(){if(this.#closed)return;this.lock().catch(()=>{});this.#closed=true;const client=this.#client;this.#disposeWorker();releaseKdf(client).catch(()=>{});this.#bus?.close();document.removeEventListener('visibilitychange',this.hide);removeEventListener('pagehide',this.pagehide);}
}
// A credential prompt starts while locked. A hidden result cannot unlock; the UI
// offers explicit continuation while visible, never an automatic prompt loop.
export async function credentialPrf(credential_id,salt,rpId){
  ensure(rpId===location.hostname,'INVALID_RP');ensure(navigator.credentials&&globalThis.PublicKeyCredential,'PRF_UNAVAILABLE');
  const un64=s=>Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0)),challenge=crypto.getRandomValues(new Uint8Array(32));
  const c=await navigator.credentials.get({publicKey:{challenge,rpId,...(credential_id?{allowCredentials:[{type:'public-key',id:un64(credential_id)}]}:{}),userVerification:'required',timeout:60000,extensions:{prf:{eval:{first:un64(salt)}}}}});
  const r=c?.getClientExtensionResults()?.prf?.results?.first;
  ensure(c&&(!credential_id||c.id===credential_id)&&/^[A-Za-z0-9_-]{1,1366}$/.test(c.id)&&r instanceof ArrayBuffer&&r.byteLength===32,'PRF_UNAVAILABLE');
  return {credential_id:c.id,bytes:new Uint8Array(r)};
}
