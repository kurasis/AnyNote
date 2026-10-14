// Genuine maintained WebAuthn/root bootstrap over the owned verified HTTPS stack.
import {Browser,authenticator,options,verify,control,check,request} from '../notes/http-fixture.mjs';
import {initialRoot,registrationRequest} from '../auth-client.mjs';
import {VaultEngine} from '../vault/engine.mjs';
import {Store,phrase} from '../notes/test-fixture.mjs';
import {sodium,b64} from '../adapters/primitives.mjs';
export const ident=()=>b64(sodium.randombytes_buf(16));
export async function ok(browser,path,body,method){const r=await browser.call(path,body,method);check(r.status===200,'P11_HTTP:'+path.split('?')[0]+':'+r.status+':'+r.json?.error?.code);return r.json;}
export const notes=(f,operation,args=[])=>f.engine.notes(f.cap,operation,structuredClone(args));
export async function account(handle,engineOptions={}){
 const browser=new Browser();await browser.start();const o=await options(browser,'register',{invitation:control('invite').token,handle}),passkey=authenticator(o.account_id),att=await verify(browser,o,passkey.create(o.publicKey));check(att.status===200,'REAL_WEBAUTHN');
 const capabilities=await request('/capabilities'),initial=await initialRoot(capabilities.json.service_id,o.account_id),pins={service_id:initial.identity.body.service_id,account_id:o.account_id,root_fingerprint:initial.fingerprint},profile={service_id:pins.service_id,account_id:pins.account_id,device_id:initial.device.device_id,profile_id:ident()},store=new Store(profile),engine=new VaultEngine(store,engineOptions);
 const prep=await ok(browser,'/accounts/registration-challenge',{version:1,registration_id:att.json.registration_id,identity:initial.identity,device:initial.device}),registration=registrationRequest(att.json.registration_id,initial,prep.challenge);
 await engine.initialize(phrase,{device_signing_secret:b64(initial.keys.signing.privateKey),device_encryption_secret:b64(initial.keys.encryption.privateKey),group_keys:[]},pins,registration);await ok(browser,'/accounts/register',registration);
 const f={browser,passkey,initial,pins,profile,store,engine,cap:(await engine.unlock(phrase)).capability},s=await ok(browser,'/accounts/'+pins.account_id+'/roster');
 await engine.devices(f.cap,'snapshotStart',[s.identity,s.head,s.generation]);await engine.devices(f.cap,'snapshotPage',[s.events]);await engine.devices(f.cap,'snapshotFinish');
 const settings=await engine.devices(f.cap,'genesis');f.settings=await ok(browser,'/me/settings-genesis',settings.request);await engine.devices(f.cap,'finishRegistration');return f;
}
export const content=(title='',markdown='')=>({title,markdown,metadata_kind:'content',tags:[],checklist:[],summary_entry_id:null,preferences:[]});
export const edit=(group,kind,object_id=null,thread_id=null,c=content(),parents=[],action=parents.length?'update':'create')=>({draft_id:null,group_id:group,object_id,object_kind:kind,thread_id,action,parents,archived:false,content:c});
export function pathFor(r){const c=r.bundle.envelope.header.context;return c.action==='soft-delete'?'/objects/'+c.object_id+'/tombstone':c.action==='restore'?'/objects/'+c.object_id+'/restore':c.action==='create'&&c.object_kind==='thread'?'/groups/'+c.group_id+'/threads':c.action==='create'&&c.object_kind==='entry'?'/threads/'+c.thread_id+'/entries':'/objects/'+c.object_id+'/revisions';}
export async function prepare(f,e){const d=await notes(f,'save',[e]),a=await notes(f,'queue',[d.draft_id]),s=await notes(f,'send',[a.attempt_id]);return {...d,...a,request:s.request};}
export async function publish(f,e){const p=await prepare(f,e),receipt=await ok(f.browser,pathFor(p.request),p.request);await notes(f,'ack',[p.attempt_id,receipt]);return {...p,receipt};}
export async function privateGroup(f,title='PUBLIC P11 group'){const made=await notes(f,'prepareGroup'),status=await ok(f.browser,'/groups',made.request);await notes(f,'group',[status]);await publish(f,edit(status.group_id,'group-metadata',status.group_id,null,content(title)));return status;}
