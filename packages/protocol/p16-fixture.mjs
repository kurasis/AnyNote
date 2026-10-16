// Actual production-template HTTPS sessions and public synthetic WebAuthn keys.
import https from 'node:https';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {authenticator} from './p16-authenticator.mjs';
import {initialRoot,registrationRequest} from './auth-client.mjs';
import {VaultEngine} from './vault/engine.mjs';
import {Store,phrase} from './notes/test-fixture.mjs';
import {sodium,b64} from './adapters/primitives.mjs';
const ident=()=>b64(sodium.randombytes_buf(16));
const notes=(f,op,args=[])=>f.engine.notes(f.cap,op,args);
async function ok(browser,path,body,method){const r=await browser.call(path,body,method);if(r.status!==200)throw Error('STAGING_HTTP:'+path+':'+r.status+':'+r.json?.error?.code);return r.json;}
const content=(title='',markdown='')=>({title,markdown,metadata_kind:'content',tags:[],checklist:[],summary_entry_id:null,preferences:[]});
const edit=(group,kind,object_id=null,thread_id=null,c=content(),parents=[],action=parents.length?'update':'create')=>({draft_id:null,group_id:group,object_id,object_kind:kind,thread_id,action,parents,archived:false,content:c});
async function publish(f,e){const d=await notes(f,'save',[e]),a=await notes(f,'queue',[d.draft_id]),sent=await notes(f,'send',[a.attempt_id]),c=sent.request.bundle.envelope.header.context,path=c.action==='create'&&c.object_kind==='thread'?'/groups/'+c.group_id+'/threads':c.action==='create'&&c.object_kind==='entry'?'/threads/'+c.thread_id+'/entries':'/objects/'+c.object_id+'/revisions',receipt=await ok(f.browser,path,sent.request);await notes(f,'ack',[a.attempt_id,receipt]);return {...d,...a,request:sent.request,receipt};}
async function privateGroup(f){const made=await notes(f,'prepareGroup'),status=await ok(f.browser,'/groups',made.request);await notes(f,'group',[status]);return status;}
const origin='https://app.anynote.test:19443';
export function control(operation,input,target='source'){return JSON.parse(execFileSync('python3',['scripts/p16-drill.py','control',operation],{input:input?JSON.stringify(input):undefined,encoding:'utf8',env:{...process.env,ANYNOTE_P16_TARGET:target}}));}
export class Browser{
 cookie;csrf;
 constructor({target='source',port=19443}={}){this.target=target;this.port=port;this.origin='https://app.anynote.test:'+port;this.ca=readFileSync('.local/p16/'+target+'/tls/ca.crt');}
 async call(path,body,method=body?'POST':'GET',extra={}){
  const text=body===undefined?undefined:JSON.stringify(body);
  const r=await new Promise((done,reject)=>{const request=https.request({hostname:'127.0.0.1',port:this.port,servername:'api.anynote.test',ca:this.ca,path:'/api/v1'+path,method,headers:{Host:'api.anynote.test:'+this.port,Origin:this.origin,...(this.cookie?{Cookie:this.cookie}:{}),...(this.csrf?{'X-CSRF-TOKEN':this.csrf}:{}),...(text?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(text)}:{}),...extra}},response=>{const chunks=[];let size=0;response.on('data',b=>{size+=b.length;if(size>4194304)request.destroy(Error('BOUNDED_RESPONSE'));else chunks.push(b);});response.on('end',()=>{let json;try{json=JSON.parse(Buffer.concat(chunks));}catch{}done({status:response.statusCode,json,headers:response.headers});});});request.setTimeout(30000,()=>request.destroy(Error('HTTP_TIMEOUT')));request.on('error',reject);request.end(text);});
  if(r.headers['set-cookie'])this.cookie=r.headers['set-cookie'].filter(c=>c.startsWith('__Host-vault_session=')).map(c=>c.split(';')[0]).join('; ');
  if(r.json?.csrf_token)this.csrf=r.json.csrf_token;return r;
 }
}
export async function binary(f,path,bytes){return new Promise((done,reject)=>{const request=https.request({hostname:'127.0.0.1',port:f.browser.port,servername:'api.anynote.test',ca:f.browser.ca,path:'/api/v1'+path,method:'PUT',headers:{Host:'api.anynote.test:'+f.browser.port,Origin:f.browser.origin,Cookie:f.browser.cookie,'X-CSRF-TOKEN':f.browser.csrf,'Content-Type':'application/octet-stream','Content-Length':bytes.length}},r=>{let b='';r.on('data',c=>b+=c);r.on('end',()=>done({status:r.statusCode,json:JSON.parse(b)}));});request.setTimeout(120000,()=>request.destroy(Error('UPLOAD_TIMEOUT')));request.on('error',reject);request.end(bytes);});}
export async function account(configuration={}){
 const browser=new Browser(configuration);if((await browser.call('/auth/csrf')).status!==200)throw Error('CSRF_FAILED');
 const invitation=control('invite',undefined,browser.target).token,o=await browser.call('/auth/passkeys/options',{version:1,ceremony:'register',invitation,handle:'p16-synthetic-'+Date.now()});if(o.status!==200)throw Error('OPTIONS:'+o.status);
 const passkey=authenticator(o.json.account_id),att=await browser.call('/auth/passkeys/verify',{version:1,challenge_id:o.json.challenge_id,credential:passkey.create(o.json.publicKey,{clientOrigin:browser.origin})});if(att.status!==200)throw Error('VERIFY:'+att.status);
 const capabilities=await browser.call('/capabilities'),initial=await initialRoot(capabilities.json.service_id,o.json.account_id),pins={service_id:initial.identity.body.service_id,account_id:o.json.account_id,root_fingerprint:initial.fingerprint},profile={...pins,device_id:initial.device.device_id,profile_id:ident()};delete profile.root_fingerprint;
 const store=new Store(profile),engine=new VaultEngine(store),prep=await browser.call('/accounts/registration-challenge',{version:1,registration_id:att.json.registration_id,identity:initial.identity,device:initial.device});
 const registration=registrationRequest(att.json.registration_id,initial,prep.json.challenge);await engine.initialize(phrase,{device_signing_secret:b64(initial.keys.signing.privateKey),device_encryption_secret:b64(initial.keys.encryption.privateKey),group_keys:[]},pins,registration);const registered=await browser.call('/accounts/register',registration);if(registered.status!==200)throw Error('REGISTER:'+registered.status);
 const f={browser,passkey,initial,pins,profile,store,engine,cap:(await engine.unlock(phrase)).capability},snapshot=(await browser.call('/accounts/'+pins.account_id+'/roster')).json;
 await engine.devices(f.cap,'snapshotStart',[snapshot.identity,snapshot.head,snapshot.generation]);await engine.devices(f.cap,'snapshotPage',[snapshot.events]);await engine.devices(f.cap,'snapshotFinish');const settings=await engine.devices(f.cap,'genesis');const status=await browser.call('/me/settings-genesis',settings.request);if(status.status!==200)throw Error('SETTINGS:'+status.status);await engine.devices(f.cap,'finishRegistration');f.snapshot=snapshot;return f;
}
export {notes,privateGroup,edit,content,publish,ident};

export async function resetIdentity(f){
 const browser=new Browser({target:f.browser.target,port:f.browser.port});await browser.call('/auth/csrf');const options=await browser.call('/auth/passkeys/options',{version:1,ceremony:'login'}),login=await browser.call('/auth/passkeys/verify',{version:1,challenge_id:options.json.challenge_id,credential:f.passkey.get(options.json.publicKey,{clientOrigin:browser.origin})});if(login.status!==200)throw Error('FRESH_LOGIN_FAILED');
 const {deviceKeys}=await import('./adapters/primitives.mjs'),{verifiedSnapshot}=await import('./devices/client.mjs'),{recoverRoot}=await import('./adapters/identity.mjs'),{wire}=await import('./adapters/codecs/identity-codec.mjs'),{rootEventForEvaluation}=await import('./devices/enrollment.mjs');
 const keys=deviceKeys(),device={...f.initial.device,device_id:ident(),signing_key:b64(keys.signing.publicKey),encryption_key:b64(keys.encryption.publicKey)},challenge=await browser.call('/me/recovery-challenge',{version:1,device}),proof=verifiedSnapshot(f.snapshot,f.pins),root=await recoverRoot(wire(f.initial.kit),wire(f.pins));
 try{const event=JSON.parse(new TextDecoder().decode(rootEventForEvaluation(proof.roster,wire(challenge.json.challenge),keys,root.signing.privateKey))),result=await browser.call('/me/recovery-reset',{version:1,event});if(result.status!==200)throw Error('SIGNED_RESET_DENIED:'+result.status);const latest=(await browser.call('/accounts/'+f.pins.account_id+'/roster')).json;return {head:latest.head,generation:latest.generation,old_device_revoked:verifiedSnapshot(latest,f.pins).details.devices.find(d=>d.device_id===f.profile.device_id)?.status==='REVOKED'};}
 finally{sodium.memzero(root.signing.privateKey);sodium.memzero(root.recovery.privateKey);sodium.memzero(keys.signing.privateKey);sodium.memzero(keys.encryption.privateKey);}
}
export async function enroll(f){
 const browser=new Browser({target:f.browser.target,port:f.browser.port});await browser.call('/auth/csrf');const options=await ok(browser,'/auth/passkeys/options',{version:1,ceremony:'login'}),login=await ok(browser,'/auth/passkeys/verify',{version:1,challenge_id:options.challenge_id,credential:f.passkey.get(options.publicKey,{clientOrigin:browser.origin})});
 const {deviceKeys}=await import('./adapters/primitives.mjs'),{verifiedSnapshot}=await import('./devices/client.mjs'),{wire}=await import('./adapters/codecs/identity-codec.mjs'),{stateDigest}=await import('./adapters/codecs/state-codec.mjs'),E=await import('./devices/enrollment.mjs'),C=await import('./devices/pairing-channel.mjs'),{createHash}=await import('node:crypto');
 const parse=b=>JSON.parse(new TextDecoder().decode(b)),snapshot=await ok(f.browser,'/accounts/'+f.pins.account_id+'/roster'),proof=verifiedSnapshot(snapshot,f.pins),keys=deviceKeys(),device={...f.initial.device,device_id:ident(),signing_key:b64(keys.signing.publicKey),encryption_key:b64(keys.encryption.publicKey)},op=ident(),expires=String(Date.now()+500000),binding=createHash('sha256').update('AnyNote/P06/session-binding\0'+login.session.id).digest('base64url'),offer=E.offerForEvaluation(proof.roster,wire(device),binding,op,expires,keys.signing.privateKey),channelKey=C.generatePairingKey(),channel=C.scannedChannelForEvaluation(C.pairingQr('new-device-offer',offer,channelKey),'approver');sodium.memzero(channelKey);
 try{
  await ok(browser,'/me/enrollments',{version:1,mode:'new-device-offer',record:parse(offer)});
  const response=E.responseForEvaluation(proof.roster,offer,f.profile.device_id,f.initial.keys.signing.privateKey,null,BigInt(Date.now())),frame=C.sealPairingFrame(channel,'approver-response',response.response,stateDigest('offer',offer));await ok(f.browser,'/me/enrollments/'+op+'/relay',{version:1,frame:parse(frame),offer:null});
  const approval=E.approvalForEvaluation(proof.roster,response.transcript,f.initial.keys.signing.privateKey,BigInt(Date.now())),approvalFrame=C.sealPairingFrame(channel,'approver-approval',approval,stateDigest('transcript',response.transcript));await ok(f.browser,'/me/enrollments/'+op+'/approve',{version:1,transcript:parse(response.transcript),approval:parse(approval),frame:parse(approvalFrame)});
  const confirmation=E.confirmationForEvaluation(proof.roster,response.transcript,approval,keys.encryption.privateKey,keys.signing.privateKey,BigInt(Date.now())),event=E.enrollmentEventForEvaluation(proof.roster,response.transcript,approval,confirmation,keys.signing.privateKey);await ok(browser,'/me/enrollments/'+op+'/confirm',{version:1,event:parse(event)});
  const latest=await ok(f.browser,'/accounts/'+f.pins.account_id+'/roster');await f.engine.devices(f.cap,'snapshotStart',[latest.identity,latest.head,latest.generation]);await f.engine.devices(f.cap,'snapshotPage',[latest.events]);await f.engine.devices(f.cap,'snapshotFinish');return device.device_id;
 }finally{C.closePairingChannel(channel);sodium.memzero(keys.signing.privateKey);sodium.memzero(keys.encryption.privateKey);}
}
export async function uploadFile(f,group,source,name='P16 recovered file.bin'){
 const made=await notes(f,'files',['prepare',{group_id:group,source,name}]);await ok(f.browser,'/groups/'+group+'/uploads',made.request);
 for(let index=0;index<Math.ceil(source.size/8388608);index++){const part=await notes(f,'files',['part',{draft_id:made.draft_id,source,index}]),put=await binary(f,'/uploads/'+part.upload_id+'/parts/'+index,part.ciphertext);if(put.status!==200)throw Error('UPLOAD_PART_DENIED');await notes(f,'files',['ackPart',{draft_id:made.draft_id,part:put.json}]);}
 const finish=await notes(f,'files',['finish',{draft_id:made.draft_id}]),receipt=await ok(f.browser,'/uploads/'+finish.upload_id+'/commit',finish.request);await notes(f,'files',['committed',{draft_id:made.draft_id,receipt}]);return receipt;
}
export async function downloadFile(f,group,version){
 const {createHash}=await import('node:crypto'),manifest=await ok(f.browser,'/files/'+version+'/manifest'),reader=await notes(f,'files',['open',{group_id:group,file_version_id:version,record:manifest}]),hash=createHash('sha256');let bytes=0,cors=true;
 for(let index=0;index<Number(manifest.envelope.header.framing.chunk_count);index++){
  const part=await new Promise((done,reject)=>{const r=https.request({hostname:'127.0.0.1',port:f.browser.port,servername:'api.anynote.test',ca:f.browser.ca,path:'/api/v1/files/'+version+'/chunks/'+index,headers:{Host:'api.anynote.test:'+f.browser.port,Origin:f.browser.origin,Cookie:f.browser.cookie}},res=>{const chunks=[];let size=0;res.on('data',b=>{size+=b.length;if(size>8388624)r.destroy(Error('CHUNK_RESPONSE_TOO_LARGE'));else chunks.push(b);});res.on('end',()=>done({status:res.statusCode,headers:res.headers,bytes:Buffer.concat(chunks)}));});r.setTimeout(30000,()=>r.destroy(Error('DOWNLOAD_TIMEOUT')));r.on('error',reject);r.end();});
  if(part.status!==200)throw Error('DOWNLOAD_DENIED:'+part.status);cors&&=part.headers['access-control-allow-origin']===f.browser.origin&&part.headers['access-control-allow-credentials']==='true'&&!part.headers['x-accel-redirect'];const plain=await notes(f,'files',['decrypt',{reader_id:reader.reader_id,ciphertext:part.bytes}]);try{bytes+=plain.plaintext.length;hash.update(plain.plaintext);}finally{plain.plaintext.fill(0);}
 }
 await notes(f,'files',['complete',{reader_id:reader.reader_id}]);return {bytes,sha256:hash.digest('hex'),exact_cors_and_hidden_internal_ticket:cors};
}
