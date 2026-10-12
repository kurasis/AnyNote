// P08 real HTTPS -> Nginx -> Laravel -> MariaDB. Synthetic authenticator uses Node's maintained P-256.
// No mock verifier or HTTP token issuer. Secret fixtures are memory-only, excluded from reports.
import https from 'node:https';
import http from 'node:http';
import {createInterface} from 'node:readline';
import {generateKeyPairSync,sign,createHash,randomBytes} from 'node:crypto';
import {readFileSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {spawnSync,spawn} from 'node:child_process';
import {resolve} from 'node:path';
import {initialRoot,registrationRequest,possession,deviceCommitment,authValue,recoveryKitExport} from './auth-client.mjs';
import {wire} from './adapters/codecs/identity-codec.mjs';
const root=resolve(import.meta.dirname,'../..'),issuer='https://api.anynote.test:18443',origin='https://app.anynote.test:18443';
const ca=readFileSync(root+'/.local/p06/tls/ca.crt');
const sortJson=v=>Array.isArray(v)?v.map(sortJson):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,sortJson(v[k])])):v;
let checks=0;
function check(v,why){if(!v)throw Error(why);checks++;}
function control(op, input){const r=spawnSync('python3',['scripts/p06-stack.py','control',op],{cwd:root,encoding:'utf8',input});if(r.status!==0)throw Error('CONTROL_FAILED:'+op);try{return JSON.parse(r.stdout);}catch{throw Error('CONTROL_INVALID_RESULT:'+op);}}
export function request(path,{body,method=body?'POST':'GET',cookie,csrf,origin:requestOrigin=origin,headers={}}={}){
  return new Promise((done,reject)=>{const text=body===undefined?undefined:JSON.stringify(body);const req=https.request({hostname:'127.0.0.1',port:18443,servername:'api.anynote.test',ca,path:'/api/v1'+path,method,headers:{Host:'api.anynote.test:18443',Accept:'application/json',...(requestOrigin?{Origin:requestOrigin}:{}),...(cookie?{Cookie:cookie}:{}),...(csrf?{'X-CSRF-TOKEN':csrf}:{}),...(text?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(text)}:{}),...headers}},res=>{const chunks=[];let n=0;res.on('data',b=>{n+=b.length;if(n>262144)req.destroy(Error('RESPONSE_TOO_LARGE'));else chunks.push(b);});res.on('end',()=>{let json;try{json=JSON.parse(Buffer.concat(chunks));}catch{json=null;}done({status:res.statusCode,headers:res.headers,json});});});req.setTimeout(10000,()=>req.destroy(Error('HTTP_TIMEOUT')));req.on('error',reject);req.end(text);});
}
class Browser {
  cookie;csrf;
  async call(path,body,method,extra={}){const r=await request(path,{body,method,cookie:this.cookie,csrf:this.csrf,...extra});const cookies=r.headers['set-cookie'];if(cookies)this.cookie=cookies.filter(c=>c.startsWith('__Host-vault_session=')).map(c=>c.split(';')[0]).join('; ');if(r.json?.csrf_token)this.csrf=r.json.csrf_token;return r;}
  async start(){const x=await this.call('/auth/csrf');check(x.status===200,'CSRF_START');check(/; secure/i.test(x.headers['set-cookie'][0])&&/; httponly/i.test(x.headers['set-cookie'][0])&&/; samesite=strict/i.test(x.headers['set-cookie'][0])&&!/; domain=/i.test(x.headers['set-cookie'][0]),'HOST_COOKIE');check(!x.headers['set-cookie'].some(x=>x.startsWith('XSRF-TOKEN=')),'NO_READABLE_CSRF_COOKIE');return x;}
}
// CBOR fixture framing only, not application crypto. Verifier parses this with maintained cbor-php.
const byte=b=>Buffer.concat([Buffer.from(b.length<24?[0x40+b.length]:b.length<256?[0x58,b.length]:[0x59,b.length>>8,b.length&255]),b]);
const sha=b=>createHash('sha256').update(b).digest();
const b64=b=>Buffer.from(b).toString('base64url');
function authenticator(account){const kp=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),j=kp.publicKey.export({format:'jwk'}),id=randomBytes(32);let counter=0;
  return {id,account,create(options,{uv=true,rp='app.anynote.test',clientOrigin=origin}={}){
    const client=Buffer.from(JSON.stringify({type:'webauthn.create',challenge:options.challenge,origin:clientOrigin,crossOrigin:false}));
    const cose=Buffer.concat([Buffer.from([0xa5,1,2,3,0x26,0x20,1,0x21]),byte(Buffer.from(j.x,'base64url')),Buffer.from([0x22]),byte(Buffer.from(j.y,'base64url'))]);
    const auth=Buffer.concat([sha(rp),Buffer.from([uv?0x45:0x41,0,0,0,0]),Buffer.alloc(16),Buffer.from([0,id.length]),id,cose]);
    const attestation=Buffer.concat([Buffer.from([0xa3,0x63]),Buffer.from('fmt'),Buffer.from([0x64]),Buffer.from('none'),Buffer.from([0x68]),Buffer.from('authData'),byte(auth),Buffer.from([0x67]),Buffer.from('attStmt'),Buffer.from([0xa0])]);
    return {id:b64(id),rawId:b64(id),type:'public-key',response:{clientDataJSON:b64(client),attestationObject:b64(attestation),transports:['internal']}};
  },get(options,{uv=true,rp='app.anynote.test',clientOrigin=origin,challenge=options.challenge,user=account,count=++counter}={}){
    const client=Buffer.from(JSON.stringify({type:'webauthn.get',challenge,origin:clientOrigin,crossOrigin:false}));const n=Buffer.alloc(4);n.writeUInt32BE(count);const auth=Buffer.concat([sha(rp),Buffer.from([uv?5:1]),n]);
    return {id:b64(id),rawId:b64(id),type:'public-key',response:{clientDataJSON:b64(client),authenticatorData:b64(auth),signature:b64(sign('sha256',Buffer.concat([auth,sha(client)]),kp.privateKey)),userHandle:b64(Buffer.from(user,'base64url'))}};
  }};
}
async function options(browser,ceremony,extra={}){const x=await browser.call('/auth/passkeys/options',{version:1,ceremony,...extra});check(x.status===200,'OPTIONS:'+x.status+':'+x.json?.error?.code);authValue('options-result',x.json);return x.json;}
async function verify(browser,o,c){return browser.call('/auth/passkeys/verify',{version:1,challenge_id:o.challenge_id,credential:c});}
async function login(browser,key){await browser.start();const o=await options(browser,'login');const x=await verify(browser,o,key.get(o.publicKey));check(x.status===200&&x.json.session.state==='restricted','RESTRICTED_LOGIN');return x.json;}

import {sodium,deviceKeys} from './adapters/primitives.mjs';
import {stateDigest} from './adapters/codecs/state-codec.mjs';
import {deviceValue,verifiedSnapshot} from './devices/client.mjs';
import {privateGenesis} from './devices/genesis.mjs';
import {groupCodecForProfile} from './adapters/codecs/group-codec.mjs';
const stateDigestForPolicy=policy=>groupCodecForProfile('p02-group-c2').groupDigest('policy',wire(policy));
import {rosterDetails,applyRosterEventForEvaluation} from './devices/roster.mjs';
import {invitationForEvaluation,offerForEvaluation,responseForEvaluation,approvalForEvaluation,confirmationForEvaluation,enrollmentEventForEvaluation,revokeEventForEvaluation,rootEventForEvaluation,randomOperationId} from './devices/enrollment.mjs';
import {pairingQr,scannedChannelForEvaluation,sealPairingFrame,openPairingFrame,generatePairingKey,closePairingChannel} from './devices/pairing-channel.mjs';
import {recoverRoot} from './adapters/identity.mjs';
import {nativeHarness} from './devices/native-harness.mjs';
import {phraseKek,unwrapLocalKey,openLocal} from './adapters/local.mjs';
import {openLifecycle} from './devices/local.mjs';
import {sealGroupKeyForEvaluation} from './devices/proofs.mjs';
import {activeRecipientForRosterEvaluation} from './devices/roster.mjs';
import {activeCertificateForEvaluation} from './devices/roster.mjs';
import {senderForCertificate,certificateDetails} from './devices/proofs.mjs';
const pinsFor=i=>({service_id:i.identity.body.service_id,account_id:i.identity.body.account_id,root_fingerprint:i.fingerprint});
const parse=b=>JSON.parse(Buffer.from(b));
const ok=async(browser,path,body,shape,method)=>{const r=await browser.call(path,body,method);check(r.status===200,'HTTP:'+path+':'+r.status+':'+r.json?.error?.code);if(shape)deviceValue(shape,r.json);return r.json;};
const snapshot=async(browser,initial)=>{const v=await ok(browser,'/accounts/'+initial.identity.body.account_id+'/roster',undefined,'roster-result');check(v.next===null,'BOUNDED_INITIAL_ROSTER');return {identity:v.identity,events:v.events,head:v.head,generation:v.generation};};
const denied=async(browser,path,body,codes)=>{const r=await browser.call(path,body);check(r.status>=400&&codes.includes(r.json?.error?.code),'EXPECTED_DENIAL:'+path+':'+r.status+':'+r.json?.error?.code);return r;};

async function staged(approver,actor,signing,passkey,initial,pins,{cap=false}={}) {
 const local=await snapshot(approver,initial),proof=verifiedSnapshot(local,pins),browser=new Browser(),session=await login(browser,passkey),keys=deviceKeys(),device={...initial.device,device_id:randomOperationId(),signing_key:b64(keys.signing.publicKey),encryption_key:b64(keys.encryption.publicKey)},op=randomOperationId(),expires=String(Date.now()+500000);
 const offer=offerForEvaluation(proof.roster,wire(device),b64(sha('AnyNote/P06/session-binding\0'+session.session.id)),op,expires,keys.signing.privateKey),key=generatePairingKey(),qr=pairingQr('new-device-offer',offer,key),old=scannedChannelForEvaluation(qr,'approver');sodium.memzero(key);
 try {
  await ok(browser,'/me/enrollments',{version:1,mode:'new-device-offer',record:parse(offer)},'pending-result');
  const response=responseForEvaluation(proof.roster,offer,actor,signing,null,BigInt(Date.now())),frame=sealPairingFrame(old,'approver-response',response.response,stateDigest('offer',offer));await ok(approver,'/me/enrollments/'+op+'/relay',{version:1,frame:parse(frame),offer:null},'relay-result');
  const approval=approvalForEvaluation(proof.roster,response.transcript,signing,BigInt(Date.now())),af=sealPairingFrame(old,'approver-approval',approval,stateDigest('transcript',response.transcript)),body={version:1,transcript:parse(response.transcript),approval:parse(approval),frame:parse(af)};
  if(cap){await denied(approver,'/me/enrollments/'+op+'/approve',body,['RESOURCE_LIMIT']);return {browser,keys,device,op};}
  await ok(approver,'/me/enrollments/'+op+'/approve',body,'pending-result');const confirmation=confirmationForEvaluation(proof.roster,response.transcript,approval,keys.encryption.privateKey,keys.signing.privateKey,BigInt(Date.now())),event=parse(enrollmentEventForEvaluation(proof.roster,response.transcript,approval,confirmation,keys.signing.privateKey));return {browser,keys,device,op,event};
 }finally{closePairingChannel(old);}
}
async function nativeGrant(approver,device){
 const verifier=b64(randomBytes(32)),params={client_id:'anynote-windows',redirect_uri:'http://127.0.0.1:49871/callback/'+randomOperationId(),state:b64(randomBytes(32)),code_challenge:b64(sha(verifier)),code_challenge_method:'S256',device_commitment:deviceCommitment(device)};
 const start=await request('/auth/native/authorize?'+new URLSearchParams(params),{origin:null});check(start.status===200,'NATIVE_AUTHORIZATION');await ok(approver,'/auth/native/authorizations/'+start.json.authorization_id);const approval=await ok(approver,'/auth/native/approve',{version:1,authorization_id:start.json.authorization_id}),callback=new URL(approval.redirect_uri);return {version:1,grant_type:'authorization_code',client_id:'anynote-windows',issuer,authorization_id:start.json.authorization_id,redirect_uri:params.redirect_uri,code:callback.searchParams.get('code'),code_verifier:verifier};
}
const browser=new Browser();await browser.start();const invitation=control('invite').token;
const opts=await options(browser,'register',{invitation,handle:'p08-http'}),passkey=authenticator(opts.account_id);const att=await verify(browser,opts,passkey.create(opts.publicKey));check(att.status===200,'ACTUAL_WEBAUTHN_ATTESTATION');
const capabilities=await request('/capabilities'),initial=await initialRoot(capabilities.json.service_id,opts.account_id),pins=pinsFor(initial);
try{
 const preparation=await ok(browser,'/accounts/registration-challenge',{version:1,registration_id:att.json.registration_id,identity:initial.identity,device:initial.device});
 await ok(browser,'/accounts/register',registrationRequest(att.json.registration_id,initial,preparation.challenge));
 let current=await snapshot(browser,initial),proof=verifiedSnapshot(current,pins);
 const genesis=privateGenesis(proof.roster,proof.identity,initial.device.device_id,initial.keys.signing.privateKey);
 await ok(browser,'/me/settings-genesis',genesis.request,'genesis-result');await ok(browser,'/me/settings-genesis',genesis.request,'genesis-result');
 const recoveryBefore=await ok(browser,'/me/recovery-envelopes',undefined,'envelope-result');check(recoveryBefore.records.length===1,'REAL_RECOVERY_ENVELOPE');
 const newBrowser=new Browser(),session=await login(newBrowser,passkey),keys=deviceKeys(),device={...initial.device,device_id:randomOperationId(),signing_key:b64(keys.signing.publicKey),encryption_key:b64(keys.encryption.publicKey)};
 await denied(newBrowser,'/me/settings-genesis',genesis.request,['SESSION_DEVICE_PROOF_REQUIRED']);
 const op=randomOperationId(),expires=String(Date.now()+500000),invite=invitationForEvaluation(proof.roster,initial.device.device_id,op,expires,initial.keys.signing.privateKey),channelKey=generatePairingKey(),qr=pairingQr('existing-device-invitation',invite,channelKey),oldChannel=scannedChannelForEvaluation(qr,'approver'),newChannel=scannedChannelForEvaluation(qr,'new-device');sodium.memzero(channelKey);
 await ok(browser,'/me/enrollments',{version:1,mode:'existing-device-invitation',record:parse(invite)},'pending-result');
 const offer=offerForEvaluation(proof.roster,wire(device),createHash('sha256').update('AnyNote/P06/session-binding\0'+session.session.id).digest('base64url'),op,expires,keys.signing.privateKey,invite);
 const offerFrame=sealPairingFrame(newChannel,'new-device-offer',offer,stateDigest('invitation',invite));await ok(newBrowser,'/me/enrollments/'+op+'/relay',{version:1,frame:parse(offerFrame),offer:parse(offer)},'relay-result');
 const relay=await ok(browser,'/me/enrollments/'+op+'/relay',undefined,'relay-result');check(Buffer.from(openPairingFrame(oldChannel,wire(relay.frames[0]),'new-device-offer',stateDigest('invitation',invite))).equals(offer),'REAL_OPAQUE_RELAY_OFFER');
 const response=responseForEvaluation(proof.roster,offer,initial.device.device_id,initial.keys.signing.privateKey,invite,BigInt(Date.now())),responseFrame=sealPairingFrame(oldChannel,'approver-response',response.response,stateDigest('offer',offer));
 await ok(browser,'/me/enrollments/'+op+'/relay',{version:1,frame:parse(responseFrame),offer:null},'relay-result');
 const approval=approvalForEvaluation(proof.roster,response.transcript,initial.keys.signing.privateKey,BigInt(Date.now())),approvalFrame=sealPairingFrame(oldChannel,'approver-approval',approval,stateDigest('transcript',response.transcript));
 await ok(browser,'/me/enrollments/'+op+'/approve',{version:1,transcript:parse(response.transcript),approval:parse(approval),frame:parse(approvalFrame)},'pending-result');
 const confirmation=confirmationForEvaluation(proof.roster,response.transcript,approval,keys.encryption.privateKey,keys.signing.privateKey,BigInt(Date.now())),event=enrollmentEventForEvaluation(proof.roster,response.transcript,approval,confirmation,keys.signing.privateKey),result=await ok(newBrowser,'/me/enrollments/'+op+'/confirm',{version:1,event:parse(event)},'event-result');
 check(result.session.state==='trusted'&&result.session.device_id===device.device_id,'ATOMIC_ACTIVE_AND_TRUSTED');await ok(newBrowser,'/me/enrollments/'+op+'/confirm',{version:1,event:parse(event)},'event-result');
 current=await snapshot(browser,initial);proof=verifiedSnapshot(current,pins);check(rosterDetails(proof.roster).devices.filter(d=>d.status==='ACTIVE').length===2,'VERIFIED_COMPLETE_ROSTER');
 // Native-generated independent keys and native sealed-box/secretstream custody, over real HTTP.
 const nativeBrowser=new Browser(),nativeSession=await login(nativeBrowser,passkey),native=await nativeHarness({scope:{service_id:pins.service_id,account_id:pins.account_id,device_id:randomOperationId(),profile_id:randomOperationId()},pins,phrase:'public synthetic purple harbor paper lantern'});
 try {
  const nativeDevice=native.device;check(nativeDevice.signing_key!==device.signing_key&&nativeDevice.encryption_key!==device.encryption_key,'ACTUAL_NATIVE_INDEPENDENT_KEYS');
  await native.call({operation:'device-snapshot',snapshot:current});
  const nativeOffer=await native.call({operation:'device-offer',session_id:nativeSession.session.id,invitation:null}),nop=nativeOffer.body.operation_id,nqr=await native.call({operation:'pairing-qr',record:nativeOffer,mode:'new-device-offer'}),nodeChannel=scannedChannelForEvaluation(wire(nqr.qr),'approver');
  await ok(nativeBrowser,'/me/enrollments',{version:1,mode:'new-device-offer',record:nativeOffer},'pending-result');
  const nr=responseForEvaluation(proof.roster,wire(nativeOffer),device.device_id,keys.signing.privateKey,null,BigInt(Date.now())),nf=sealPairingFrame(nodeChannel,'approver-response',nr.response,stateDigest('offer',wire(nativeOffer)));
  await ok(newBrowser,'/me/enrollments/'+nop+'/relay',{version:1,frame:parse(nf),offer:null},'relay-result');
  const ndecoded=await native.call({operation:'pairing-frame',handle:nqr.handle,message:'approver-response',value:parse(nf),anchor:stateDigest('offer',wire(nativeOffer)),seal:false});check(JSON.stringify(sortJson(ndecoded))===JSON.stringify(sortJson(parse(nr.response))),'NATIVE_NODE_SECRETSTREAM_BYTES');
  const replay=await native.call({operation:'pairing-frame',handle:nqr.handle,message:'approver-response',value:parse(nf),anchor:stateDigest('offer',wire(nativeOffer)),seal:false});check(!!replay.error,'ACTUAL_NATIVE_REPLAY_DENIAL');
  const na=approvalForEvaluation(proof.roster,nr.transcript,keys.signing.privateKey,BigInt(Date.now())),naf=sealPairingFrame(nodeChannel,'approver-approval',na,stateDigest('transcript',nr.transcript));
  await ok(newBrowser,'/me/enrollments/'+nop+'/approve',{version:1,transcript:parse(nr.transcript),approval:parse(na),frame:parse(naf)},'pending-result');
  // Concurrent identical transitions serialize to one event and the same immutable receipt.
  const nevent=await native.call({operation:'device-confirmation',transcript:parse(nr.transcript),approval:parse(na),session_id:nativeSession.session.id,confirmed:true});check(!nevent.error,'NATIVE_ACTUAL_BOTH_KEY_CONFIRMATION');
  const faultBefore=control('p08-state');control('p08-fault-on');try{await denied(nativeBrowser,'/me/enrollments/'+nop+'/confirm',{version:1,event:nevent},['TEMPORARY_UNAVAILABLE']);}finally{control('p08-fault-off');}check(JSON.stringify(control('p08-state'))===JSON.stringify(faultBefore),'ACTUAL_SQL_FAULT_ROLLS_BACK_ALL_MATERIALIZATIONS');
  const nresults=await Promise.all([1,2].map(()=>nativeBrowser.call('/me/enrollments/'+nop+'/confirm',{version:1,event:nevent})));check(nresults.every(r=>r.status===200)&&JSON.stringify(sortJson(nresults[0].json.receipt))===JSON.stringify(sortJson(nresults[1].json.receipt)),'SQL_CONCURRENT_CONFIRM_SINGLE_RECEIPT:'+nresults.map(r=>r.status+':'+r.json?.error?.code).join(','));
  current=await snapshot(browser,initial);proof=verifiedSnapshot(current,pins);check(current.events.length===3,'ONE_NATIVE_EVENT_FOR_TWO_COMMITS');await native.call({operation:'device-snapshot',snapshot:current});
  const recipient=activeRecipientForRosterEvaluation(proof.roster,nativeDevice.device_id),ctx={purpose:'group-key-distribution',contract:'p02-identity-c1',protocol:'anynote',protocol_version:1,service_id:pins.service_id,group_id:genesis.secret.group_id,key_epoch:'0',epoch_digest:genesis.secret.epoch_digest,membership_head:{version:'0',digest:stateDigestForPolicy(genesis.request.commit.body.policy)},operation_id:randomOperationId(),issuer:senderForCertificate(activeCertificateForEvaluation(proof.roster,initial.device.device_id,'distribute-group-key'),proof.details.head),recipient};
  const grant=parse(sealGroupKeyForEvaluation(wire(ctx),Buffer.from(genesis.secret.group_secret,'base64url'),Buffer.from(nativeDevice.encryption_key,'base64url'),initial.keys.signing.privateKey,activeCertificateForEvaluation(proof.roster,initial.device.device_id,'distribute-group-key')));
  const recipientSwap=structuredClone(grant);recipientSwap.body.context.recipient.device_id=initial.device.device_id;await denied(browser,'/me/device-envelopes',{version:1,records:[recipientSwap]},['INVALID_SIGNATURE','ROSTER_CHANGED']);
  control('p08-exhaust-reserve');await denied(browser,'/me/device-envelopes',{version:1,records:[grant]},['INSUFFICIENT_STORAGE']);control('p08-release-reserve');control('p08-fill-content');
  await ok(browser,'/me/device-envelopes',{version:1,records:[grant]},'cancel-result');await ok(browser,'/me/device-envelopes',{version:1,records:[grant]},'cancel-result');
  const changed=structuredClone(grant);changed.body.sealed_ciphertext=b64(randomBytes(Buffer.from(grant.body.sealed_ciphertext,'base64url').length));await denied(browser,'/me/device-envelopes',{version:1,records:[changed]},['INVALID_SIGNATURE','IDEMPOTENCY_MISMATCH']);
  control('p08-remove-membership');const removed=await ok(nativeBrowser,'/me/recovery-envelopes',undefined,'envelope-result');check(removed.records.length===0,'REMOVED_MEMBERSHIP_NO_RECOVERY_KEY_RELEASE');control('p08-restore-membership');

  const ng=await ok(nativeBrowser,'/me/device-envelopes',undefined,'envelope-result');check(ng.records.length===1,'CURRENT_NATIVE_RECIPIENT_ONLY');const accepted=await native.call({operation:'device-group-keys',evidence:genesis.request,records:ng.records,kit:null,target:null,confirmed:true});check(!accepted.error,'NATIVE_PROTECTED_G_DELIVERY');
  const disk=await native.call({operation:'test-inspect-ciphertext'});check(!JSON.stringify(disk).includes(genesis.secret.group_secret)&&!JSON.stringify(disk).includes(initial.kit.recovery_secret),'NATIVE_REAL_SQLITE_NO_G_OR_R');
  const w=disk.state.wrappers[0],{nonce,ciphertext,...descriptor}=w,kek=await phraseKek('public synthetic purple harbor paper lantern',wire(w.parameters)),localKey=unwrapLocalKey('phrase-wrapper',wire(w),wire(descriptor),kek);
  try{const own=disk.rows.find(r=>r.id===disk.state.vault_id),secrets=openLocal(wire(own.frame),localKey,wire(own.frame.context)).data;check(secrets.group_keys[0].group_secret===genesis.secret.group_secret,'NODE_OPENS_NATIVE_FROZEN_L_WRAPPER_AND_MATCHES_G');const control=disk.rows.find(r=>r.frame.context?.record_kind==='device-control'),decoded=openLifecycle(control.frame,disk.state.scope,pins,control.id,'device-control',localKey);check(decoded.head.digest===current.head.digest,'NODE_NATIVE_ADDITIVE_FRAME_AAD_AND_BYTES');secrets.device_signing_secret='';secrets.device_encryption_secret='';for(const g of secrets.group_keys)g.group_secret='';}finally{sodium.memzero(kek);sodium.memzero(localKey);}
  await native.call({operation:'lock'});const restartDisk=await native.call({operation:'test-inspect-ciphertext'});await native.close();const restarted=await nativeHarness({scope:restartDisk.state.scope,pins,phrase:'public synthetic purple harbor paper lantern',snapshot:restartDisk});try{check(JSON.stringify(sortJson(restarted.device))===JSON.stringify(sortJson(nativeDevice)),'FRESH_NATIVE_PROCESS_REOPENS_SAME_PRIVATE_KEYS_WITHOUT_EXPORT');const restored=await restarted.call({operation:'device-snapshot',snapshot:current});check(!restored.error&&restored.head.digest===current.head.digest,'FRESH_NATIVE_PROCESS_ACCEPTS_PROTECTED_CHECKPOINT');}finally{await restarted.close();}
  closePairingChannel(nodeChannel);
  const bad=structuredClone(nevent);bad.signature=b64(Buffer.alloc(64));await denied(nativeBrowser,'/me/enrollments/'+nop+'/confirm',{version:1,event:bad},['IDEMPOTENCY_MISMATCH']);
  const parentRevoke=revokeEventForEvaluation(proof.roster,initial.device.device_id,[device.device_id],initial.keys.signing.privateKey);check(parse(parentRevoke).body.payload.affected_devices.length===2,'EXACT_TRANSITIVE_DESCENDANT_CLOSURE');
  const incomplete=parse(parentRevoke);incomplete.body.payload.affected_devices=[device.device_id];await denied(browser,'/me/devices/'+device.device_id+'/revoke',{version:1,event:incomplete},['ROLE_FORBIDDEN','INVALID_SIGNATURE']);
 } finally { await native.close(); }
 const delayed=await staged(newBrowser,device.device_id,keys.signing.privateKey,passkey,initial,pins),grantKeys=deviceKeys(),nativeCode=await nativeGrant(newBrowser,{...device,device_id:randomOperationId(),signing_key:b64(grantKeys.signing.publicKey),encryption_key:b64(grantKeys.encryption.publicKey)});
 const token=await request('/auth/native/token',{origin:null,body:nativeCode});check(token.status===200&&token.json.session.state==='restricted','REAL_NATIVE_RESTRICTED_GRANT');const unusedCode=await nativeGrant(newBrowser,{...device,device_id:randomOperationId()});
 const siblings=[];for(let n=0;n<2;n++){const sibling=await staged(browser,initial.device.device_id,initial.keys.signing.privateKey,passkey,initial,pins);await ok(sibling.browser,'/me/enrollments/'+sibling.op+'/confirm',{version:1,event:sibling.event},'event-result');siblings.push(sibling);}
 const capped=await staged(browser,initial.device.device_id,initial.keys.signing.privateKey,passkey,initial,pins,{cap:true});check((await ok(browser,'/me/devices',undefined,'devices-result')).devices.filter(d=>d.status==='active').length===5,'EXACT_ROOT_SIGNED_ACTIVE_DEVICE_CAP');
 control('p08-expire-pending');const expired=await ok(capped.browser,'/me/enrollments/'+capped.op+'/relay',undefined,'relay-result');check(expired.state==='expired','ACTUAL_PENDING_EXPIRY_NO_APPROVAL_OR_KEYS');
 current=await snapshot(browser,initial);proof=verifiedSnapshot(current,pins);
 const revoke=revokeEventForEvaluation(proof.roster,initial.device.device_id,[device.device_id],initial.keys.signing.privateKey);await ok(browser,'/me/devices/'+device.device_id+'/revoke',{version:1,event:parse(revoke)},'event-result');await denied(newBrowser,'/me/recovery-challenge',{version:1,device:{...device,device_id:randomOperationId()}},['SESSION_EXPIRED','DEVICE_REVOKED']);
 await denied(delayed.browser,'/me/enrollments/'+delayed.op+'/confirm',{version:1,event:delayed.event},['ENROLLMENT_EXPIRED','ROSTER_CHANGED']);
 const oldNative=await request('/me',{origin:null,headers:{Authorization:'Bearer '+token.json.access_token}});check(oldNative.status===401,'DERIVED_NATIVE_SESSION_REVOKED');const oldCode=await request('/auth/native/token',{origin:null,body:unusedCode});check(oldCode.status===401,'DERIVED_UNUSED_NATIVE_CODE_REVOKED');
 const surviving=await ok(siblings[0].browser,'/me/devices',undefined,'devices-result');check(surviving.devices.filter(d=>d.status==='active').length===3,'INDEPENDENT_SIBLINGS_SURVIVE_CASCADE');
 sodium.memzero(grantKeys.signing.privateKey);sodium.memzero(grantKeys.encryption.privateKey);for(const x of [delayed,capped,...siblings]){sodium.memzero(x.keys.signing.privateKey);sodium.memzero(x.keys.encryption.privateKey);}

 const recoveryBrowser=new Browser(),recoverySession=await login(recoveryBrowser,passkey),freshKeys=deviceKeys(),freshDevice={...device,device_id:randomOperationId(),signing_key:b64(freshKeys.signing.publicKey),encryption_key:b64(freshKeys.encryption.publicKey)};
 const challenge=await ok(recoveryBrowser,'/me/recovery-challenge',{version:1,device:freshDevice},'challenge-result');current=await snapshot(recoveryBrowser,initial);proof=verifiedSnapshot(current,pins);
 const rootKeys=await recoverRoot(wire(initial.kit),wire(pins)),reset=rootEventForEvaluation(proof.roster,wire(challenge.challenge),freshKeys,rootKeys.signing.privateKey);
 try{
  const substitute=parse(reset);substitute.signature=b64(randomBytes(64));await denied(recoveryBrowser,'/me/recovery-reset',{version:1,event:substitute},['INVALID_SIGNATURE']);
  const contenderBrowser=new Browser(),contenderSession=await login(contenderBrowser,passkey),contenderKeys=deviceKeys(),contenderDevice={...freshDevice,device_id:randomOperationId(),signing_key:b64(contenderKeys.signing.publicKey),encryption_key:b64(contenderKeys.encryption.publicKey)};
  try {
   const contenderChallenge=await ok(contenderBrowser,'/me/recovery-challenge',{version:1,device:contenderDevice},'challenge-result'),contenderReset=rootEventForEvaluation(proof.roster,wire(contenderChallenge.challenge),contenderKeys,rootKeys.signing.privateKey);
   const results=await Promise.all([recoveryBrowser.call('/me/recovery-reset',{version:1,event:parse(reset)}),contenderBrowser.call('/me/recovery-reset',{version:1,event:parse(contenderReset)})]);
   check(results.filter(r=>r.status===200).length===1&&results.filter(r=>[401,409].includes(r.status)).length===1,'ACTUAL_ROOT_RESET_CAS_ONE_WINNER');const winner=results[0].status===200?recoveryBrowser:contenderBrowser,winningEvent=results[0].status===200?reset:contenderReset,winningResult=results.find(r=>r.status===200).json;
   deviceValue('event-result',winningResult);check(winningResult.session.generation==='1'&&winningResult.session.state==='trusted','ROOT_RESET_NEW_GENERATION');await ok(winner,'/me/recovery-reset',{version:1,event:parse(winningEvent)},'event-result');
   await denied(browser,'/me/recovery-challenge',{version:1,device:freshDevice},['SESSION_EXPIRED','DEVICE_REVOKED']);const envelopes=await ok(winner,'/me/recovery-envelopes',undefined,'envelope-result');check(envelopes.records.length===1,'RECOVERY_AFTER_ACTIVE_WITHOUT_KEY_DEADLOCK');
   const latest=await snapshot(winner,initial),verified=verifiedSnapshot(latest,pins);check(verified.details.generation==='1'&&verified.details.devices.filter(d=>d.status==='ACTIVE').length===1,'CAS_RESET_REVOKES_EVERY_OLD_DEVICE_AND_ADVANCES_EXACTLY_ONCE');
  }finally{sodium.memzero(contenderKeys.signing.privateKey);sodium.memzero(contenderKeys.encryption.privateKey);}
 }finally{sodium.memzero(rootKeys.signing.privateKey);sodium.memzero(rootKeys.recovery.privateKey);sodium.memzero(freshKeys.signing.privateKey);sodium.memzero(freshKeys.encryption.privateKey);}

 closePairingChannel(oldChannel);closePairingChannel(newChannel);sodium.memzero(keys.signing.privateKey);sodium.memzero(keys.encryption.privateKey);genesis.secret.group_secret='';
 mkdirSync(root+'/artifacts/p08',{recursive:true});writeFileSync(root+'/artifacts/p08/http-report.json',JSON.stringify({purpose:'P08 actual trusted-device lifecycle over verified HTTPS and MariaDB',status:'PASS',source_commit:spawnSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).stdout.trim(),source_tree_dirty:!!spawnSync('git',['status','--porcelain'],{encoding:'utf8'}).stdout.trim(),checks,physical_acceptance:false,independent_review:'NOT_RUN'},null,2)+'\n');console.log('PASS P08 actual HTTP/SQL',checks);
}finally{initial.dispose();}
