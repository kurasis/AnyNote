// P07 real HTTPS -> Nginx -> Laravel -> MariaDB. Synthetic authenticator uses Node's maintained P-256.
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

const report={purpose:'P07 native encrypted custody and fresh P06 device proof over actual HTTPS/SQL',status:'PENDING',source_commit:spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).stdout.trim(),physical_acceptance:false,independent_review:'NOT_RUN'};
const binary=root+'/packages/vault-native/target/debug/p07-integration'+(process.platform==='win32'?'.exe':'');
const native=input=>{const r=spawnSync(binary,[],{cwd:root,input:JSON.stringify(input),encoding:'utf8',timeout:120000,maxBuffer:8388608});if(r.status!==0)throw Error('NATIVE_VAULT_OPERATION_FAILED');return JSON.parse(r.stdout);};
const browser=new Browser();await browser.start();const invite=control('invite').token;
const opts=await options(browser,'register',{invitation:invite,handle:'p07-http'}),passkey=authenticator(opts.account_id);
const enrolled=await verify(browser,opts,passkey.create(opts.publicKey));check(enrolled.status===200,'ATTESTATION');
const caps=await request('/capabilities'),initial=await initialRoot(caps.json.service_id,opts.account_id);
try{
 const preparation=await browser.call('/accounts/registration-challenge',{version:1,registration_id:enrolled.json.registration_id,identity:initial.identity,device:initial.device});check(preparation.status===200,'PUBLIC_ROOT_PREPARATION');
 const registration=await browser.call('/accounts/register',registrationRequest(enrolled.json.registration_id,initial,preparation.json.challenge));check(registration.status===200&&registration.json.session.state==='trusted','SIGNED_FIRST_DEVICE');
 const profile={service_id:caps.json.service_id,account_id:opts.account_id,device_id:initial.device.device_id,profile_id:b64(randomBytes(16))},pins={service_id:profile.service_id,account_id:profile.account_id,root_fingerprint:initial.fingerprint};
 const input={scope:profile,pins,secrets:{device_signing_secret:b64(initial.keys.signing.privateKey),device_encryption_secret:b64(initial.keys.encryption.privateKey),group_keys:[]},phrase:'public synthetic purple harbor paper lantern',records:[]};
 check((await browser.call('/auth/logout',{version:1})).status===200,'LOGOUT');const current=await login(browser,passkey);check(!current.content_access,'LOGIN_NOT_LOCAL_UNLOCK');
 const challenge=await browser.call('/auth/device-challenge',{version:1,device_id:profile.device_id});check(challenge.status===200,'CURRENT_SESSION_CHALLENGE');
 const result=native({...input,challenge:challenge.json.challenge,session_id:current.session.id});check(result.status==='PASS','RUST_SQLITE_UNWRAP_AND_SIGN');
 const upgraded=await browser.call('/auth/device-proof',{version:1,challenge_id:challenge.json.challenge.context.challenge_id,proof:result.proof});check(upgraded.status===200&&upgraded.json.session.state==='trusted','ACTUAL_NATIVE_BOTH_KEY_PROOF');
 check((await browser.call('/auth/device-proof',{version:1,challenge_id:challenge.json.challenge.context.challenge_id,proof:result.proof})).status===401,'PROOF_REPLAY_DENIED');
 const wrong=native=>spawnSync(binary,[],{cwd:root,input:JSON.stringify(native),encoding:'utf8',timeout:120000,maxBuffer:1048576});
 const other=await browser.call('/auth/device-challenge',{version:1,device_id:profile.device_id});check(wrong({...input,challenge:other.json.challenge,session_id:b64(randomBytes(16))}).status!==0,'WRONG_SESSION_NO_NATIVE_SIGNATURE');
 check(wrong({...input,challenge:other.json.challenge,session_id:current.session.id,pins:{...pins,root_fingerprint:b64(randomBytes(32))}}).status!==0,'WRONG_ROOT_NO_NATIVE_SIGNATURE');
 const verifier=b64(randomBytes(32)),state=b64(randomBytes(32)),params={client_id:'anynote-windows',redirect_uri:'http://127.0.0.1:49871/callback/'+b64(randomBytes(16)),state,code_challenge:b64(sha(verifier)),code_challenge_method:'S256',device_commitment:deviceCommitment(initial.device)};
 const start=await request('/auth/native/authorize?'+new URLSearchParams(params),{origin:null});check(start.status===200,'NATIVE_GRANT_START');check((await browser.call('/auth/native/authorizations/'+start.json.authorization_id)).status===200,'NATIVE_CONSENT_BINDING');const approval=await browser.call('/auth/native/approve',{version:1,authorization_id:start.json.authorization_id});check(approval.status===200,'NATIVE_GRANT_CONSENT');const callback=new URL(approval.json.redirect_uri);
 const token=await request('/auth/native/token',{origin:null,body:{version:1,grant_type:'authorization_code',client_id:'anynote-windows',issuer,authorization_id:start.json.authorization_id,redirect_uri:params.redirect_uri,code:callback.searchParams.get('code'),code_verifier:verifier}});check(token.status===200&&token.json.session.state==='restricted','MAINTAINED_REAL_NATIVE_TOKEN');
 const transported=native({...input,native_transport:{issuer,app:origin,ca_path:root+'/.local/p06/tls/ca.crt',credentials:{access:token.json.access_token,refresh:token.json.refresh_token,session_id:token.json.session.id,state:token.json.session.state}}});check(transported.status==='PASS'&&transported.snapshot.state.rotation===null,'NATIVE_ENCRYPTED_CREDENTIAL_ADOPTION_AND_REAL_ROTATION');
 const serialized=JSON.stringify(transported.snapshot);check(!serialized.includes(token.json.access_token)&&!serialized.includes(token.json.refresh_token),'NO_RAW_BEARER_IN_SQLITE_SNAPSHOT');
 check((await request('/me',{origin:null,headers:{Authorization:'Bearer '+token.json.access_token}})).status===401,'OLD_ACCESS_ROTATED');
 const reuse=await request('/auth/native/token',{origin:null,body:{version:1,grant_type:'refresh_token',client_id:'anynote-windows',issuer,refresh_token:token.json.refresh_token}});check(reuse.status===401,'USED_REFRESH_DENIED');
 report.status='PASS';report.checks=checks;report.transport='Native maintained P06 OAuth2 refresh through verified TLS; P05 frozen wrappers, actual native SQLite and fresh both-key proof against Laravel/MariaDB';
}finally{initial.dispose();}
mkdirSync(root+'/artifacts/p07',{recursive:true});writeFileSync(root+'/artifacts/p07/http-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
