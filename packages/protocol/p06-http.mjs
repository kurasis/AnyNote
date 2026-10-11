// Real HTTPS -> Nginx -> Laravel -> MariaDB. Synthetic authenticator uses Node's maintained P-256.
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
const report={purpose:'P06 actual HTTPS/SQL synthetic-authenticator attack evidence',status:'PENDING',source_commit:spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).stdout.trim(),physical_acceptance:false,independent_review:'NOT_RUN'};
async function main(){
  const a=new Browser();await a.start();
  check((await a.call('/auth/passkeys/options',{version:1,ceremony:'login'},undefined,{csrf:undefined})).status===400,'CSRF_REQUIRED');
  check((await a.call('/auth/passkeys/options',{version:1,ceremony:'login'},undefined,{csrf:undefined,headers:{'Sec-Fetch-Site':'same-origin'}})).status===400,'FETCH_METADATA_NO_BYPASS');
  check((await a.call('/auth/csrf',undefined,undefined,{origin:'https://attacker.invalid'})).status===404,'HOSTILE_ORIGIN');
  const invite=control('invite').token;const o=await options(a,'register',{invitation:invite,handle:'p06-alice'}),key=authenticator(o.account_id);
  const att=key.create(o.publicKey);const enrolled=await verify(a,o,att);check(enrolled.status===200&&enrolled.json.verified,'ENROLLMENT:'+enrolled.status+':'+enrolled.json?.error?.code);
  check((await verify(a,o,att)).status===401,'REGISTER_CHALLENGE_REPLAY');
  const initial=await initialRoot('AAAAAAAAAAAAAAAAAAAAAQ',o.account_id);
  try{
    const exported=recoveryKitExport(issuer,initial.kit);check(exported.service_url===issuer&&exported.kit===initial.kit&&exported.instructions.includes('Never send'),'COMPLETE_OFFLINE_KIT');
    const prepare={version:1,registration_id:o.registration_id,identity:initial.identity,device:initial.device};
    const c=await a.call('/accounts/registration-challenge',prepare);check(c.status===200,'ROOT_PREPARE:'+c.json?.error?.code);
    const register=registrationRequest(o.registration_id,initial,c.json.challenge);
    const bad=structuredClone(register);bad.roster.body.payload.confirmation.body.challenge_response=b64(randomBytes(32));
    check((await a.call('/accounts/register',bad)).status>=400,'BOTH_KEY_PROOF');check(control('counts').users===0,'REGISTER_ROLLBACK');
    const registrations=await Promise.all(Array.from({length:8},()=>request('/accounts/register',{body:register,cookie:a.cookie,csrf:a.csrf})));check(registrations.filter(x=>x.status===200).length===1&&registrations.filter(x=>x.status===401).length===7,'REGISTER_RACE:'+JSON.stringify(registrations.map(x=>({status:x.status,code:x.json?.error?.code}))));const registered=registrations.find(x=>x.status===200);a.cookie=registered.headers['set-cookie'].find(c=>c.startsWith('__Host-vault_session=')).split(';')[0];a.csrf=registered.json.csrf_token;check(registered.json.session.state==='trusted','REGISTER_TRUSTED_SESSION');report.registration_concurrency={requests:8,winners:1,denials:7};
    check((await a.call('/accounts/register',register)).status===200,'REGISTER_RECEIPT');check(control('counts').users===1,'NO_DUPLICATE_IDENTITY');
    const me=await a.call('/me');check(me.json.content_access===true,'REGISTER_TRUSTED:'+me.status+':'+me.json?.error?.code);
    check((await a.call('/auth/passkeys/options',{version:1,ceremony:'register',invitation:invite,handle:'p06-again'})).status===401,'CONSUMED_INVITE');
    const keys=await a.call('/me/passkeys');check(keys.status===200&&keys.json.passkeys.length===1,'PASSKEY_LIST');
    const removal=await a.call('/me/passkeys/'+keys.json.passkeys[0].id,{version:1},'DELETE');check(removal.status===403,'LAST_METHOD_DENIED:'+removal.status+':'+removal.json?.error?.code);
    const add=await options(a,'add'),second=authenticator(o.account_id);check((await verify(a,add,second.create(add.publicKey))).status===200,'ADD_PASSKEY');
    check((await a.call('/me/passkeys')).json.passkeys.length===2,'TWO_PASSKEYS');
    const recovery=await a.call('/me/recovery-codes',{version:1});check(recovery.status===200&&recovery.json.codes.length===10,'RECOVERY_CODES');
    const b=new Browser();const logged=await login(b,key);check((await b.call('/me')).json.content_access===false,'LOGIN_NO_CONTENT');
    check((await b.call('/admin/account-invitations',{valid_hours:48,recipient_binding_hash:null})).status>=400,'RESTRICTED_ADMIN');
    const ch=await b.call('/auth/device-challenge',{version:1,device_id:initial.device.device_id});check(ch.status===200,'DEVICE_CHALLENGE');
    const proof=possession(ch.json.challenge,initial.keys,{service_id:initial.identity.body.service_id,account_id:o.account_id,root_fingerprint:initial.fingerprint,session_id:logged.session.id});
    const upgrade={version:1,challenge_id:ch.json.challenge.context.challenge_id,proof};
    check((await b.call('/auth/device-proof',upgrade)).status===200,'DEVICE_UPGRADE');check((await b.call('/auth/device-proof',upgrade)).status===401,'DEVICE_PROOF_REPLAY');
    check((await b.call('/me')).json.content_access===true,'POST_PROOF_CONTENT');
    const stranger=new Browser();await stranger.start();const reauth=await options(b,'reauth');const assertion=key.get(reauth.publicKey);check((await verify(stranger,reauth,assertion)).status===401,'CHALLENGE_COOKIE_BINDING');check((await verify(b,reauth,assertion)).status===200,'OWN_CHALLENGE_SURVIVES_OTHER_COOKIE');
    for(const [label,change]of [['origin',{clientOrigin:'https://evil.invalid'}],['rp',{rp:'evil.invalid'}],['UV',{uv:false}],['challenge',{challenge:b64(randomBytes(32))}],['account',{user:b64(randomBytes(16))}],['counter',{count:0}]]){
      const c=await options(b,'reauth');const wrong=key.get(c.publicKey,change);check((await verify(b,c,wrong)).status===401,'WEBAUTHN_'+label);check((await verify(b,c,key.get(c.publicKey))).status===401,'CONSUMED_BAD_'+label);
    }
    control('clear-rates');const expired=await options(b,'reauth');control('expire-challenges');check((await verify(b,expired,key.get(expired.publicKey))).status===401,'EXPIRED_CHALLENGE');
    control('age-auth');check((await b.call('/me/recovery-codes',{version:1})).status===403,'RECENT_AUTH_REQUIRED');const fresh=await options(b,'reauth');check((await verify(b,fresh,key.get(fresh.publicKey))).status===200,'RECENT_AUTH_RESTORED');
    const codeBrowser=new Browser();await codeBrowser.start();const recovered=await codeBrowser.call('/auth/recovery-code',{version:1,code:recovery.json.codes[0]});check(recovered.status===200&&recovered.json.session.state==='restricted','AUTH_RECOVERY_RESTRICTED');
    const replay=new Browser();await replay.start();check((await replay.call('/auth/recovery-code',{version:1,code:recovery.json.codes[0]})).status===401,'RECOVERY_ONCE');
    const expiredInvite=control('invite').token;control('expire-invitations');check((await replay.call('/auth/passkeys/options',{version:1,ceremony:'register',invitation:expiredInvite,handle:'p06-expired'})).status===401,'EXPIRED_INVITATION');
    const unknown=await options(replay,'login');check(unknown.publicKey.allowCredentials.length===0&&!('account_id'in unknown),'NO_ACCOUNT_ENUMERATION');
    const native=async()=>{
      const verifier=b64(randomBytes(32)),state=b64(randomBytes(32));const params={client_id:'anynote-windows',redirect_uri:'http://127.0.0.1:49873/callback/'+b64(randomBytes(16)),state,code_challenge:b64(sha(verifier)),code_challenge_method:'S256',device_commitment:deviceCommitment(initial.device)};
      const start=await request('/auth/native/authorize?'+new URLSearchParams(params),{origin:null});check(start.status===200,'NATIVE_AUTHORIZE:'+start.json?.error?.code);
      const id=start.json.authorization_id;check((await b.call('/auth/native/authorizations/'+id)).status===200,'NATIVE_CONSENT');
      const approval=await b.call('/auth/native/approve',{version:1,authorization_id:id});check(approval.status===200,'NATIVE_APPROVE:'+approval.json?.error?.code);const callback=new URL(approval.json.redirect_uri);check(callback.searchParams.get('state')===state&&callback.searchParams.get('iss')===issuer&&!callback.searchParams.has('access_token'),'CODE_ONLY_CALLBACK');
      return {version:1,grant_type:'authorization_code',client_id:'anynote-windows',issuer,authorization_id:id,redirect_uri:params.redirect_uri,code:callback.searchParams.get('code'),code_verifier:verifier};
    };
    const sdk=spawn(resolve(root,'packages/auth-native/target/debug/p06-integration'),[],{cwd:root,stdio:['pipe','pipe','pipe']});
    let sdkError=false;sdk.stderr.on('data',()=>{sdkError=true;});const lines=createInterface({input:sdk.stdout});const iterator=lines[Symbol.asyncIterator]();
    sdk.stdin.end(JSON.stringify({issuer,app:origin,ca_path:root+'/.local/p06/tls/ca.crt',device_commitment:deviceCommitment(initial.device)}));
    const ready=await iterator.next();check(!ready.done,'NATIVE_SDK_START');const consentURL=new URL(JSON.parse(ready.value).consent_url);const sdkID=consentURL.searchParams.get('authorization');
    check((await b.call('/auth/native/authorizations/'+sdkID)).status===200,'NATIVE_SDK_CONSENT');const approved=await b.call('/auth/native/approve',{version:1,authorization_id:sdkID});check(approved.status===200,'NATIVE_SDK_APPROVAL');
    const callback=new URL(approved.json.redirect_uri);const rejected=new URL(callback);rejected.searchParams.set('state',b64(randomBytes(32)));
    const local=u=>new Promise((done,reject)=>{const r=http.get(u,s=>{s.resume();done(s.statusCode);});r.setTimeout(5000,()=>r.destroy(Error('CALLBACK_TIMEOUT')));r.on('error',reject);});
    check(await local(rejected)===400,'NATIVE_SDK_WRONG_STATE');check(await local(callback)===200,'NATIVE_SDK_ACTUAL_TCP_CALLBACK');
    const finish=await iterator.next();check(!finish.done&&JSON.parse(finish.value).status==='PASS'&&!sdkError,'NATIVE_SDK_HTTPS_PKCE_REFRESH_REUSE');report.native_sdk_transport='actual maintained Rust OAuth2 to PHP League through HTTPS, loopback TCP and refresh/reuse';
    const parallelCode=await native();const codeBefore=control('counts');control('clear-rates');
    const redemptions=await Promise.all(Array.from({length:8},()=>request('/auth/native/token',{body:parallelCode,origin:null})));
    check(redemptions.filter(x=>x.status===200).length===1&&redemptions.filter(x=>x.status===401).length===7,'CODE_RACE_ONE_WINNER:'+JSON.stringify(redemptions.map(x=>({status:x.status,code:x.json?.error?.code}))));
    const codeAfter=control('counts');check(codeAfter.refresh_tokens===codeBefore.refresh_tokens+1&&codeAfter.oauth_access===codeBefore.oauth_access+1,'CODE_RACE_NO_PARTIAL_DUPLICATE_TOKENS');
    report.code_concurrency={requests:8,configured_php_workers:8,winners:1,denials:7,token_rows_added:1};
    const grant=await native();
    check((await request('/auth/native/token',{body:{...grant,issuer:'https://wrong.invalid'},origin:null})).status===401,'NATIVE_ISSUER');
    check((await request('/auth/native/token',{body:{...grant,code_verifier:b64(randomBytes(32))},origin:null})).status===401,'PKCE_REQUIRED');
    check((await request('/auth/native/token',{body:grant,cookie:b.cookie,csrf:b.csrf})).status===401,'TOKEN_FORBIDDEN_TO_BROWSER');
    const token=await request('/auth/native/token',{body:grant,origin:null});check(token.status===200&&token.json.session.state==='restricted','TOKEN_GRANT:'+token.status+':'+token.json?.error?.code);check(!token.headers['set-cookie'],'NO_NATIVE_COOKIE');
    check((await request('/auth/native/token',{body:grant,origin:null})).status===401,'CODE_ONCE');
    const bearer={origin:null,headers:{Authorization:'Bearer '+token.json.access_token}};
    check((await request('/me',bearer)).json.content_access===false,'NATIVE_NO_AUTO_TRUST');check(control('content-authorization',token.json.access_token).code==='SESSION_DEVICE_PROOF_REQUIRED','REAL_BEARER_CONTENT_DENIAL');
    const dc=await request('/auth/device-challenge',{...bearer,body:{version:1,device_id:initial.device.device_id}});check(dc.status===200,'NATIVE_DEVICE_CHALLENGE');
    const dp=possession(dc.json.challenge,initial.keys,{service_id:initial.identity.body.service_id,account_id:o.account_id,root_fingerprint:initial.fingerprint,session_id:token.json.session.id});check((await request('/auth/device-proof',{...bearer,body:{version:1,challenge_id:dc.json.challenge.context.challenge_id,proof:dp}})).status===200,'NATIVE_DEVICE_UPGRADE');
    check(control('content-authorization',token.json.access_token).status==='ALLOWED','REAL_BOUND_BEARER_CONTENT_AUTHORIZATION');
    const refresh={version:1,grant_type:'refresh_token',client_id:'anynote-windows',issuer,refresh_token:token.json.refresh_token};
    const rotated=await request('/auth/native/token',{body:refresh,origin:null});check(rotated.status===200&&rotated.json.session.state==='trusted','ROTATE_BOUND_TRUST:'+rotated.status+':'+rotated.json?.error?.code);
    check((await request('/me',bearer)).status===401,'OLD_ACCESS_INVALID');
    check((await request('/auth/native/token',{body:refresh,origin:null})).status===401,'REFRESH_REUSE');
    check((await request('/me',{origin:null,headers:{Authorization:'Bearer '+rotated.json.access_token}})).status===401,'REUSE_REVOKES_FAMILY');
    const raceGrant=await native();const raceToken=await request('/auth/native/token',{body:raceGrant,origin:null});check(raceToken.status===200,'RACE_TOKEN');
    control('clear-rates');const parallel=await Promise.all(Array.from({length:8},()=>request('/auth/native/token',{body:{...refresh,refresh_token:raceToken.json.refresh_token},origin:null})));check(parallel.filter(x=>x.status===200).length===1&&parallel.filter(x=>x.status===401).length===7,'REFRESH_RACE_ONE_WINNER:'+JSON.stringify(parallel.map(x=>({status:x.status,code:x.json?.error?.code}))));const winner=parallel.find(x=>x.status===200);check((await request('/me',{origin:null,headers:{Authorization:'Bearer '+winner.json.access_token}})).status===401,'RACE_REUSE_REVOKED');
    for(const uri of ['http://0.0.0.0:1234/callback/'+b64(randomBytes(16)),'https://127.0.0.1:1234/callback/'+b64(randomBytes(16)),'http://localhost:1234/callback/'+b64(randomBytes(16))])check((await request('/auth/native/authorize?'+new URLSearchParams({client_id:'anynote-windows',redirect_uri:uri,state:b64(randomBytes(32)),code_challenge:b64(randomBytes(32)),code_challenge_method:'S256',device_commitment:deviceCommitment(initial.device)}),{origin:null})).status===400,'LITERAL_LOOPBACK_ONLY');
    const sessions=await b.call('/me/sessions');check(sessions.status===200&&sessions.json.sessions.some(x=>x.current),'SESSION_LIST');
    const recoveredID=recovered.json.session.id;check((await b.call('/me/sessions/'+recoveredID,{version:1},'DELETE')).status===200,'REVOKE_OTHER_SESSION');check((await codeBrowser.call('/me')).status===401,'OTHER_SESSION_REVOKED');
    check((await b.call('/auth/logout',{version:1})).status===200,'LOGOUT');check((await b.call('/me')).status===401,'LOGOUT_REVOKED');
    const afterLogout=await options(b,'login');check((await verify(b,afterLogout,key.get(afterLogout.publicKey))).status===200,'LOGIN_WITH_REGENERATED_CSRF');
    control('expire-pwa');check((await b.call('/me')).status===401,'PWA_IDLE_EXPIRY');
    const afterExpiry=await options(b,'login');check((await verify(b,afterExpiry,key.get(afterExpiry.publicKey))).status===200,'EXPIRED_COOKIE_LOGIN_RECOVERS');
    const expiredSession=await a.call('/auth/logout',{version:1});check(expiredSession.status===200,'EXPIRED_LOGOUT_IDEMPOTENT');check((await a.call('/auth/logout',{version:1})).status===200,'ANONYMOUS_LOGOUT_IDEMPOTENT');
    const ownerLogin=await options(a,'login');const ownerSession=await verify(a,ownerLogin,key.get(ownerLogin.publicKey));check(ownerSession.status===200,'OWNER_LOGIN');
    const ownerChallenge=await a.call('/auth/device-challenge',{version:1,device_id:initial.device.device_id});check(ownerChallenge.status===200,'OWNER_CHALLENGE');
    const ownerProof=possession(ownerChallenge.json.challenge,initial.keys,{service_id:initial.identity.body.service_id,account_id:o.account_id,root_fingerprint:initial.fingerprint,session_id:ownerSession.json.session.id});
    check((await a.call('/auth/device-proof',{version:1,challenge_id:ownerChallenge.json.challenge.context.challenge_id,proof:ownerProof})).status===200,'OWNER_BOTH_KEY_PROOF');
    control('bootstrap-admin');check((await a.call('/me')).json.is_admin===true,'INITIAL_ADMIN_CONSOLE');
    check((await a.call('/admin/accounts/'+o.account_id+'/disable',{version:1})).status===403,'ADMIN_CANNOT_DISABLE_SELF');
    const adminInvite=await a.call('/admin/account-invitations',{valid_hours:48,recipient_binding_hash:sha('p06-bob').toString('hex')});check(adminInvite.status===200,'ADMIN_INVITE');
    const bob=new Browser();await bob.start();check((await bob.call('/auth/passkeys/options',{version:1,ceremony:'register',invitation:adminInvite.json.token,handle:'p06-wrong'})).status===401,'INVITE_RECIPIENT_BINDING');
    const bo=await options(bob,'register',{invitation:adminInvite.json.token,handle:'p06-bob'}),bobKey=authenticator(bo.account_id);check((await verify(bob,bo,bobKey.create(bo.publicKey))).status===200,'SECOND_ACCOUNT_WEBAUTHN');
    const bobRoot=await initialRoot('AAAAAAAAAAAAAAAAAAAAAQ',bo.account_id);
    try{
      const bc=await bob.call('/accounts/registration-challenge',{version:1,registration_id:bo.registration_id,identity:bobRoot.identity,device:bobRoot.device});check(bc.status===200,'SECOND_ACCOUNT_ROOT_CHALLENGE');
      check((await bob.call('/accounts/register',registrationRequest(bo.registration_id,bobRoot,bc.json.challenge))).status===200,'SECOND_ACCOUNT_REGISTER');
      check((await a.call('/me/sessions/'+(await bob.call('/me')).json.session.id,{version:1},'DELETE')).status===404,'OTHER_ACCOUNT_SESSION_HIDDEN');
      const aKeys=await a.call('/me/passkeys');check((await bob.call('/me/passkeys/'+aKeys.json.passkeys[0].id,{version:1},'DELETE')).status===404,'OTHER_ACCOUNT_PASSKEY_HIDDEN');
      check((await bob.call('/admin/account-invitations',{valid_hours:48,recipient_binding_hash:null})).status===403,'NON_ADMIN_INVITE');
      check((await a.call('/admin/accounts/'+bo.account_id+'/disable',{version:1})).status===200,'ADMIN_DISABLE');check((await bob.call('/me')).status===401,'DISABLED_SESSION_DENIED');
      const disabledOptions=await options(bob,'login');check((await verify(bob,disabledOptions,bobKey.get(disabledOptions.publicKey))).status===401,'DISABLED_PASSKEY_DENIED');
      check((await bob.call('/auth/logout',{version:1})).status===200,'DISABLED_LOGOUT');
    }finally{bobRoot.dispose();}
    check((await a.call('/me/sessions',{version:1},'DELETE')).status===200,'REVOKE_ALL');check((await a.call('/me')).status===401&&(await b.call('/me')).status===401,'ALL_PWA_SESSIONS_REVOKED');
    control('clear-rates');const counterBrowsers=Array.from({length:8},()=>new Browser());await Promise.all(counterBrowsers.map(x=>x.start()));
    const counterOptions=await Promise.all(counterBrowsers.map(x=>options(x,'login')));
    const counterResults=await Promise.all(counterBrowsers.map((x,i)=>verify(x,counterOptions[i],second.get(counterOptions[i].publicKey,{count:1}))));
    check(counterResults.filter(x=>x.status===200).length===1&&counterResults.filter(x=>x.status===401).length===7,'COUNTER_RACE_CURRENT_CREDENTIAL:'+JSON.stringify(counterResults.map(x=>({status:x.status,code:x.json?.error?.code}))));
    report.counter_concurrency={requests:8,winners:1,denials:7,same_nonzero_counter:1};
    const cleanup=control('prune-expired');check(cleanup.expired_challenges>0&&cleanup.remaining_challenges===0&&cleanup.removed>=cleanup.expired_challenges,'BOUNDED_AUTH_EXPIRY_CLEANUP');check(cleanup.users===2&&cleanup.devices===2&&cleanup.rosters===2,'CLEANUP_PRESERVES_ROOT_DEVICES');
    control('clear-rates');const rate=new Browser();await rate.start();let limited=false;for(let i=0;i<25;i++){const x=await rate.call('/auth/recovery-code',{version:1,code:b64(randomBytes(32))});if(x.status===429){limited=true;break;}check(x.status===401,'INVALID_CODES_CONCEALED');}check(limited,'RATE_PERSISTS_DENIAL');
    control('clear-rates');const admission=[];
    const admit=()=>request('/auth/native/authorize?'+new URLSearchParams({client_id:'anynote-windows',redirect_uri:'http://127.0.0.1:49873/callback/'+b64(randomBytes(16)),state:b64(randomBytes(32)),code_challenge:b64(randomBytes(32)),code_challenge_method:'S256',device_commitment:deviceCommitment(initial.device)}),{origin:null});
    for(let i=0;i<8;i++)admission.push(...await Promise.all(Array.from({length:8},admit)));
    check(admission.filter(x=>x.status===200).length===60&&admission.filter(x=>x.status===429&&x.json?.error?.code==='RATE_LIMITED').length===4,'CONCURRENT_ADMISSION_EXACT_BOUND:'+JSON.stringify(admission.map(x=>({status:x.status,code:x.json?.error?.code}))));
    control('expire-rates');check((await admit()).status===200,'EXPIRED_RATE_WINDOW_RESET');
    report.rate_concurrency={requests:64,simultaneous_requests:8,admitted:60,limited:4,expired_window_reset:'PASS'};
    report.refresh_concurrency={requests:8,configured_php_workers:8,winners:1,denials:7,reuse_family_revocation:'PASS'};
    report.authentication_vs_content='Fresh login/recovery/native grants restricted; both-key current-device proof required';
  }finally{initial.dispose();}
  report.status='PASS';report.checks=checks;
}
rmSync(root+'/artifacts/p06/http-report.json',{force:true});
await main();
mkdirSync(root+'/artifacts/p06',{recursive:true});writeFileSync(root+'/artifacts/p06/http-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
