// P08 real HTTPS -> Nginx -> Laravel -> MariaDB. Synthetic authenticator uses Node's maintained P-256.
// No mock verifier or HTTP token issuer. Secret fixtures are memory-only, excluded from reports.
import https from 'node:https';
import http from 'node:http';
import {createInterface} from 'node:readline';
import {generateKeyPairSync,sign,createHash,randomBytes} from 'node:crypto';
import {readFileSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {spawnSync,spawn} from 'node:child_process';
import {resolve} from 'node:path';
import {initialRoot,registrationRequest,possession,deviceCommitment,authValue,recoveryKitExport} from '../auth-client.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
const root=resolve(import.meta.dirname,'../../..'),issuer='https://api.anynote.test:18443',origin='https://app.anynote.test:18443';
const ca=readFileSync(root+'/.local/p06/tls/ca.crt');
const sortJson=v=>Array.isArray(v)?v.map(sortJson):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,sortJson(v[k])])):v;
let checks=0;
function check(v,why){if(!v)throw Error(why);checks++;}
function control(op, input){const r=spawnSync('python3',['scripts/p06-stack.py','control',op],{cwd:root,encoding:'utf8',input});if(r.status!==0)throw Error('CONTROL_FAILED:'+op);try{return JSON.parse(r.stdout);}catch{throw Error('CONTROL_INVALID_RESULT:'+op);}}
export function request(path,{body,method=body?'POST':'GET',cookie,csrf,origin:requestOrigin=origin,headers={}}={}){
  return new Promise((done,reject)=>{const text=body===undefined?undefined:JSON.stringify(body);const req=https.request({hostname:'127.0.0.1',port:18443,servername:'api.anynote.test',ca,path:'/api/v1'+path,method,headers:{Host:'api.anynote.test:18443',Accept:'application/json',...(requestOrigin?{Origin:requestOrigin}:{}),...(cookie?{Cookie:cookie}:{}),...(csrf?{'X-CSRF-TOKEN':csrf}:{}),...(text?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(text)}:{}),...headers}},res=>{const chunks=[];let n=0;res.on('data',b=>{n+=b.length;if(n>4194304)req.destroy(Error('RESPONSE_TOO_LARGE'));else chunks.push(b);});res.on('end',()=>{let json;try{json=JSON.parse(Buffer.concat(chunks));}catch{json=null;}done({status:res.statusCode,headers:res.headers,json});});});req.setTimeout(10000,()=>req.destroy(Error('HTTP_TIMEOUT')));req.on('error',reject);req.end(text);});
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


export {Browser,authenticator,options,verify,login,control,check};
export const fixtureCheckCount=()=>checks;
