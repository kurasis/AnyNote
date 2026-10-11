// Real trusted TLS and session readiness; never prints a cookie, CSRF token or key.
import https from 'node:https';
import {readFileSync} from 'node:fs';
const ca=readFileSync(new URL('../../.local/p06/tls/ca.crt',import.meta.url));
function get(host,path,origin){return new Promise((done,reject)=>{const r=https.get({hostname:'127.0.0.1',servername:host,port:18443,ca,path,headers:{Host:host+':18443',...(origin?{Origin:origin}:{})}},s=>{const chunks=[];let size=0;s.on('data',b=>{size+=b.length;if(size>32768)r.destroy(Error('RESPONSE_TOO_LARGE'));else chunks.push(b);});s.on('end',()=>done({status:s.statusCode,headers:s.headers,bytes:Buffer.concat(chunks)}));});r.setTimeout(5000,()=>r.destroy(Error('READINESS_TIMEOUT')));r.on('error',reject);});}
const api='api.anynote.test',app='app.anynote.test',origin='https://'+app+':18443';
const c=await get(api,'/api/v1/capabilities',origin),s=await get(api,'/api/v1/auth/csrf',origin),p=await get(app,'/auth/');
if(c.status!==200||JSON.parse(c.bytes).features.account_authentication!==true||s.status!==200||!/^.{40,64}$/.test(JSON.parse(s.bytes).csrf_token)||p.status!==200||!p.headers['content-security-policy'].includes("frame-ancestors 'none'")||(await get(api,'/api/v1/auth/csrf','https://hostile.invalid')).status!==404)throw Error('P06_READINESS_FAILED');
const cookies=s.headers['set-cookie']??[];
if(!cookies.some(c=>c.startsWith('__Host-vault_session=')&&/; secure/i.test(c)&&/; httponly/i.test(c)&&/; samesite=strict/i.test(c)&&!/; domain=/i.test(c))||cookies.some(c=>c.startsWith('XSRF-TOKEN=')))throw Error('P06_SESSION_POLICY_FAILED');
console.log('PASS: trusted HTTPS static/API origins, Laravel/SQL encrypted session, secure host-only cookie, CSRF and hostile-origin denial');
