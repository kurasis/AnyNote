import https from 'node:https';
import {readFileSync} from 'node:fs';
const ca=readFileSync(new URL('../../../.local/p06/tls/ca.crt',import.meta.url));
export function binary(browser,path,bytes,method=bytes?'PUT':'GET',headers={}){
 return new Promise((resolve,reject)=>{
  const req=https.request({hostname:'127.0.0.1',port:18443,servername:'api.anynote.test',ca,path:'/api/v1'+path,method,headers:{Host:'api.anynote.test:18443',Origin:'https://app.anynote.test:18443',Cookie:browser.cookie,'X-CSRF-TOKEN':browser.csrf,...(bytes?{'Content-Type':'application/octet-stream','Content-Length':bytes.length}:{}),...headers}},res=>{
   const parts=[];let length=0;res.on('data',b=>{length+=b.length;if(length>8388624)req.destroy(Error('RESOURCE_LIMIT'));else parts.push(b);});res.on('end',()=>{const bytes=Buffer.concat(parts);let json;try{json=JSON.parse(bytes);}catch{}resolve({status:res.statusCode,json,bytes});});
  });req.setTimeout(30000,()=>req.destroy(Error('HTTP_TIMEOUT')));req.on('error',reject);req.end(bytes);
 });
}
// Genuine socket loss: the client submits only a prefix of an authenticated part.
export function cutPart(browser,path,bytes){
 return new Promise(resolve=>{const req=https.request({hostname:'127.0.0.1',port:18443,servername:'api.anynote.test',ca,path:'/api/v1'+path,method:'PUT',headers:{Host:'api.anynote.test:18443',Origin:'https://app.anynote.test:18443',Cookie:browser.cookie,'X-CSRF-TOKEN':browser.csrf,'Content-Type':'application/octet-stream','Content-Length':bytes.length}},res=>res.destroy());req.on('error',()=>resolve());req.write(bytes.subarray(0,Math.min(65536,bytes.length-1)),()=>req.destroy(Error('PUBLIC_SYNTHETIC_DISCONNECT')));});
}
// Drop the actual response body after server transaction headers, before client acknowledgement.
export function loseCommitResponse(browser,path,body){
 return new Promise((resolve,reject)=>{const data=JSON.stringify(body),req=https.request({hostname:'127.0.0.1',port:18443,servername:'api.anynote.test',ca,path:'/api/v1'+path,method:'POST',headers:{Host:'api.anynote.test:18443',Origin:'https://app.anynote.test:18443',Cookie:browser.cookie,'X-CSRF-TOKEN':browser.csrf,'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)}},res=>{const status=res.statusCode;res.destroy();resolve(status);});req.on('error',reject);req.setTimeout(30000,()=>req.destroy(Error('HTTP_TIMEOUT')));req.end(data);});
}
