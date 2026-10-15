// Ephemeral Windows CI signer and HTTPS fixtures. Never production signing material.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdirSync,readdirSync,copyFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
export function updateFixture(root,appRoot){
 assert(process.platform==='win32'&&process.env.GITHUB_ACTIONS==='true');
 const owned=JSON.parse(readFileSync(join(root,'.local/p14-webview/owner.json')));assert.equal(owned.purpose,'P14 synthetic installed host software acceptance');
 const work=join(root,'.local/p14-update-signing'),site=join(root,'.local/p06/static/p14-update');mkdirSync(work);mkdirSync(site,{recursive:true});
 const cli=join(root,'apps/desktop/node_modules/@tauri-apps/cli/tauri.js'),key=join(work,'ephemeral.key');
 const run=args=>{
  try{return execFileSync(process.execPath,[cli,...args],{cwd:root,env:{...process.env,CI:'true',TAURI_SIGNING_PRIVATE_KEY_PASSWORD:''},stdio:['ignore','pipe','pipe']});}
  catch(error){
   // execFileSync errors retain stdout/stderr and may include the ephemeral key.
   for(const bytes of [error.stdout,error.stderr,...(error.output??[])])if(Buffer.isBuffer(bytes))bytes.fill(0);
   throw Error('EPHEMERAL_SIGNER_FAILED: private output withheld');
  }
 };
 const candidate=join(root,'.local/p14-candidate'),names=readdirSync(candidate).filter(n=>n.endsWith('.exe'));assert.equal(names.length,1);const installer=join(candidate,names[0]);
 try{
  // CLI output includes private key text: capture it in memory, never log it.
  const generated=run(['signer','generate','--ci','--write-keys',key]);generated.fill(0);
  const publicKey=readFileSync(key+'.pub','utf8').trim();
  const sign=(path,version='0.14.1')=>{const output=run(['signer','sign','--private-key-path',key,'--app-version',version,path]);output.fill(0);return readFileSync(path+'.sig','utf8').trim();};
  const artifactSignature=sign(installer);copyFileSync(installer,join(site,'candidate.exe'));
  const url='https://app.anynote.test:18443/p14-update/candidate.exe';
  const claims={application_id:'org.anynote.desktop',artifact_sha256:createHash('sha256').update(readFileSync(installer)).digest('base64url'),channel:'candidate',platform:'windows-x86_64',protocol:'anynote-update-v1',url,version:'0.14.1'};
  const claimsFile=join(work,'claims.json');writeFileSync(claimsFile,JSON.stringify(claims));
  const manifest={version:'0.14.1',url,signature:artifactSignature,anynote_claims:claims,anynote_claims_signature:sign(claimsFile)};
  writeFileSync(join(appRoot,'update-policy.json'),JSON.stringify({endpoint:'https://app.anynote.test:18443/p14-update/manifest.json',public_key:publicKey,channel:'candidate'}));
  return {installer,manifest,set(value){writeFileSync(join(site,'manifest.json'),JSON.stringify(value));},restoreArtifact(){copyFileSync(installer,join(site,'candidate.exe'));},tamperArtifact(){const bytes=readFileSync(installer);bytes[bytes.length-1]^=1;writeFileSync(join(site,'candidate.exe'),bytes);},site,claims};
 }finally{rmSync(work,{recursive:true});}
}
