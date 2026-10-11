// Hosted real-browser bridge for the P05 public-signature slice needed by P04.
import {build} from 'esbuild';
import {chromium} from 'playwright-core';
import {existsSync,readFileSync,writeFileSync,mkdirSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {createServer} from 'node:http';
import {spawnSync} from 'node:child_process';
const root=resolve(import.meta.dirname,'../..');
const fixturePath=join(root,'apps/api/storage/framework/testing/p04-fixtures.json');
const fixture=JSON.parse(readFileSync(fixturePath));
const native=spawnSync(join(root,'packages/crypto-native/target/debug/anynote-public-signature'),[fixturePath],{encoding:'utf8'});
if(native.status!==0)throw new Error('Native public signature test failed');
const nativeReport=JSON.parse(native.stdout);
if(nativeReport.native_signature_hex!==fixture.signature_hex)throw new Error('Native/Node signature mismatch');
const scratch=mkdtempSync(join(tmpdir(),'anynote-p04-public-'));
const worker=join(scratch,'worker.js');
await build({stdin:{contents:`import {publicSigningBytes,verifyPublicHeader,signPublicHeader} from ${JSON.stringify(join(root,'packages/protocol/adapters/public-signatures.mjs'))};
import sodium from ${JSON.stringify(join(root,'packages/protocol/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs'))};
await sodium.ready;
self.onmessage=({data:f})=>{try{const b=Uint8Array.from;const enc=new TextEncoder();const h=enc.encode(f.canonical_header);const sig=sodium.from_hex(f.signature_hex),pub=sodium.from_hex(f.public_key_hex);let checks=0;
if(!verifyPublicHeader(h,sig,pub))throw new Error('Verify failed');checks++;
if(sodium.to_hex(publicSigningBytes(h))!==f.signing_input_hex)throw new Error('Signing input changed');checks++;
const key=sodium.crypto_sign_seed_keypair(new Uint8Array(32).fill(1));
if(sodium.to_hex(signPublicHeader(h,key.privateKey))!==f.signature_hex)throw new Error('Browser/native sign mismatch');checks++;
const bad=new Uint8Array(sig);bad[0]^=1;try{verifyPublicHeader(h,bad,pub);throw new Error('accepted');}catch(e){if(e.message==='accepted')throw e;}checks++;
for(const invalid of ['{"x":1,"x":2}','{"x":"\\\\ud800"}',f.canonical_header.replace('"protocol_version":1','"protocol_version":2')]){try{publicSigningBytes(enc.encode(invalid));throw new Error('accepted');}catch(e){if(e.message==='accepted')throw e;}checks++;}
postMessage({status:'PASS',checks,browser_signature_hex:sodium.to_hex(signPublicHeader(h,key.privateKey))});}catch{postMessage({status:'FAIL'});}};
// Module initialization awaits libsodium. Send inputs only after the listener exists.
postMessage({status:'READY'});`,resolveDir:root,sourcefile:'p04-public-worker.mjs'},outfile:worker,bundle:true,platform:'browser',format:'esm',target:['chrome120','safari18'],logLevel:'silent'});
const server=createServer((req,res)=>{if(req.url==='/worker.js'){res.setHeader('Content-Type','text/javascript');res.end(readFileSync(worker));}else{res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Public signature test</title>');}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
let browser;const report={public_fixture_sha256:createHash('sha256').update(readFileSync(fixturePath)).digest('hex'),inputs:['experiments/p01/p04-public-signatures.mjs','packages/protocol/p04-fixtures.mjs','packages/protocol/adapters/public-signatures.mjs','packages/protocol/src/strict-json.mjs','packages/protocol/package-lock.json','packages/crypto-native/src/lib.rs','packages/crypto-native/src/main.rs','packages/crypto-native/Cargo.lock'].map(path=>({path,sha256:createHash('sha256').update(readFileSync(join(root,path))).digest('hex')})),purpose:'P04 required P05 public signature interoperability',native:{status:'PASS',checks:nativeReport.checks},source_commit:spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).stdout.trim(),source_tree_dirty:spawnSync('git',['status','--porcelain'],{cwd:root,encoding:'utf8'}).stdout.trim()!=='',physical_acceptance:false};
try{
 browser=await chromium.launch({executablePath:process.env.CHROMIUM_EXECUTABLE??['/usr/bin/google-chrome','/usr/bin/chromium'].find(existsSync)??'/usr/bin/google-chrome',headless:true,chromiumSandbox:true});
 const page=await browser.newPage();await page.goto(`http://127.0.0.1:${server.address().port}`);
 const result=await page.evaluate(f=>new Promise((resolve,reject)=>{const w=new Worker('/worker.js',{type:'module'});const timer=setTimeout(()=>{w.terminate();reject(new Error('Public worker timeout'));},30000);w.onmessage=e=>{if(e.data.status==='READY'){w.postMessage(f);return;}clearTimeout(timer);w.terminate();resolve(e.data);};w.onerror=()=>{clearTimeout(timer);w.terminate();reject(new Error('Public worker failed'));};}),fixture);
 if(result.status!=='PASS'||result.browser_signature_hex!==nativeReport.native_signature_hex)throw new Error('Browser/Node/Rust/PHP corpus mismatch');
 report.browser={status:'PASS',checks:result.checks,version:browser.version(),sandbox:true};report.status='PASS';
}catch(error){
 if(process.argv.includes('--allow-cloud-sandbox-block')&&/No usable sandbox|Operation not permitted|Failed to move to new namespace|SUID sandbox helper binary/.test(error.message)){report.browser={status:'BLOCKED',reason:'Cloud browser sandbox unavailable; hosted real-browser check required'};report.status='BLOCKED';}
 else throw error;
}finally{await browser?.close();await new Promise(r=>server.close(r));rmSync(scratch,{recursive:true,force:true});}
const out=join(root,'artifacts/p04/public-signature-report.json');mkdirSync(join(root,'artifacts/p04'),{recursive:true});writeFileSync(out,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
