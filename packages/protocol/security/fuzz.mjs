// Bounded deterministic mutation campaign, not exhaustive proof or coverage-guided fuzzing.
import assert from 'node:assert/strict';
import {readFileSync,mkdirSync,writeFileSync} from 'node:fs';
import {execFileSync,spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {strictJson} from '../src/strict-json.mjs';
import * as reference from '../src/protocol-codec.mjs';
import * as portable from '../adapters/codecs/protocol-codec.mjs';
import {decode as refFile} from '../src/codec.mjs';
import {decode as portFile} from '../adapters/codecs/codec.mjs';
import {decodeIdentity as refIdentity} from '../src/identity-codec.mjs';
import {decodeIdentity as portIdentity} from '../adapters/codecs/identity-codec.mjs';
import {stateDecode as refState} from '../src/state-codec.mjs';
import {stateDecode as portState} from '../adapters/codecs/state-codec.mjs';
import {groupCodecForProfile as refGroup} from '../src/group-codec.mjs';
import {groupCodecForProfile as portGroup} from '../adapters/codecs/group-codec.mjs';
import {tarEntries,parseTar} from '../content/archive.mjs';
import {openObject,verifyObject,phraseKek} from '../adapters/objects.mjs';
import {sodium,b64} from '../adapters/primitives.mjs';
import {wire} from '../src/identity-codec.mjs';

const started=performance.now(),seed='AnyNote/P17/bounded-mutation/v1',corpus=createHash('sha256');
let state=0x17c0ffee;const random=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;};
const sha=b=>createHash('sha256').update(b).digest('hex'),load=p=>JSON.parse(readFileSync('fixtures/protocol/p02/'+p+'.json'));
const file=load('vectors').cases[0].input,identity=load('identity-vectors'),roster=load('state-vectors'),group=load('group-vectors'),f=load('v1/crypto'),g1=refGroup(),g2=portGroup();
const families=[['file',refFile,portFile,[['context',file.context],['header',file.header],['wrap',file.wrap],['manifest',file.manifest],['checkpoint',file.checkpoint]]],
 ['identity',refIdentity,portIdentity,[['identity',identity.outputs.identity],['kit',identity.outputs.kit],['certificate',identity.outputs.certificates[0].record]]],
 ['state',refState,portState,[['event',roster.inputs.events[0]],['event-body',roster.inputs.events[0].body]]],
 ['group',g1.groupDecode,g2.groupDecode,[['policy',group.inputs.genesis]]],
 ['object',reference.decode,portable.decode,[['bundle',f.objects.bundle],['payload',f.objects.payload],['local-envelope',f.objects.local_cipher],['export-header',f.objects.header],['export-footer',f.objects.footer],['native-wrapper',f.objects.native_wrapper]]]];
const outcome=(fn,kind,bytes)=>{try{return {ok:true,value:fn(kind,bytes)};}catch(e){assert(e.code&&!(e instanceof RangeError)&&!(e instanceof TypeError),'Unexpected parser exception: '+e.name+':'+e.message);return {ok:false,code:e.code};}};
const totals={};const rawCases=[];
function record(bytes){corpus.update(String(bytes.length)+':').update(bytes);}
function mutate(bytes,n){const out=Buffer.from(bytes);switch(n%6){
 case 0:out[random()%out.length]^=1<<(random()%8);return out;
 case 1:return out.subarray(0,random()%out.length);
 case 2:return Buffer.concat([out,Buffer.from('x')]);
 case 3:return Buffer.from('{"p17_duplicate":0,"p17_duplicate":1,"value":'+bytes.toString()+'}');
 case 4:return Buffer.concat([Buffer.from([0xff]),out]);
 default:return Buffer.from(' '+bytes.toString()+'\n');
}}
for(const [name,a,b,seeds]of families){let accepted=0,rejected=0;
 for(const[k,v]of seeds){const original=wire(v);assert(a(k,original)&&b(k,original),'Positive seed failed '+name+'/'+k);
  for(let n=0;n<256;n++){const bytes=mutate(original,n);record(bytes);const x=outcome(a,k,bytes),y=outcome(b,k,bytes);assert.deepEqual(x,y,'Differential mismatch '+name+'/'+k+'/'+n);x.ok?accepted++:rejected++;}
 }
 totals[name]={seeds:seeds.length,cases:seeds.length*256,accepted,rejected};assert(rejected>accepted);
}
// PHP and JS raw-control parsers must agree within their common object/byte bound.
const rawSeeds=['{}','{"a":1,"b":[true,null,{"x":"€"}]}','{"__proto__":{"polluted":true},"constructor":1}',...Array.from({length:34},(_,n)=>'{"a":'.repeat(n)+'{}'+'}'.repeat(n))];
for(const s of rawSeeds)for(let n=0;n<64;n++)rawCases.push(mutate(Buffer.from(s),n));
for(const s of ['{"a":1,"\\u0061":2}','{"a":"\\ud800"}','{"a":1e9999}','\ufeff{}','{"a":1,}','{"a":01}','{"a":NaN}'])rawCases.push(Buffer.from(s));
rawCases.push(Buffer.from('{"a":"'+'x'.repeat(4194304)+'"}'));
const expected=rawCases.map(bytes=>{record(bytes);try{const v=strictJson(bytes,4194304);return !!v&&typeof v==='object'&&!Array.isArray(v);}catch(e){assert(e.code);return false;}});
const php=spawnSync('python3',['scripts/p17-php-parser.py'],{input:rawCases.map(b=>b.toString('base64')).join('\n')+'\n',encoding:'utf8',maxBuffer:16777216,timeout:120000});
assert.equal(php.status,0,'Offline PHP differential subprocess failed');const actual=php.stdout.trim().split('\n').map(s=>{assert(['0','1'].includes(s));return s==='1';});assert.deepEqual(actual,expected,'PHP/JS raw-control disagreement');
totals.raw_control={cases:rawCases.length,accepted:expected.filter(Boolean).length,rejected:expected.filter(v=>!v).length};
// Authenticated negative controls: schema-valid context/key/cipher/signature substitution.
const key=Buffer.from(f.inputs.group_key_hex,'hex'),publicKey=Buffer.from(f.inputs.signing_public_hex,'hex'),original=f.objects.bundle;
assert.deepEqual(openObject(wire(original),key,publicKey,wire(original.envelope.header.context)),f.objects.payload);
let envelopeRejections=0;
for(let n=0;n<512;n++){
 const changed=structuredClone(original),header=changed.envelope.header;const field=['ciphertext','signature','wrap','group','epoch','parent','author','thread'][n%8],id=b64(createHash('sha256').update(seed+':'+n).digest().subarray(0,16));
 const flip=s=>{const b=Buffer.from(s,'base64url');b[random()%b.length]^=1<<(random()%8);return b.toString('base64url');};
 if(field==='ciphertext')changed.ciphertext=flip(changed.ciphertext);
 if(field==='signature')changed.envelope.signature=flip(changed.envelope.signature);
 if(field==='wrap')changed.wrap.ciphertext=flip(changed.wrap.ciphertext);
 if(field==='group')header.context.group_id=id;
 if(field==='epoch')header.context.policy.key_epoch='999';
 if(field==='parent')header.context.parents=[{revision_id:id,envelope_digest:b64(new Uint8Array(32))}];
 if(field==='author')header.context.author.device_id=id;
 if(field==='thread')header.context.thread_id=id;
 record(wire(changed));assert.throws(()=>verifyObject(wire(changed),publicKey,wire(original.envelope.header.context)));envelopeRejections++;
}
for(const values of [{opslimit:2},{opslimit:11},{memlimit:67108863},{memlimit:268435457},{algorithm:'argon2i13'}])await assert.rejects(()=>phraseKek(f.inputs.phrase,wire({...f.objects.parameters,...values})),e=>e.code==='SCHEMA_MISMATCH');
// Real streaming archive parser, one-bit mutations in every header byte, then
// valid data split at arbitrary boundaries; no path is extracted to disk.
const chunks=[];for await(const c of tarEntries([{path:'export-header.json',bytes:new Uint8Array([1,2,3])}]))chunks.push(Buffer.from(c));const tar=Buffer.concat(chunks);
async function* stream(bytes){for(let n=0;n<bytes.length;){const count=1+random()%127;yield bytes.subarray(n,n+count);n+=count;}}
let visited=0;await parseTar(stream(tar),()=>visited++);assert.equal(visited,1);
for(let n=0;n<512;n++){const bytes=Buffer.from(tar);bytes[n]^=1<<(n%8);record(bytes);let visits=0;await assert.rejects(()=>parseTar(stream(bytes),()=>visits++));assert.equal(visits,0);}
const git=(...a)=>execFileSync('git',a,{encoding:'utf8'}).trim(),report={purpose:'P17 bounded deterministic parser/envelope mutation campaign',status:'PASS',source_commit:git('rev-parse','HEAD'),source_tree_dirty:git('status','--porcelain')!=='',seed,prng:'xorshift32 mutation selection; not cryptography',corpus_sha256:corpus.digest('hex'),families:totals,authenticated_envelope_rejections:envelopeRejections,kdf_preallocation_rejections:5,archive_header_rejections:512,archive_positive_visits:visited,elapsed_ms:performance.now()-started,observed_process_max_rss_kib:process.resourceUsage().maxRSS,independent_review:'NOT_RUN',limitations:['Finite mutation campaign; Node reference and portable codecs share frozen design and dependencies','PHP differential covers raw control syntax, not secret AEAD or every PHP schema','RSS is this Node process high-water mark, not devices or aggregate children']};
mkdirSync('artifacts/p17',{recursive:true});writeFileSync('artifacts/p17/fuzz-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
