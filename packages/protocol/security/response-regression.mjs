// Execute the exact old function and current function against the same observable
// stream/GC behavior. Historical source is trusted Git data, never network input.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {Buffer} from '../adapters/bytes.mjs';
import {boundedResponse} from '../auth-client.mjs';
assert.equal(typeof global.gc,'function','Run with --expose-gc');
const base='81298cc8cc110a25347e40a56011f84c65f8c66b',path='packages/protocol/auth-client.mjs';
const git=(...args)=>execFileSync('git',args,{encoding:'utf8'}).trim(),original=execFileSync('git',['show',base+':'+path],{encoding:'utf8'});
const start=original.indexOf('export async function boundedResponse('),end=original.indexOf('\nexport function authValue(',start);assert(start>0&&end>start);
const source=original.slice(start,end),before=new Function('Buffer',source.replace(/^export /,'')+';return boundedResponse;')(Buffer);
async function observe(read){
 let weak,n=0,collected=false;
 const stream=new ReadableStream({pull(c){if(n++<17){const b=new Uint8Array(32);if(n===1)weak=new WeakRef(b);c.enqueue(b);return;}return new Promise(resolve=>setImmediate(()=>{global.gc();collected=weak.deref()===undefined;c.close();resolve();}));}});
 await read(new Response(stream),1024);
 const failed=new Response(new ReadableStream({pull(c){c.error(Error('SYNTHETIC_NETWORK_CUT'));}}));
 await assert.rejects(()=>read(failed,1024),/SYNTHETIC_NETWORK_CUT/);
 return {consumed_chunk_collectible_before_eof:collected,reader_locked_after_failure:failed.body.locked};
}
const old=await observe(before),current=await observe(boundedResponse);
assert.deepEqual(old,{consumed_chunk_collectible_before_eof:false,reader_locked_after_failure:true});
assert.deepEqual(current,{consumed_chunk_collectible_before_eof:true,reader_locked_after_failure:false});
const report={purpose:'P17 exact old/new response resource regression reproduction',status:'PASS',source_commit:git('rev-parse','HEAD'),source_tree_dirty:git('status','--porcelain')!=='',historical_source:{commit:base,path,sha256:createHash('sha256').update(original).digest('hex'),evaluated_function_sha256:createHash('sha256').update(source).digest('hex')},before:old,after:current,scope:'Actual Web Streams and V8 GC observations; not a device memory budget or throughput benchmark',independent_review:'NOT_RUN'};
mkdirSync('artifacts/p17',{recursive:true});writeFileSync('artifacts/p17/remediation-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
