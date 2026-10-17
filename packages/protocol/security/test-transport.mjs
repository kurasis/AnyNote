import test from 'node:test';
import assert from 'node:assert/strict';
import {boundedResponse,AuthClient} from '../auth-client.mjs';
import {SyncClient} from '../sync/client.mjs';
import {decode as fileDecode} from '../adapters/codecs/codec.mjs';
import {readFileSync} from 'node:fs';
import {createHash as nativeHash} from 'node:crypto';
import {createHash as portableHash} from '../adapters/bytes.mjs';
import PortableAjv from '../adapters/schema-validation.mjs';

test('bounded WASM hash updates preserve empty, Unicode, chunk-boundary and multipart SHA-256 bytes',()=>{
 const data=new Uint8Array(8388624);for(let i=0;i<data.length;i++)data[i]=i%251;
 for(const size of [0,65535,65536,65537,data.length]){
  const bytes=data.subarray(0,size),expected=nativeHash('sha256').update(bytes).digest('hex');
  assert.equal(portableHash('sha256').update(bytes).digest('hex'),expected);
  const multipart=portableHash('sha256');for(let at=0;at<size;at+=65531)multipart.update(bytes.subarray(at,at+65531));
  assert.equal(multipart.digest('hex'),expected);
 }
 assert.equal(portableHash('sha256').update('Тест €').digest('hex'),nativeHash('sha256').update('Тест €').digest('hex'));
});
test('deferred schema compilation validates the first call and preserves format, own-property and error denials',()=>{
 const ajv=new PortableAjv({strict:true,ownProperties:true});let calls=0;
 ajv.addFormat('checked',value=>{calls++;if(value==='throw')throw Error('bad encoding');return value==='valid';});
 ajv.addSchema({$id:'urn:anynote:test:deferred',type:'object',required:['value'],additionalProperties:false,properties:{value:{type:'string',format:'checked'}}});
 const validate=ajv.compile({$ref:'urn:anynote:test:deferred'});
 assert.equal(calls,0);assert.equal(validate({value:'invalid'}),false);assert(validate.errors.length>0);
 assert.equal(validate({value:'valid'}),true);assert.equal(validate.errors,null);
 assert.equal(validate({value:'throw'}),false);assert.equal(validate(Object.create({value:'valid'})),false);
 assert.equal(validate({value:'valid',extra:true}),false);
});

function response(chunks,headers={}) {
 let cancelled=false;
 const stream=new ReadableStream({pull(c){const v=chunks.next();if(v.done)c.close();else c.enqueue(v.value);},cancel(){cancelled=true;}});
 return {value:new Response(stream,{headers}),cancelled:()=>cancelled};
}
test('fragmented hostile response uses one bounded backing allocation',async()=>{
 const count=65536,r=response((function*(){for(let n=0;n<count;n++)yield new Uint8Array([n%251]);})());
 const bytes=await boundedResponse(r.value,count);
 assert.equal(bytes.length,count);assert.equal(bytes.buffer.byteLength,count);
 for(let n=0;n<count;n++)assert.equal(bytes[n],n%251);
});
test('consumed response chunks can be collected before end of body',async()=>{
 assert.equal(typeof global.gc,'function','Run the security suite with --expose-gc');let observed=false,weak,n=0;
 const stream=new ReadableStream({pull(c){
  if(n++<17){const bytes=new Uint8Array(32);if(n===1)weak=new WeakRef(bytes);c.enqueue(bytes);return;}
  return new Promise(resolve=>setImmediate(()=>{global.gc();observed=weak.deref()===undefined;c.close();resolve();}));
 }});
 await boundedResponse(new Response(stream),1024);assert(observed,'A consumed transport chunk remained retained until EOF');
});
test('encoded length never overrides observed decoded response bound',async()=>{
 const r=response([new Uint8Array(31),new Uint8Array(2)].values(),{'Content-Length':'1','Content-Encoding':'gzip'});
 await assert.rejects(()=>boundedResponse(r.value,32),/AUTH_RESPONSE_TOO_LARGE/);assert(r.cancelled());
 for(const length of ['33','1e3','-1']){const x=response([new Uint8Array(1)].values(),{'Content-Length':length});await assert.rejects(()=>boundedResponse(x.value,32),/AUTH_RESPONSE_TOO_LARGE/);assert(x.cancelled());}
});
test('nonprogressing response is cancelled and response errors release reader lock',async()=>{
 const r=response((function*(){for(let n=0;n<1025;n++)yield new Uint8Array();})());
 await assert.rejects(()=>boundedResponse(r.value,32),/AUTH_RESPONSE_TOO_LARGE/);assert(r.cancelled());assert.equal(r.value.body.locked,false);
 const stream=new ReadableStream({pull(c){c.error(Error('synthetic network cut'));}}),value=new Response(stream);
 await assert.rejects(()=>boundedResponse(value,32),/synthetic network cut/);assert.equal(value.body.locked,false);
});
test('transport rejects duplicate JSON, invalid UTF8, hostile scope and redirected fetch policy',async()=>{
 let options;const auth=new AuthClient('https://api.anynote.test',async(_url,o)=>{options=o;return new Response('{"version":1,"version":1}');});
 await assert.rejects(()=>auth.call('/auth/csrf',null,'csrf-result'),/DUPLICATE_PROPERTY/);
 assert.equal(options.redirect,'error');assert.equal(options.cache,'no-store');assert.equal(options.credentials,'include');
 auth.fetcher=async()=>new Response(new Uint8Array([0xff]));await assert.rejects(()=>auth.call('/auth/csrf',null,'csrf-result'),/INVALID_UTF8/);
 const id='AAAAAAAAAAAAAAAAAAAAAA',client=new SyncClient(auth);
 auth.fetcher=async()=>new Response(JSON.stringify({version:1,snapshot_id:'BBBBBBBBBBBBBBBBBBBBBQ',state:'CANCELLED'}));
 await assert.rejects(()=>client.call('/snapshots/'+id,null,'cancel-result',undefined,'GET'),/CONTEXT_MISMATCH/);
 await assert.rejects(()=>client.call('/snapshots/'+id+'/../auth/csrf',null,'cancel-result'),/INVALID_SYNC_PATH/);
});
test('noncanonical base64 padding is a typed schema denial in the portable verifier',()=>{
 const context=JSON.parse(readFileSync('fixtures/protocol/p02/vectors.json')).cases[0].input.context;
 context.service_id='A'.repeat(21)+'B';
 assert.throws(()=>fileDecode('context',new TextEncoder().encode(JSON.stringify(context))),e=>e.code==='SCHEMA_MISMATCH');
});
