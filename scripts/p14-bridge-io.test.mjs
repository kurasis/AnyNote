// Real inherited pipes and the maintained permission boundary; no vault keys.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {once} from 'node:events';
import {createHash} from 'node:crypto';
import {PassThrough} from 'node:stream';
import {frameReader} from '../apps/desktop/bridge/framed-input.mjs';

const frame=(kind,bytes=Buffer.alloc(0))=>{const h=Buffer.alloc(8);h.writeUInt32BE(kind);h.writeUInt32BE(bytes.length,4);return Buffer.concat([h,bytes]);};
test('fragmented input preserves selective prefetch, zeroes released members and reuses their bounded storage',async()=>{
 const input=new PassThrough(),reader=frameReader(input),bytes=Buffer.alloc(8388608,97);
 try{
  const first=reader.take([3]);input.write(frame(13,Buffer.from('PUBLIC_REQUEST')));
  const message=frame(3,bytes);for(let i=0;i<message.length;i+=65531)input.write(message.subarray(i,i+65531));
  const received=await first;assert.deepEqual(received.bytes,bytes);
  assert.equal((await reader.take([13])).bytes.toString(),'PUBLIC_REQUEST');
  const allocation=received.bytes.buffer;reader.release(received.bytes);assert(received.bytes.every(b=>b===0));
  const second=reader.take([3]);input.write(frame(3,bytes));const reused=await second;
  assert.equal(reused.bytes.buffer,allocation);assert.deepEqual(reused.bytes,bytes);
  reader.release(reused.bytes);reader.close();assert(reused.bytes.every(b=>b===0));
 }finally{reader.close();}
});
test('input rejects oversize declarations and truncated headers/bodies without waiting for untrusted allocation',async()=>{
 for(const bytes of [frame(3).subarray(0,7),Buffer.from([0,0,0,3,1,0,0,1]),frame(3,Buffer.alloc(16)).subarray(0,23)]){
  const input=new PassThrough(),reader=frameReader(input);
  try{const denied=assert.rejects(reader.take(),/BRIDGE_CLOSED|RESOURCE_LIMIT/);input.end(bytes);await denied;}
  finally{reader.close();}
 }
});

test('restricted async frame output drains input before output is read, retaining concurrent frame order',async()=>{
 const root=mkdtempSync(join(tmpdir(),'anynote-duplex-')),entry=join(root,'public.mjs'),writer=resolve(import.meta.dirname,'../apps/desktop/bridge/framed-output.mjs');const size=8388608;let child,timer;
 try{
  writeFileSync(entry,`import {sendFrame} from ${JSON.stringify(pathToFileURL(writer).href)};let count=0;const input=new Promise(resolve=>{process.stdin.on('data',b=>count+=b.length);process.stdin.on('end',resolve);});const frames=Promise.all([sendFrame(16,Buffer.from('PUBLIC_META')),sendFrame(3,Buffer.alloc(${size},97)),sendFrame(9)]);await input;await frames;if(count!==${size})process.exitCode=1;\n`);
  child=spawn(process.execPath,['--no-addons','--disable-proto=throw','--permission','--allow-fs-read='+entry,'--allow-fs-read='+writer,entry],{env:{NODE_NO_WARNINGS:'1',...(process.env.SystemRoot?{SystemRoot:process.env.SystemRoot}:{})},windowsHide:true,stdio:['pipe','pipe','pipe']});
  let diagnostic='';child.stderr.on('data',b=>diagnostic=(diagnostic+b).slice(-4096));const exited=once(child,'exit');timer=setTimeout(()=>child.kill(),20000);const sent=new Promise((resolve,reject)=>{child.stdin.on('error',reject);child.stdin.end(Buffer.alloc(size,98),resolve);});let wait;const inputDrained=await Promise.race([sent.then(()=>true),new Promise(resolve=>{wait=setTimeout(()=>resolve(false),5000);})]);clearTimeout(wait);
  // Only now consume stdout. Synchronous Windows stdout would have blocked
  // the child from consuming the parent's pending 8 MiB stdin write.
  const pieces=[];for await(const bytes of child.stdout)pieces.push(bytes);const [code]=await exited;await sent;assert.equal(code,0,diagnostic);assert.equal(inputDrained,true,'input must drain while stdout is backpressured');
  const bytes=Buffer.concat(pieces);let offset=0;const frames=[];while(offset<bytes.length){assert(offset+8<=bytes.length);const kind=bytes.readUInt32BE(offset),n=bytes.readUInt32BE(offset+4);offset+=8;assert(offset+n<=bytes.length);frames.push({kind,bytes:bytes.subarray(offset,offset+n)});offset+=n;}
  assert.deepEqual(frames.map(f=>f.kind),[16,3,9]);assert.equal(frames[0].bytes.toString(),'PUBLIC_META');assert.equal(frames[1].bytes.length,size);assert.equal(createHash('sha256').update(frames[1].bytes).digest('hex'),createHash('sha256').update(Buffer.alloc(size,97)).digest('hex'));assert.equal(frames[2].bytes.length,0);
 }finally{clearTimeout(timer);if(child?.exitCode===null){child.kill();await once(child,'exit');}rmSync(root,{recursive:true,force:true});}
});
