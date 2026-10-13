import test from 'node:test';
import assert from 'node:assert/strict';
import {browserSink} from './browser-sink.mjs';
async function fixture(onEnd){
 let port;const navigatorBefore=Object.getOwnPropertyDescriptor(globalThis,'navigator'),documentBefore=globalThis.document;
 Object.defineProperty(globalThis,'navigator',{configurable:true,value:{serviceWorker:{controller:{postMessage(data,ports){port=ports[0];port.onmessage=({data})=>{if(data.bytes)port.postMessage({pull:true});if(data.end)onEnd(port);};port.postMessage({ready:true,url:'https://app.test/auth/file-export/opaque'});}}}}});
 globalThis.document={createElement(){return {click(){},set href(value){assert(value.startsWith('https://app.test/'));}};}};
 try{return {sink:await browserSink('CON.txt',3),close(){port?.close();Object.defineProperty(globalThis,'navigator',navigatorBefore);globalThis.document=documentBefore;}};}catch(e){port?.close();Object.defineProperty(globalThis,'navigator',navigatorBefore);globalThis.document=documentBefore;throw e;}
}
test('an explicit export cannot finish before the worker authenticates and closes its complete stream',async()=>{
 let acknowledge;const f=await fixture(port=>{acknowledge=()=>port.postMessage({complete:true});});try{await f.sink.write(new Uint8Array([1,2,3]));let finished=false;const completion=f.sink.finish().then(()=>{finished=true;});await new Promise(resolve=>setTimeout(resolve,20));assert.equal(finished,false);assert.equal(typeof acknowledge,'function');acknowledge();await completion;assert.equal(finished,true);}finally{f.close();}
});
test('a worker failure after the last chunk refuses export completion',async()=>{
 const f=await fixture(port=>port.postMessage({error:true}));try{await f.sink.write(new Uint8Array([1,2,3]));await assert.rejects(f.sink.finish(),/EXPORT_INTERRUPTED/);}finally{f.close();}
});
