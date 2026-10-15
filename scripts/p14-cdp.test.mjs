// Exercise the real V8 Runtime protocol, including native-shaped string rejections.
import test from 'node:test';
import assert from 'node:assert/strict';
import {Session} from 'node:inspector';
import {CDP} from './p14-cdp.mjs';
async function evaluate(expression){
 const session=new Session();session.connect();
 const command=(method,params)=>new Promise((resolve,reject)=>session.post(method,params,(error,value)=>error?reject(error):resolve(value)));
 try{return await CDP.prototype.evaluate.call({command},expression);}finally{session.disconnect();}
}
test('native-shaped primitive rejection retains its actual error code',async()=>{
 await assert.rejects(evaluate("Promise.reject('INVALID_REQUEST')"),error=>error instanceof Error&&error.message==='INVALID_REQUEST');
});
test('JavaScript Error rejection retains its description',async()=>{
 await assert.rejects(evaluate("Promise.reject(new Error('SYNTHETIC_TYPED_ERROR'))"),/SYNTHETIC_TYPED_ERROR/);
});
test('resolved error-looking strings remain successful values',async()=>{
 assert.equal(await evaluate("Promise.resolve('INVALID_REQUEST')"),'INVALID_REQUEST');
});
test('resolved typed data survives the real Runtime wire response',async()=>{
 assert.deepEqual(await evaluate("Promise.resolve({state:'unlocked',items:[]})"),{state:'unlocked',items:[]});
});
