import test from 'node:test';
import assert from 'node:assert/strict';
import {archiveUI} from '../../../apps/notes-web/archive.mjs';
import {LocalVault} from '../vault/client.mjs';
import {AuthClient} from '../auth-client.mjs';

test('locked archive masking cannot restart custody or cancel a later unlock',async t=>{
 const elements=new Map();
 class Element extends EventTarget{
  constructor(){super();this.dataset={};this.children=[];this.value='';this.hidden=false;}
  append(...values){this.children.push(...values);}
  setAttribute(){}
  replaceChildren(...values){this.children=values;}
  querySelectorAll(){return [];}
  set id(value){this.identifier=value;elements.set(value,this);}
  get id(){return this.identifier;}
 }
 const document=Object.assign(new EventTarget(),{hidden:false,createElement:()=>new Element(),getElementById:id=>elements.get(id)});
 const workspace=new Element();workspace.id='workspace';
 let spawned=0;const requests=[];
 const replacements={document,addEventListener:()=>{},removeEventListener:()=>{},Worker:class{
  constructor(){spawned++;queueMicrotask(()=>this.onmessage?.({data:{version:1,status:'READY'}}));}
  postMessage(r){requests.push(r);const result=r.op==='unlock'?{capability:'public-host-regression-capability',epoch:'1'}:{};queueMicrotask(()=>this.onmessage?.({data:{version:1,id:r.id,generation:r.generation,result}}));}
  terminate(){}
 }};
 const saved=new Map(Object.keys(replacements).map(k=>[k,Object.getOwnPropertyDescriptor(globalThis,k)]));let client,ui,masks=0;
 t.mock.method(globalThis,'setTimeout',()=>0);t.mock.method(globalThis,'clearTimeout',()=>{});
 try{
  for(const [k,v]of Object.entries(replacements))Object.defineProperty(globalThis,k,{value:v,configurable:true,writable:true});
  client=new LocalVault('/host-regression-worker',()=>{masks++;ui?.close({locked:true});});
  ui=archiveUI({vault:client,auth:new AuthClient('https://api.anynote.test'),getGroup:()=>null,authorize:async()=>{},run:fn=>fn(),text:key=>key});
  await client.unlock('public host regression phrase');
  // This host-only test needs no KDF DB; invalidation/disposal precede its release.
  await client.lock().catch(()=>{});await new Promise(setImmediate);
  assert.equal(masks,1);assert.equal(spawned,1);assert.equal(requests.filter(r=>r.op==='notes').length,0);
  assert.equal(elements.get('save-export-kit').hidden,true);assert.equal(elements.get('import-audience').textContent,'');
  await client.unlock('public host regression phrase');await new Promise(setImmediate);
  assert.equal(masks,1);assert.equal(spawned,2);assert.equal(requests.filter(r=>r.op==='notes').length,0);
  // A visible group/access change still cancels an active custody job normally.
  ui.close();await new Promise(setImmediate);
  assert.equal(requests.at(-1).op,'notes');assert.deepEqual(requests.at(-1).args.slice(1),['portable',['cancel',{}]]);
 }finally{client?.close();t.mock.restoreAll();for(const [k,v]of saved)if(v)Object.defineProperty(globalThis,k,v);else delete globalThis[k];}
});
