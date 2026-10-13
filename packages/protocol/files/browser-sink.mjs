// Explicit user export only. No plaintext Cache Storage, OPFS spill or remote helper.
import {safeFilename} from './client.mjs';
import {ensure} from '../vault/store.mjs';
export async function browserSink(name,size){
 ensure(Number.isSafeInteger(size)&&size>=0&&size<=1000000000,'RESOURCE_LIMIT');
 if(!navigator.serviceWorker?.controller&&typeof showSaveFilePicker==='function'){
  const handle=await showSaveFilePicker({suggestedName:safeFilename(name)}),writer=await handle.createWritable({keepExistingData:false});return {write:b=>writer.write(b),finish:()=>writer.close(),abort:()=>writer.abort()};
 }
 const worker=navigator.serviceWorker?.controller;ensure(worker,'STREAM_SINK_UNAVAILABLE');const channel=new MessageChannel();let pending,closed=false;
 const ticket=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('STREAM_SINK_UNAVAILABLE')),10000);channel.port1.onmessage=({data})=>{if(data?.ready){clearTimeout(timer);resolve(data.url);}else if(data?.pull){clearTimeout(pending?.timer);pending?.resolve();pending=null;}else if(data?.error){closed=true;clearTimeout(pending?.timer);pending?.reject(Error('EXPORT_INTERRUPTED'));pending=null;reject(Error('EXPORT_INTERRUPTED'));}};});
 worker.postMessage({kind:'p12-export',size,name:safeFilename(name)},[channel.port2]);const url=await ticket;const a=document.createElement('a');a.href=url;a.download=safeFilename(name);a.rel='noopener';a.click();
 return {
  async write(bytes){ensure(!closed&&!pending,'EXPORT_INTERRUPTED');await new Promise((resolve,reject)=>{pending={resolve,reject,timer:setTimeout(()=>{closed=true;reject(Error('EXPORT_INTERRUPTED'));channel.port1.postMessage({cancel:true});channel.port1.close();},120000)};channel.port1.postMessage({bytes:bytes.slice()},[]);});},
  async finish(){ensure(!closed,'EXPORT_INTERRUPTED');closed=true;channel.port1.postMessage({end:true});},
  async abort(){closed=true;clearTimeout(pending?.timer);pending?.reject(Error('EXPORT_INTERRUPTED'));channel.port1.postMessage({cancel:true});channel.port1.close();},
 };
}
