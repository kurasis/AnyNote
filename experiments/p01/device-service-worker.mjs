import {openTrialOutput} from './device-disk.mjs';
// Synthetic exports only. No vault keys, arbitrary paths, network proxy or runtime caching.
const CACHE=__DEVICE_CACHE__,ASSETS=__DEVICE_ASSETS__.map(name=>new URL(name,self.registration.scope).href);
const tickets=new Map(),TTL=300000,CHUNK=262144;
function prune(){for(const[token,ticket]of tickets)if(ticket.expires<Date.now())tickets.delete(token);}
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(ASSETS)).then(()=>self.skipWaiting())));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('message',event=>{
  if(event.data?.kind!=='prepare-download'||!event.ports[0])return;
  event.waitUntil((async()=>{
    const port=event.ports[0];
    try{
      const client=await self.clients.get(event.source?.id);
      if(!client||client.type!=='window'||!client.url.startsWith(self.registration.scope))throw new Error('Client outside kit scope');
      if(!navigator.locks)throw new Error('Web Locks unavailable in service worker');
      const {owner_id,name}=event.data;
      await openTrialOutput(owner_id,name);
      prune();for(const[token,ticket]of tickets)if(ticket.client===client.id)tickets.delete(token);
      if(tickets.size>=64)throw new Error('Too many pending synthetic downloads');
      const token=crypto.randomUUID().replaceAll('-','');
      tickets.set(token,{owner_id,name,client:client.id,expires:Date.now()+TTL});
      port.postMessage({url:new URL(`download/${token}`,self.registration.scope).href});
    }catch(error){port.postMessage({error:error.message});}
  })());
});
function download(event,token){
  prune();const ticket=tickets.get(token);tickets.delete(token);
  const denied=()=>new Response('Synthetic download unavailable. Reopen the kit to retry.',{status:410,headers:{'Cache-Control':'no-store'}});
  if(!ticket||event.request.method!=='GET'||event.request.headers.has('Range')){event.respondWith(denied());return;}
  let respond;const response=new Promise(resolve=>{respond=resolve;});event.respondWith(response);
  event.waitUntil(navigator.locks.request('anynote-p01-device-kit',{ifAvailable:true},async lock=>{
    if(!lock){respond(denied());return;}
    let complete,offset=0,timer,done=false;
    const ended=new Promise(resolve=>{complete=resolve;});
    const notify=async(status)=>{const client=await self.clients.get(ticket.client);client?.postMessage({kind:'stream-download',status,bytes:offset,expected_bytes:1000000000});};
    const finish=(status)=>{if(done)return;done=true;clearTimeout(timer);complete();void notify(status);};
    try{
      const file=await openTrialOutput(ticket.owner_id,ticket.name);
      const stream=new ReadableStream({
        start(controller){timer=setTimeout(()=>{controller.error(new Error('Download idle timeout'));finish('INTERRUPTED');},120000);},
        async pull(controller){
          try{
            if(done)throw new Error('Synthetic download ended');
            clearTimeout(timer);
            const bytes=new Uint8Array(await file.slice(offset,Math.min(offset+CHUNK,file.size)).arrayBuffer());
            if(bytes.length!==Math.min(CHUNK,file.size-offset))throw new Error('Short synthetic output read');
            controller.enqueue(bytes);offset+=bytes.length;
            if(offset===file.size){controller.close();finish('STREAM_SENT_NOT_FILES_VERIFIED');}
            else timer=setTimeout(()=>{controller.error(new Error('Download idle timeout'));finish('INTERRUPTED');},120000);
          }catch(error){controller.error(error);finish('INTERRUPTED');}
        },cancel(){finish('CANCELLED');}
      },{highWaterMark:0});
      respond(new Response(stream,{headers:{'Content-Type':'application/octet-stream','Content-Length':String(file.size),
        'Content-Disposition':`attachment; filename="${ticket.name}"`,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}}));
      await notify('STARTED');await ended;
    }catch{respond(denied());finish('UNAVAILABLE');}
  }).catch(()=>respond(denied())));
}
self.addEventListener('fetch',event=>{
  const prefix=new URL('download/',self.registration.scope).href;
  if(event.request.url.startsWith(prefix)){
    const token=event.request.url.slice(prefix.length);
    if(!/^[0-9a-f]{32}$/.test(token)){event.respondWith(new Response('Unavailable',{status:404,headers:{'Cache-Control':'no-store'}}));return;}
    download(event,token);return;
  }
  if(event.request.method==='GET'&&ASSETS.includes(event.request.url))event.respondWith(caches.open(CACHE).then(async cache=>(await cache.match(event.request))??fetch(event.request)));
});
