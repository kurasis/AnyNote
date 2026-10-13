// In-memory single-use export capabilities. This code never fetches or caches plaintext.
const tickets=new Map();
self.addEventListener('message',event=>{
 if(event.data?.kind!=='p12-export')return;
 const port=event.ports[0];if(!port)return;
 event.waitUntil((async()=>{
  const client=await self.clients.get(event.source?.id),x=event.data;
  if(!client||client.type!=='window'||new URL(client.url).origin!==self.location.origin||new URL(client.url).pathname!=='/auth/notes.html'||!Number.isSafeInteger(x.size)||x.size<0||x.size>1000000000||typeof x.name!=='string'||!/^[^\x00-\x1f\x7f<>:"/\\|?*]{1,120}$/.test(x.name)||tickets.size>=2){port.postMessage({error:true});port.close();return;}
  const token=crypto.randomUUID().replaceAll('-',''),ticket={port,size:x.size,name:x.name,client:client.id,expires:Date.now()+60000};tickets.set(token,ticket);setTimeout(()=>{if(tickets.get(token)===ticket){tickets.delete(token);port.postMessage({error:true});port.close();}},60000);port.postMessage({ready:true,url:new URL('file-export/'+token,self.registration.scope).href});
 })());
});
self.addEventListener('fetch',event=>{
 const prefix=new URL('file-export/',self.registration.scope).href;if(!event.request.url.startsWith(prefix))return;
 const token=event.request.url.slice(prefix.length),ticket=tickets.get(token);tickets.delete(token);
 const denied=()=>new Response('Export unavailable',{status:410,headers:{'Cache-Control':'no-store'}});
 if(!/^[0-9a-f]{32}$/.test(token)||!ticket||ticket.expires<Date.now()||event.request.method!=='GET'||event.request.headers.has('Range')){event.respondWith(denied());return;}
 let resolve,bytes=0,buffer,ended=false,timer,done;const lifetime=new Promise(r=>done=r);event.waitUntil(lifetime);
 const finish=()=>{ended=true;resolve?.();resolve=null;clearTimeout(timer);buffer?.fill(0);buffer=null;ticket.port.postMessage({error:true});ticket.port.close();done();};
 const stream=new ReadableStream({
  start(controller){
   ticket.port.onmessage=({data})=>{
    if(data?.cancel){controller.error(Error('EXPORT_INTERRUPTED'));finish();return;}
    if(data?.end){if(bytes!==ticket.size||buffer){controller.error(Error('EXPORT_TRUNCATED'));finish();}else{controller.close();ended=true;resolve?.();clearTimeout(timer);ticket.port.close();done();}return;}
    if(!(data?.bytes instanceof Uint8Array)||data.bytes.length>8388608||buffer||bytes+data.bytes.length>ticket.size){controller.error(Error('EXPORT_INTEGRITY_FAILURE'));finish();return;}
    buffer=data.bytes;resolve?.();resolve=null;
   };timer=setTimeout(()=>{controller.error(Error('EXPORT_INTERRUPTED'));finish();},120000);
  },
  async pull(controller){
   clearTimeout(timer);const client=await self.clients.get(ticket.client);if(!client||client.visibilityState==='hidden'){controller.error(Error('EXPORT_INTERRUPTED'));finish();return;}timer=setTimeout(()=>{controller.error(Error('EXPORT_INTERRUPTED'));finish();},120000);if(!buffer&&!ended)await new Promise(r=>resolve=r);if(ended)return;clearTimeout(timer);
   bytes+=buffer.length;controller.enqueue(buffer);buffer=null;ticket.port.postMessage({pull:true});timer=setTimeout(()=>{controller.error(Error('EXPORT_INTERRUPTED'));finish();},120000);
  },
  cancel(){ticket.port.postMessage({error:true});finish();},
 },{highWaterMark:0});
 event.respondWith(new Response(stream,{headers:{'Content-Type':'application/octet-stream','Content-Length':String(ticket.size),'Content-Disposition':'attachment; filename="'+ticket.name.replace(/[^\x20-\x7e]/g,'_')+'"','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}}));
});
