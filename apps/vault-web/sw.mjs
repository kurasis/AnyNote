// No dynamic/API/auth/recovery/plaintext caching. Activation leaves every local
// encrypted database untouched, including pending work from the previous app.
const cacheName='anynote-p07-static-'+ANYNOTE_STATIC_REVISION;
const paths=new Set(['/auth/style.css','/auth/vault.html','/auth/vault.js','/auth/vault-worker.js','/auth/vault-client.js','/auth/vault-store.js']);
self.addEventListener('install',event=>event.waitUntil((async()=>{const cache=await caches.open(cacheName);for(const path of paths){const r=await fetch(new Request(path,{credentials:'omit',cache:'reload',redirect:'error'}));if(!r.ok||r.type!=='basic')throw Error('STATIC_INSTALL_FAILED');await cache.put(path,r);}})()));
self.addEventListener('activate',event=>event.waitUntil((async()=>{for(const key of await caches.keys())if(key.startsWith('anynote-p07-static-')&&key!==cacheName)await caches.delete(key);await self.clients.claim();})()));
self.addEventListener('fetch',event=>{const u=new URL(event.request.url);if(event.request.method!=='GET'||u.origin!==self.location.origin||u.search||!paths.has(u.pathname))return;event.respondWith((async()=>{const r=await caches.match(u.pathname,{cacheName});return r??fetch(event.request);})());});
