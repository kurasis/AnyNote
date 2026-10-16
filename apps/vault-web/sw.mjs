import './export-worker.mjs';
// No dynamic/API/auth/recovery/plaintext caching. Activation leaves every local
// encrypted database untouched, including pending work from the previous app.
const cacheName='anynote-p07-static-'+ANYNOTE_STATIC_REVISION;
const paths=new Set(['/auth/manifest.webmanifest','/auth/icon-192.png','/auth/icon-512.png','/auth/style.css','/auth/vault.html','/auth/vault.js','/auth/vault-worker.js','/auth/vault-client.js','/auth/vault-store.js','/auth/notes.html','/auth/notes.js','/auth/notes.css','/auth/preview-render.mjs','/auth/preview-parser.mjs']);
self.addEventListener('install',event=>event.waitUntil((async()=>{try{const cache=await caches.open(cacheName);for(const path of paths){const r=await fetch(new Request(path,{credentials:'omit',cache:'reload',redirect:'error'}));if(!r.ok||r.type!=='basic')throw Error('STATIC_INSTALL_FAILED');await cache.put(path,r);}}catch(error){await caches.delete(cacheName);throw error;}})()));
self.addEventListener('activate',event=>event.waitUntil((async()=>{for(const key of await caches.keys())if(key.startsWith('anynote-p07-static-')&&key!==cacheName)await caches.delete(key);await self.clients.claim();})()));
self.addEventListener('fetch',event=>{const u=new URL(event.request.url);if(event.request.method!=='GET'||u.origin!==self.location.origin||u.search||!paths.has(u.pathname))return;event.respondWith((async()=>{const r=await caches.match(u.pathname,{cacheName});return r??fetch(event.request);})());});
// Optional push is only a neutral hint. Never interpret relay payloads as text,
// account identifiers, links, authority or an instruction to decrypt/synchronize.
self.addEventListener('push',event=>event.waitUntil(self.registration.showNotification('AnyNote',{
 body:self.navigator?.language?.startsWith('ru')?'Новая активность в хранилище.':'New activity in your vault.',
 tag:'anynote-activity',icon:'/auth/icon-192.png',badge:'/auth/icon-192.png',
})));
self.addEventListener('notificationclick',event=>{
 event.notification.close();
 event.waitUntil((async()=>{const target=new URL('notes.html',self.registration.scope).href;for(const client of await self.clients.matchAll({type:'window',includeUncontrolled:false})){if(client.url===target)return client.focus();}return self.clients.openWindow(target);})());
});
