import { build } from 'esbuild';
import { mkdir, writeFile } from 'node:fs/promises';

await mkdir('dist', { recursive: true });
await build({ entryPoints: { page: 'page.mjs', worker: 'worker.mjs', 'physical-page':'physical-page.mjs', 'physical-worker':'physical-worker.mjs' }, outdir: 'dist',
  bundle: true, format: 'esm', platform: 'browser', target: ['chrome120', 'safari18'],
  minify: false, sourcemap: false });
await writeFile('dist/index.html', '<!doctype html><meta charset="utf-8"><title>AnyNote P01 synthetic test runner</title><script type="module" src="/page.js"></script>');
console.log('Built local P01 worker; no remote scripts or application bundle.');
await writeFile('dist/physical.html', `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="manifest" href="/manifest.webmanifest"><title>AnyNote P01 synthetic platform trial</title>
<h1>AnyNote P01 synthetic platform trial</h1><p>Use disposable synthetic files only. This is an isolated feasibility experiment. No account, recovery, recipient protocol or production resume is implemented.</p>
<p>Backgrounding locks the live trial. Saving 1 GB to iOS Files remains an open physical gate.</p>
<button id="capabilities">Probe storage and export capabilities</button> <button id="storage">Check ciphertext storage</button>
<button id="measure-kdf">Measure public 64 MiB Argon2id profile</button>
<p><label>Synthetic source file <input type="file"></label></p>
<button id="upload">Encrypt and upload selected source</button> <button id="reselect">Verify reselected source</button> <button id="export">Download, verify and explicitly save</button>
<p>Experimental iPhone candidate: a verified temporary disk export followed by a separate share action. A completed share does not prove that Files received the output.</p>
<button id="prepare-share">Prepare verified temporary export</button> <button id="share">Share verified export</button> <button id="cleanup-export">Remove leftover marked test exports</button>
<pre><output aria-live="polite">Ready for a synthetic trial.</output></pre><script type="module" src="/physical-page.js"></script></html>`);
await writeFile('dist/manifest.webmanifest',JSON.stringify({name:'AnyNote P01 synthetic trial',short_name:'AnyNote P01',start_url:'/physical/',scope:'/physical/',display:'standalone',icons:[{src:'/icon.svg',sizes:'any',type:'image/svg+xml'}]}));
await writeFile('dist/icon.svg','<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192"><rect width="192" height="192" rx="32" fill="#123"><text x="96" y="116" text-anchor="middle" font-size="58" fill="white">P01</text></svg>');
await writeFile('dist/service-worker.js',`// Static synthetic harness assets only; no ciphertext/plaintext transfer cache.
const CACHE='anynote-p01-static-v1';
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(['/physical/','/physical-page.js','/physical-worker.js','/manifest.webmanifest','/icon.svg']))));
self.addEventListener('fetch',event=>{const url=new URL(event.request.url);if(event.request.method==='GET'&&url.origin===self.location.origin&&!url.pathname.startsWith('/ciphertext/'))event.respondWith(fetch(event.request).catch(()=>caches.match(event.request)));});`);
