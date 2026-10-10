import { createServer } from 'node:http';
import { createServer as createSecureServer } from 'node:https';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { gzipSync } from 'node:zlib';

export async function serve({ scratch, tls, host = "127.0.0.1", port = 0 } = {}) {
  const directory = join(scratch, 'ciphertext'); await mkdir(directory);
  let uploadedBytes = 0, downloadedBytes = 0;
  let heldUpload;
  let heldDownload,downloadFault;
  const assets = new Map([['/', ['index.html', 'text/html']], ['/page.js', ['page.js', 'text/javascript']], ['/worker.js', ['worker.js', 'text/javascript']], ['/physical/', ['physical.html', 'text/html']], ['/physical-page.js', ['physical-page.js', 'text/javascript']], ['/physical-worker.js', ['physical-worker.js', 'text/javascript']], ['/service-worker.js', ['service-worker.js', 'text/javascript']], ['/manifest.webmanifest', ['manifest.webmanifest', 'application/manifest+json']], ['/icon.svg', ['icon.svg', 'image/svg+xml']]]);
  const handler = (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; manifest-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    (async () => {
      if (req.method === 'GET' && assets.has(req.url)) {
        const [name, type] = assets.get(req.url);
        res.setHeader('Content-Type', type); await pipeline(createReadStream(join('dist', name)), res); return;
      }
      const match = /^\/ciphertext\/(0|[1-9][0-9]{0,2})$/.exec(req.url);
      if (!match || Number(match[1]) >= 120) { res.writeHead(404).end(); return; }
      const path = join(directory, `${match[1]}.bin`);
      if (req.method === 'PUT') {
        const declared = Number(req.headers['content-length']);
        if (!Number.isSafeInteger(declared) || declared < 16 || declared > 8388624) { res.writeHead(413).end(); return; }
        let length = 0;
        const bounded = new Transform({ transform(chunk, _encoding, callback) {
          length += chunk.length;
          callback(length > declared ? new Error('Chunk exceeds declared bound') : null, chunk);
        } });
        await pipeline(req, bounded, createWriteStream(path, { flags: 'wx' }));
        if (length !== declared) throw new Error('Truncated upload');
        uploadedBytes += length;
        if (heldUpload) { const gate=heldUpload; heldUpload=null;gate.arrive();await gate.wait; }
        res.writeHead(204).end(); return;
      }
      if (req.method === 'GET') {
        const metadata = await stat(path);
        if(heldDownload?.index===Number(match[1])){
          const gate=heldDownload;heldDownload=null;gate.arrive();await gate.wait;
        }
        const fault=downloadFault?.index===Number(match[1])?downloadFault.mode:null;
        if(fault)downloadFault=null;
        res.setHeader('Content-Type', 'application/octet-stream'); res.setHeader('Content-Length', metadata.size);
        if(fault==='corrupt'){
          let changed=false;
          const flip=new Transform({transform(chunk,_encoding,callback){if(!changed){chunk[0]^=1;changed=true;}callback(null,chunk);}});
          await pipeline(createReadStream(path),flip,res);return;
        }
        if(fault==='truncate'){
          await pipeline(createReadStream(path,{end:metadata.size-2}),res);return;
        }
        if(fault==='decoded-overflow'){
          // Real gzip response with the correct encoded Content-Length but an
          // oversized decoded body. Restricted to a small synthetic test part.
          if(metadata.size>65536)throw new Error('Decoded-overflow fixture must be small');
          const compressed=gzipSync(Buffer.alloc(metadata.size+1)),padding=metadata.size-compressed.length-2;
          if(padding<0||padding>65535)throw new Error('Invalid gzip fixture bound');
          const header=Buffer.from(compressed.subarray(0,10));header[3]|=4;
          const extra=Buffer.alloc(padding+2);extra.writeUInt16LE(padding);
          res.setHeader('Content-Encoding','gzip');
          res.end(Buffer.concat([header,extra,compressed.subarray(10)]));return;
        }
        await pipeline(createReadStream(path), res); downloadedBytes += metadata.size; return;
      }
      res.writeHead(405).end();
    })().catch((error) => { if (!res.headersSent) res.writeHead(error.code === 'ENOENT' ? 404 : 500); res.end(); });
  };
  const server = tls ? createSecureServer(tls, handler) : createServer(handler);
  await new Promise((done, fail) => { server.once('error', fail); server.listen(port, host, done); });
  return { server, origin: `${tls ? "https" : "http"}://${host}:${server.address().port}`,
    // Internal runner fault injection only; never an HTTP/IPC endpoint.
    holdNextUpload: () => {
      if(heldUpload)throw new Error('Upload gate already pending');
      let arrive,release;
      const arrived=new Promise(resolve=>{arrive=resolve;}),wait=new Promise(resolve=>{release=resolve;});
      heldUpload={arrive,wait};
      return {arrived,release:()=>{heldUpload=null;release();}};
    },
    holdNextDownload: (index) => {
      if(heldDownload)throw new Error('Download gate already pending');
      let arrive,release;
      const arrived=new Promise(resolve=>{arrive=resolve;}),wait=new Promise(resolve=>{release=resolve;});
      heldDownload={index,arrive,wait};
      return {arrived,release:()=>{heldDownload=null;release();}};
    },
    faultNextDownload: (mode,index=0) => {
      if(downloadFault||!['corrupt','truncate','decoded-overflow'].includes(mode))throw new Error('Invalid pending download fault');
      downloadFault={mode,index};
    },
    counts: () => ({ uploaded_bytes: uploadedBytes, downloaded_bytes: downloadedBytes }),
    reset: async () => { await rm(directory, { recursive: true }); await mkdir(directory); uploadedBytes = 0; downloadedBytes = 0; } };
}

