import { createServer } from 'node:http';
import { createServer as createSecureServer } from 'node:https';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';

export async function serve({ scratch, tls, host = "127.0.0.1", port = 0 } = {}) {
  const directory = join(scratch, 'ciphertext'); await mkdir(directory);
  let uploadedBytes = 0, downloadedBytes = 0;
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
        uploadedBytes += length; res.writeHead(204).end(); return;
      }
      if (req.method === 'GET') {
        const metadata = await stat(path);
        res.setHeader('Content-Type', 'application/octet-stream'); res.setHeader('Content-Length', metadata.size);
        await pipeline(createReadStream(path), res); downloadedBytes += metadata.size; return;
      }
      res.writeHead(405).end();
    })().catch((error) => { if (!res.headersSent) res.writeHead(error.code === 'ENOENT' ? 404 : 500); res.end(); });
  };
  const server = tls ? createSecureServer(tls, handler) : createServer(handler);
  await new Promise((done, fail) => { server.once('error', fail); server.listen(port, host, done); });
  return { server, origin: `${tls ? "https" : "http"}://${host}:${server.address().port}`,
    counts: () => ({ uploaded_bytes: uploadedBytes, downloaded_bytes: downloadedBytes }),
    reset: async () => { await rm(directory, { recursive: true }); await mkdir(directory); uploadedBytes = 0; downloadedBytes = 0; } };
}

