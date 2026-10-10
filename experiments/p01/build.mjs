import { build } from 'esbuild';
import { mkdir, writeFile } from 'node:fs/promises';

await mkdir('dist', { recursive: true });
await build({ entryPoints: { page: 'page.mjs', worker: 'worker.mjs' }, outdir: 'dist',
  bundle: true, format: 'esm', platform: 'browser', target: ['chrome120', 'safari18'],
  minify: false, sourcemap: false });
await writeFile('dist/index.html', '<!doctype html><meta charset="utf-8"><title>AnyNote P01 synthetic test runner</title><script type="module" src="/page.js"></script>');
console.log('Built local P01 worker; no remote scripts or application bundle.');
