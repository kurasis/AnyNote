import {build} from 'esbuild';
import {mkdir,readFile,writeFile,copyFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {deflateSync} from 'node:zlib';

const directory='dist/device-kit';await mkdir(directory,{recursive:true});
const source=process.env.ANYNOTE_PROBE_SOURCE??execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
const buildReceipt={source_commit:source,version:'0.1.4',kind:'P01 synthetic static device kit',production:false};
await build({entryPoints:{'device-page':'device-page.mjs','device-worker':'device-worker.mjs'},outdir:directory,
  bundle:true,format:'esm',platform:'browser',target:['chrome120','safari18'],minify:false,sourcemap:false,
  define:{__DEVICE_BUILD__:JSON.stringify(buildReceipt)}});
await writeFile(`${directory}/index.html`,`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'">
<link rel="stylesheet" href="./style.css"><link rel="manifest" href="./manifest.webmanifest"><link rel="apple-touch-icon" href="./icon-180.png"><title>AnyNote device test</title></head>
<body><main><h1>AnyNote device test</h1><p>Tap once to run the automatic local checks, including an exact 1 GB synthetic file. Keep the page open. Allow about 3.1 GB of browser storage.</p>
<p id="install">For the PWA trial: Safari → Share → Add to Home Screen, then open the installed app.</p>
<p>Test kit 0.1.4 — stream download avoids sending 1 GB through system Share; selected bytes must still be verified.</p>
<button id="start">Run all automatic tests</button><input id="saved-file" type="file" accept=".bin,application/octet-stream" hidden><pre id="status" role="status" aria-live="polite">Ready. Only disposable generated data is used. No account or password is needed.</pre>
<a id="download-sample" hidden>Download the 1 GB sample again</a><button id="legacy-share" hidden>Use system Share instead (experimental)</button><button id="save-report" hidden>Save report now</button><details><summary>Report text — select and copy if saving is unavailable</summary><textarea id="report-text" readonly rows="12" aria-label="Diagnostic report"></textarea></details><button id="new-trial" hidden>Run a new trial</button>
<p>After the automatic run, the same button downloads the verified disk output as a stream, without Web Share. Then select the saved .bin sample from Files for verification (exactly 1 GB). The small .json report is a separate file; do not select it for the sample check. System dialogs require your confirmation.</p>
<p>This is a P01 experiment. Network/backend transfers, passkeys, actual process memory, force-close recovery and physical low-space tests remain separate gates.</p></main><script type="module" src="./device-page.js"></script></body></html>`);
await writeFile(`${directory}/style.css`,'body{margin:0;background:#101827;color:#eef3ff;font:17px system-ui}main{max-width:680px;margin:auto;padding:26px}h1{font-size:30px}p{line-height:1.5;color:#c4cfdf}button{width:100%;padding:18px;border:0;border-radius:12px;background:#8cc9ff;color:#101827;font:700 18px system-ui;margin-bottom:12px}button:disabled{opacity:.5}a{display:block;padding:18px;color:#8cc9ff}a[hidden]{display:none}textarea{box-sizing:border-box;width:100%;margin:12px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:18px;background:#1b293c;border-radius:12px;min-height:90px;line-height:1.5}');
// Original generated solid-color PNG icons, no downloaded art or extra dependencies.
function crc32(bytes){let crc=0xffffffff;for(const byte of bytes){crc^=byte;for(let i=0;i<8;i++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}return(crc^0xffffffff)>>>0;}
function png(size){const chunk=(kind,data)=>{const tag=Buffer.from(kind),out=Buffer.alloc(data.length+12);out.writeUInt32BE(data.length);tag.copy(out,4);data.copy(out,8);out.writeUInt32BE(crc32(Buffer.concat([tag,data])),8+data.length);return out;};
  const header=Buffer.alloc(13);header.writeUInt32BE(size);header.writeUInt32BE(size,4);header[8]=8;header[9]=2;
  const rows=Buffer.alloc(size*(1+size*3));for(let y=0;y<size;y++)for(let x=0;x<size;x++){const offset=y*(1+size*3)+1+x*3;const mark=x>size*.28&&x<size*.72&&y>size*.25&&y<size*.75;rows.set(mark?[140,201,255]:[16,24,39],offset);}
  return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',header),chunk('IDAT',deflateSync(rows)),chunk('IEND',Buffer.alloc(0))]);}
for(const size of [180,192,512])await writeFile(`${directory}/icon-${size}.png`,png(size));
await writeFile(`${directory}/manifest.webmanifest`,JSON.stringify({id:'./',name:'AnyNote P01 device test',short_name:'AnyNote test',start_url:'./',scope:'./',display:'standalone',background_color:'#101827',theme_color:'#101827',icons:[192,512].map(size=>({src:`./icon-${size}.png`,sizes:`${size}x${size}`,type:'image/png'}))}));
const assets=['index.html','style.css','device-page.js','device-worker.js','manifest.webmanifest','icon-180.png','icon-192.png','icon-512.png'];
const hash=createHash('sha256');for(const asset of assets)hash.update(await readFile(`${directory}/${asset}`));
const cache=`anynote-p01-device-${hash.digest('hex').slice(0,24)}`;
await build({entryPoints:['device-service-worker.mjs'],outfile:`${directory}/service-worker.js`,bundle:true,
  format:'iife',platform:'browser',target:['chrome120','safari18'],
  define:{__DEVICE_CACHE__:JSON.stringify(cache),__DEVICE_ASSETS__:JSON.stringify(assets)}});
await writeFile(`${directory}/BUILD.json`,JSON.stringify({...buildReceipt,cache},null,2));
await copyFile('device-kit-README.md',`${directory}/README.md`);
for(const [pkg,name]of [['libsodium-wrappers-sumo','libsodium-wrappers-ISC.txt'],['libsodium-sumo','libsodium-core-ISC.txt']])
  await copyFile(`node_modules/${pkg}/LICENSE`,`${directory}/${name}`);
const all=[...assets,'service-worker.js','BUILD.json','README.md','libsodium-wrappers-ISC.txt','libsodium-core-ISC.txt'];
await writeFile(`${directory}/SHA256SUMS.txt`,(await Promise.all(all.map(async name=>`${createHash('sha256').update(await readFile(`${directory}/${name}`)).digest('hex')}  ${name}`))).join('\n')+'\n');
console.log(`Packaged static iPhone kit at ${directory}; all paths are relative.`);
