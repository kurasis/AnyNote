// Product static bundle uses maintained Ajv standalone compilation; no runtime eval/CSP exception.
import {build} from 'esbuild';
import Ajv from '../../packages/protocol/node_modules/ajv/dist/2020.js';
import standalone from '../../packages/protocol/node_modules/ajv/dist/standalone/index.js';
import {_} from '../../packages/protocol/node_modules/ajv/dist/compile/codegen/index.js';
import {formats} from '../../packages/protocol/auth-formats.mjs';
import {readFileSync,writeFileSync,mkdirSync,copyFileSync,readdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
const root=resolve(import.meta.dirname,'../..'),dir=resolve(root,'.local/p06/static/auth');
mkdirSync(dir,{recursive:true});
const documents=JSON.parse(readFileSync(resolve(root,'packages/contracts/generated/runtime-schemas.json')));
documents.push(JSON.parse(readFileSync(resolve(root,'packages/contracts/p02-group-c1.schema.json'))));
const ajv=new Ajv({strict:true,ownProperties:true,code:{source:true,esm:true,formats:_`formats`}});
for(const [name,check] of Object.entries(formats))ajv.addFormat(name,check);
for(const d of documents)ajv.addSchema(d);
const refs={},map={};let i=0;
for(const d of documents)for(const k of Object.keys(d.$defs)){const name='v'+i++;refs[name]=d.$id+'#/$defs/'+k;map[refs[name]]=name;}
const generated=resolve(root,'.local/p06/validators.mjs');
writeFileSync(generated,`import {formats} from ${JSON.stringify(resolve(root,'packages/protocol/auth-formats.mjs').replaceAll('\\','/'))};\n`+standalone(ajv,refs));
const shim=resolve(root,'.local/p06/ajv.mjs');
writeFileSync(shim,`import * as validators from './validators.mjs';\nconst map=${JSON.stringify(map)};\nexport default class {addSchema(){} addFormat(){} compile({$ref}){if(!map[$ref])throw Error('UNCOMPILED_SCHEMA');return validators[map[$ref]];}}\n`);
for(const [name,entry] of Object.entries({'app.js':'apps/auth-web/app.mjs','client.js':'packages/protocol/auth-client.mjs','vault-worker.js':'packages/protocol/vault/worker.mjs','vault-client.js':'packages/protocol/vault/client.mjs','vault-store.js':'packages/protocol/vault/store.mjs','vault.js':'apps/vault-web/app.mjs','devices.js':'apps/devices-web/app.mjs','notes.js':'apps/notes-web/app.mjs'}))await build({entryPoints:[resolve(root,entry)],outfile:resolve(dir,name),bundle:true,format:'esm',platform:'browser',nodePaths:[resolve(root,'packages/protocol/node_modules')],target:['safari18','chrome120'],minify:true,plugins:[{name:'compiled-validators',setup(b){b.onResolve({filter:/^ajv\/dist\/2020.js$/},()=>({path:shim}));}}],define:{ANYNOTE_AUTH_ISSUER:JSON.stringify(process.env.ANYNOTE_API_ISSUER??'https://api.anynote.test:18443')},logLevel:'silent'});
for(const name of ['index.html','style.css'])copyFileSync(resolve(root,'apps/auth-web',name),resolve(dir,name));
copyFileSync(resolve(root,'apps/vault-web/index.html'),resolve(dir,'vault.html'));
copyFileSync(resolve(root,'apps/devices-web/index.html'),resolve(dir,'devices.html'));
copyFileSync(resolve(root,'apps/notes-web/index.html'),resolve(dir,'notes.html'));
copyFileSync(resolve(root,'apps/notes-web/style.css'),resolve(dir,'notes.css'));
// Public maintained font/CMap bytes are embedded; preview workers cannot fetch URLs.
const fontData={};for(const [folder,kind]of [['standard_fonts','standardFontDataUrl'],['cmaps','cMapUrl']])for(const name of readdirSync(resolve(root,'packages/content-browser/node_modules/pdfjs-dist',folder)).sort())if(/\.(?:pfb|ttf|bcmap)$/.test(name))fontData[kind+'/'+name]=readFileSync(resolve(root,'packages/content-browser/node_modules/pdfjs-dist',folder,name)).toString('base64');
const fontModule=resolve(root,'.local/p06/p13-fonts.mjs');writeFileSync(fontModule,'export const fontData='+JSON.stringify(fontData)+';\n');
await build({entryPoints:[resolve(root,'packages/content-browser/preview-render.mjs')],outfile:resolve(dir,'preview-render.mjs'),bundle:true,format:'esm',platform:'browser',target:['safari18','chrome120'],minify:true,external:['node:*','@napi-rs/canvas'],plugins:[{name:'embedded-public-fonts',setup(b){b.onResolve({filter:/^anynote-p13-fonts$/},()=>({path:fontModule}));}}],logLevel:'silent'});
await build({entryPoints:[resolve(root,'packages/content-browser/preview-parser.mjs')],outfile:resolve(dir,'preview-parser.mjs'),bundle:true,format:'esm',platform:'browser',target:['safari18','chrome120'],minify:true,external:['node:*'],logLevel:'silent'});
const revision=createHash('sha256').update(readFileSync(resolve(dir,'vault-worker.js'))).update(readFileSync(resolve(dir,'vault.js'))).update(readFileSync(resolve(dir,'notes.js'))).update(readFileSync(resolve(dir,'notes.css'))).update(readFileSync(resolve(dir,'notes.html'))).update(readFileSync(resolve(dir,'preview-render.mjs'))).update(readFileSync(resolve(dir,'preview-parser.mjs'))).digest('hex');await build({entryPoints:[resolve(root,'apps/vault-web/sw.mjs')],outfile:resolve(dir,'sw.js'),bundle:true,format:'esm',platform:'browser',target:['safari18','chrome120'],define:{ANYNOTE_STATIC_REVISION:JSON.stringify(revision)},logLevel:'silent'});
console.log('PASS: static authentication bundle, offline maintained validators, strict CSP');
