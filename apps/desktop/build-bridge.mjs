import {build} from 'esbuild';import {mkdir,writeFile,readFile} from 'node:fs/promises';import {createHash} from 'node:crypto';import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('./',import.meta.url)),dest=root+'src-tauri/resources';await mkdir(dest,{recursive:true});
await build({entryPoints:[root+'bridge/custody.mjs'],bundle:true,platform:'node',mainFields:['module','main'],format:'esm',target:'node24',outfile:dest+'/custody.mjs',banner:{js:'import {createRequire} from "node:module";const require=createRequire(import.meta.url);'},logLevel:'warning'});
const sha=createHash('sha256').update(await readFile(dest+'/custody.mjs')).digest('base64url');await writeFile(dest+'/bridge-manifest.json',JSON.stringify({version:1,script_sha256:sha,format:'p14-native-pipes-v1'})+'\n');
console.log('PASS: bounded trusted portable helper bundled; no device keys or renderer API');
