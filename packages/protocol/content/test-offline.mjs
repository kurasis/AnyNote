import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,readFileSync,readdirSync,existsSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
const corpus=JSON.parse(readFileSync(new URL('../../../fixtures/protocol/p02/v1/crypto.json',import.meta.url))).objects;
const archive=fileURLToPath(new URL('../../../fixtures/protocol/p02/v1/rust.age',import.meta.url));
const cli=fileURLToPath(new URL('../../../scripts/p13-offline.mjs',import.meta.url));
test('clean offline command requires plaintext intent, verifies complete input and never replaces a destination',()=>{
 const root=mkdtempSync(join(tmpdir(),'anynote-p13-public-offline-'));try{
  const kit=join(root,'public.kit.json');writeFileSync(kit,JSON.stringify(corpus.kit));const output=join(root,'recovered');
  const run=(...more)=>spawnSync(process.execPath,[cli,'--archive',archive,'--kit',kit,...more],{encoding:'utf8'});
  const inspect=run();assert.equal(inspect.status,0);assert.equal(JSON.parse(inspect.stdout).network_used,false);assert.deepEqual(readdirSync(root),['public.kit.json']);
  assert.notEqual(run('--output',output).status,0);assert(!existsSync(output));
  const recover=run('--output',output,'--plaintext-confirm');assert.equal(recover.status,0);assert.equal(JSON.parse(recover.stdout).plaintext_output,true);assert(readdirSync(output).some(n=>n.startsWith('note-')));
  const files=readdirSync(output);const before=files.map(n=>readFileSync(join(output,n)));assert.notEqual(run('--output',output,'--plaintext-confirm').status,0);assert.deepEqual(readdirSync(output),files);assert.deepEqual(files.map(n=>readFileSync(join(output,n))),before);
  assert(!readdirSync(root).some(n=>n.includes('.incomplete-')||n.endsWith('.reservation')));
  writeFileSync(kit,JSON.stringify({...corpus.kit,archive_sha256:'A'.repeat(43)}));const bad=join(root,'denied');assert.notEqual(run('--output',bad,'--plaintext-confirm').status,0);assert(!existsSync(bad));
 }finally{rmSync(root,{recursive:true,force:true});}
});
