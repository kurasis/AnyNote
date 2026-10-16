import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,writeFile,rename,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {once} from 'node:events';
import {executableIdentity} from './p14-installer-observation.mjs';
import {sourceStamp} from './p14-source.mjs';
test('metadata observes an actual executable replacement and missing files',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'anynote-observer-'));
 try{
  const path=join(dir,'candidate.exe');await assert.rejects(executableIdentity(path),{code:'ENOENT'});
  await writeFile(path,'synthetic original');const before=await executableIdentity(path);
  assert.equal(await executableIdentity(path),before);
  const next=join(dir,'next.exe');await writeFile(next,'synthetic next version');await rename(next,path);
  assert.notEqual(await executableIdentity(path),before);
 }finally{await rm(dir,{recursive:true});}
});
test('real Windows Restart Manager lists a read-handle observer, not metadata polling',{
 skip:process.platform!=='win32',timeout:60000,
},async()=>{
 assert.equal(process.env.GITHUB_ACTIONS,'true');
 const root=resolve(import.meta.dirname,'..'),stamp=sourceStamp(root),dir=await mkdtemp(join(tmpdir(),'anynote-rm-'));
 const path=join(dir,'synthetic.exe');await writeFile(path,'Synthetic resource, never an installed application');let child;
 const users=()=>JSON.parse(execFileSync('powershell',['-NoProfile','-NonInteractive','-File',join(root,'scripts/p14-restart-manager.ps1'),'-Path',path],{encoding:'utf8',windowsHide:true,timeout:20000}));
 try{
  // A separate owned process holds the same read handle used by hash polling.
  child=spawn(process.execPath,['--input-type=module','-e',"import {openSync,closeSync} from 'node:fs';const fd=openSync(process.argv[1],'r');process.stdout.write('READY\\n');process.stdin.resume();process.stdin.on('end',()=>{closeSync(fd);process.exit(0);});",path],{stdio:['pipe','pipe','pipe'],windowsHide:true});
  await Promise.race([once(child.stdout,'data'),once(child,'exit').then(()=>{throw Error('RM_READER_EXITED');})]);
  const held=users();assert(held.includes(child.pid),'Actual RM registration must identify the read-handle test process');
  child.stdin.end();await once(child,'exit');
  for(let i=0;i<20;i++)await executableIdentity(path);
  const released=users();assert(!released.includes(child.pid));assert(!released.includes(process.pid),'Metadata polling must leave no registered observer handle');
  const report={purpose:'Read-only real Windows Restart Manager observer regression; no shutdown invoked',status:'PASS',...stamp(),rm_read_handle_registers_test_process:true,metadata_polling_registers_test_process:false,physical_acceptance:false};
  await mkdir(join(root,'artifacts/p14'),{recursive:true});
  await writeFile(join(root,'artifacts/p14/installer-observation.json'),JSON.stringify(report,null,2)+'\n');
 }finally{if(child?.exitCode===null){child.kill();await once(child,'exit');}await rm(dir,{recursive:true});}
});
