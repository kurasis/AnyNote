// CI-owned early installed-host infrastructure check, never owner/hardware acceptance.
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {existsSync,mkdirSync,readdirSync,rmdirSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {once} from 'node:events';
import {mainWindow,until,targets} from './p14-cdp.mjs';
import {sourceStamp} from './p14-source.mjs';
assert(process.platform==='win32'&&process.env.GITHUB_ACTIONS==='true');
const root=resolve(import.meta.dirname,'..'),stamp=sourceStamp(root),appRoot=join(process.env.LOCALAPPDATA,'org.anynote.desktop'),work=join(root,'.local/p14-host-preflight');
assert(!existsSync(appRoot)&&!existsSync(work),'Refusing existing private/fixture state');mkdirSync(work,{recursive:true});writeFileSync(join(work,'owner.json'),JSON.stringify({purpose:'P14 synthetic empty-profile WebView2 preflight',root}));
const app=spawn(join(root,'apps/desktop/src-tauri/target/release/anynote-desktop.exe'),[],{stdio:'ignore'});let cdp,checks=0,failure;
const report={purpose:'P14 real empty-profile WebView2 and typed IPC preflight; complete installed workflows are separate',physical_acceptance:false};
try{
 cdp=await mainWindow(app);assert(await until(()=>cdp.evaluate("!!document.querySelector('.onboarding')"),'Actual React onboarding'));checks++;
 const profiles=await cdp.evaluate("window.__TAURI_INTERNALS__.invoke('profile',{request:{operation:'list'}})");assert.deepEqual(profiles,{items:[]});checks++;
 assert((await targets()).some(t=>t.type==='page'&&t.url.startsWith('http://tauri.localhost/')),'Actual native WebView2 page');checks++;
 report.status='PASS';
}catch(error){
 failure=error;report.status='FAIL';report.error=String(error).slice(0,600);
 // This new, owned process has no account/profile/keys. Record only its browser
 // argument forwarding for diagnosis; never inspect other processes or values.
 try{const command="$all=Get-CimInstance Win32_Process;$ids=[Collections.Generic.HashSet[int]]::new();[void]$ids.Add("+app.pid+");do{$changed=$false;foreach($p in $all){if($ids.Contains([int]$p.ParentProcessId) -and !$ids.Contains([int]$p.ProcessId)){[void]$ids.Add([int]$p.ProcessId);$changed=$true}}}while($changed);$all|?{$ids.Contains([int]$_.ProcessId)}|%{@{pid=$_.ProcessId;parent=$_.ParentProcessId;name=$_.Name;command_line=$_.CommandLine}}|ConvertTo-Json -Depth 4 -Compress";report.owned_empty_profile_processes=JSON.parse(execFileSync('powershell',['-NoProfile','-NonInteractive','-Command',command],{stdio:['ignore','pipe','pipe'],timeout:20000,encoding:'utf8'}));}catch{report.process_diagnostic='UNAVAILABLE';}
}finally{
 try{
 cdp?.close();
 if(app.exitCode===null){const ended=once(app,'exit');execFileSync('taskkill',['/PID',String(app.pid),'/T','/F'],{stdio:'ignore',timeout:20000});await ended;}
 await until(async()=>{try{await targets();return false;}catch{return true;}},'Owned preflight CDP endpoint closed',15000);
 if(existsSync(appRoot)){assert.deepEqual(readdirSync(appRoot),['profiles'],'Refusing unknown private state cleanup');assert.deepEqual(readdirSync(join(appRoot,'profiles')),[],'Refusing nonempty private profiles');rmdirSync(join(appRoot,'profiles'));rmdirSync(appRoot);}
 }catch(error){report.cleanup_error=String(error).slice(0,500);report.status='FAIL';failure??=error;}
 Object.assign(report,{checks,...stamp()});mkdirSync(join(root,'artifacts/p14'),{recursive:true});writeFileSync(join(root,'artifacts/p14/windows-host-preflight.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}
if(failure)throw failure;
