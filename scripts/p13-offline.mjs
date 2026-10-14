#!/usr/bin/env node
// Clean offline recovery: archive + independent kit only. No network or original vault.
import {open,mkdir,rename,rm,rmdir,readFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {Readable} from 'node:stream';
import {PortableReader} from '../packages/protocol/content/portable.mjs';
import {safeFilename} from '../packages/protocol/files/client.mjs';
import {strictJson} from '../packages/protocol/src/strict-json.mjs';
const args=process.argv.slice(2),options={};
for(let i=0;i<args.length;i++){if(!['--archive','--kit','--output','--plaintext-confirm'].includes(args[i]))throw Error('INVALID_ARGUMENT');const name=args[i];if(name==='--plaintext-confirm')options[name]=true;else options[name]=args[++i];}
if(!options['--archive']||!options['--kit'])throw Error('ARCHIVE_AND_INDEPENDENT_KIT_REQUIRED');
if(options['--output']&&!options['--plaintext-confirm'])throw Error('PLAINTEXT_EXPORT_CONFIRMATION_REQUIRED');
const archive=await open(options['--archive'],'r'),kitBytes=await readFile(options['--kit']);
if(kitBytes.length>65536)throw Error('RESOURCE_LIMIT');
const kit=strictJson(kitBytes,65536);kitBytes.fill(0);const stat=await archive.stat();
if(!stat.isFile()||stat.size>116010000000)throw Error('RESOURCE_LIMIT');
// Each scan starts at zero on the same open handle; chunks are independently bound
// to the validated inventory. No archive-supplied path is opened or executed.
const reader=new PortableReader(()=>Readable.toWeb(archive.createReadStream({start:0,autoClose:false,highWaterMark:65536})),kit);kit.export_identity='';
let staging;
try{
 const report=await reader.validate();
 if(options['--output']){
  const destination=resolve(options['--output']);staging=destination+'.incomplete-'+crypto.randomUUID();await mkdir(staging,{recursive:false,mode:0o700});
  const handles=new Map();
  try{await reader.recover({
   async note(revision,payload){const handle=await open(join(staging,'note-'+revision+'.txt'),'wx',0o600);try{await handle.writeFile(payload.title+'\n\n'+payload.markdown+'\n');await handle.sync();}finally{await handle.close();}},
   async fileStart(version,context,metadata){const handle=await open(join(staging,version+'-'+safeFilename(metadata.name)),'wx',0o600);handles.set(version,handle);},
   async filePart(version,index,bytes){await handles.get(version).writeFile(bytes);},
   async fileFinish(version){const handle=handles.get(version);await handle.sync();await handle.close();handles.delete(version);}
  });}finally{for(const handle of handles.values())await handle.close();}
  // Never replace an existing destination or follow archive-controlled paths.
  const reservation=await open(destination+'.reservation','wx',0o600);try{try{await mkdir(destination,{recursive:false,mode:0o700});}catch{throw Error('DESTINATION_EXISTS');}await rmdir(destination);await rename(staging,destination);staging=undefined;}finally{await reservation.close();await rm(destination+'.reservation',{force:true});}
 }
 console.log(JSON.stringify({status:report.status,notes:report.notes.length,files:report.files.length,live_destination_mutations:0,plaintext_output:!!options['--output'],network_used:false}));
}finally{reader.close();await archive.close();if(staging)await rm(staging,{recursive:true,force:true});}
