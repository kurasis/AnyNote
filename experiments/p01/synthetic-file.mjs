// Disposable test data only. No plaintext upload or production import/export.
import { createHash, randomFillSync } from 'node:crypto';
import { open } from 'node:fs/promises';

const [operation,path,sizeText,...extra]=process.argv.slice(2),MAX=1000000001,PART=8388608;
if(extra.length||!path||!['create','inspect'].includes(operation)
  ||(operation==='inspect'&&sizeText!==undefined))throw new Error('usage: synthetic-file.mjs create PATH BYTES | inspect PATH');
if(operation==='create'){
  const size=Number(sizeText);
  if(!/^(0|[1-9][0-9]*)$/.test(sizeText??'')||!Number.isSafeInteger(size)||size>MAX)throw new Error('Size must be 0..1,000,000,001 bytes (last size is rejection-only)');
  const file=await open(path,'wx'),hash=createHash('sha256'); // Never overwrite an existing file.
  try{
    for(let offset=0;offset<size;offset+=PART){const bytes=Buffer.alloc(Math.min(PART,size-offset));randomFillSync(bytes);hash.update(bytes);await file.writeFile(bytes);}
    await file.sync();if((await file.stat()).size!==size)throw new Error('Synthetic file length mismatch');
    console.log(JSON.stringify({status:'CREATED_SYNTHETIC',bytes:size,sha256:hash.digest('hex'),max_buffer_bytes:PART}));
  }finally{await file.close();}
}else{
  const file=await open(path,'r'),hash=createHash('sha256'),bytes=Buffer.alloc(PART);
  try{
    const before=await file.stat();if(!before.isFile()||before.size>MAX)throw new Error('Expected a regular synthetic file of at most 1,000,000,001 bytes');
    let total=0;
    for(;;){const {bytesRead}=await file.read(bytes,0,Math.min(PART,MAX+1-total),null);if(!bytesRead)break;
      total+=bytesRead;if(total>MAX)throw new Error('File grew beyond the test limit');hash.update(bytes.subarray(0,bytesRead));}
    const after=await file.stat();
    if(total!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs)throw new Error('File changed during inspection');
    console.log(JSON.stringify({status:'INSPECTED_SYNTHETIC',bytes:total,sha256:hash.digest('hex'),max_buffer_bytes:PART}));
  }finally{await file.close();}
}
