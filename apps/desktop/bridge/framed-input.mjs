// Bounded anonymous-pipe frames. Large export members have one reusable owner;
// archive input passed into a ReadableStream retains its own independent bytes.
const CAP=16777216;
export function frameReader(input){
 const iterator=input[Symbol.asyncIterator](),queue=[],waiters=[];
 let pending=new Uint8Array(),at=0,running=false,ended,spare;
 async function read(n){
  const bytes=n>=1048576&&spare?.length>=n?spare.subarray(0,n):Buffer.alloc(n);
  if(bytes.buffer===spare?.buffer)spare=undefined;
  let written=0;
  try{while(written<n){
   if(at===pending.length){const next=await iterator.next();if(next.done)throw Error('BRIDGE_CLOSED');pending=next.value;at=0;}
   const count=Math.min(n-written,pending.length-at);bytes.set(pending.subarray(at,at+count),written);at+=count;written+=count;
  }return bytes;}catch(error){bytes.fill(0);throw error;}
 }
 function deliver(){for(let i=0;i<waiters.length;){
  const w=waiters[i],index=queue.findIndex(f=>!w.kinds||w.kinds.includes(f.kind));
  if(index>=0){waiters.splice(i,1);w.resolve(queue.splice(index,1)[0]);}
  else if(ended){waiters.splice(i,1);w.reject(ended);}else i++;
 }}
 async function pump(){
  if(running||ended)return;running=true;
  try{while(queue.length<4){const h=await read(8),kind=h.readUInt32BE(0),size=h.readUInt32BE(4);if(size>CAP)throw Error('RESOURCE_LIMIT');queue.push({kind,bytes:await read(size)});deliver();}}
  catch(error){ended=error;deliver();}finally{running=false;}
 }
 return {
  async take(kinds){const index=queue.findIndex(f=>!kinds||kinds.includes(f.kind));
   if(index>=0){const frame=queue.splice(index,1)[0];void pump();return frame;}
   if(ended)throw ended;
   return new Promise((resolve,reject)=>{waiters.push({kinds,resolve,reject});void pump();});
  },
  release(bytes){bytes.fill(0);if(bytes.length>=1048576&&(!spare||spare.length<bytes.length))spare=bytes;},
  close(){ended=Error('BRIDGE_CLOSED');for(const frame of queue)frame.bytes.fill(0);queue.length=0;spare?.fill(0);spare=undefined;pending.fill(0);input.destroy();deliver();}
 };
}
