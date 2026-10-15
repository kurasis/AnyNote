// Anonymous stdout only. Windows process.stdout writes pipes synchronously,
// so use maintained async descriptor writes while stdin continues to drain.
import {write} from 'node:fs';
const CAP=16777216,MAX_PENDING=4;let output=Promise.resolve(),pending=0;
export async function sendFrame(kind,bytes=Buffer.alloc(0)){
 if(!Number.isInteger(kind)||kind<0||kind>0xffffffff||!(bytes instanceof Uint8Array)||bytes.length>CAP||pending>=MAX_PENDING)throw Error('RESOURCE_LIMIT');
 const header=Buffer.alloc(8);header.writeUInt32BE(kind);header.writeUInt32BE(bytes.length,4);const frame=Buffer.concat([header,bytes]);pending++;
 const written=output.then(()=>new Promise((resolve,reject)=>{let offset=0;const next=()=>write(1,frame,offset,frame.length-offset,null,(error,count)=>{if(error)return reject(error);if(!Number.isInteger(count)||count<=0)return reject(Error('BRIDGE_CLOSED'));offset+=count;offset===frame.length?resolve():next();});next();}));
 output=written.catch(()=>{});
 try{await written;}finally{frame.fill(0);pending--;}
}
