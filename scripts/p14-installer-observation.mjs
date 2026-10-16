import {stat} from 'node:fs/promises';
// Inspect directory metadata only while NSIS may run Restart Manager shutdown.
// Opening the installed EXE here can register the observer as a resource user.
export async function executableIdentity(path){
 const s=await stat(path,{bigint:true});
 return [s.dev,s.ino,s.size,s.mtimeNs,s.ctimeNs].map(String).join(':');
}
