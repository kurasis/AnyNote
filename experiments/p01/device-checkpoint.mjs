// Small diagnostic state only: no File, file handles, buffers, plaintext or keys.
const LIMIT=65536;
export function checkpointKey(path){return `anynote-p01-report-v1:${path}`;}
export function saveCheckpoint(storage,key,stage,report){
  const text=JSON.stringify({version:1,stage,report});
  if(text.length>LIMIT)throw new Error('Diagnostic checkpoint exceeds 64 KiB');
  storage.setItem(key,text);
  if(storage.getItem(key)!==text)throw new Error('Diagnostic checkpoint readback failed');
}
export function readCheckpoint(storage,key){
  const text=storage.getItem(key);if(text===null)return null;
  if(text.length>LIMIT)throw new Error('Oversized diagnostic checkpoint');
  const value=JSON.parse(text);
  if(value.version!==1||!['run','share','handoff','verify','verifying','report'].includes(value.stage)
    ||value.report?.physical_acceptance!==false||typeof value.report.status!=='string'
    ||(value.report.files!==undefined&&!Array.isArray(value.report.files))
    ||value.report.build?.kind!=='P01 synthetic static device kit'
    ||!/^[0-9a-f]{40}$/.test(value.report.build.source_commit))throw new Error('Invalid diagnostic checkpoint');
  return value;
}
export function savedOutputExpected(report){
  const item=Array.isArray(report.files)?report.files.find(item=>item?.bytes===1000000000):null;
  return item?.status==='PASS'&&/^[0-9a-f]{64}$/.test(item.sha256)?item:null;
}
