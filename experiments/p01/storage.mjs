import { sodium } from './crypto.mjs';

const PREFIX = 'anynote-p01-';
function owned(id) {
  if (typeof id !== 'string' || !/^anynote-p01-[0-9a-f]{32}$/.test(id)) throw new Error('Invalid test storage owner');
  return id;
}
const requestResult = (request) => new Promise((resolve, reject) => {
  request.onsuccess = () => resolve(request.result);
  request.onerror = () => reject(request.error);
});
const transactionDone = (transaction) => new Promise((resolve, reject) => {
  transaction.oncomplete = resolve;
  transaction.onerror = transaction.onabort = () => reject(transaction.error ?? new Error('Transaction aborted'));
});
async function database(id) {
  const request = indexedDB.open(owned(id), 1);
  request.onupgradeneeded = () => request.result.createObjectStore('ciphertext');
  return requestResult(request);
}
export async function capabilities() {
  const estimate = await navigator.storage?.estimate?.();
  return { secure_context: self.isSecureContext, indexeddb: typeof indexedDB !== 'undefined',
    opfs: typeof navigator.storage?.getDirectory === 'function',
    usage_bytes: estimate?.usage ?? null, quota_bytes: estimate?.quota ?? null,
    persisted: await navigator.storage?.persisted?.() ?? null };
}
export async function persistRequest() {
  return { granted: await navigator.storage?.persist?.() ?? false,
    interpretation: 'A false result is denial, not permission to rely on durable storage.' };
}
export async function writeStorage(createWriter = (file) => file.createWritable()) {
  await sodium.ready;
  const id = PREFIX + sodium.to_hex(sodium.randombytes_buf(16));
  const marker = sodium.from_string('PUBLIC SYNTHETIC PLAINTEXT MUST NOT ENTER NORMAL CACHE');
  const key = sodium.randombytes_buf(32), nonce = sodium.randombytes_buf(24);
  let cipher;
  try { cipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(marker, null, null, nonce, key); }
  finally { sodium.memzero(key); }
  const db = await database(id);
  try {
    const tx = db.transaction('ciphertext', 'readwrite'), done = transactionDone(tx);
    tx.objectStore('ciphertext').put(cipher, 'opaque-object');
    await done;
  } finally { db.close(); }
  try {
    const directory = await (await navigator.storage.getDirectory()).getDirectoryHandle(id, {create: true});
    const file = await directory.getFileHandle('opaque-object', {create: true});
    const writer = await createWriter(file);
    try { await writer.write(cipher); await writer.close(); }
    catch (error) { await writer.abort().catch(() => {}); throw error; }
  } catch (error) {
    await cleanupStorage(id);
    throw error;
  }
  return { id, ciphertext_sha256: sodium.to_hex(sodium.crypto_hash_sha256(cipher)), length: cipher.length,
    plaintext_marker_hex: sodium.to_hex(marker), stored_fields: ['ciphertext bytes only'] };
}
export async function inspectStorage(expected) {
  await sodium.ready;
  const db = await database(expected.id);
  let idb;
  try {
    const tx = db.transaction('ciphertext'), done = transactionDone(tx);
    idb = await requestResult(tx.objectStore('ciphertext').get('opaque-object'));
    await done;
  } finally { db.close(); }
  const directory = await (await navigator.storage.getDirectory()).getDirectoryHandle(owned(expected.id));
  const file = await (await directory.getFileHandle('opaque-object')).getFile();
  if (file.size !== expected.length || !(idb instanceof Uint8Array) || idb.length !== expected.length) throw new Error('Durability length mismatch');
  const opfs = new Uint8Array(await file.arrayBuffer()); // Only the small bounded synthetic record.
  for (const bytes of [opfs, idb]) {
    if (sodium.to_hex(sodium.crypto_hash_sha256(bytes)) !== expected.ciphertext_sha256) throw new Error('Durability digest mismatch');
    if (sodium.to_hex(bytes).includes(expected.plaintext_marker_hex)) throw new Error('Unexpected plaintext cache');
  }
  return { status: 'PASS', ciphertext_only: true, indexeddb_reopened: true, opfs_reopened: true };
}
export async function deniedWrite() {
  const id = PREFIX + crypto.randomUUID().replaceAll('-', '');
  const db = await database(id);
  try {
    const tx = db.transaction('ciphertext'), done = transactionDone(tx);
    try { tx.objectStore('ciphertext').put(new Uint8Array([1]), 'forbidden'); throw new Error('Readonly write unexpectedly succeeded'); }
    catch (error) { if (error.name !== 'ReadOnlyError') throw error; }
    await done;
    return { status: 'PASS', readonly_denial: true,
      quota_exhaustion: 'NOT RUN: readonly denial is not quota exhaustion' };
  } finally { db.close(); await requestResult(indexedDB.deleteDatabase(id)); }
}
export async function cleanupStorage(id) {
  owned(id);
  await requestResult(indexedDB.deleteDatabase(id));
  try { await (await navigator.storage.getDirectory()).removeEntry(id, {recursive:true}); }
  catch (error) { if (error.name !== 'NotFoundError') throw error; }
}

export async function quotaTrial() {
  const id=PREFIX+crypto.randomUUID().replaceAll('-','');
  const directory=await(await navigator.storage.getDirectory()).getDirectoryHandle(id,{create:true});
  let writer;
  try {
    writer=await(await directory.getFileHandle('opaque-ciphertext',{create:true})).createWritable();
    await sodium.ready;
    // CSPRNG opaque bytes represent ciphertext; no plaintext record enters cache.
    const bytes=new Uint8Array(2097152);
    for(let offset=0;offset<bytes.length;offset+=65536)crypto.getRandomValues(bytes.subarray(offset,offset+65536));
    await writer.write(bytes);await writer.close();writer=null;
    return {status:'WRITE_ALLOWED',limit_bytes:bytes.length};
  }catch(error){
    if(error.name!=='QuotaExceededError')throw error;
    return {status:'QUOTA_EXCEEDED',bounded_attempt_bytes:2097152,
      interpretation:'Browser quota error under injected CDP limit, not physical disk exhaustion.'};
  }finally{
    if(writer)await writer.abort().catch(()=>{});
    await(await navigator.storage.getDirectory()).removeEntry(id,{recursive:true});
  }
}
