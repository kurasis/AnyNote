import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { derive, invalidProfiles } from './local-unlock.mjs';
import { sodium } from './crypto.mjs';

export async function checkLocalUnlock(native, page) {
  const fixture = JSON.parse(await readFile('fixtures/argon2id.json', 'utf8'));
  const results = { kdf_vectors: [], profile_rejections: {}, physical_iphone: 'NOT RUN' };
  for (const test of fixture.cases) {
    const rust = JSON.parse(execFileSync(native, ['kdf'], {input:JSON.stringify(test.request),timeout:60000}));
    const node = await derive(test.request);
    assert.equal(rust.derived_hex, test.derived_hex); assert.equal(node.derived_hex, test.derived_hex);
    const worker = page ? (await page.evaluate((request) => p01({kind:'kdf',request}), test.request)).result : null;
    if (worker) assert.equal(worker.derived_hex, test.derived_hex);
    results.kdf_vectors.push({native_ms:rust.elapsed_ms, node_ms:node.elapsed_ms,
      worker_ms:worker?.elapsed_ms ?? null, worker_wasm_heap_bytes:worker?.wasm_heap_bytes ?? null,
      memlimit:test.request.memlimit,opslimit:test.request.opslimit});
  }
  for (const request of invalidProfiles(fixture.cases[0].request)) {
    assert.equal(spawnSync(native, ['kdf'], {input:JSON.stringify(request),timeout:10000}).status, 1);
    await assert.rejects(derive(request));
    if (page) await assert.rejects(page.evaluate((request) => p01({kind:'kdf',request}), request));
  }
  results.profile_rejections = {native:14,node:14,worker:page ? 14 : 'NOT RUN'};
  const base = fixture.cases[0];
  await sodium.ready;
  const key = sodium.from_hex(base.derived_hex), value = sodium.randombytes_buf(32), nonce = sodium.randombytes_buf(24);
  const aad = sodium.from_string('AnyNote.P01.PhraseWrapper.v1');
  const envelope = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(value, aad, null, nonce, key);
  assert(sodium.memcmp(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,envelope,aad,nonce,key),value));
  const wrong = {...base.request,phrase:base.request.phrase+' wrong'};
  const wrongNative = JSON.parse(execFileSync(native,['kdf'],{input:JSON.stringify(wrong),timeout:60000}));
  const wrongNode = await derive(wrong);
  const wrongWorker = page ? (await page.evaluate((request)=>p01({kind:'kdf',request}),wrong)).result : null;
  for (const derived of [wrongNative,wrongNode,wrongWorker].filter(Boolean)) {
    assert.notEqual(derived.derived_hex,base.derived_hex);
    const wrongKey=sodium.from_hex(derived.derived_hex);
    assert.throws(()=>sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,envelope,aad,nonce,wrongKey));
    sodium.memzero(wrongKey);
  }
  sodium.memzero(key); sodium.memzero(value);
  results.wrong_phrase_rejections = page ? 3 : 2;
  if (page) {
    const concurrent = await page.evaluate(async (request) => {
      const active = p01({kind:'kdf',request});
      const denied = await p01({kind:'kdf',request}).then(()=>false,()=>true);
      await active; return denied;
    },base.request);
    assert.equal(concurrent,true);
    results.concurrent_kdf_rejected = true;
    results.storage_capabilities = (await page.evaluate(()=>p01({kind:'storage-capabilities'}))).result;
    assert.equal(results.storage_capabilities.opfs,true); assert.equal(results.storage_capabilities.indexeddb,true);
    // Persistence requires a Window in several engines, not a dedicated worker.
    results.persistence = {granted: await page.evaluate(()=>navigator.storage.persist()),
      interpretation:'Observed permission outcome only; not an eviction guarantee.'};
    const stored = (await page.evaluate(()=>p01({kind:'storage-write'}))).result;
    try {
      await page.reload(); await page.waitForFunction(()=>typeof p01==='function');
      results.storage_durability = (await page.evaluate((expected)=>p01({kind:'storage-inspect',expected}),stored)).result;
      results.storage_denial = (await page.evaluate(()=>p01({kind:'storage-denied'}))).result;
    } finally { await page.evaluate((id)=>p01({kind:'storage-cleanup',id}),stored.id); }
    const cdp=await page.context().newCDPSession(page),origin=new URL(page.url()).origin;
    try{
      await cdp.send('Storage.overrideQuotaForOrigin',{origin,quotaSize:1048576});
      results.quota_injection=(await page.evaluate(()=>p01({kind:'storage-quota'}))).result;
      assert.equal(results.quota_injection.status,'QUOTA_EXCEEDED');
    }finally{await cdp.send('Storage.overrideQuotaForOrigin',{origin});await cdp.detach();}
  } else results.browser = 'NOT RUN';
  console.log('PASS: Argon2id cross-binding vectors, bounded profiles and wrong phrase; storage',page?'real browser':'NOT RUN');
  return results;
}
