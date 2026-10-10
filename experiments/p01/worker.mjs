import { sodium, emitFixture, verifyFixture } from './crypto.mjs';

const CHUNK = 8388608, MAX_FILE = 1000000000;
async function roundtrip(length) {
  if (!Number.isSafeInteger(length) || length < 0 || length > MAX_FILE) throw new Error('File exceeds experiment bound');
  await sodium.ready;
  const started = performance.now();
  const key = sodium.randombytes_buf(32), prefix = sodium.randombytes_buf(16);
  const count = Math.ceil(length / CHUNK);
  const inputHash = sodium.crypto_hash_sha256_init(), outputHash = sodium.crypto_hash_sha256_init();
  let transferred = 0;
  const timings = { random_ms: 0, crypto_ms: 0, upload_ms: 0, download_ms: 0, verify_ms: 0 };
  const initialWasmHeap = sodium.libsodium?.HEAPU8?.buffer.byteLength ?? null;
  let peakWasmHeap = initialWasmHeap;
  for (let index = 0; index < count; index++) {
    const part = Math.min(CHUNK, length - index * CHUNK);
    let before = performance.now();
    // Test source only: Web Crypto CSPRNG, respecting its 64 KiB request limit.
    // The wrapper's per-byte entropy bridge is unsuitable for bulk test data;
    // content keys/nonces still use libsodium. Real uploads read a selected file.
    const source = new Uint8Array(part);
    for (let offset = 0; offset < part; offset += 65536) {
      crypto.getRandomValues(source.subarray(offset, Math.min(offset + 65536, part)));
    }
    timings.random_ms += performance.now() - before; before = performance.now();
    sodium.crypto_hash_sha256_update(inputHash, source);
    const nonce = new Uint8Array(24); nonce.set(prefix); new DataView(nonce.buffer).setBigUint64(16, BigInt(index), true);
    const aad = sodium.from_string(`anynote/p01/browser-file-only/${index}/${count}/${part}`);
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(source, aad, null, nonce, key);
    const digest = sodium.crypto_hash_sha256(encrypted);
    timings.crypto_ms += performance.now() - before; before = performance.now();
    const uploaded = await fetch(`/ciphertext/${index}`, { method: 'PUT', body: encrypted });
    if (!uploaded.ok) throw new Error(`Upload failed: ${uploaded.status}`);
    timings.upload_ms += performance.now() - before; before = performance.now();
    const downloaded = await fetch(`/ciphertext/${index}`, { cache: 'no-store' });
    if (!downloaded.ok) throw new Error(`Download failed: ${downloaded.status}`);
    const ciphertext = new Uint8Array(await downloaded.arrayBuffer()); // One bounded chunk, never the full file.
    timings.download_ms += performance.now() - before; before = performance.now();
    if (ciphertext.length !== part + 16 || !sodium.memcmp(sodium.crypto_hash_sha256(ciphertext), digest)) throw new Error('Ciphertext inventory mismatch');
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, key);
    if (!sodium.memcmp(plaintext, source)) throw new Error('Decrypted chunk mismatch');
    sodium.crypto_hash_sha256_update(outputHash, plaintext);
    timings.verify_ms += performance.now() - before;
    transferred += encrypted.length;
    const heap = sodium.libsodium?.HEAPU8?.buffer.byteLength ?? null;
    if (heap !== null) peakWasmHeap = Math.max(peakWasmHeap ?? 0, heap);
    postMessage({ kind: 'progress', index, count });
  }
  const sourceHash = sodium.crypto_hash_sha256_final(inputHash), recoveredHash = sodium.crypto_hash_sha256_final(outputHash);
  if (!sodium.memcmp(sourceHash, recoveredHash)) throw new Error('Full stream digest mismatch');
  sodium.memzero(key);
  return { mode: 'chromium-worker-loopback-roundtrip', plaintext_bytes: length, chunks: count,
    ciphertext_bytes: transferred, sha256: sodium.to_hex(sourceHash), elapsed_ms: Math.round(performance.now() - started),
    sodium_version: sodium.sodium_version_string(),
    initial_wasm_heap_bytes: initialWasmHeap, peak_wasm_heap_bytes: peakWasmHeap,
    timings_ms: Object.fromEntries(Object.entries(timings).map(([name, value]) => [name, Math.round(value)])),
    limitation: 'synthetic generated stream through local ciphertext-only HTTP; no iPhone, file picker, manifest, resume or Files export acceptance' };
}

let busy = false;
self.onmessage = async ({ data }) => {
  if (busy) { postMessage({ kind: 'error', message: 'Experiment already running' }); return; }
  busy = true;
  try {
    if (data.kind === 'interop') {
      const checks = await verifyFixture(data.fixture);
      postMessage({ kind: 'result', checks, fixture: await emitFixture('browser-worker') });
    } else if (data.kind === 'roundtrip') {
      postMessage({ kind: 'result', result: await roundtrip(data.length) });
    } else throw new Error('Unknown experiment command');
  } catch (error) { postMessage({ kind: 'error', message: String(error.message) }); }
  finally { busy = false; }
};
