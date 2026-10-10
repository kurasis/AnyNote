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
  for (let index = 0; index < count; index++) {
    const part = Math.min(CHUNK, length - index * CHUNK);
    const source = sodium.randombytes_buf(part); // CSPRNG-generated incompressible synthetic stream.
    sodium.crypto_hash_sha256_update(inputHash, source);
    const nonce = new Uint8Array(24); nonce.set(prefix); new DataView(nonce.buffer).setBigUint64(16, BigInt(index), true);
    const aad = sodium.from_string(`anynote/p01/browser-file-only/${index}/${count}/${part}`);
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(source, aad, null, nonce, key);
    const digest = sodium.crypto_hash_sha256(encrypted);
    const uploaded = await fetch(`/ciphertext/${index}`, { method: 'PUT', body: encrypted });
    if (!uploaded.ok) throw new Error(`Upload failed: ${uploaded.status}`);
    const downloaded = await fetch(`/ciphertext/${index}`, { cache: 'no-store' });
    if (!downloaded.ok) throw new Error(`Download failed: ${downloaded.status}`);
    const ciphertext = new Uint8Array(await downloaded.arrayBuffer()); // One bounded chunk, never the full file.
    if (ciphertext.length !== part + 16 || !sodium.memcmp(sodium.crypto_hash_sha256(ciphertext), digest)) throw new Error('Ciphertext inventory mismatch');
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, key);
    if (!sodium.memcmp(plaintext, source)) throw new Error('Decrypted chunk mismatch');
    sodium.crypto_hash_sha256_update(outputHash, plaintext);
    transferred += encrypted.length;
    postMessage({ kind: 'progress', index, count });
  }
  const sourceHash = sodium.crypto_hash_sha256_final(inputHash), recoveredHash = sodium.crypto_hash_sha256_final(outputHash);
  if (!sodium.memcmp(sourceHash, recoveredHash)) throw new Error('Full stream digest mismatch');
  sodium.memzero(key);
  return { mode: 'chromium-worker-loopback-roundtrip', plaintext_bytes: length, chunks: count,
    ciphertext_bytes: transferred, sha256: sodium.to_hex(sourceHash), elapsed_ms: Math.round(performance.now() - started),
    sodium_version: sodium.sodium_version_string(),
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
