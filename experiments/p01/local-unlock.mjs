import { sodium } from './crypto.mjs';

export function validateProfile(request) {
  const fields = ['profile_version', 'algorithm', 'phrase', 'salt_hex', 'opslimit', 'memlimit'];
  if (!request || Object.keys(request).sort().join() !== fields.sort().join()
    || request.profile_version !== 1 || request.algorithm !== 'argon2id13'
    || !Number.isSafeInteger(request.opslimit) || request.opslimit < 3 || request.opslimit > 10
    || !Number.isSafeInteger(request.memlimit) || request.memlimit < 67108864 || request.memlimit > 268435456
    || typeof request.phrase !== 'string' || new TextEncoder().encode(request.phrase).length < 16
    || new TextEncoder().encode(request.phrase).length > 1024
    || typeof request.salt_hex !== 'string' || !/^[0-9a-f]{32}$/.test(request.salt_hex)) {
    throw new Error('Invalid bounded P01 KDF profile');
  }
}

export async function derive(request) {
  validateProfile(request);
  await sodium.ready;
  const before = performance.now();
  const phrase = new TextEncoder().encode(request.phrase); // UTF-8 bytes; no normalization or NUL truncation.
  let key;
  try {
    key = sodium.crypto_pwhash(32, phrase, sodium.from_hex(request.salt_hex),
      request.opslimit, request.memlimit, sodium.crypto_pwhash_ALG_ARGON2ID13);
    return { derived_hex: sodium.to_hex(key), elapsed_ms: Math.round(performance.now() - before),
      algorithm: 'argon2id13', opslimit: request.opslimit, memlimit: request.memlimit,
      sodium_version: sodium.sodium_version_string(), wasm_heap_bytes: sodium.libsodium?.HEAPU8?.buffer.byteLength ?? null,
      warning: 'PUBLIC SYNTHETIC KDF VECTOR; NEVER USE THIS KEY' };
  } finally { sodium.memzero(phrase); if (key) sodium.memzero(key); }
}

export const publicProfiles = [
  { profile_version: 1, algorithm: 'argon2id13', phrase: 'public synthetic strong phrase alpha',
    salt_hex: '000102030405060708090a0b0c0d0e0f', opslimit: 3, memlimit: 67108864 },
  { profile_version: 1, algorithm: 'argon2id13', phrase: 'Public UTF-8 café 🗝️\u0000tail remains',
    salt_hex: '000102030405060708090a0b0c0d0e0f', opslimit: 3, memlimit: 67108864 },
  { profile_version: 1, algorithm: 'argon2id13', phrase: 'public synthetic strong phrase alpha',
    salt_hex: '101112131415161718191a1b1c1d1e1f', opslimit: 3, memlimit: 67108864 },
];

export const invalidProfiles = (base) => [
  {...base, opslimit: 2}, {...base, opslimit: 11}, {...base, opslimit: 3.5},
  {...base, memlimit: 67108863}, {...base, memlimit: 268435457}, {...base, memlimit: 2**40},
  {...base, memlimit: 67108864.5}, {...base, profile_version: 2}, {...base, algorithm: 'argon2i13'},
  {...base, salt_hex: '00'}, {...base, salt_hex: 'GG'.repeat(16)}, {...base, phrase: 'short'},
  {...base, phrase: 'x'.repeat(1025)}, {...base, unexpected: true},
];
