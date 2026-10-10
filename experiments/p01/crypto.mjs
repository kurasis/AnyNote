// PUBLIC test fixtures only. This module is not an application crypto provider.
import sodium from 'libsodium-wrappers-sumo';

export { sodium };
export const WARNING = 'PUBLIC NONSECRET SYNTHETIC P01 FIXTURE; NEVER USE THESE KEYS';
const toHex = (bytes) => sodium.to_hex(bytes);
function bytes(text) {
  if (typeof text !== 'string' || text.length > 131072 || text.length % 2 || !/^[0-9a-f]*$/.test(text)) {
    throw new Error('Invalid or oversized lowercase hex fixture');
  }
  return sodium.from_hex(text);
}
function equal(a, b) { return a.length === b.length && sodium.memcmp(a, b); }
function altered(a) { const b = new Uint8Array(a); b[0] ^= 1; return b; }
function exactKeys(object, names) {
  if (!object || Object.keys(object).sort().join(',') !== names.sort().join(',')) {
    throw new Error('Unknown or missing experimental fixture fields');
  }
}

export async function emitFixture(origin) {
  await sodium.ready;
  const key = Uint8Array.from({ length: 32 }, (_, i) => i);
  const aead = [0, 1, 31, 1024].map((length, index) => {
    const nonce = new Uint8Array(24).fill(0x42); nonce[23] = index;
    const message = Uint8Array.from({ length }, (_, i) => i % 251);
    const aad = sodium.from_string(`anynote/p01/primitive-only/aead/${index}`);
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(message, aad, null, nonce, key);
    return Object.fromEntries(Object.entries({ key, nonce, aad, message, ciphertext }).map(([k, v]) => [k, toHex(v)]));
  });
  const signSeed = new Uint8Array(32).fill(0x53);
  const signer = sodium.crypto_sign_seed_keypair(signSeed);
  const signMessage = sodium.from_string('anynote/p01/signature/public synthetic data');
  const boxSeed = new Uint8Array(32).fill(0x62);
  const recipient = sodium.crypto_box_seed_keypair(boxSeed);
  const boxMessage = sodium.from_string('anynote/p01/sealed-box/public synthetic key');
  return {
    fixture_version: 1, warning: WARNING, origin, sodium_version: sodium.sodium_version_string(), aead,
    sign: { seed: toHex(signSeed), public_key: toHex(signer.publicKey), message: toHex(signMessage),
      signature: toHex(sodium.crypto_sign_detached(signMessage, signer.privateKey)) },
    sealed_box: { seed: toHex(boxSeed), public_key: toHex(recipient.publicKey), message: toHex(boxMessage),
      ciphertext: toHex(sodium.crypto_box_seal(boxMessage, recipient.publicKey)) },
  };
}

export async function verifyFixture(f) {
  await sodium.ready;
  exactKeys(f, ['fixture_version', 'warning', 'origin', 'sodium_version', 'aead', 'sign', 'sealed_box']);
  if (f.fixture_version !== 1 || f.warning !== WARNING || !Array.isArray(f.aead) || f.aead.length !== 4) {
    throw new Error('Unknown or incomplete experimental fixture');
  }
  const checks = [];
  function check(condition, name) { if (!condition) throw new Error(`Failed: ${name}`); checks.push(name); }
  function reject(fn, name) {
    let rejected = false;
    try { fn(); } catch { rejected = true; }
    check(rejected, name);
  }
  for (const [i, item] of f.aead.entries()) {
    exactKeys(item, ['key', 'nonce', 'aad', 'message', 'ciphertext']);
    const { key, nonce, aad, message, ciphertext } = Object.fromEntries(Object.entries(item).map(([k, v]) => [k, bytes(v)]));
    const decrypt = (c = ciphertext, a = aad, n = nonce, k = key) => sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, c, a, n, k);
    check(equal(decrypt(), message), `aead-${i}-decrypt`);
    check(equal(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(message, aad, null, nonce, key), ciphertext), `aead-${i}-exact-ciphertext`);
    reject(() => decrypt(ciphertext, aad, nonce, altered(key)), `aead-${i}-wrong-key`);
    reject(() => decrypt(ciphertext, altered(aad)), `aead-${i}-wrong-aad`);
    reject(() => decrypt(ciphertext, aad, altered(nonce)), `aead-${i}-wrong-nonce`);
    reject(() => decrypt(altered(ciphertext)), `aead-${i}-corruption`);
    reject(() => decrypt(ciphertext.slice(0, -1)), `aead-${i}-truncation`);
  }
  exactKeys(f.sign, ['seed', 'public_key', 'message', 'signature']);
  const signer = sodium.crypto_sign_seed_keypair(bytes(f.sign.seed));
  const publicKey = bytes(f.sign.public_key), signMessage = bytes(f.sign.message), signature = bytes(f.sign.signature);
  check(equal(signer.publicKey, publicKey), 'ed25519-exact-public-key');
  check(equal(sodium.crypto_sign_detached(signMessage, signer.privateKey), signature), 'ed25519-exact-signature');
  check(sodium.crypto_sign_verify_detached(signature, signMessage, publicKey), 'ed25519-verify');
  check(!sodium.crypto_sign_verify_detached(signature, altered(signMessage), publicKey), 'ed25519-changed-message');
  check(!sodium.crypto_sign_verify_detached(altered(signature), signMessage, publicKey), 'ed25519-changed-signature');
  check(!sodium.crypto_sign_verify_detached(signature, signMessage, sodium.crypto_sign_seed_keypair(new Uint8Array(32).fill(0x54)).publicKey), 'ed25519-wrong-public-key');
  exactKeys(f.sealed_box, ['seed', 'public_key', 'message', 'ciphertext']);
  const recipient = sodium.crypto_box_seed_keypair(bytes(f.sealed_box.seed));
  const boxMessage = bytes(f.sealed_box.message), sealed = bytes(f.sealed_box.ciphertext);
  check(toHex(recipient.publicKey) === f.sealed_box.public_key, 'sealed-box-exact-public-key');
  check(equal(sodium.crypto_box_seal_open(sealed, recipient.publicKey, recipient.privateKey), boxMessage), 'sealed-box-open');
  const other = sodium.crypto_box_seed_keypair(new Uint8Array(32).fill(0x63));
  reject(() => sodium.crypto_box_seal_open(sealed, other.publicKey, other.privateKey), 'sealed-box-wrong-recipient');
  reject(() => sodium.crypto_box_seal_open(altered(sealed), recipient.publicKey, recipient.privateKey), 'sealed-box-corruption');
  reject(() => sodium.crypto_box_seal_open(sealed.slice(0, -1), recipient.publicKey, recipient.privateKey), 'sealed-box-truncation');
  return { status: 'PASS', checks, sodium_version: sodium.sodium_version_string() };
}
