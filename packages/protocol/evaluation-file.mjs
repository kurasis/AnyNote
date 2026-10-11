// Bounded synthetic reference only: <=64 KiB in memory, no I/O/product endpoint.
import sodium from 'libsodium-wrappers-sumo';
import { ContractError, requireCondition as check } from './src/strict-json.mjs';
import { wire, same } from './src/identity-codec.mjs';
import { certificateDetails } from './src/identity-crypto.mjs';
import { decode, encode, fileAad, signingInput, chunkNonce, sha256, wrapDigest,
  checkFileBundle, checkManifestCiphertext } from './src/codec.mjs';
await sodium.ready;
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const un64 = value => Buffer.from(value, 'base64url');
const encrypt = (plaintext, aad, nonce, key) => Buffer.from(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key));
function decrypt(ciphertext, aad, nonce, key) {
  try { return Buffer.from(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, key)); }
  catch { throw new ContractError('AEAD_INTEGRITY_FAILURE'); }
}
export function prepareEvaluationFile(contextBytes, plaintext, keys, deviceSecretKey) {
  const context = decode('context', contextBytes);
  check(plaintext instanceof Uint8Array && plaintext.length > 0 && plaintext.length <= 65536, 'EVALUATION_SIZE_LIMIT');
  const framing = { plaintext_bytes: String(plaintext.length), chunk_plaintext_bytes: '8388608', chunk_count: '1',
    parts: [{ index: '0', ciphertext_bytes: String(plaintext.length + 16), ciphertext_digest: sha256(Buffer.alloc(0)) }] };
  const wrap = { purpose: 'file-manifest-key-wrap', context, nonce: b64(keys.wrapNonce), ciphertext: b64(Buffer.alloc(48)) };
  const header = { purpose: 'file-manifest', context, framing, manifest_nonce: b64(keys.manifestNonce),
    manifest_ciphertext_bytes: '16', manifest_ciphertext_digest: sha256(Buffer.alloc(0)), key_wrap_digest: wrapDigest(wire(wrap)) };
  // Chunk AAD excludes the hash of its own ciphertext.
  const chunk = encrypt(plaintext, fileAad(wire(header), 'chunk-aad', 0n), chunkNonce(keys.noncePrefix, 0n), keys.fileKey);
  framing.parts[0].ciphertext_digest = sha256(chunk);
  const manifest = { purpose: 'file-manifest-plaintext', context, framing, file_data_key: b64(keys.fileKey),
    nonce_prefix: b64(keys.noncePrefix), original_name: 'PUBLIC TEST — résumé.bin', client_media_type: 'application/octet-stream', plaintext_digest: sha256(plaintext) };
  wrap.ciphertext = b64(encrypt(keys.manifestKey, fileAad(wire(header), 'wrap-aad'), keys.wrapNonce, keys.groupKey));
  header.key_wrap_digest = wrapDigest(wire(wrap));
  const manifestCiphertext = encrypt(encode('manifest', wire(manifest)), fileAad(wire(header), 'manifest-aad'), keys.manifestNonce, keys.manifestKey);
  header.manifest_ciphertext_bytes = String(manifestCiphertext.length);
  header.manifest_ciphertext_digest = sha256(manifestCiphertext);
  const envelope = { header, signature: b64(sodium.crypto_sign_detached(signingInput('header', wire(header)), deviceSecretKey)) };
  return { envelope: decode('envelope', wire(envelope)), wrap: decode('wrap', wire(wrap)),
    manifest_ciphertext: b64(manifestCiphertext), chunks: [b64(chunk)] };
}
export function decryptEvaluationFile(bundle, groupKey, certificateProof, expectedContextBytes) {
  const envelope = decode('envelope', wire(bundle.envelope)), header = envelope.header;
  const expected = decode('context', expectedContextBytes), cert = certificateDetails(certificateProof);
  check(same(header.context, expected) && expected.service_id === cert.body.service_id &&
    expected.author.account_id === cert.body.account_id && expected.author.device_id === cert.body.device_id &&
    expected.author.root_fingerprint === cert.body.root_fingerprint && expected.author.recovery_generation === cert.body.recovery_generation &&
    cert.body.capabilities.includes('sign-content'), 'FILE_AUTHOR_CONTEXT_MISMATCH');
  check(sodium.crypto_sign_verify_detached(un64(envelope.signature), signingInput('header', wire(header)), un64(cert.body.device_signing_key)), 'SIGNATURE_INVALID');
  check(Number(header.framing.plaintext_bytes) > 0 && Number(header.framing.plaintext_bytes) <= 65536 &&
    Array.isArray(bundle.chunks) && bundle.chunks.length === 1, 'EVALUATION_SIZE_LIMIT');
  const wrap = decode('wrap', wire(bundle.wrap));
  check(same(wrap.context, expected) && wrapDigest(wire(wrap)) === header.key_wrap_digest, 'KEY_WRAP_MISMATCH');
  const ciphertext = un64(bundle.manifest_ciphertext);
  checkManifestCiphertext(wire(header), ciphertext);
  const manifestKey = decrypt(un64(wrap.ciphertext), fileAad(wire(header), 'wrap-aad'), un64(wrap.nonce), groupKey);
  let plaintextManifest, fileKey;
  try {
    plaintextManifest = decrypt(ciphertext, fileAad(wire(header), 'manifest-aad'), un64(header.manifest_nonce), manifestKey);
    const manifest = decode('manifest', plaintextManifest);
    checkFileBundle(wire(header), wire(wrap), plaintextManifest, expectedContextBytes);
    const chunk = un64(bundle.chunks[0]), part = header.framing.parts[0];
    check(chunk.length === Number(part.ciphertext_bytes) && sha256(chunk) === part.ciphertext_digest, 'CHUNK_DIGEST_MISMATCH');
    fileKey = un64(manifest.file_data_key);
    const plaintext = decrypt(chunk, fileAad(wire(header), 'chunk-aad', 0n), chunkNonce(un64(manifest.nonce_prefix), 0n), fileKey);
    check(plaintext.length === Number(header.framing.plaintext_bytes) && sha256(plaintext) === manifest.plaintext_digest, 'PLAINTEXT_MISMATCH');
    return plaintext;
  } finally {
    sodium.memzero(manifestKey);
    if (plaintextManifest) sodium.memzero(plaintextManifest);
    if (fileKey) sodium.memzero(fileKey);
  }
}
