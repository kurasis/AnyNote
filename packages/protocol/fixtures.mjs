import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { encode, signingInput, fileAad, wrapDigest, envelopeDigest, inventoryCommitment,
  checkpointDigest, chunkNonce, sha256 } from './src/codec.mjs';

export const raw = value => Buffer.from(JSON.stringify(value), 'utf8');
export const publicBytes = (size, start = 0) => Buffer.from(Array.from({ length: size }, (_, i) => (start + i) % 256)).toString('base64url');
const byteHex = bytes => bytes.toString('hex');
export function sample(size = 8_388_609) {
  const context = { protocol: 'anynote', protocol_version: 1, contract: 'p02-file-c1', service_id: publicBytes(16),
    group_id: publicBytes(16, 16), file_id: publicBytes(16, 32), file_version_id: publicBytes(16, 48), operation_id: publicBytes(16, 64),
    author: { account_id: publicBytes(16, 80), device_id: publicBytes(16, 96), root_fingerprint: publicBytes(32, 112),
      recovery_generation: '2', roster: { version: '3', digest: publicBytes(32, 144) } },
    policy: { membership: { version: '4', digest: publicBytes(32, 176) }, key_epoch: '5', epoch_digest: publicBytes(32, 208), history_checkpoint_digest: null },
    parents: [], file_format: 'xchacha20poly1305-chunks-c1', manifest_schema: 1 };
  const count = Math.ceil(size / 8_388_608);
  const framing = { plaintext_bytes: String(size), chunk_plaintext_bytes: '8388608', chunk_count: String(count),
    parts: Array.from({ length: count }, (_, i) => ({ index: String(i), ciphertext_bytes: String(Math.min(8_388_608, size - i * 8_388_608) + 16),
      ciphertext_digest: sha256(Buffer.from(`PUBLIC framing-only chunk ${i}, file size ${size}`)) })) };
  // Known public bytes for serialization only. These are not encrypted payloads
  // or real signatures, and must never be passed as crypto known-answer vectors.
  const wrap = { purpose: 'file-manifest-key-wrap', context, nonce: publicBytes(24), ciphertext: publicBytes(48) };
  const header = { purpose: 'file-manifest', context, framing, manifest_nonce: publicBytes(24, 24),
    manifest_ciphertext_bytes: '32', manifest_ciphertext_digest: sha256(Buffer.from(publicBytes(32), 'base64url')), key_wrap_digest: wrapDigest(raw(wrap)) };
  const manifest = { purpose: 'file-manifest-plaintext', context, framing, file_data_key: publicBytes(32), nonce_prefix: publicBytes(16),
    original_name: 'Résumé 📄.bin', client_media_type: 'application/octet-stream', plaintext_digest: null };
  const envelope = { header, signature: publicBytes(64) };
  const pages = size === 0 ? [] : [{ purpose: 'history-inventory-page', contract: 'p02-file-c1', version: 1,
    service_id: context.service_id, group_id: context.group_id, page_index: '0', records: [{ object_kind: 'file-manifest',
      object_id: context.file_id, revision_id: context.file_version_id, envelope_digest: envelopeDigest(raw(envelope)), parents: [], payload_status: 'retained' }] }];
  const inventory = inventoryCommitment(pages.map(raw));
  const checkpoint = { purpose: 'history-checkpoint', contract: 'p02-file-c1', version: 1,
    service_id: context.service_id, group_id: context.group_id, predecessor_checkpoint_digest: null,
    closed_policy: context.policy, closed_rosters: [{ account_id: context.author.account_id, root_fingerprint: context.author.root_fingerprint,
      recovery_generation: context.author.recovery_generation, roster: context.author.roster }], record_count: inventory.record_count,
    page_count: inventory.page_count, inventory_digest: inventory.digest, signer: context.author };
  return { context, wrap, header, manifest, envelope, pages, checkpoint };
}

export function vectors() {
  return { status: 'PUBLIC_NONSECRET_SERIALIZATION_ONLY', contract: 'p02-file-c1', cases:
    [0, 1, 8_388_607, 8_388_608, 8_388_609, 1_000_000_000].map(size => {
      const input = sample(size);
      const canonical = {};
      for (const kind of ['context', 'wrap', 'header', 'manifest', 'envelope', 'checkpoint']) canonical[kind] = byteHex(encode(kind, raw(input[kind])));
      canonical.pages = input.pages.map(page => byteHex(encode('checkpoint-page', raw(page))));
      const outputs = { canonical_hex: canonical, header_signing_input_hex: byteHex(signingInput('header', raw(input.header))),
        checkpoint_signing_input_hex: byteHex(signingInput('checkpoint', raw(input.checkpoint))),
        wrap_digest: wrapDigest(raw(input.wrap)), envelope_digest: envelopeDigest(raw(input.envelope)), checkpoint_digest: checkpointDigest(raw(input.checkpoint)),
        manifest_aad_hex: byteHex(fileAad(raw(input.header), 'manifest-aad')),
        wrap_aad_hex: byteHex(fileAad(raw(input.header), 'wrap-aad')),
        chunks: Array.from({ length: Number(input.header.framing.chunk_count) }, (_, index) => ({
          aad_hex: byteHex(fileAad(raw(input.header), 'chunk-aad', BigInt(index))),
          nonce_hex: chunkNonce(Buffer.from(input.manifest.nonce_prefix, 'base64url'), BigInt(index)).toString('hex'),
        })) };
      return { name: `file-${size}`, input, outputs };
    }) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const path = new URL('../../fixtures/protocol/p02/vectors.json', import.meta.url);
  const expected = JSON.stringify(vectors(), null, 2) + '\n';
  if (process.argv.includes('--write')) {
    mkdirSync(new URL('../../fixtures/protocol/p02/', import.meta.url), { recursive: true });
    writeFileSync(path, expected);
    console.log('Wrote public candidate serialization fixtures; review before committing');
  } else {
    if (readFileSync(path, 'utf8') !== expected) throw new Error('FIXTURE_DRIFT');
    console.log('PASS: six exact-size public serialization/context fixtures; no crypto/authorization verdict');
  }
}
