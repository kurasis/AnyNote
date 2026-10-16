// Portable P05 codec; frozen predicates preserved by scripts/p05-port-codecs.py.
import { Buffer, createHash, readFileSync } from '../bytes.mjs';
import Ajv2020 from '../schema-validation.mjs';
import canonicalize from 'canonicalize';
import { strictJson, requireCondition as check } from '../../src/strict-json.mjs';

const schema = strictJson(readFileSync(new URL('../../contracts/p02-file-c1.schema.json', import.meta.url)));
const ajv = new Ajv2020({ strict: true, ownProperties: true, allErrors: false });
for (const size of [16, 24, 32, 48, 64]) {
  ajv.addFormat(`base64url-${size}`, value => {
    if (value.length !== Math.ceil(size * 8 / 6) || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
    const decoded = Buffer.from(value, 'base64url');
    return decoded.length === size && decoded.toString('base64url') === value;
  });
}
for (const limit of [119, 120, 199, 200, 65536, 100000, 8388608, 8388624, 1000000000, 9223372036854775807n]) {
  ajv.addFormat(`decimal-${limit}`, value => value.length <= String(limit).length &&
    /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) <= BigInt(limit));
}
ajv.addSchema(schema);
const validators = new Map(Object.keys(schema.$defs).map(kind => [kind,
  ajv.compile({ $ref: `${schema.$id}#/$defs/${kind}` })]));

const jcs = value => Buffer.from(canonicalize(value), 'utf8');
const same = (a, b) => jcs(a).equals(jcs(b));
export const sha256 = bytes => createHash('sha256').update(bytes).digest('base64url');
const prefix = (family, purpose) => Buffer.from(`AnyNote/p02-file-c1/${family}/${purpose}\0`, 'utf8');
const digest = (purpose, bytes) => sha256(Buffer.concat([prefix('hash', purpose), bytes]));
const CHUNK = 8_388_608;

function ordered(items, identity) {
  for (let i = 1; i < items.length; i++) check(identity(items[i - 1]) < identity(items[i]), 'UNORDERED_OR_DUPLICATE');
}

function contextRules(context) {
  ordered(context.parents, parent => parent.revision_id);
  for (const parent of context.parents) check(parent.revision_id !== context.file_version_id, 'SELF_PARENT');
}

function framingRules(framing) {
  const size = Number(framing.plaintext_bytes);
  const count = Math.ceil(size / CHUNK);
  check(Number(framing.chunk_count) === count && framing.parts.length === count, 'INVALID_CHUNK_COUNT');
  for (let index = 0; index < count; index++) {
    const part = framing.parts[index];
    check(part.index === String(index), 'INVALID_CHUNK_ORDER');
    const plainLength = Math.min(CHUNK, size - index * CHUNK);
    check(Number(part.ciphertext_bytes) === plainLength + 16, 'INVALID_CHUNK_LENGTH');
  }
}

function semanticRules(kind, value) {
  if (kind === 'context') contextRules(value);
  if (value.context) contextRules(value.context);
  if (kind === 'framing') framingRules(value);
  if (value.framing) framingRules(value.framing);
  if (kind === 'envelope') semanticRules('header', value.header);
  if (kind === 'header') check(Number(value.manifest_ciphertext_bytes) >= 16, 'INVALID_MANIFEST_LENGTH');
  if (kind === 'chunk-aad') {
    const index = Number(value.chunk_index), count = Number(value.chunk_count), length = Number(value.plaintext_chunk_bytes);
    check(index < count && length > 0 && (index === count - 1 || length === CHUNK), 'INVALID_CHUNK_LENGTH');
  }
  if (kind === 'checkpoint') {
    ordered(value.closed_rosters, roster => roster.account_id);
    const pages = Number(value.page_count), records = Number(value.record_count);
    check((records === 0 && pages === 0) || (pages > 0 && pages <= records && records <= pages * 500), 'INVALID_PAGE_COUNT');
  }
  if (kind === 'inventory-record') {
    ordered(value.parents, parent => parent.revision_id);
    for (const parent of value.parents) check(parent.revision_id !== value.revision_id, 'SELF_PARENT');
  }
  if (kind === 'checkpoint-page') {
    ordered(value.records, record => record.revision_id);
    for (const record of value.records) semanticRules('inventory-record', record);
  }
}

// Only byte input is public. Callers cannot insert toJSON hooks, accessors or
// an already-parsed last-wins object before validation.
export function decode(kind, bytes) {
  check(validators.has(kind), 'UNSUPPORTED_SCHEMA');
  const value = strictJson(bytes);
  check(validators.get(kind)(value), 'SCHEMA_MISMATCH');
  semanticRules(kind, value);
  return value;
}

export const canonicalBytes = bytes => jcs(strictJson(bytes));
export const encode = (kind, bytes) => jcs(decode(kind, bytes));

export function signingInput(kind, bytes) {
  check(kind === 'header' || kind === 'checkpoint', 'UNSUPPORTED_PURPOSE');
  return Buffer.concat([prefix('sign', kind === 'header' ? 'file-manifest' : 'history-checkpoint'), encode(kind, bytes)]);
}

export function aadInput(kind, bytes) {
  check(['chunk-aad', 'manifest-aad', 'wrap-aad'].includes(kind), 'UNSUPPORTED_PURPOSE');
  const value = decode(kind, bytes);
  return Buffer.concat([prefix('aad', value.purpose), jcs(value)]);
}

export const wrapDigest = bytes => digest('key-wrap', encode('wrap', bytes));
export const envelopeDigest = bytes => digest('file-envelope', encode('envelope', bytes));
export const checkpointDigest = bytes => digest('history-checkpoint', encode('checkpoint', bytes));
export const pageDigest = bytes => digest('history-page', encode('checkpoint-page', bytes));

export function chunkNonce(prefixBytes, index) {
  check(prefixBytes instanceof Uint8Array && prefixBytes.length === 16, 'INVALID_NONCE_PREFIX');
  check(typeof index === 'bigint' && index >= 0n && index <= 119n, 'INVALID_CHUNK_INDEX');
  const suffix = Buffer.alloc(8);
  suffix.writeBigUInt64LE(index);
  return Buffer.concat([prefixBytes, suffix]);
}

export function fileAad(headerBytes, purpose, index) {
  const header = decode('header', headerBytes);
  const context = header.context;
  if (purpose === 'wrap-aad') return aadInput(purpose, jcs({ purpose: 'file-manifest-key-wrap', context }));
  if (purpose === 'manifest-aad') return aadInput(purpose, jcs({ purpose: 'file-manifest', context, framing: header.framing }));
  check(purpose === 'chunk-aad' && typeof index === 'bigint' && index >= 0n && index < BigInt(header.framing.chunk_count), 'INVALID_CHUNK_INDEX');
  return aadInput(purpose, jcs({ purpose: 'file-chunk', context, chunk_index: String(index),
    plaintext_chunk_bytes: String(Number(header.framing.parts[Number(index)].ciphertext_bytes) - 16), chunk_count: header.framing.chunk_count }));
}

// Consistency only. Signature/AEAD/identity/authorization verification is a
// separate mandatory layer; success here never means trusted or decrypted.
export function checkFileBundle(headerBytes, wrapBytes, manifestBytes, expectedContextBytes) {
  const header = decode('header', headerBytes), wrap = decode('wrap', wrapBytes), manifest = decode('manifest', manifestBytes);
  const expected = decode('context', expectedContextBytes);
  check([header.context, wrap.context, manifest.context].every(context => same(context, expected)), 'CONTEXT_MISMATCH');
  check(same(header.framing, manifest.framing), 'FRAMING_MISMATCH');
  check(header.key_wrap_digest === wrapDigest(wrapBytes), 'KEY_WRAP_MISMATCH');
}

export function checkManifestCiphertext(headerBytes, ciphertext) {
  const header = decode('header', headerBytes);
  check(ciphertext instanceof Uint8Array && ciphertext.length === Number(header.manifest_ciphertext_bytes), 'INVALID_MANIFEST_LENGTH');
  check(sha256(ciphertext) === header.manifest_ciphertext_digest, 'MANIFEST_DIGEST_MISMATCH');
}

// Frozen candidate binary inventory commitment: domain, uint32be page count,
// uint64be record count, then each index/count/JCS-byte-length as uint32be and
// its 32-byte domain-separated page digest. No recursive signature digest.
export function inventoryCommitment(pageInputs) {
  check(Array.isArray(pageInputs) && pageInputs.length <= 200, 'RESOURCE_LIMIT');
  const pages = pageInputs.map(bytes => decode('checkpoint-page', bytes));
  const total = pages.reduce((sum, page) => sum + page.records.length, 0);
  const framing = Buffer.alloc(12);
  framing.writeUInt32BE(pages.length, 0);
  framing.writeBigUInt64BE(BigInt(total), 4);
  const hash = createHash('sha256').update(prefix('hash', 'history-inventory')).update(framing);
  pages.forEach((page, index) => {
    check(page.page_index === String(index), 'INVALID_PAGE_ORDER');
    if (index < pages.length - 1 && page.records.length < 500) {
      const next = pages[index + 1].records[0];
      check(jcs({ ...page, records: [...page.records, next] }).length > 1_048_576, 'INVALID_PAGE_PACKING');
    }
    if (index > 0) {
      check(page.service_id === pages[0].service_id && page.group_id === pages[0].group_id, 'CONTEXT_MISMATCH');
      check(pages[index - 1].records.at(-1).revision_id < page.records[0].revision_id, 'UNORDERED_OR_DUPLICATE');
    }
    const length = Buffer.alloc(12);
    length.writeUInt32BE(index, 0);
    length.writeUInt32BE(page.records.length, 4);
    length.writeUInt32BE(encode('checkpoint-page', pageInputs[index]).length, 8);
    hash.update(length).update(Buffer.from(pageDigest(pageInputs[index]), 'base64url'));
  });
  return { digest: hash.digest('base64url'), record_count: String(total), page_count: String(pages.length) };
}

// Reproduce closure bytes and compact ancestry. The caller must authenticate
// descriptor signatures, signer role, policy/roster chains and predecessor.
// This function deliberately cannot return an authorization verdict.
export function checkCheckpoint(checkpointBytes, pageInputs, expectedPredecessor) {
  const descriptor = decode('checkpoint', checkpointBytes);
  check(descriptor.predecessor_checkpoint_digest === expectedPredecessor &&
    descriptor.closed_policy.history_checkpoint_digest === expectedPredecessor, 'CHECKPOINT_ANCESTRY_MISMATCH');
  const commitment = inventoryCommitment(pageInputs);
  check(descriptor.inventory_digest === commitment.digest && descriptor.record_count === commitment.record_count &&
    descriptor.page_count === commitment.page_count, 'INVENTORY_MISMATCH');
  const records = new Map();
  for (const bytes of pageInputs) {
    const page = decode('checkpoint-page', bytes);
    check(page.service_id === descriptor.service_id && page.group_id === descriptor.group_id, 'CONTEXT_MISMATCH');
    for (const record of page.records) records.set(record.revision_id, record);
  }
  for (const record of records.values()) {
    for (const parent of record.parents) {
      const found = records.get(parent.revision_id);
      check(found && found.envelope_digest === parent.envelope_digest && found.object_id === record.object_id &&
        found.object_kind === record.object_kind, 'MISSING_OR_WRONG_ANCESTOR');
    }
  }
  const done = new Set(), visiting = new Set();
  // Iterative walk: adversarial long ancestry must not overflow the JS stack.
  for (const id of records.keys()) {
    const stack = [{ id, exit: false }];
    while (stack.length) {
      const frame = stack.pop();
      if (frame.exit) { visiting.delete(frame.id); done.add(frame.id); continue; }
      if (done.has(frame.id)) continue;
      check(!visiting.has(frame.id), 'CYCLIC_ANCESTRY');
      visiting.add(frame.id);
      stack.push({ id: frame.id, exit: true });
      for (const parent of records.get(frame.id).parents) stack.push({ id: parent.revision_id, exit: false });
    }
  }
}
