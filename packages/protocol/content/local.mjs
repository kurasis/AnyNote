import {sodium, b64, un64, hash, Buffer, encrypt, decrypt} from '../adapters/primitives.mjs';
import {canonicalBytes} from '../adapters/core.mjs';
import {wire, same} from '../adapters/codecs/identity-codec.mjs';
import {strictJson} from '../src/strict-json.mjs';
import {ensure, id} from '../vault/store.mjs';

export const CONTENT_PROFILE = 'p13-content-v1';
export const CONTENT_KINDS = new Set(['content-control', 'search-page', 'file-metadata', 'export-state', 'import-state', 'preview-state', 'content-part']);
const MAX_BYTES = 16777216;
const PART_BYTES = 262144;
export const contentControlId = scope => b64(un64(hash(Buffer.concat([
  Buffer.from('AnyNote/P13/content-control\0'), canonicalBytes(wire(scope)),
]))).subarray(0, 16));

function context(scope, pins, record_id, record_kind) {
  ensure(id(record_id) && CONTENT_KINDS.has(record_kind), 'INVALID_CONTENT_RECORD');
  return {purpose: 'protected-content-context', version: 1, ...scope,
    record_id, record_kind, root_fingerprint: pins.root_fingerprint};
}
const aad = c => Buffer.concat([Buffer.from('AnyNote/P13/protected-content\0'), canonicalBytes(wire(c))]);
export function contentFrame(value) {
  ensure(value && Object.keys(value).sort().join(',') === 'ciphertext,context,contract,nonce,protocol,protocol_version,purpose' &&
    value.contract === CONTENT_PROFILE && value.protocol === 'anynote' && value.protocol_version === 1 &&
    value.purpose === 'protected-content-local' && CONTENT_KINDS.has(value.context?.record_kind) &&
    typeof value.nonce === 'string' && un64(value.nonce).length === 24 &&
    typeof value.ciphertext === 'string' && un64(value.ciphertext).length <= 360448, 'INVALID_CONTENT_FRAME');
  return value;
}
function seal(scope, pins, record, kind, data, key) {
  const c = context(scope, pins, record, kind), bytes = canonicalBytes(wire(data));
  ensure(bytes.length <= 360432, 'RESOURCE_LIMIT');
  const nonce = sodium.randombytes_buf(24);
  try { return contentFrame({contract: CONTENT_PROFILE, protocol: 'anynote', protocol_version: 1,
    purpose: 'protected-content-local', context: c, nonce: b64(nonce), ciphertext: b64(encrypt(bytes, aad(c), nonce, key))}); }
  finally { sodium.memzero(bytes); }
}
function open(frame, scope, pins, record, kind, key) {
  const f = contentFrame(frame), c = context(scope, pins, record, kind);
  ensure(same(f.context, c), 'LOCAL_CONTEXT_MISMATCH');
  const plain = decrypt(un64(f.ciphertext), aad(c), un64(f.nonce), key);
  try { return strictJson(plain, 360432); } finally { sodium.memzero(plain); }
}
export function contentManifest(frame, scope, pins, record, kind, key) {
  ensure(kind !== 'content-part', 'INVALID_CONTENT_RECORD');
  const m = open(frame, scope, pins, record, kind, key);
  ensure(m.purpose === 'protected-content-manifest' && m.version === 1 && m.kind === kind &&
    Number.isSafeInteger(m.bytes) && m.bytes > 0 && m.bytes <= MAX_BYTES &&
    Array.isArray(m.parts) && m.parts.length === Math.ceil(m.bytes / PART_BYTES) && m.parts.length <= 64 &&
    new Set(m.parts.map(p => p.record_id)).size === m.parts.length && m.parts.every((p, n) =>
      id(p.record_id) && p.index === n && Number.isSafeInteger(p.bytes) && p.bytes > 0 && p.bytes <= PART_BYTES &&
      typeof p.digest === 'string' && un64(p.digest).length === 32), 'INTEGRITY_FAILURE');
  return m;
}
export function prepareContent(scope, pins, record, kind, data, key) {
  ensure(kind !== 'content-part', 'INVALID_CONTENT_RECORD');
  const bytes = canonicalBytes(wire(data)), parts = [], records = [];
  ensure(bytes.length > 0 && bytes.length <= MAX_BYTES, 'RESOURCE_LIMIT');
  try {
    for (let offset = 0; offset < bytes.length; offset += PART_BYTES) {
      const chunk = bytes.subarray(offset, offset + PART_BYTES), part_id = b64(sodium.randombytes_buf(16));
      const part = {purpose: 'protected-content-part', version: 1, root_id: record, root_kind: kind,
        index: parts.length, bytes: chunk.length, digest: hash(chunk), record_bytes: b64(chunk)};
      records.push({id: part_id, frame: seal(scope, pins, part_id, 'content-part', part, key)});
      parts.push({record_id: part_id, index: part.index, bytes: chunk.length, digest: part.digest});
    }
    const manifest = {purpose: 'protected-content-manifest', version: 1, kind, bytes: bytes.length, digest: hash(bytes), parts};
    return {frame: seal(scope, pins, record, kind, manifest, key), records};
  } finally { sodium.memzero(bytes); }
}
export async function readContent(frame, scope, pins, record, kind, key, read) {
  const manifest = contentManifest(frame, scope, pins, record, kind, key), chunks = [];
  try {
    for (const p of manifest.parts) {
      const row = await read(p.record_id); ensure(row, 'RECORD_NOT_FOUND');
      const data = open(row.frame, scope, pins, p.record_id, 'content-part', key);
      ensure(data.purpose === 'protected-content-part' && data.version === 1 && data.root_id === record &&
        data.root_kind === kind && data.index === p.index && data.bytes === p.bytes && data.digest === p.digest, 'INTEGRITY_FAILURE');
      const bytes = un64(data.record_bytes);
      ensure(bytes.length === p.bytes && hash(bytes) === p.digest &&
        (p.index === manifest.parts.length - 1 || bytes.length === PART_BYTES), 'INTEGRITY_FAILURE');
      chunks.push(bytes);
    }
    const all = Buffer.concat(chunks);
    try { ensure(all.length === manifest.bytes && hash(all) === manifest.digest, 'INTEGRITY_FAILURE');
      return strictJson(all, MAX_BYTES); }
    finally { sodium.memzero(all); }
  } finally { for (const bytes of chunks) sodium.memzero(bytes); }
}
export function rotateContent(frame, scope, pins, record, key, nextKey) {
  const kind = contentFrame(frame).context.record_kind, data = open(frame, scope, pins, record, kind, key);
  try { return seal(scope, pins, record, kind, data, nextKey); }
  finally { if (kind === 'content-part') data.record_bytes = ''; }
}
