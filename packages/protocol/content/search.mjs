import {ensure} from '../vault/store.mjs';
import {hash, Buffer} from '../adapters/primitives.mjs';
import {canonicalBytes} from '../adapters/core.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';

export const SEARCH_LIMITS = Object.freeze({documents: 10000, textBytes: 262144, tokens: 1024, tokenChars: 64, results: 100, queryChars: 256});
export function tokens(text) {
  ensure(typeof text === 'string' && Buffer.byteLength(text) <= SEARCH_LIMITS.textBytes, 'SEARCH_RESOURCE_LIMIT');
  const words = text.normalize('NFKC').toLocaleLowerCase('en-US').match(/[\p{L}\p{N}]+/gu) ?? [];
  return [...new Set(words.filter(w => w.length <= SEARCH_LIMITS.tokenChars))].slice(0, SEARCH_LIMITS.tokens);
}
export const searchFingerprint = value => hash(canonicalBytes(wire(value)));
export function indexDocument(context, content, envelope_digest) {
  ensure(context && ['entry', 'thread', 'group-metadata'].includes(context.object_kind) && typeof envelope_digest === 'string', 'INVALID_SEARCH_DOCUMENT');
  const title = content.title ?? '', body = content.markdown ?? '', checklist = (content.checklist ?? []).map(x => x.text ?? '').join(' ');
  const text = [title, body, checklist].join('\n');
  const words = tokens(text);
  const allWords = new Set(text.normalize('NFKC').toLocaleLowerCase('en-US').match(/[\p{L}\p{N}]+/gu) ?? []);
  return {group_id: context.group_id, object_id: context.object_id, revision_id: context.revision_id,
    thread_id: context.thread_id, object_kind: context.object_kind, envelope_digest,
    tombstone: context.action === 'soft-delete', title: title.slice(0, 512), snippet: body.slice(0, 512),
    tokens: words, token_coverage: allWords.size > words.length ? 'bounded' : 'complete'};
}
export function searchDocument(document, query) {
  ensure(typeof query === 'string' && query.length <= SEARCH_LIMITS.queryChars, 'SEARCH_RESOURCE_LIMIT');
  const wanted = tokens(query); ensure(wanted.length > 0 && wanted.length <= 16, 'INVALID_SEARCH_QUERY');
  return !document.tombstone && wanted.every(w => document.tokens.includes(w));
}
export function coverage(catalog, indexed, accessible) {
  const map = new Map(indexed.map(x => [x.object_id + '/' + x.revision_id, x]));
  const result = {known: 0, indexed: 0, unavailable: 0, unanchored: 0, stale: 0, not_indexed: 0, bounded: 0};
  for (const item of catalog) {
    if (!accessible.has(item.group_id) || item.object_kind === 'file-manifest') continue;
    result.known++;
    if (item.payload_status === 'pruned') { result.unavailable++; continue; }
    if (item.payload_status === 'unanchored') { result.unanchored++; continue; }
    const found = map.get(item.object_id + '/' + item.revision_id);
    if (!found) result.not_indexed++;
    else if (found.envelope_digest !== item.envelope_digest) result.stale++;
    else { result.indexed++; if (found.token_coverage === 'bounded') result.bounded++; }
  }
  return result;
}
