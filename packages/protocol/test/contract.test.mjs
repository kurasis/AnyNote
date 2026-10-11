import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { strictJson, ContractError } from '../src/strict-json.mjs';
import { canonicalBytes, decode, encode, signingInput, aadInput, fileAad, chunkNonce, sha256,
  checkFileBundle, checkManifestCiphertext, checkCheckpoint, inventoryCommitment, wrapDigest } from '../src/codec.mjs';
import { sample, raw, publicBytes, vectors } from '../fixtures.mjs';

const rejects = (fn, code) => assert.throws(fn, error => error instanceof ContractError && error.code === code);
const clone = value => structuredClone(value);
const fixture = sample();

test('RFC 8785 section 3.2.2 exact sample (external expected bytes)', () => {
  const input = { numbers: [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
    string: "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/", literals: [null, true, false] };
  const expected = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\\"\\\\\\\\\\\"/"}';
  assert.equal(canonicalBytes(raw(input)).toString(), expected);
});

test('RFC 8785 UTF-16 key ordering and Unicode preservation', () => {
  const input = '{"€":"Euro Sign","\\r":"Carriage Return","דּ":"Hebrew Letter Dalet With Dagesh","1":"One","😀":"Emoji: Grinning Face","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis"}';
  const expected = '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}';
  assert.equal(canonicalBytes(Buffer.from(input)).toString(), expected);
  assert.notDeepEqual(canonicalBytes(raw({ name: 'é' })), canonicalBytes(raw({ name: 'e\u0301' })));
});

for (const [name, source, code] of [
  ['duplicate', '{"a":1,"a":2}', 'DUPLICATE_PROPERTY'],
  ['escaped duplicate', '{"a":1,"\\u0061":2}', 'DUPLICATE_PROPERTY'],
  ['nested duplicate', '[{"a":{"z":1,"z":2}}]', 'DUPLICATE_PROPERTY'],
  ['lone high surrogate', '"\\ud800"', 'INVALID_UNICODE'],
  ['lone low surrogate', '{"value":"\\udfff"}', 'INVALID_UNICODE'],
  ['invalid property surrogate', '{"\\ud800":1}', 'INVALID_UNICODE'],
  ['overflow', '{"value":1e999}', 'NONFINITE_NUMBER'],
  ['negative overflow', '[-1e999]', 'NONFINITE_NUMBER'],
  ['NaN', '[NaN]', 'INVALID_JSON'], ['Infinity', '[Infinity]', 'INVALID_JSON'],
  ['comment', '{/*comment*/"a":1}', 'INVALID_JSON'],
  ['trailing comma', '{"a":1,}', 'INVALID_JSON'], ['trailing value', '{}{}', 'INVALID_JSON'],
  ['empty', '', 'INVALID_JSON'], ['BOM', '\ufeff{}', 'INVALID_JSON'],
  ['depth', '['.repeat(33) + '0' + ']'.repeat(33), 'RESOURCE_LIMIT'],
]) test(`raw JSON rejects ${name}`, () => rejects(() => strictJson(Buffer.from(source)), code));

test('raw JSON rejects invalid UTF-8 and replacement instead of decoding', () => {
  for (const bytes of [[0x22, 0xc0, 0xaf, 0x22], [0x22, 0xed, 0xa0, 0x80, 0x22], [0x22, 0xf4, 0x90, 0x80, 0x80, 0x22]])
    rejects(() => strictJson(Uint8Array.from(bytes)), 'INVALID_UTF8');
  rejects(() => strictJson({ a: 1 }), 'RAW_BYTES_REQUIRED');
  rejects(() => strictJson(Buffer.alloc(1_048_577)), 'RESOURCE_LIMIT');
});

test('raw JSON accepts valid surrogate pairs and repeated names in distinct objects', () => {
  assert.equal(strictJson(Buffer.from('"\\ud83d\\ude00"')), '😀');
  assert.deepEqual(strictJson(Buffer.from('[{"a":1},{"a":2}]')), [{ a: 1 }, { a: 2 }]);
});

for (const [name, change] of [
  ['unknown field', value => { value.extra = true; }],
  ['missing field', value => { delete value.service_id; }],
  ['nested override', value => { value.author.is_owner = true; }],
  ['protocol version', value => { value.protocol_version = 2; }],
  ['missing candidate marker', value => { delete value.contract; }],
  ['wrong candidate', value => { value.contract = 'p02-file-c2'; }],
  ['unsafe numeric counter', value => { value.policy.key_epoch = 9007199254740992; }],
  ['counter overflow', value => { value.policy.key_epoch = '9223372036854775808'; }],
  ['leading zero', value => { value.policy.key_epoch = '05'; }],
  ['counter exponent', value => { value.policy.key_epoch = '5e0'; }],
  ['padding', value => { value.service_id += '=='; }],
  ['noncanonical base64 bits', value => { value.service_id = value.service_id.slice(0, -1) + 'x'; }],
  ['user name as ID', value => { value.service_id = 'alice'; }],
  ['prototype property', value => { Object.defineProperty(value, '__proto__', { value: {}, enumerable: true }); }],
]) test(`candidate context rejects ${name}`, () => {
  const value = clone(fixture.context); change(value);
  rejects(() => decode('context', raw(value)), 'SCHEMA_MISMATCH');
});

test('parent references reject duplicates, self and unsorted revisions', () => {
  const value = clone(fixture.context), parent = { revision_id: publicBytes(16), envelope_digest: publicBytes(32) };
  value.parents = [parent, parent]; rejects(() => decode('context', raw(value)), 'UNORDERED_OR_DUPLICATE');
  value.parents = [{ ...parent, revision_id: value.file_version_id }]; rejects(() => decode('context', raw(value)), 'SELF_PARENT');
});

test('committed fixture bytes match regenerated candidate outputs', () => {
  const stored = JSON.parse(readFileSync(new URL('../../../fixtures/protocol/p02/vectors.json', import.meta.url)));
  assert.deepEqual(vectors(), stored);
});

for (const size of [0, 1, 8_388_607, 8_388_608, 8_388_609, 1_000_000_000]) test(`file framing ${size} and bundle agreement`, () => {
  const input = sample(size);
  checkFileBundle(raw(input.header), raw(input.wrap), raw(input.manifest), raw(input.context));
  checkCheckpoint(raw(input.checkpoint), input.pages.map(raw), null);
  checkManifestCiphertext(raw(input.header), Buffer.from(publicBytes(32), 'base64url'));
  if (size === 1_000_000_000) {
    assert.equal(input.header.framing.parts.length, 120);
    assert.equal(input.header.framing.parts[119].ciphertext_bytes, '1755664');
    assert.equal(input.header.framing.parts.reduce((total, part) => total + Number(part.ciphertext_bytes), 0), 1_000_001_920);
  }
  if (size === 0) rejects(() => fileAad(raw(input.header), 'chunk-aad', 0n), 'INVALID_CHUNK_INDEX');
});

for (const [name, change, code] of [
  ['too large', v => { v.plaintext_bytes = '1000000001'; }, 'SCHEMA_MISMATCH'],
  ['wrong count', v => { v.chunk_count = '1'; }, 'INVALID_CHUNK_COUNT'],
  ['missing part', v => { v.parts.pop(); }, 'INVALID_CHUNK_COUNT'],
  ['trailing part', v => { v.parts.push(v.parts[0]); }, 'INVALID_CHUNK_COUNT'],
  ['swapped part', v => { v.parts.reverse(); }, 'INVALID_CHUNK_ORDER'],
  ['short final part', v => { v.parts[1].ciphertext_bytes = '16'; }, 'INVALID_CHUNK_LENGTH'],
]) test(`file framing rejects ${name}`, () => {
  const value = clone(fixture.header.framing); change(value); rejects(() => decode('framing', raw(value)), code);
});

for (const [name, change] of [
  ['service', c => { c.service_id = publicBytes(16, 1); }], ['group', c => { c.group_id = publicBytes(16, 1); }],
  ['file', c => { c.file_id = publicBytes(16, 1); }], ['version', c => { c.file_version_id = publicBytes(16, 1); }],
  ['operation', c => { c.operation_id = publicBytes(16, 1); }], ['author account', c => { c.author.account_id = publicBytes(16, 1); }],
  ['author device', c => { c.author.device_id = publicBytes(16, 1); }], ['root', c => { c.author.root_fingerprint = publicBytes(32, 1); }],
  ['generation', c => { c.author.recovery_generation = '3'; }], ['roster', c => { c.author.roster.digest = publicBytes(32, 1); }],
  ['membership', c => { c.policy.membership.digest = publicBytes(32, 1); }], ['epoch', c => { c.policy.key_epoch = '6'; }],
  ['epoch digest', c => { c.policy.epoch_digest = publicBytes(32, 1); }], ['history boundary', c => { c.policy.history_checkpoint_digest = publicBytes(32, 1); }],
]) test(`R19 candidate bytes bind ${name}`, () => {
  const modified = clone(fixture); change(modified.context);
  assert.notDeepEqual(signingInput('header', raw(modified.header)), signingInput('header', raw(fixture.header)));
  assert.notDeepEqual(fileAad(raw(modified.header), 'wrap-aad'), fileAad(raw(fixture.header), 'wrap-aad'));
  assert.notDeepEqual(fileAad(raw(modified.header), 'manifest-aad'), fileAad(raw(fixture.header), 'manifest-aad'));
  assert.notDeepEqual(fileAad(raw(modified.header), 'chunk-aad', 0n), fileAad(raw(fixture.header), 'chunk-aad', 0n));
  rejects(() => checkFileBundle(raw(modified.header), raw(modified.wrap), raw(modified.manifest), raw(fixture.context)), 'CONTEXT_MISMATCH');
});

test('R19 wrap bytes are immutable digest material, independent of database references', () => {
  const wrap = clone(fixture.wrap); wrap.ciphertext = publicBytes(48, 1);
  rejects(() => checkFileBundle(raw(fixture.header), raw(wrap), raw(fixture.manifest), raw(fixture.context)), 'KEY_WRAP_MISMATCH');
  const header = clone(fixture.header); header.framing.parts[0].ciphertext_digest = publicBytes(32, 1);
  rejects(() => checkFileBundle(raw(header), raw(fixture.wrap), raw(fixture.manifest), raw(fixture.context)), 'FRAMING_MISMATCH');
  rejects(() => checkManifestCiphertext(raw(fixture.header), Buffer.alloc(32)), 'MANIFEST_DIGEST_MISMATCH');
  rejects(() => checkManifestCiphertext(raw(fixture.header), Buffer.alloc(31)), 'INVALID_MANIFEST_LENGTH');
});

test('purpose domains, chunk order and nonce endianness cannot alias', () => {
  const outputs = ['wrap-aad', 'manifest-aad', 'chunk-aad'].map(kind => fileAad(raw(fixture.header), kind, 0n));
  assert.equal(new Set(outputs.map(v => v.toString('base64url'))).size, 3);
  assert.notDeepEqual(fileAad(raw(fixture.header), 'chunk-aad', 0n), fileAad(raw(fixture.header), 'chunk-aad', 1n));
  const bytes = chunkNonce(Buffer.alloc(16), 119n);
  assert.equal(bytes.toString('hex'), '000000000000000000000000000000007700000000000000');
  for (const index of [-1n, 120n, 0]) rejects(() => chunkNonce(Buffer.alloc(16), index), 'INVALID_CHUNK_INDEX');
  rejects(() => chunkNonce(Buffer.alloc(15), 0n), 'INVALID_NONCE_PREFIX');
  rejects(() => signingInput('manifest', raw(fixture.manifest)), 'UNSUPPORTED_PURPOSE');
  rejects(() => aadInput('header', raw(fixture.header)), 'UNSUPPORTED_PURPOSE');
  rejects(() => decode('future-schema', raw({})), 'UNSUPPORTED_SCHEMA');
});

function checkpointSet(count = 501) {
  const input = sample(1), records = [];
  for (let index = 0; index < count; index++) {
    const id = Buffer.alloc(16); id.writeUInt32BE(index);
    records.push({ ...input.pages[0].records[0], revision_id: id.toString('base64url'), parents: [] });
  }
  records.sort((a, b) => a.revision_id < b.revision_id ? -1 : 1);
  const pages = [];
  for (let index = 0; index * 500 < count; index++) pages.push({ ...input.pages[0], page_index: String(index), records: records.slice(index * 500, (index + 1) * 500) });
  const commitment = inventoryCommitment(pages.map(raw));
  const checkpoint = { ...input.checkpoint, record_count: commitment.record_count, page_count: commitment.page_count, inventory_digest: commitment.digest };
  return { pages, checkpoint };
}

test('R14 complete inventory binds paginated boundary, ancestry and predecessor', () => {
  const input = checkpointSet(); checkCheckpoint(raw(input.checkpoint), input.pages.map(raw), null);
  rejects(() => checkCheckpoint(raw(input.checkpoint), input.pages.slice(0, 1).map(raw), null), 'INVENTORY_MISMATCH');
  rejects(() => inventoryCommitment(input.pages.toReversed().map(raw)), 'INVALID_PAGE_ORDER');
  const changed = clone(input); changed.pages[1].records[0].payload_status = 'pruned';
  rejects(() => checkCheckpoint(raw(input.checkpoint), changed.pages.map(raw), null), 'INVENTORY_MISMATCH');
  rejects(() => checkCheckpoint(raw(input.checkpoint), input.pages.map(raw), publicBytes(32)), 'CHECKPOINT_ANCESTRY_MISMATCH');
  changed.checkpoint.closed_policy.history_checkpoint_digest = publicBytes(32);
  rejects(() => checkCheckpoint(raw(changed.checkpoint), input.pages.map(raw), null), 'CHECKPOINT_ANCESTRY_MISMATCH');
});

test('R14 ancestors are compact exact revisions, not mutable object IDs', () => {
  const input = checkpointSet(2), [parent, child] = input.pages[0].records;
  child.parents = [{ revision_id: parent.revision_id, envelope_digest: parent.envelope_digest }];
  const rehash = () => { input.checkpoint.inventory_digest = inventoryCommitment(input.pages.map(raw)).digest; };
  rehash(); checkCheckpoint(raw(input.checkpoint), input.pages.map(raw), null);
  child.parents[0].envelope_digest = publicBytes(32); rehash();
  rejects(() => checkCheckpoint(raw(input.checkpoint), input.pages.map(raw), null), 'MISSING_OR_WRONG_ANCESTOR');
  child.parents[0].envelope_digest = parent.envelope_digest;
  parent.parents = [{ revision_id: child.revision_id, envelope_digest: child.envelope_digest }]; rehash();
  rejects(() => checkCheckpoint(raw(input.checkpoint), input.pages.map(raw), null), 'CYCLIC_ANCESTRY');
  parent.parents = []; child.parents[0].revision_id = publicBytes(16, 99); rehash();
  rejects(() => checkCheckpoint(raw(input.checkpoint), input.pages.map(raw), null), 'MISSING_OR_WRONG_ANCESTOR');
});

test('checkpoint duplicates, extra pages, bad framing and cross-group pages fail', () => {
  const input = checkpointSet();
  rejects(() => inventoryCommitment(Array(201).fill(raw(input.pages[0]))), 'RESOURCE_LIMIT');
  const changed = clone(input); changed.pages[1].group_id = publicBytes(16);
  rejects(() => inventoryCommitment(changed.pages.map(raw)), 'CONTEXT_MISMATCH');
  changed.pages[1].group_id = input.pages[1].group_id; changed.pages[1].records[0] = changed.pages[0].records[499];
  rejects(() => inventoryCommitment(changed.pages.map(raw)), 'UNORDERED_OR_DUPLICATE');
  const page = clone(input.pages[0]); page.records.pop();
  rejects(() => inventoryCommitment([raw(page), raw(input.pages[1])]), 'INVALID_PAGE_PACKING');
  const checkpoint = clone(input.checkpoint); checkpoint.page_count = '1';
  rejects(() => decode('checkpoint', raw(checkpoint)), 'INVALID_PAGE_COUNT');
});

test('checkpoint greedy pages respect byte cap before 500 large ancestry records', () => {
  const input = checkpointSet(300);
  const parents = Array.from({ length: 32 }, (_, index) => ({ revision_id: publicBytes(16, index + 32), envelope_digest: publicBytes(32) }));
  parents.sort((a, b) => a.revision_id < b.revision_id ? -1 : 1);
  const records = input.pages[0].records.map(record => ({ ...record, parents }));
  const page = { ...input.pages[0], records: [] };
  for (const record of records) {
    if (raw({ ...page, records: [...page.records, record] }).length > 1_048_576) break;
    page.records.push(record);
  }
  assert.ok(page.records.length < 300 && page.records.length > 0);
  const tail = { ...page, page_index: '1', records: records.slice(page.records.length) };
  const commitment = inventoryCommitment([raw(page), raw(tail)]);
  assert.equal(commitment.record_count, '300');
  rejects(() => decode('checkpoint-page', raw({ ...page, records })), 'RESOURCE_LIMIT');
  const early = { ...page, records: page.records.slice(0, -1) };
  const tooManyTail = { ...tail, records: records.slice(early.records.length) };
  rejects(() => inventoryCommitment([raw(early), raw(tooManyTail)]), 'INVALID_PAGE_PACKING');
});

test('reordered source properties canonicalize identically without unsigned extras', () => {
  const bytes = encode('header', raw(fixture.header));
  assert.deepEqual(encode('header', raw(Object.fromEntries(Object.entries(fixture.header).reverse()))), bytes);
  const header = clone(fixture.header); header.key_wrap_id = publicBytes(16);
  rejects(() => decode('header', raw(header)), 'SCHEMA_MISMATCH');
  header.manifest_ciphertext_bytes = '0'; delete header.key_wrap_id;
  rejects(() => decode('header', raw(header)), 'INVALID_MANIFEST_LENGTH');
  assert.equal(wrapDigest(raw(fixture.wrap)), fixture.header.key_wrap_digest);
  assert.equal(sha256(Buffer.from('abc')), 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0');
});
