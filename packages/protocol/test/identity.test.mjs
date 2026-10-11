import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hkdfSync } from 'node:crypto';
import { bech32m } from '@scure/base';
import sodium from 'libsodium-wrappers-sumo';
import { ContractError } from '../src/strict-json.mjs';
import { wire, decodeIdentity, identitySigningInput, identityDigest } from '../src/identity-codec.mjs';
import * as c from '../src/identity-crypto.mjs';
import { fixturePath, deriveFixture, publicSeed, common, checkCryptoVectors } from '../crypto-vectors.mjs';
import { decryptEvaluationFile } from '../evaluation-file.mjs';
import { signingInput, wrapDigest, sha256 } from '../src/codec.mjs';
await sodium.ready;
const fixture = JSON.parse(readFileSync(fixturePath)), d = deriveFixture(fixture.input), o = d.outputs;
const clone = structuredClone, b64 = bytes => Buffer.from(bytes).toString('base64url');
const un64 = value => Buffer.from(value, 'base64url');
const rejects = (fn, code) => assert.throws(fn, e => e instanceof ContractError && (!code || e.code === code));
const signedGrant = body => wire({ body, signature: b64(sodium.crypto_sign_detached(identitySigningInput('grant-body', wire(body)), d.devices[0].signing.privateKey)) });
const open = (record = fixture.sealed_inputs[0], context = o.grant_contexts[0], keys = d.devices[1].encryption, issuer = d.devices[0].certificateProof) =>
  c.openGroupKeyForEvaluation(wire(record), wire(context), issuer, keys.publicKey, keys.privateKey);
const fileRead = (bundle = o.file, groupKey = d.fileKeys.groupKey, context = o.file_context) => decryptEvaluationFile(bundle, groupKey, d.devices[0].certificateProof, wire(context));
const resignFile = bundle => { bundle.envelope.signature = b64(sodium.crypto_sign_detached(signingInput('header', wire(bundle.envelope.header)), d.devices[0].signing.privateKey)); return bundle; };

test('Node HKDF reproduces RFC 5869 test case 1 external expected bytes', () => {
  const output = hkdfSync('sha256', Buffer.alloc(22, 0x0b), Buffer.from('000102030405060708090a0b0c', 'hex'), Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'), 42);
  assert.equal(Buffer.from(output).toString('hex'), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});
test('Bech32m BIP 350 external checksum example accepted; Bech32 variant rejected', () => {
  assert.equal(bech32m.decode('a1lqfn3a').prefix, 'a');
  assert.throws(() => bech32m.decode('a12uel5l'));
});
test('frozen crypto vectors reproduce keys, signatures, full file and both fresh recipient paths', () => {
  assert.equal(checkCryptoVectors(fixture).status, 'PASS');
});
test('root signing and recovery encryption seeds and keys are independent', () => {
  assert.notEqual(o.hkdf[0].seed_hex, o.hkdf[1].seed_hex);
  assert.notEqual(o.identity.body.root_signing_key, o.identity.body.recovery_encryption_key);
  assert.equal(c.identityDetails(d.identityProof).fingerprint, o.pin.root_fingerprint);
});
for (const field of ['service_id', 'account_id']) test(`HKDF ${field} separation and pinned root rejection`, () => {
  const context = clone(fixture.input.context); context[field] = b64(publicSeed(224).slice(0, 16));
  const identity = c.createIdentity(publicSeed(0), wire(context));
  assert.notEqual(c.rootFingerprint(identity), o.pin.root_fingerprint);
  rejects(() => c.verifyRootIdentity(identity, wire(o.pin)), 'ROOT_PIN_MISMATCH');
});
test('HKDF rejects purpose/version changes rather than implicitly falling back', () => {
  rejects(() => c.derivationParameters(wire(fixture.input.context), 'local-vault'), 'UNSUPPORTED_PURPOSE');
  const context = clone(fixture.input.context); context.protocol_version = 2;
  rejects(() => c.deriveRoot(publicSeed(0), wire(context)), 'SCHEMA_MISMATCH');
});
for (const bad of [Buffer.alloc(31), Buffer.alloc(33), 'password', null]) test(`R requires raw 32 bytes: ${typeof bad}/${bad?.length}`, () => {
  rejects(() => c.deriveRoot(bad, wire(fixture.input.context)), 'INVALID_KEY_LENGTH');
  rejects(() => c.encodeRecoverySecret(bad), 'INVALID_KEY_LENGTH');
});
test('a valid alternate self-signed root is rejected against independent identity pin', () => {
  const replacement = c.createIdentity(publicSeed(1), wire(fixture.input.context));
  rejects(() => c.verifyRootIdentity(replacement, wire(o.pin)), 'ROOT_PIN_MISMATCH');
});
test('root identity signature does not participate in fingerprint but must verify', () => {
  const identity = clone(o.identity); identity.signature = b64(Buffer.alloc(64));
  assert.equal(c.rootFingerprint(wire(identity)), o.pin.root_fingerprint);
  rejects(() => c.verifyRootIdentity(wire(identity), wire(o.pin)), 'SIGNATURE_INVALID');
});
test('root fingerprint changes when recovery key is substituted', () => {
  const identity = clone(o.identity); identity.body.recovery_encryption_key = b64(publicSeed(1));
  rejects(() => c.verifyRootIdentity(wire(identity), wire(o.pin)), 'ROOT_PIN_MISMATCH');
});
test('recovery kit derives exactly the already pinned root, without a previous device cache', () => {
  const recovered = c.recoverRoot(wire(o.kit), wire(o.pin));
  assert.equal(b64(recovered.keys.signing.publicKey), o.identity.body.root_signing_key);
  assert.equal(b64(recovered.keys.recovery.publicKey), o.identity.body.recovery_encryption_key);
});
for (const [name, mutate] of [
  ['checksum', s => s.slice(0, -1) + (s.at(-1) === 'q' ? 'p' : 'q')], ['uppercase', s => s.toUpperCase()],
  ['space', s => ' ' + s], ['Unicode', s => s.slice(0, -1) + 'а'], ['truncation', s => s.slice(0, -1)],
]) test(`recovery secret rejects ${name}`, () => rejects(() => c.decodeRecoverySecret(mutate(o.kit.recovery_secret)), 'INVALID_RECOVERY_ENCODING'));
test('recovery checksum profile rejects wrong HRP/version/payload/padding and Bech32 checksum', () => {
  for (const [hrp, payload] of [['other', Buffer.concat([Buffer.from([1]), publicSeed(0)])], ['anr', Buffer.concat([Buffer.from([2]), publicSeed(0)])], ['anr', Buffer.alloc(32)]])
    rejects(() => c.decodeRecoverySecret(bech32m.encode(hrp, bech32m.toWords(payload), 90)), 'INVALID_RECOVERY_ENCODING');
  const words = bech32m.toWords(Buffer.concat([Buffer.from([1]), publicSeed(0)])); words[words.length - 1] |= 1;
  rejects(() => c.decodeRecoverySecret(bech32m.encode('anr', words, 90)), 'INVALID_RECOVERY_ENCODING');
});
test('well-checksummed wrong R does not recover the supplied identity', () => {
  const kit = clone(o.kit); kit.recovery_secret = c.encodeRecoverySecret(publicSeed(1));
  rejects(() => c.recoverRoot(wire(kit), wire(o.pin)), 'RECOVERY_IDENTITY_MISMATCH');
});
for (const field of ['service_id', 'account_id', 'root_fingerprint']) test(`kit ${field} must match independent pin`, () => {
  const kit = clone(o.kit); kit[field] = b64(publicSeed(240).slice(0, field === 'root_fingerprint' ? 32 : 16));
  rejects(() => c.recoverRoot(wire(kit), wire(o.pin)), 'ROOT_PIN_MISMATCH');
});
for (const [kind, value] of [['identity', o.identity], ['kit', o.kit], ['certificate', o.certificates[0].record], ['grant', fixture.sealed_inputs[0]]]) {
  test(`${kind} rejects unknown fields, duplicate fields, bad Unicode, oversized input`, () => {
    const altered = clone(value); altered.server_override = true;
    rejects(() => decodeIdentity(kind, wire(altered)), 'SCHEMA_MISMATCH');
    rejects(() => decodeIdentity(kind, Buffer.from('{"x":1,"\\u0078":2}')), 'DUPLICATE_PROPERTY');
    rejects(() => decodeIdentity(kind, Buffer.from('"\\ud800"')), 'INVALID_UNICODE');
    rejects(() => decodeIdentity(kind, Buffer.alloc(16385)), 'RESOURCE_LIMIT');
  });
}
test('canonical fixed binary fields reject noncanonical base64url pad bits', () => {
  const identity = clone(o.identity); identity.body.root_signing_key += '=';
  rejects(() => decodeIdentity('identity', wire(identity)), 'SCHEMA_MISMATCH');
});
test('signature-only proofs cannot be forged with a JSON boolean', () => {
  rejects(() => c.identityDetails({ signature_valid: true }), 'SIGNATURE_PROOF_REQUIRED');
  rejects(() => c.certificateDetails({ signature_valid: true }), 'SIGNATURE_PROOF_REQUIRED');
  assert.equal(d.identityProof.authorization, 'NOT_EVALUATED');
  assert.equal(d.devices[0].certificateProof.authorization, 'NOT_EVALUATED');
});
test('random device key generation uses independent signing/encryption keys on each call', () => {
  const a = c.generateDeviceKeys(), b = c.generateDeviceKeys();
  const keys = [a.signing.publicKey, a.encryption.publicKey, b.signing.publicKey, b.encryption.publicKey].map(b64);
  assert.equal(new Set(keys).size, 4);
});
for (const field of ['device_id', 'device_signing_key', 'device_encryption_key', 'pairing_transcript_digest', 'recovery_generation', 'predecessor_roster', 'capabilities']) test(`certificate exact expected ${field} rejects substitution`, () => {
  const body = clone(o.certificates[0].record.body);
  if (field === 'predecessor_roster') body[field] = { version: '2', digest: b64(publicSeed(4)) };
  else if (field === 'capabilities') body[field] = [];
  else if (field === 'recovery_generation') { body[field] = '1'; body.predecessor_roster = { version: '2', digest: b64(publicSeed(4)) }; }
  else body[field] = b64(publicSeed(4).slice(0, field === 'device_id' ? 16 : 32));
  const cert = c.signCertificate(wire(body), d.root.signing.privateKey);
  rejects(() => c.verifyCertificateSignature(cert, d.identityProof, wire(o.certificates[0].record.body)), 'CERTIFICATE_CONTEXT_MISMATCH');
});
test('certificate with expected body but wrong signing key fails', () => {
  const body = o.certificates[0].record.body;
  const cert = c.signCertificate(wire(body), d.devices[1].signing.privateKey);
  rejects(() => c.verifyCertificateSignature(cert, d.identityProof, wire(body)), 'SIGNATURE_INVALID');
});
test('device certificate signature domains cannot be replayed as an identity signature', () => {
  assert.notEqual(identitySigningInput('certificate-body', wire(o.certificates[0].record.body)).toString('hex'), o.identity_signing_input_hex);
  rejects(() => identitySigningInput('kit', wire(o.kit)), 'UNSUPPORTED_PURPOSE');
});
function delegateBody() {
  const body = clone(o.certificates[1].record.body);
  body.issuer = { kind: 'device', device_id: o.certificates[0].record.body.device_id, certificate_digest: o.certificates[0].digest };
  body.predecessor_roster = o.grant_contexts[0].issuer.roster_head;
  return body;
}
test('delegated certificate verifies against pinned issuer certificate and separate expected body', () => {
  const body = delegateBody(), cert = c.signCertificate(wire(body), d.devices[0].signing.privateKey);
  const proof = c.verifyCertificateSignature(cert, d.identityProof, wire(body), d.devices[0].certificateProof);
  assert.equal(c.certificateDetails(proof).body.issuer.device_id, body.issuer.device_id);
  assert.equal(proof.authorization, 'NOT_EVALUATED');
});
test('delegation rejects missing/wrong issuer proof, self-approval, and generation mismatch', () => {
  const body = delegateBody(), cert = c.signCertificate(wire(body), d.devices[0].signing.privateKey);
  rejects(() => c.verifyCertificateSignature(cert, d.identityProof, wire(body)), 'SIGNATURE_PROOF_REQUIRED');
  rejects(() => c.verifyCertificateSignature(cert, d.identityProof, wire(body), d.devices[1].certificateProof), 'ISSUER_CONTEXT_MISMATCH');
  const wrong = clone(body); wrong.recovery_generation = '1';
  const signed = c.signCertificate(wire(wrong), d.devices[0].signing.privateKey);
  rejects(() => c.verifyCertificateSignature(signed, d.identityProof, wire(wrong), d.devices[0].certificateProof), 'ISSUER_CONTEXT_MISMATCH');
  const self = clone(body); self.device_id = body.issuer.device_id;
  rejects(() => c.signCertificate(wire(self), d.devices[0].signing.privateKey), 'SELF_DELEGATION');
});
test('delegate without capability cannot issue another certificate', () => {
  const body = clone(o.certificates[0].record.body); body.capabilities = ['receive-group-key'];
  const cert = c.signCertificate(wire(body), d.root.signing.privateKey);
  const issuer = c.verifyCertificateSignature(cert, d.identityProof, wire(body));
  const child = delegateBody(); child.issuer.certificate_digest = identityDigest('certificate', cert);
  const childCert = c.signCertificate(wire(child), d.devices[0].signing.privateKey);
  rejects(() => c.verifyCertificateSignature(childCert, d.identityProof, wire(child), issuer), 'ISSUER_CONTEXT_MISMATCH');
});
test('duplicate or unordered capabilities and signing/encryption key reuse rejected', () => {
  for (const caps of [['sign-content', 'receive-group-key'], ['receive-group-key', 'receive-group-key']]) {
    const body = clone(o.certificates[0].record.body); body.capabilities = caps;
    rejects(() => c.signCertificate(wire(body), d.root.signing.privateKey));
  }
  const body = clone(o.certificates[0].record.body); body.device_encryption_key = body.device_signing_key;
  rejects(() => c.signCertificate(wire(body), d.root.signing.privateKey), 'KEY_PURPOSE_COLLISION');
});
test('real CSPRNG sealed boxes decrypt identically but do not reuse ciphertext', () => {
  const args = [wire(o.grant_contexts[0]), d.fileKeys.groupKey, d.devices[1].encryption.publicKey, d.devices[0].signing.privateKey, d.devices[0].certificateProof];
  const a = c.sealGroupKeyForEvaluation(...args), b = c.sealGroupKeyForEvaluation(...args);
  assert.notDeepEqual(a, b);
  assert.deepEqual(open(decodeIdentity('grant', a)), Buffer.from(d.fileKeys.groupKey));
  assert.deepEqual(open(decodeIdentity('grant', b)), Buffer.from(d.fileKeys.groupKey));
});
for (const field of ['service_id', 'group_id', 'key_epoch', 'epoch_digest', 'membership_head', 'operation_id', 'issuer', 'recipient']) test(`grant expected ${field} rejects substituted context`, () => {
  const context = clone(o.grant_contexts[0]);
  if (field === 'key_epoch') context[field] = '2';
  else if (field === 'membership_head') context[field].version = '2';
  else if (field === 'issuer') context[field].roster_head.version = '2';
  else if (field === 'recipient') context[field].roster_head.version = '2';
  else context[field] = b64(publicSeed(8).slice(0, field === 'epoch_digest' ? 32 : 16));
  rejects(() => open(fixture.sealed_inputs[0], context), 'GRANT_CONTEXT_MISMATCH');
});
test('known revocation/new roster changes exact required coverage; old grants rejected', () => {
  const contexts = clone(o.grant_contexts); contexts[0].recipient.roster_head.version = '2';
  rejects(() => c.checkDistributionCoverage(fixture.sealed_inputs.map(wire), contexts.map(wire), d.devices[0].certificateProof), 'RECIPIENT_COVERAGE_MISMATCH');
  rejects(() => c.checkDistributionCoverage(fixture.sealed_inputs.map(wire), [wire(o.grant_contexts[1])], d.devices[0].certificateProof), 'RECIPIENT_COVERAGE_MISMATCH');
});
test('missing, extra, duplicate and replacement recipient records fail exact coverage', () => {
  const records = fixture.sealed_inputs.map(wire), contexts = o.grant_contexts.map(wire), proof = d.devices[0].certificateProof;
  assert.equal(c.checkDistributionCoverage(records, contexts, proof).authorization, 'NOT_EVALUATED');
  for (const bad of [[records[0]], [...records, records[0]], [records[0], records[0]]]) rejects(() => c.checkDistributionCoverage(bad, contexts, proof), 'RECIPIENT_COVERAGE_MISMATCH');
  rejects(() => c.checkDistributionCoverage(records, [contexts[0], contexts[0]], proof), 'RECIPIENT_COVERAGE_MISMATCH');
});
test('a decryptable sealed box signed by an unexpected certified sender is rejected', () => {
  const body = clone(fixture.sealed_inputs[0].body);
  const record = { body, signature: b64(sodium.crypto_sign_detached(identitySigningInput('grant-body', wire(body)), d.devices[1].signing.privateKey)) };
  assert.ok(sodium.crypto_box_seal_open(un64(body.sealed_ciphertext), d.devices[1].encryption.publicKey, d.devices[1].encryption.privateKey));
  rejects(() => open(record), 'SIGNATURE_INVALID');
  rejects(() => open(record, o.grant_contexts[0], d.devices[1].encryption, d.devices[1].certificateProof), 'ISSUER_CONTEXT_MISMATCH');
});
test('wrong recipient secret or supplied substituted public key is rejected before unwrap', () => {
  rejects(() => open(fixture.sealed_inputs[0], o.grant_contexts[0], d.devices[0].encryption), 'RECIPIENT_KEY_MISMATCH');
  rejects(() => open(fixture.sealed_inputs[0], o.grant_contexts[0], { publicKey: d.devices[1].encryption.publicKey, privateKey: d.devices[0].encryption.privateKey }), 'RECIPIENT_KEY_MISMATCH');
});
test('signed corrupt sealed ciphertext still fails authenticated decryption', () => {
  const body = clone(fixture.sealed_inputs[0].body), ciphertext = un64(body.sealed_ciphertext); ciphertext[ciphertext.length - 1] ^= 1; body.sealed_ciphertext = b64(ciphertext);
  rejects(() => open(decodeIdentity('grant', signedGrant(body))), 'SEALED_INTEGRITY_FAILURE');
});
test('valid outer signature and sealed box cannot hide a different inner epoch context', () => {
  const body = clone(fixture.sealed_inputs[0].body), innerContext = clone(body.context); innerContext.key_epoch = '2';
  body.sealed_ciphertext = b64(sodium.crypto_box_seal(wire({ purpose: 'group-key-plaintext', context: innerContext, group_key: b64(d.fileKeys.groupKey) }), d.devices[1].encryption.publicKey));
  rejects(() => open(decodeIdentity('grant', signedGrant(body))), 'INNER_CONTEXT_MISMATCH');
});
test('valid signed distribution can contain a wrong group key; file AEAD rejects it', () => {
  const record = c.sealGroupKeyForEvaluation(wire(o.grant_contexts[0]), publicSeed(1), d.devices[1].encryption.publicKey, d.devices[0].signing.privateKey, d.devices[0].certificateProof);
  const key = open(decodeIdentity('grant', record));
  rejects(() => fileRead(o.file, key), 'AEAD_INTEGRITY_FAILURE');
});
test('file author signature must verify against the expected certificate', () => {
  const bundle = clone(o.file); bundle.envelope.signature = b64(Buffer.alloc(64));
  rejects(() => fileRead(bundle), 'SIGNATURE_INVALID');
});
test('known changed file epoch/roster and wrong account are rejected, with no plaintext fallback', () => {
  for (const update of [ctx => ctx.policy.key_epoch = '2', ctx => ctx.author.roster.version = '2', ctx => ctx.author.account_id = b64(publicSeed(8).slice(0, 16))]) {
    const context = clone(o.file_context); update(context);
    rejects(() => fileRead(o.file, d.fileKeys.groupKey, context), 'FILE_AUTHOR_CONTEXT_MISMATCH');
  }
});
test('corrupted manifest/chunk bytes fail exact signed ciphertext digest before output', () => {
  const bundle = clone(o.file); const bytes = un64(bundle.manifest_ciphertext); bytes[0] ^= 1; bundle.manifest_ciphertext = b64(bytes);
  rejects(() => fileRead(bundle), 'MANIFEST_DIGEST_MISMATCH');
  const other = clone(o.file); const chunk = un64(other.chunks[0]); chunk[0] ^= 1; other.chunks[0] = b64(chunk);
  rejects(() => fileRead(other), 'CHUNK_DIGEST_MISMATCH');
});
test('corrupt manifest with a renewed valid signature/hash still fails AEAD', () => {
  const bundle = clone(o.file); const bytes = un64(bundle.manifest_ciphertext); bytes[0] ^= 1; bundle.manifest_ciphertext = b64(bytes);
  bundle.envelope.header.manifest_ciphertext_digest = sha256(bytes);
  rejects(() => fileRead(resignFile(bundle)), 'AEAD_INTEGRITY_FAILURE');
});
test('altered manifest wrap with valid signed new digest still fails AEAD', () => {
  const bundle = clone(o.file); bundle.wrap.nonce = b64(publicSeed(1).slice(0, 24));
  bundle.envelope.header.key_wrap_digest = wrapDigest(wire(bundle.wrap));
  rejects(() => fileRead(resignFile(bundle)), 'AEAD_INTEGRITY_FAILURE');
});

test('coverage cannot mix epochs/operations or repeat one device under alternate keys', () => {
  for (const mutate of [ctx => ctx.key_epoch = '2', ctx => ctx.operation_id = b64(publicSeed(8).slice(0, 16)),
    ctx => { ctx.recipient = clone(o.grant_contexts[0].recipient); ctx.recipient.encryption_key_fingerprint = b64(publicSeed(1)); }]) {
    const contexts = clone(o.grant_contexts); mutate(contexts[1]);
    rejects(() => c.checkDistributionCoverage(fixture.sealed_inputs.map(wire), contexts.map(wire), d.devices[0].certificateProof), 'RECIPIENT_COVERAGE_MISMATCH');
  }
});

test('recovery generation creates independent 32-byte CSPRNG secrets', () => {
  const a = c.generateRecoverySecret(), b = c.generateRecoverySecret();
  assert.equal(a.length, 32); assert.equal(b.length, 32); assert.notDeepEqual(a, b);
});
for (const field of ['account_id', 'root_fingerprint', 'recovery_generation', 'device_id', 'certificate_digest', 'encryption_key_fingerprint']) test(`recipient nested ${field} remains pinned`, () => {
  const context = clone(o.grant_contexts[0]);
  context.recipient[field] = field === 'recovery_generation' ? '1' : b64(publicSeed(8).slice(0, ['account_id', 'device_id'].includes(field) ? 16 : 32));
  rejects(() => open(fixture.sealed_inputs[0], context), 'GRANT_CONTEXT_MISMATCH');
});
test('candidate markers, versions, recipient types and oversized counters fail closed', () => {
  for (const mutate of [ctx => ctx.contract = 'p02-identity-c2', ctx => ctx.protocol_version = 2,
    ctx => ctx.recipient.kind = 'administrator', ctx => ctx.key_epoch = '9223372036854775808',
    ctx => ctx.key_epoch = '01', ctx => ctx.membership_head.version = 1]) {
    const context = clone(o.grant_contexts[0]); mutate(context);
    rejects(() => decodeIdentity('grant-context', wire(context)), 'SCHEMA_MISMATCH');
  }
});
test('received sealed input is size bounded before expensive signature/decryption', () => {
  const record = clone(fixture.sealed_inputs[0]); record.body.sealed_ciphertext = b64(Buffer.alloc(4097));
  rejects(() => open(record), 'SCHEMA_MISMATCH');
});
