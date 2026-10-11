// Isolated synthetic candidate reference. Signature proof != active device,
// current group permission, authenticated pairing, or production acceptance.
import { createHash, hkdfSync } from 'node:crypto';
import { bech32m } from '@scure/base';
import sodium from 'libsodium-wrappers-sumo';
import { ContractError, requireCondition as check } from './strict-json.mjs';
import { decodeIdentity as decode, encodeIdentity as encode, domain, wire, same,
  identitySigningInput as signing, identityDigest as digest } from './identity-codec.mjs';
await sodium.ready;

const common = purpose => ({ purpose, contract: 'p02-identity-c1', protocol: 'anynote', protocol_version: 1 });
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const un64 = value => Buffer.from(value, 'base64url');
const bytes32 = bytes => check(bytes instanceof Uint8Array && bytes.length === 32, 'INVALID_KEY_LENGTH');
const identities = new WeakMap(), certificates = new WeakMap();
function proof(map, value) {
  const token = Object.freeze({ signature_valid: true, authorization: 'NOT_EVALUATED' });
  map.set(token, value);
  return token;
}
function proven(map, token) {
  check(map.has(token), 'SIGNATURE_PROOF_REQUIRED');
  return map.get(token);
}
function verify(kind, envelope, publicKey) {
  check(sodium.crypto_sign_verify_detached(un64(envelope.signature), signing(kind, wire(envelope.body)), un64(publicKey)), 'SIGNATURE_INVALID');
}
function sign(kind, body, secretKey) {
  check(secretKey instanceof Uint8Array && secretKey.length === 64, 'INVALID_KEY_LENGTH');
  const normalized = decode(kind, wire(body));
  return { body: normalized, signature: b64(sodium.crypto_sign_detached(signing(kind, wire(normalized)), secretKey)) };
}

export function derivationParameters(contextBytes, purpose) {
  check(['root-signing-seed', 'recovery-encryption-seed'].includes(purpose), 'UNSUPPORTED_PURPOSE');
  const context = encode('derivation-context', contextBytes);
  return { salt: createHash('sha256').update(domain('hkdf', 'extract-salt')).update(context).digest(),
    info: Buffer.concat([domain('hkdf', purpose), context]) };
}
export const generateRecoverySecret = () => sodium.randombytes_buf(32);
export function deriveRoot(secret, contextBytes) {
  bytes32(secret);
  const seed = purpose => {
    const p = derivationParameters(contextBytes, purpose);
    return Buffer.from(hkdfSync('sha256', secret, p.salt, p.info, 32));
  };
  const signingSeed = seed('root-signing-seed'), encryptionSeed = seed('recovery-encryption-seed');
  try { return { signing: sodium.crypto_sign_seed_keypair(signingSeed), recovery: sodium.crypto_box_seed_keypair(encryptionSeed) }; }
  finally { sodium.memzero(signingSeed); sodium.memzero(encryptionSeed); }
}
export function createIdentity(secret, contextBytes) {
  const context = decode('derivation-context', contextBytes), keys = deriveRoot(secret, contextBytes);
  try {
    const body = { ...common('account-root-identity'), derivation: 'hkdf-sha256-c1',
      service_id: context.service_id, account_id: context.account_id,
      root_signing_key: b64(keys.signing.publicKey), recovery_encryption_key: b64(keys.recovery.publicKey) };
    return encode('identity', wire(sign('identity-body', body, keys.signing.privateKey)));
  } finally { sodium.memzero(keys.signing.privateKey); sodium.memzero(keys.recovery.privateKey); }
}
export function rootFingerprint(identityBytes) {
  const identity = decode('identity', identityBytes);
  return digest('identity-body', wire(identity.body));
}
export function verifyRootIdentity(identityBytes, pinBytes) {
  const identity = decode('identity', identityBytes), pin = decode('identity-pin', pinBytes);
  check(identity.body.service_id === pin.service_id && identity.body.account_id === pin.account_id &&
    rootFingerprint(identityBytes) === pin.root_fingerprint, 'ROOT_PIN_MISMATCH');
  verify('identity-body', identity, identity.body.root_signing_key);
  return proof(identities, { ...identity, fingerprint: pin.root_fingerprint });
}
export const identityDetails = token => structuredClone(proven(identities, token));

export function encodeRecoverySecret(secret) {
  bytes32(secret);
  return bech32m.encode('anr', bech32m.toWords(Buffer.concat([Buffer.from([1]), secret])), 90);
}
export function decodeRecoverySecret(encoded) {
  check(typeof encoded === 'string' && encoded.length === 63 && /^[a-z0-9]+$/.test(encoded), 'INVALID_RECOVERY_ENCODING');
  try {
    const value = bech32m.decode(encoded, 90), payload = bech32m.fromWords(value.words);
    check(value.prefix === 'anr' && payload.length === 33 && payload[0] === 1 &&
      bech32m.encode(value.prefix, bech32m.toWords(payload), 90) === encoded, 'INVALID_RECOVERY_ENCODING');
    return Buffer.from(payload.slice(1));
  } catch { throw new ContractError('INVALID_RECOVERY_ENCODING'); }
}
export function createRecoveryKit(secret, contextBytes) {
  const context = decode('derivation-context', contextBytes), identityBytes = createIdentity(secret, contextBytes);
  return encode('kit', wire({ ...common('account-recovery-kit'), service_id: context.service_id,
    account_id: context.account_id, root_fingerprint: rootFingerprint(identityBytes),
    recovery_secret: encodeRecoverySecret(secret), identity: decode('identity', identityBytes) }));
}
export function recoverRoot(kitBytes, pinBytes) {
  const kit = decode('kit', kitBytes), pin = decode('identity-pin', pinBytes);
  check(kit.service_id === pin.service_id && kit.account_id === pin.account_id && kit.root_fingerprint === pin.root_fingerprint, 'ROOT_PIN_MISMATCH');
  const identity = verifyRootIdentity(wire(kit.identity), pinBytes);
  const secret = decodeRecoverySecret(kit.recovery_secret);
  const context = wire({ ...common('account-root-derivation'), service_id: kit.service_id, account_id: kit.account_id });
  try {
    check(same(decode('identity', createIdentity(secret, context)), kit.identity), 'RECOVERY_IDENTITY_MISMATCH');
    return { identity, keys: deriveRoot(secret, context) };
  } finally { sodium.memzero(secret); }
}

export const generateDeviceKeys = () => ({ signing: sodium.crypto_sign_keypair(), encryption: sodium.crypto_box_keypair() });
export const signCertificate = (bodyBytes, issuerSecretKey) => encode('certificate', wire(sign('certificate-body', decode('certificate-body', bodyBytes), issuerSecretKey)));
export function verifyCertificateSignature(certificateBytes, identityProof, expectedBodyBytes, issuerProof) {
  const certificate = decode('certificate', certificateBytes), body = certificate.body;
  const identity = proven(identities, identityProof), expected = decode('certificate-body', expectedBodyBytes);
  check(same(body, expected), 'CERTIFICATE_CONTEXT_MISMATCH');
  check(body.service_id === identity.body.service_id && body.account_id === identity.body.account_id &&
    body.root_fingerprint === identity.fingerprint, 'CERTIFICATE_CONTEXT_MISMATCH');
  let signingKey = identity.body.root_signing_key;
  if (body.issuer.kind === 'device') {
    const issuer = proven(certificates, issuerProof);
    check(issuer.digest === body.issuer.certificate_digest && issuer.body.device_id === body.issuer.device_id &&
      issuer.body.service_id === body.service_id && issuer.body.account_id === body.account_id &&
      issuer.body.root_fingerprint === body.root_fingerprint && issuer.body.recovery_generation === body.recovery_generation &&
      issuer.body.capabilities.includes('delegate-device'), 'ISSUER_CONTEXT_MISMATCH');
    signingKey = issuer.body.device_signing_key;
  }
  verify('certificate-body', certificate, signingKey);
  return proof(certificates, { ...certificate, digest: digest('certificate', certificateBytes) });
}
export const certificateDetails = token => structuredClone(proven(certificates, token));
export function encryptionKeyFingerprint(publicKey) {
  bytes32(publicKey);
  return createHash('sha256').update(domain('hash', 'x25519-public-key')).update(publicKey).digest('base64url');
}
export function senderForCertificate(token, rosterHead) {
  const cert = proven(certificates, token), body = cert.body;
  return decode('sender', wire({ account_id: body.account_id, device_id: body.device_id,
    root_fingerprint: body.root_fingerprint, recovery_generation: body.recovery_generation,
    roster_head: rosterHead, certificate_digest: cert.digest }));
}
export function recipientForDevice(token, rosterHead) {
  const cert = proven(certificates, token), body = cert.body;
  check(body.capabilities.includes('receive-group-key'), 'CAPABILITY_MISMATCH');
  return decode('recipient', wire({ kind: 'device', ...senderForCertificate(token, rosterHead),
    encryption_key_fingerprint: encryptionKeyFingerprint(un64(body.device_encryption_key)) }));
}
export function recipientForRecovery(token, generation, rosterHead) {
  const identity = proven(identities, token);
  return decode('recipient', wire({ kind: 'account-recovery', account_id: identity.body.account_id,
    root_fingerprint: identity.fingerprint, recovery_generation: generation, roster_head: rosterHead,
    encryption_key_fingerprint: encryptionKeyFingerprint(un64(identity.body.recovery_encryption_key)) }));
}
function checkSender(context, token) {
  const cert = proven(certificates, token), body = cert.body;
  check(context.service_id === body.service_id && same(context.issuer, senderForCertificate(token, context.issuer.roster_head)) &&
    body.capabilities.includes('distribute-group-key'), 'ISSUER_CONTEXT_MISMATCH');
  return cert;
}
export function sealGroupKeyForEvaluation(contextBytes, groupKey, recipientPublicKey, issuerSecretKey, issuerProof) {
  const context = decode('grant-context', contextBytes);
  bytes32(groupKey); bytes32(recipientPublicKey);
  checkSender(context, issuerProof);
  check(encryptionKeyFingerprint(recipientPublicKey) === context.recipient.encryption_key_fingerprint, 'RECIPIENT_KEY_MISMATCH');
  const plaintext = encode('grant-plaintext', wire({ purpose: 'group-key-plaintext', context, group_key: b64(groupKey) }));
  try {
    const sealed = sodium.crypto_box_seal(plaintext, recipientPublicKey);
    const result = encode('grant', wire(sign('grant-body', { context, sealed_ciphertext: b64(sealed) }, issuerSecretKey)));
    verifyDistributionSignature(result, contextBytes, issuerProof);
    return result;
  } finally { sodium.memzero(plaintext); }
}
export function verifyDistributionSignature(recordBytes, expectedContextBytes, issuerProof) {
  const record = decode('grant', recordBytes), expected = decode('grant-context', expectedContextBytes);
  check(same(record.body.context, expected), 'GRANT_CONTEXT_MISMATCH');
  const issuer = checkSender(expected, issuerProof);
  verify('grant-body', record, issuer.body.device_signing_key);
  return { record, signature_valid: true, authorization: 'NOT_EVALUATED' };
}
export function openGroupKeyForEvaluation(recordBytes, expectedContextBytes, issuerProof, publicKey, secretKey) {
  const { record } = verifyDistributionSignature(recordBytes, expectedContextBytes, issuerProof);
  bytes32(publicKey); bytes32(secretKey);
  check(encryptionKeyFingerprint(publicKey) === record.body.context.recipient.encryption_key_fingerprint &&
    b64(sodium.crypto_scalarmult_base(secretKey)) === b64(publicKey), 'RECIPIENT_KEY_MISMATCH');
  let plaintext;
  try { plaintext = sodium.crypto_box_seal_open(un64(record.body.sealed_ciphertext), publicKey, secretKey); }
  catch { throw new ContractError('SEALED_INTEGRITY_FAILURE'); }
  try {
    const inner = decode('grant-plaintext', plaintext);
    check(same(inner.context, record.body.context), 'INNER_CONTEXT_MISMATCH');
    return un64(inner.group_key);
  } finally { sodium.memzero(plaintext); }
}
// Expected contexts must come from already verified local policy/current rosters.
// This checks exact coverage/signatures only; it cannot authenticate those heads.
export function checkDistributionCoverage(recordInputs, expectedContexts, issuerProof) {
  check(Array.isArray(recordInputs) && Array.isArray(expectedContexts) && expectedContexts.length > 0 &&
    expectedContexts.length <= 60 && recordInputs.length === expectedContexts.length, 'RECIPIENT_COVERAGE_MISMATCH');
  const contexts = expectedContexts.map(bytes => decode('grant-context', bytes));
  const base = ({ recipient, ...rest }) => rest;
  check(contexts.every(context => same(base(context), base(contexts[0]))), 'RECIPIENT_COVERAGE_MISMATCH');
  const recipientId = recipient => `${recipient.kind}/${recipient.account_id}/${recipient.kind === 'device' ? recipient.device_id : ''}`;
  check(new Set(contexts.map(context => recipientId(context.recipient))).size === contexts.length, 'RECIPIENT_COVERAGE_MISMATCH');
  const expected = new Map(expectedContexts.map(bytes => [digest('grant-context', bytes), bytes]));
  check(expected.size === expectedContexts.length, 'RECIPIENT_COVERAGE_MISMATCH');
  for (const bytes of recordInputs) {
    const record = decode('grant', bytes), key = digest('grant-context', wire(record.body.context));
    check(expected.has(key), 'RECIPIENT_COVERAGE_MISMATCH');
    verifyDistributionSignature(bytes, expected.get(key), issuerProof);
    expected.delete(key);
  }
  check(expected.size === 0, 'RECIPIENT_COVERAGE_MISMATCH');
  return { signature_valid: true, exact_coverage: true, authorization: 'NOT_EVALUATED' };
}
