import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hkdfSync } from 'node:crypto';
import sodium from 'libsodium-wrappers-sumo';
import { wire, encodeIdentity, decodeIdentity, identityDigest, identitySigningInput } from './src/identity-codec.mjs';
import { deriveRoot, derivationParameters, createIdentity, rootFingerprint, createRecoveryKit, verifyRootIdentity,
  signCertificate, verifyCertificateSignature, recipientForDevice, recipientForRecovery, senderForCertificate,
  sealGroupKeyForEvaluation, openGroupKeyForEvaluation, recoverRoot, checkDistributionCoverage } from './src/identity-crypto.mjs';
import { sample } from './fixtures.mjs';
import { sha256 } from './src/codec.mjs';
import { prepareEvaluationFile, decryptEvaluationFile } from './evaluation-file.mjs';
await sodium.ready;
export const fixturePath = new URL('../../fixtures/protocol/p02/identity-vectors.json', import.meta.url);
export const publicSeed = start => Uint8Array.from({ length: 32 }, (_, i) => (start + i) % 256);
export const common = purpose => ({ purpose, contract: 'p02-identity-c1', protocol: 'anynote', protocol_version: 1 });
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const id = start => b64(publicSeed(start).slice(0, 16));
export function syntheticInputs() {
  return { status: 'PUBLIC_TEST_KEYS_NEVER_USE_FOR_CONTENT', root_secret_hex: Buffer.from(publicSeed(0)).toString('hex'),
    device_signing_seed_hex: Buffer.from(publicSeed(32)).toString('hex'), device_encryption_seed_hex: Buffer.from(publicSeed(64)).toString('hex'),
    receiver_signing_seed_hex: Buffer.from(publicSeed(96)).toString('hex'), receiver_encryption_seed_hex: Buffer.from(publicSeed(128)).toString('hex'),
    context: { ...common('account-root-derivation'), service_id: id(0), account_id: id(16) } };
}
export function deriveFixture(input = syntheticInputs()) {
  const rootSecret = Buffer.from(input.root_secret_hex, 'hex'), contextBytes = wire(input.context);
  const root = deriveRoot(rootSecret, contextBytes), identity = decodeIdentity('identity', createIdentity(rootSecret, contextBytes));
  const pin = { service_id: input.context.service_id, account_id: input.context.account_id, root_fingerprint: rootFingerprint(wire(identity)) };
  const identityProof = verifyRootIdentity(wire(identity), wire(pin));
  const devices = [['device', 160], ['receiver', 176]].map(([name, deviceStart]) => {
    const signing = sodium.crypto_sign_seed_keypair(Buffer.from(input[`${name}_signing_seed_hex`], 'hex'));
    const encryption = sodium.crypto_box_seed_keypair(Buffer.from(input[`${name}_encryption_seed_hex`], 'hex'));
    const body = { ...common('provisional-device-certificate'), service_id: pin.service_id, account_id: pin.account_id,
      root_fingerprint: pin.root_fingerprint, recovery_generation: '0', predecessor_roster: null,
      issuer: { kind: 'root', root_fingerprint: pin.root_fingerprint }, device_id: id(deviceStart), device_signing_key: b64(signing.publicKey),
      device_encryption_key: b64(encryption.publicKey), capabilities: ['delegate-device', 'distribute-group-key', 'receive-group-key', 'sign-content'],
      pairing_transcript_digest: sha256(Buffer.from(`PUBLIC ${name} transcript placeholder, pairing not evaluated`)) };
    const certificate = decodeIdentity('certificate', signCertificate(wire(body), root.signing.privateKey));
    const certificateProof = verifyCertificateSignature(wire(certificate), identityProof, wire(body));
    return { signing, encryption, certificate, certificateProof };
  });
  const roster = { version: '1', digest: sha256(Buffer.from('PUBLIC externally assumed roster head; chain not evaluated')) };
  const base = { ...common('group-key-distribution'), service_id: pin.service_id, group_id: id(192), key_epoch: '1',
    epoch_digest: sha256(Buffer.from('PUBLIC externally assumed epoch')), membership_head: { version: '0', digest: sha256(Buffer.from('PUBLIC externally assumed policy')) },
    operation_id: id(208), issuer: senderForCertificate(devices[0].certificateProof, roster) };
  const contexts = [recipientForDevice(devices[1].certificateProof, roster), recipientForRecovery(identityProof, '0', roster)].map(recipient => ({ ...base, recipient }));
  const fileContext = sample(1).context;
  Object.assign(fileContext, { service_id: pin.service_id, group_id: base.group_id,
    author: { account_id: pin.account_id, device_id: devices[0].certificate.body.device_id, root_fingerprint: pin.root_fingerprint, recovery_generation: '0', roster },
    policy: { membership: base.membership_head, key_epoch: base.key_epoch, epoch_digest: base.epoch_digest, history_checkpoint_digest: null } });
  const plaintext = Buffer.from('PUBLIC TEST ONLY — fresh device and offline recovery, no uploader key cache.\n');
  const fileKeys = { groupKey: publicSeed(144), manifestKey: publicSeed(176), fileKey: publicSeed(208),
    wrapNonce: publicSeed(24).slice(0, 24), manifestNonce: publicSeed(48).slice(0, 24), noncePrefix: publicSeed(80).slice(0, 16) };
  const kit = decodeIdentity('kit', createRecoveryKit(rootSecret, contextBytes));
  const outputs = { identity, pin, kit,
    hkdf: ['root-signing-seed', 'recovery-encryption-seed'].map(purpose => {
      const p = derivationParameters(contextBytes, purpose);
      return { purpose, salt_hex: p.salt.toString('hex'), info_hex: p.info.toString('hex'), seed_hex: Buffer.from(hkdfSync('sha256', rootSecret, p.salt, p.info, 32)).toString('hex') };
    }), identity_signing_input_hex: identitySigningInput('identity-body', wire(identity.body)).toString('hex'),
    identity_canonical_hex: encodeIdentity('identity', wire(identity)).toString('hex'),
    certificates: devices.map(d => ({ record: d.certificate, digest: identityDigest('certificate', wire(d.certificate)),
      signing_input_hex: identitySigningInput('certificate-body', wire(d.certificate.body)).toString('hex') })),
    grant_contexts: contexts, file_context: fileContext, file: prepareEvaluationFile(wire(fileContext), plaintext, fileKeys, devices[0].signing.privateKey),
    plaintext_hex: plaintext.toString('hex'), plaintext_sha256: sha256(plaintext) };
  return { root, devices, identityProof, fileKeys, outputs };
}
export function checkCryptoVectors(fixture) {
  const derived = deriveFixture(fixture.input);
  if (JSON.stringify(derived.outputs) !== JSON.stringify(fixture.outputs)) throw new Error('CRYPTO_FIXTURE_DRIFT');
  const o = derived.outputs;
  checkDistributionCoverage(fixture.sealed_inputs.map(wire), o.grant_contexts.map(wire), derived.devices[0].certificateProof);
  // Sealed boxes use libsodium's real random ephemeral key. Freeze them as INPUT,
  // verify decryption, never seed/override the global RNG to manufacture KATs.
  const recovered = recoverRoot(wire(o.kit), wire(o.pin));
  const recipients = [derived.devices[1].encryption, recovered.keys.recovery];
  fixture.sealed_inputs.forEach((record, index) => {
    const groupKey = openGroupKeyForEvaluation(wire(record), wire(o.grant_contexts[index]), derived.devices[0].certificateProof, recipients[index].publicKey, recipients[index].privateKey);
    const plaintext = decryptEvaluationFile(o.file, groupKey, derived.devices[0].certificateProof, wire(o.file_context));
    if (plaintext.toString('hex') !== o.plaintext_hex) throw new Error('FRESH_RECIPIENT_MISMATCH');
    sodium.memzero(groupKey); sodium.memzero(plaintext);
  });
  [derived.root.signing, derived.root.recovery, ...derived.devices.flatMap(d => [d.signing, d.encryption]), recovered.keys.signing, recovered.keys.recovery].forEach(k => sodium.memzero(k.privateKey));
  return { status: 'PASS', authorization: 'NOT_EVALUATED', fresh_recipient_paths: ['device', 'account-recovery'], plaintext_bytes: o.plaintext_hex.length / 2 };
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.includes('--write')) {
    const input = syntheticInputs(), derived = deriveFixture(input);
    const keys = [derived.devices[1].encryption.publicKey, derived.root.recovery.publicKey];
    const fixture = { status: 'PUBLIC_SYNTHETIC_CRYPTO_CANDIDATE_AUTHORIZATION_NOT_EVALUATED', contract: 'p02-identity-c1', input, outputs: derived.outputs,
      sealed_inputs: derived.outputs.grant_contexts.map((context, i) => decodeIdentity('grant', sealGroupKeyForEvaluation(wire(context), derived.fileKeys.groupKey,
        keys[i], derived.devices[0].signing.privateKey, derived.devices[0].certificateProof))) };
    checkCryptoVectors(fixture);
    writeFileSync(fixturePath, JSON.stringify(fixture, null, 2) + '\n');
    console.log('Wrote PUBLIC TEST crypto vectors; random sealed boxes frozen as input; review before commit');
  } else console.log(JSON.stringify(checkCryptoVectors(JSON.parse(readFileSync(fixturePath)))));
}
