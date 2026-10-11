// Portable P05 codec; frozen predicates preserved by scripts/p05-port-codecs.py.
import { Buffer, createHash, readFileSync } from '../bytes.mjs';
import Ajv2020 from 'ajv/dist/2020.js';
import { strictJson, requireCondition as check } from '../../src/strict-json.mjs';
import { canonicalBytes } from './codec.mjs';

const schema = strictJson(readFileSync(new URL('../../contracts/p02-identity-c1.schema.json', import.meta.url)));
const ajv = new Ajv2020({ strict: true, ownProperties: true });
for (const size of [16, 32, 64]) {
  ajv.addFormat(`base64url-${size}`, value => value.length === Math.ceil(size * 8 / 6) &&
    /^[A-Za-z0-9_-]+$/.test(value) && Buffer.from(value, 'base64url').length === size &&
    Buffer.from(value, 'base64url').toString('base64url') === value);
}
ajv.addFormat('decimal-u63', value => value.length <= 19 && /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) <= 9223372036854775807n);
ajv.addFormat('base64url-sealed', value => value.length >= 64 && value.length <= 5462 &&
  /^[A-Za-z0-9_-]+$/.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value &&
  Buffer.from(value, 'base64url').length <= 4096);
ajv.addSchema(schema);
const validators = new Map(Object.keys(schema.$defs).map(kind => [kind, ajv.compile({ $ref: `${schema.$id}#/$defs/${kind}` })]));
export const wire = value => Buffer.from(JSON.stringify(value)); // internal clean plain data only
export function decodeIdentity(kind, bytes) {
  check(validators.has(kind), 'UNSUPPORTED_SCHEMA');
  const value = strictJson(bytes, 16_384);
  check(validators.get(kind)(value), 'SCHEMA_MISMATCH');
  const body = kind === 'certificate' ? value.body : kind === 'certificate-body' ? value : null;
  if (body) {
    for (let i = 1; i < body.capabilities.length; i++) check(body.capabilities[i - 1] < body.capabilities[i], 'UNORDERED_CAPABILITIES');
    check(body.device_signing_key !== body.device_encryption_key, 'KEY_PURPOSE_COLLISION');
    if (body.predecessor_roster === null) check(body.issuer.kind === 'root' && body.recovery_generation === '0', 'INVALID_BOOTSTRAP');
    if (body.issuer.kind === 'root') check(body.issuer.root_fingerprint === body.root_fingerprint, 'ISSUER_CONTEXT_MISMATCH');
    else check(body.issuer.device_id !== body.device_id, 'SELF_DELEGATION');
  }
  return value;
}
export const encodeIdentity = (kind, bytes) => canonicalBytes(wire(decodeIdentity(kind, bytes)));
export const domain = (family, purpose) => Buffer.from(`AnyNote/p02-identity-c1/${family}/${purpose}\0`);
export function identitySigningInput(kind, bytes) {
  check(['identity-body', 'certificate-body', 'grant-body'].includes(kind), 'UNSUPPORTED_PURPOSE');
  const purpose = { 'identity-body': 'account-root-identity', 'certificate-body': 'provisional-device-certificate', 'grant-body': 'group-key-distribution' }[kind];
  return Buffer.concat([domain('sign', purpose), encodeIdentity(kind, bytes)]);
}
export function identityDigest(kind, bytes) {
  const purpose = { 'identity-body': 'account-root-identity', certificate: 'device-certificate', grant: 'group-key-distribution', 'grant-context': 'grant-context' }[kind];
  check(purpose, 'UNSUPPORTED_PURPOSE');
  return createHash('sha256').update(domain('hash', purpose)).update(encodeIdentity(kind, bytes)).digest('base64url');
}
export const same = (a, b) => canonicalBytes(wire(a)).equals(canonicalBytes(wire(b)));
