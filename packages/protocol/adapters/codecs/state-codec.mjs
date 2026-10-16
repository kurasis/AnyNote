// Portable P05 codec; frozen predicates preserved by scripts/p05-port-codecs.py.
import { Buffer, createHash, readFileSync } from '../bytes.mjs';
import Ajv2020 from '../schema-validation.mjs';
import { strictJson, requireCondition as check } from '../../src/strict-json.mjs';
import { canonicalBytes } from './codec.mjs';
import { wire } from './identity-codec.mjs';
const schemas = ['p02-identity-c1', 'p02-state-c1'].map(name => strictJson(readFileSync(new URL(`../../contracts/${name}.schema.json`, import.meta.url))));
const schema = schemas[1], ajv = new Ajv2020({ strict: true, ownProperties: true });
for (const size of [16, 24, 32, 64]) ajv.addFormat(`base64url-${size}`, s => s.length === Math.ceil(size * 8 / 6) && /^[A-Za-z0-9_-]+$/.test(s) && Buffer.from(s, 'base64url').length === size && Buffer.from(s, 'base64url').toString('base64url') === s);
ajv.addFormat('decimal-u63', s => s.length <= 19 && /^(0|[1-9][0-9]*)$/.test(s) && BigInt(s) <= 9223372036854775807n);
for (const limit of [4096, 16384]) ajv.addFormat(`bounded-binary-${limit}`, s => s.length >= (limit === 4096 ? 64 : 24) && s.length <= Math.ceil(limit * 8 / 6) && /^[A-Za-z0-9_-]+$/.test(s) && Buffer.from(s, 'base64url').length <= limit && Buffer.from(s, 'base64url').toString('base64url') === s);
ajv.addFormat('base64url-sealed', s => s.length >= 64 && s.length <= 5462 && /^[A-Za-z0-9_-]+$/.test(s) && Buffer.from(s, 'base64url').toString('base64url') === s);
for (const s of schemas) ajv.addSchema(s);
const validators = new Map(Object.keys(schema.$defs).map(kind => [kind, ajv.compile({ $ref: `${schema.$id}#/$defs/${kind}` })]));
export function stateDecode(kind, bytes) {
  check(validators.has(kind), 'UNSUPPORTED_SCHEMA');
  const value = strictJson(bytes, kind === 'qr' ? 8192 : 65536);
  check(validators.get(kind)(value), 'SCHEMA_MISMATCH');
  const ordered = values => { for (let i = 1; i < values.length; i++) check(values[i - 1] < values[i], 'UNORDERED_OR_DUPLICATE'); };
  if (kind === 'device') { ordered(value.capabilities); check(value.signing_key !== value.encryption_key, 'KEY_PURPOSE_COLLISION'); }
  if (kind === 'revoke-payload') { ordered(value.targets); ordered(value.affected_devices); }
  return value;
}
export const stateEncode = (kind, bytes) => canonicalBytes(wire(stateDecode(kind, bytes)));
export const stateDomain = (family, purpose) => Buffer.from(`AnyNote/p02-state-c1/${family}/${purpose}\0`);
export function stateSigningInput(kind, bytes) {
  check(['invitation-body','offer-body','response-body','approval-body','confirmation-body','possession-body','event-body'].includes(kind), 'UNSUPPORTED_PURPOSE');
  const value = stateDecode(kind, bytes);
  return Buffer.concat([stateDomain('sign', value.purpose), stateEncode(kind, bytes)]);
}
export function stateDigest(kind, bytes) {
  check(['invitation','offer','response','transcript','approval','confirmation','challenge','challenge-plaintext','pairing-proof-plaintext','event'].includes(kind), 'UNSUPPORTED_PURPOSE');
  return createHash('sha256').update(stateDomain('hash', kind)).update(stateEncode(kind, bytes)).digest('base64url');
}
export const stateCommon = purpose => ({ purpose, contract: 'p02-state-c1', protocol: 'anynote', protocol_version: 1 });
