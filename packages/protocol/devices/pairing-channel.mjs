// Established libsodium secretstream with a one-use random QR/OOB key.
// Camera/OOB user ceremony is simulated here, never a claimed physical result.
import {sodium,Buffer} from '../adapters/primitives.mjs';
import { ContractError, requireCondition as check } from '../src/strict-json.mjs';
import { wire, same } from '../adapters/codecs/identity-codec.mjs';
import { stateDecode, stateEncode, stateCommon, stateDomain } from '../adapters/codecs/state-codec.mjs';
await sodium.ready;
const channels = new WeakMap(), b64 = b => Buffer.from(b).toString('base64url');
const un64 = s => Buffer.from(s, 'base64url');
const messageKinds = { 'new-device-offer': 'offer', 'approver-response': 'response', 'approver-approval': 'approval', 'new-device-confirmation': 'confirmation' };
export const generatePairingKey = () => sodium.crypto_secretstream_xchacha20poly1305_keygen();
export function pairingQr(mode, recordBytes, key) {
  check(key instanceof Uint8Array && key.length === 32, 'INVALID_KEY_LENGTH');
  check(['new-device-offer','existing-device-invitation'].includes(mode), 'UNSUPPORTED_PURPOSE');
  return stateEncode('qr', wire({ ...stateCommon('pairing-qr'), mode, channel_key: b64(key), record: stateDecode(mode === 'new-device-offer' ? 'offer' : 'invitation', recordBytes) }));
}
export function scannedChannelForEvaluation(qrBytes, role) {
  const qr = stateDecode('qr', qrBytes);
  check(role === 'new-device' || role === 'approver', 'INVALID_CHANNEL_ROLE');
  const token = Object.freeze({ oob: 'DECODED_QR', channel: 'LIBSODIUM_SECRETSTREAM' });
  channels.set(token, { key: un64(qr.channel_key), role, sent: new Set(), received: new Set(), closed: false });
  return token;
}
function channel(token) { check(channels.has(token), 'CHANNEL_REQUIRED'); const value = channels.get(token); check(!value.closed, 'CHANNEL_CLOSED'); return value; }
const fromNew = message => message.startsWith('new-device-');
const contextFor = (message, anchor) => stateDecode('channel-context', wire({ ...stateCommon('pairing-channel-frame'), message, anchor_digest: anchor }));
const aad = context => Buffer.concat([stateDomain('aad', 'pairing-channel-frame'), stateEncode('channel-context', wire(context))]);
export function sealPairingFrame(token, message, payloadBytes, anchor) {
  const value = channel(token); check((value.role === 'new-device') === fromNew(message), 'CHANNEL_REFLECTION');
  check(!value.sent.has(message), 'CHANNEL_REPLAY');
  const context = contextFor(message, anchor), bytes = stateEncode(messageKinds[message], payloadBytes);
  check(bytes.length <= 16367, 'RESOURCE_LIMIT');
  const stream = sodium.crypto_secretstream_xchacha20poly1305_init_push(value.key);
  const ciphertext = sodium.crypto_secretstream_xchacha20poly1305_push(stream.state, bytes, aad(context), sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL);
  value.sent.add(message);
  return stateEncode('frame', wire({ context, header: b64(stream.header), ciphertext: b64(ciphertext) }));
}
export function openPairingFrame(token, frameBytes, message, anchor) {
  const value = channel(token); check((value.role === 'new-device') !== fromNew(message), 'CHANNEL_REFLECTION');
  check(!value.received.has(message), 'CHANNEL_REPLAY');
  const frame = stateDecode('frame', frameBytes), expected = contextFor(message, anchor);
  check(same(frame.context, expected), 'CHANNEL_CONTEXT_MISMATCH');
  let result;
  try {
    const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(un64(frame.header), value.key);
    result = sodium.crypto_secretstream_xchacha20poly1305_pull(state, un64(frame.ciphertext), aad(expected));
    if (result && result.tag !== sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) sodium.memzero(result.message);
    check(result && result.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL, 'CHANNEL_INTEGRITY_FAILURE');
  } catch { throw new ContractError('CHANNEL_INTEGRITY_FAILURE'); }
  try {
    const payload = stateEncode(messageKinds[message], result.message);
    value.received.add(message);
    return payload;
  } finally { sodium.memzero(result.message); }
}
export function closePairingChannel(token) { const value = channel(token); sodium.memzero(value.key); value.closed = true; }
