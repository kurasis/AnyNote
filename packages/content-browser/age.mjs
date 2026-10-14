import {Encrypter, Decrypter, generateX25519Identity, identityToRecipient} from 'age-encryption';

export async function independentExportIdentity() {
  const identity = await generateX25519Identity();
  return {identity, recipient: await identityToRecipient(identity)};
}
export async function encryptArchive(stream, recipient) {
  if (!(stream instanceof ReadableStream) || typeof recipient !== 'string' || !recipient.startsWith('age1')) throw Error('INVALID_EXPORT_RECIPIENT');
  const engine = new Encrypter(); engine.addRecipient(recipient);
  return engine.encrypt(stream);
}
export async function decryptArchive(stream, identity) {
  if (!(stream instanceof ReadableStream) || typeof identity !== 'string' || !identity.startsWith('AGE-SECRET-KEY-1')) throw Error('INVALID_EXPORT_IDENTITY');
  const engine = new Decrypter(); engine.addIdentity(identity);
  try { return await engine.decrypt(stream); }
  catch { throw Error('EXPORT_INTEGRITY_FAILURE'); }
}
export function streamFromIterator(iterator, authorize = () => {}) {
  const items = iterator[Symbol.asyncIterator]();
  return new ReadableStream({
    async pull(controller) {
      try { await authorize(); const next = await items.next();
        if (next.done) controller.close();
        else { if (!(next.value instanceof Uint8Array) || next.value.length > 8388624) throw Error('EXPORT_RESOURCE_LIMIT'); controller.enqueue(next.value); }
      } catch (error) { await items.return?.(); controller.error(error); }
    },
    async cancel() { await items.return?.(); },
  }, {highWaterMark: 0});
}
