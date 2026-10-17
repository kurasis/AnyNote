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
  let part, offset = 0;
  return new ReadableStream({
    async pull(controller) {
      try { await authorize();
        if (!part || offset === part.length) {
          part = undefined; offset = 0;
          const next = await items.next();
          if (next.done) { controller.close(); return; }
          if (!(next.value instanceof Uint8Array) || next.value.length > 8388624) throw Error('EXPORT_RESOURCE_LIMIT');
          part = next.value;
        }
        // age's synchronous transform emits one 64 KiB ciphertext per block.
        // Feed it one block per pull so a whole 8 MiB member cannot enqueue
        // 128 encrypted blocks before the destination acknowledges any of them.
        const end = Math.min(offset + 65536, part.length);
        controller.enqueue(part.subarray(offset, end)); offset = end;
      } catch (error) { await items.return?.(); controller.error(error); }
    },
    async cancel() { part = undefined; await items.return?.(); },
  }, {highWaterMark: 0});
}
