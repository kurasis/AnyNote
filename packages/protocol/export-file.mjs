// Independent export DEK path: no G, uploader secret, server or original cache.
import sodium from "libsodium-wrappers-sumo";
import {
  requireCondition as check,
  ContractError,
} from "./src/strict-json.mjs";
import { wire } from "./src/identity-codec.mjs";
import { certificateDetails } from "./src/identity-crypto.mjs";
import {
  decode,
  checkFileBundle,
  checkManifestCiphertext,
  fileAad,
  chunkNonce,
  sha256,
  signingInput,
} from "./src/codec.mjs";
await sodium.ready;
export function decryptExportedFileForEvaluation(
  record,
  chunks,
  key,
  certificate,
) {
  const h = record.envelope.header,
    context = h.context,
    cert = certificateDetails(certificate),
    un64 = (s) => Buffer.from(s, "base64url");
  check(
    sodium.crypto_sign_verify_detached(
      un64(record.envelope.signature),
      signingInput("header", wire(h)),
      un64(cert.body.device_signing_key),
    ),
    "SIGNATURE_INVALID",
  );
  check(Number(h.framing.plaintext_bytes) <= 65536, "EVALUATION_SIZE_LIMIT");
  const ciphertext = un64(record.manifest_ciphertext);
  checkManifestCiphertext(wire(h), ciphertext);
  let plain;
  try {
    plain = Buffer.from(
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        fileAad(wire(h), "manifest-aad"),
        un64(h.manifest_nonce),
        un64(key.object_dek),
      ),
    );
  } catch {
    throw new ContractError("INTEGRITY_FAILURE");
  }
  try {
    const manifest = decode("manifest", plain);
    checkFileBundle(wire(h), wire(record.wrap), plain, wire(context));
    check(manifest.file_data_key === key.file_data_dek, "EXPORT_KEY_MISMATCH");
    check(
      chunks.length === Number(h.framing.chunk_count),
      "EXPORT_CHUNK_MISSING",
    );
    const out = [];
    for (let i = 0; i < chunks.length; i++) {
      const part = h.framing.parts[i],
        cipher = chunks[i];
      check(
        cipher.length === Number(part.ciphertext_bytes) &&
          sha256(cipher) === part.ciphertext_digest,
        "CHUNK_DIGEST_MISMATCH",
      );
      let b;
      try {
        b = Buffer.from(
          sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null,
            cipher,
            fileAad(wire(h), "chunk-aad", BigInt(i)),
            chunkNonce(un64(manifest.nonce_prefix), BigInt(i)),
            un64(key.file_data_dek),
          ),
        );
      } catch {
        throw new ContractError("INTEGRITY_FAILURE");
      }
      out.push(b);
    }
    const bytes = Buffer.concat(out);
    check(
      bytes.length === Number(h.framing.plaintext_bytes) &&
        sha256(bytes) === manifest.plaintext_digest,
      "PLAINTEXT_MISMATCH",
    );
    return { context, bytes, original_name: manifest.original_name };
  } finally {
    sodium.memzero(plain);
  }
}
