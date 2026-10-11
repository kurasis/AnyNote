import sodium from "libsodium-wrappers-sumo";
import { Buffer, createHash } from "./bytes.mjs";
import {
  requireCondition as check,
  ContractError,
} from "../src/strict-json.mjs";
await sodium.ready;
export { sodium, Buffer };
export const b64 = (b) => Buffer.from(b).toString("base64url");
export const un64 = (s) => Buffer.from(s, "base64url");
export const hash = (b) => createHash("sha256").update(b).digest("base64url");
export function key(b, n = 32) {
  check(b instanceof Uint8Array && b.length === n, "INVALID_KEY_LENGTH");
}
export async function hkdf(secret, salt, info) {
  key(secret);
  check(
    salt instanceof Uint8Array && info instanceof Uint8Array,
    "RAW_BYTES_REQUIRED",
  );
  const k = await crypto.subtle.importKey("raw", secret, "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info },
      k,
      256,
    ),
  );
}
export function encrypt(p, a, n, k) {
  key(n, 24);
  key(k);
  check(
    p instanceof Uint8Array &&
      p.length <= 8388608 &&
      a instanceof Uint8Array &&
      a.length <= 1048576,
    "RESOURCE_LIMIT",
  );
  return Buffer.from(
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(p, a, null, n, k),
  );
}
export function decrypt(p, a, n, k) {
  key(n, 24);
  key(k);
  check(
    p instanceof Uint8Array &&
      p.length >= 16 &&
      p.length <= 8388624 &&
      a instanceof Uint8Array &&
      a.length <= 1048576,
    "RESOURCE_LIMIT",
  );
  try {
    return Buffer.from(
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, p, a, n, k),
    );
  } catch {
    throw new ContractError("INTEGRITY_FAILURE");
  }
}
export const randomKey = () => sodium.randombytes_buf(32);
export const deviceKeys = () => ({
  signing: sodium.crypto_sign_keypair(),
  encryption: sodium.crypto_box_keypair(),
});
