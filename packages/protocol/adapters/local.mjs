import { sodium, Buffer, b64, un64, key, hkdf } from "./primitives.mjs";
import { decode, aad } from "./codecs/protocol-codec.mjs";
import { wire, same } from "./codecs/identity-codec.mjs";
import canonicalize from "canonicalize";
import {
  strictJson,
  requireCondition as check,
  ContractError,
} from "../src/strict-json.mjs";
export {
  phraseKek,
  prfKek,
  wrapLocalKey,
  unwrapLocalKey,
  sealLocal,
  openLocal,
} from "./objects.mjs";
export async function nativeKek(descriptorBytes, prfResult) {
  key(prfResult);
  const d = strictJson(descriptorBytes, 65536);
  check(
    !Object.hasOwn(d, "nonce") && !Object.hasOwn(d, "ciphertext"),
    "INVALID_DESCRIPTOR",
  );
  decode(
    "native-wrapper",
    wire({
      ...d,
      nonce: b64(new Uint8Array(12)),
      ciphertext: b64(new Uint8Array(48)),
    }),
  );
  return hkdf(
    prfResult,
    un64(d.prf_salt),
    Buffer.concat([
      Buffer.from("AnyNote/p02-v1/hkdf/windows-prf-kek\0"),
      Buffer.from(canonicalize(d)),
    ]),
  );
}
export async function wrapNative(descriptorBytes, localKey, prfResult) {
  key(localKey);
  const d = strictJson(descriptorBytes, 65536),
    kek = await nativeKek(descriptorBytes, prfResult),
    nonce = sodium.randombytes_buf(12);
  try {
    const k = await crypto.subtle.importKey("raw", kek, "AES-GCM", false, [
      "encrypt",
    ]);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: aad("local-unlock", d),
          tagLength: 128,
        },
        k,
        localKey,
      ),
    );
    return wire(
      decode(
        "native-wrapper",
        wire({ ...d, nonce: b64(nonce), ciphertext: b64(ciphertext) }),
      ),
    );
  } finally {
    sodium.memzero(kek);
  }
}
export async function unwrapNative(wrapperBytes, expectedBytes, prfResult) {
  const w = decode("native-wrapper", wrapperBytes),
    { nonce, ciphertext, ...d } = w;
  check(same(d, strictJson(expectedBytes, 65536)), "LOCAL_CONTEXT_MISMATCH");
  const kek = await nativeKek(expectedBytes, prfResult);
  try {
    const k = await crypto.subtle.importKey("raw", kek, "AES-GCM", false, [
      "decrypt",
    ]);
    const out = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: un64(nonce),
          additionalData: aad("local-unlock", d),
          tagLength: 128,
        },
        k,
        un64(ciphertext),
      ),
    );
    key(out);
    return out;
  } catch {
    throw new ContractError("INTEGRITY_FAILURE");
  } finally {
    sodium.memzero(kek);
  }
}
