import { hkdfSync, createCipheriv, createDecipheriv } from "node:crypto";
import canonicalize from "canonicalize";
import sodium from "libsodium-wrappers-sumo";
import {
  ContractError,
  strictJson,
  requireCondition as check,
} from "./strict-json.mjs";
import { wire, same } from "./identity-codec.mjs";
import {
  decode,
  encode,
  common,
  aad,
  digest,
  rawDigest,
  signingInput,
} from "./protocol-codec.mjs";
await sodium.ready;
const b64 = (b) => Buffer.from(b).toString("base64url"),
  un64 = (b) => Buffer.from(b, "base64url");
function key(k, n = 32) {
  check(k instanceof Uint8Array && k.length === n, "INVALID_KEY_LENGTH");
}
const enc = (p, a, n, k) =>
  Buffer.from(
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(p, a, null, n, k),
  );
function dec(p, a, n, k) {
  try {
    return Buffer.from(
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, p, a, n, k),
    );
  } catch {
    throw new ContractError("INTEGRITY_FAILURE");
  }
}
export function encryptObjectForEvaluation(
  payloadBytes,
  groupKey,
  signingKey,
  inputs = null,
) {
  const p = decode("payload", payloadBytes),
    context = p.context;
  key(groupKey);
  key(signingKey, 64);
  const k = inputs ?? {
    objectKey: sodium.randombytes_buf(32),
    nonce: sodium.randombytes_buf(24),
    wrapNonce: sodium.randombytes_buf(24),
  };
  key(k.objectKey);
  key(k.nonce, 24);
  key(k.wrapNonce, 24);
  const wrap = {
    ...common("object-key-wrap"),
    context,
    nonce: b64(k.wrapNonce),
    ciphertext: b64(
      enc(
        k.objectKey,
        aad("object-key-wrap", { context }),
        k.wrapNonce,
        groupKey,
      ),
    ),
  };
  const ciphertext = enc(
    encode("payload", payloadBytes),
    aad("object-payload", { context }),
    k.nonce,
    k.objectKey,
  );
  const header = {
    ...common("object-revision"),
    context,
    nonce: b64(k.nonce),
    ciphertext_bytes: String(ciphertext.length),
    ciphertext_digest: rawDigest(ciphertext),
    key_wrap_digest: digest("wrap", wire(wrap)),
  };
  const envelope = {
    header,
    signature: b64(
      sodium.crypto_sign_detached(
        signingInput("header", wire(header)),
        signingKey,
      ),
    ),
  };
  return decode(
    "bundle",
    wire({ envelope, wrap, ciphertext: b64(ciphertext) }),
  );
}
export function verifyObjectForEvaluation(
  bundleBytes,
  publicKey,
  expectedContextBytes,
) {
  key(publicKey);
  const b = decode("bundle", bundleBytes),
    h = b.envelope.header,
    c = decode("context", expectedContextBytes);
  check(same(h.context, c), "CONTEXT_MISMATCH");
  check(
    sodium.crypto_sign_verify_detached(
      un64(b.envelope.signature),
      signingInput("header", wire(h)),
      publicKey,
    ),
    "SIGNATURE_INVALID",
  );
  const bytes = un64(b.ciphertext);
  check(
    bytes.length === Number(h.ciphertext_bytes) &&
      rawDigest(bytes) === h.ciphertext_digest,
    "CIPHERTEXT_MISMATCH",
  );
  check(
    digest("wrap", wire(b.wrap)) === h.key_wrap_digest,
    "KEY_WRAP_MISMATCH",
  );
  return b;
}
export function decryptObjectForEvaluation(
  bundleBytes,
  groupKey,
  publicKey,
  expectedContextBytes,
) {
  key(groupKey);
  const b = verifyObjectForEvaluation(
      bundleBytes,
      publicKey,
      expectedContextBytes,
    ),
    c = b.envelope.header.context;
  const dek = dec(
    un64(b.wrap.ciphertext),
    aad("object-key-wrap", { context: c }),
    un64(b.wrap.nonce),
    groupKey,
  );
  let plain;
  try {
    plain = dec(
      un64(b.ciphertext),
      aad("object-payload", { context: c }),
      un64(b.envelope.header.nonce),
      dek,
    );
    const p = decode("payload", plain);
    check(same(p.context, c), "CONTEXT_MISMATCH");
    return p;
  } finally {
    sodium.memzero(dek);
    if (plain) sodium.memzero(plain);
  }
}
export function encryptLocalForEvaluation(
  plaintextBytes,
  localKey,
  nonce = null,
) {
  key(localKey);
  const p = decode("local-plaintext", plaintextBytes),
    n = nonce ?? sodium.randombytes_buf(24);
  key(n, 24);
  return encode(
    "local-envelope",
    wire({
      context: p.context,
      nonce: b64(n),
      ciphertext: b64(
        enc(
          encode("local-plaintext", plaintextBytes),
          aad("local-record", p.context),
          n,
          localKey,
        ),
      ),
    }),
  );
}
export function decryptLocalForEvaluation(
  envelopeBytes,
  localKey,
  expectedContextBytes,
) {
  key(localKey);
  const e = decode("local-envelope", envelopeBytes),
    c = decode("local-context", expectedContextBytes);
  check(same(e.context, c), "LOCAL_CONTEXT_MISMATCH");
  const p = dec(
    un64(e.ciphertext),
    aad("local-record", c),
    un64(e.nonce),
    localKey,
  );
  try {
    const v = decode("local-plaintext", p);
    check(same(v.context, c), "LOCAL_CONTEXT_MISMATCH");
    return v;
  } finally {
    sodium.memzero(p);
  }
}
let kdfBusy = false;
export async function phraseKekForEvaluation(phrase, parametersBytes) {
  const p = decode("argon2-parameters", parametersBytes);
  check(
    typeof phrase === "string" &&
      phrase.isWellFormed() &&
      Buffer.byteLength(phrase) >= 24 &&
      Buffer.byteLength(phrase) <= 1024 &&
      phrase.trim().split(/\s+/u).length >= 5,
    "STRONG_PHRASE_REQUIRED",
  );
  check(!kdfBusy, "KDF_BUSY");
  kdfBusy = true;
  try {
    await Promise.resolve();
    return sodium.crypto_pwhash(
      32,
      phrase,
      un64(p.salt),
      p.opslimit,
      p.memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  } finally {
    kdfBusy = false;
  }
}
export function prfKekForEvaluation(
  contextBytes,
  credentialId,
  salt,
  prfResult,
) {
  const c = decode("unlock-context", contextBytes);
  check(c.method === "webauthn-prf", "WRAPPER_METHOD_MISMATCH");
  key(salt);
  key(prfResult);
  // Caller must obtain a verified credential PRF result through its platform adapter.
  check(
    typeof credentialId === "string" &&
      credentialId.length > 0 &&
      credentialId.length <= 1366 &&
      Buffer.from(credentialId, "base64url").toString("base64url") ===
        credentialId,
    "INVALID_CREDENTIAL_ID",
  );
  const info = Buffer.concat([
    Buffer.from("AnyNote/p02-v1/hkdf/local-prf-kek\0"),
    Buffer.from(canonicalize({ context: c, credential_id: credentialId })),
  ]);
  return new Uint8Array(hkdfSync("sha256", prfResult, salt, info, 32));
}
export function wrapLocalKeyForEvaluation(
  kind,
  descriptorBytes,
  localKey,
  kek,
  nonce = null,
) {
  check(["phrase-wrapper", "prf-wrapper"].includes(kind), "UNSUPPORTED_SCHEMA");
  key(localKey);
  key(kek);
  const descriptor = strictJson(descriptorBytes, 65536),
    n = nonce ?? sodium.randombytes_buf(24);
  key(n, 24);
  // Validate method/parameters before encrypting; zero placeholders are framing only.
  decode(
    kind,
    wire({ ...descriptor, nonce: b64(n), ciphertext: b64(new Uint8Array(48)) }),
  );
  return encode(
    kind,
    wire({
      ...descriptor,
      nonce: b64(n),
      ciphertext: b64(enc(localKey, aad("local-unlock", descriptor), n, kek)),
    }),
  );
}
export function unwrapLocalKeyForEvaluation(
  kind,
  wrapperBytes,
  expectedDescriptorBytes,
  kek,
) {
  check(["phrase-wrapper", "prf-wrapper"].includes(kind), "UNSUPPORTED_SCHEMA");
  key(kek);
  const w = decode(kind, wrapperBytes),
    { nonce, ciphertext, ...descriptor } = w;
  check(
    same(descriptor, strictJson(expectedDescriptorBytes, 65536)),
    "LOCAL_CONTEXT_MISMATCH",
  );
  return dec(
    un64(ciphertext),
    aad("local-unlock", descriptor),
    un64(nonce),
    kek,
  );
}
export function decryptExportedObjectForEvaluation(
  bundleBytes,
  objectKey,
  publicKey,
  expectedContextBytes,
) {
  key(objectKey);
  const b = verifyObjectForEvaluation(
      bundleBytes,
      publicKey,
      expectedContextBytes,
    ),
    c = b.envelope.header.context;
  const plain = dec(
    un64(b.ciphertext),
    aad("object-payload", { context: c }),
    un64(b.envelope.header.nonce),
    objectKey,
  );
  try {
    const p = decode("payload", plain);
    check(same(p.context, c), "CONTEXT_MISMATCH");
    return p;
  } finally {
    sodium.memzero(plain);
  }
}
// Byte reference only. prfResult is not an attestation of Hello/TPM eligibility.
export function nativeKekForEvaluation(descriptorBytes, prfResult) {
  const d = strictJson(descriptorBytes, 65536);
  key(prfResult);
  decode(
    "native-wrapper",
    wire({
      ...d,
      nonce: b64(Buffer.alloc(12)),
      ciphertext: b64(Buffer.alloc(48)),
    }),
  );
  const info = Buffer.concat([
    Buffer.from("AnyNote/p02-v1/hkdf/windows-prf-kek\0"),
    Buffer.from(canonicalize(d)),
  ]);
  return new Uint8Array(
    hkdfSync("sha256", prfResult, un64(d.prf_salt), info, 32),
  );
}
export function wrapNativeForEvaluation(
  descriptorBytes,
  localKey,
  prfResult,
  nonce,
) {
  key(localKey);
  key(nonce, 12);
  const descriptor = strictJson(descriptorBytes, 65536),
    kek = nativeKekForEvaluation(descriptorBytes, prfResult);
  const cipher = createCipheriv("aes-256-gcm", kek, nonce);
  cipher.setAAD(aad("local-unlock", descriptor));
  const bytes = Buffer.concat([
    cipher.update(localKey),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  sodium.memzero(kek);
  return encode(
    "native-wrapper",
    wire({ ...descriptor, nonce: b64(nonce), ciphertext: b64(bytes) }),
  );
}
export function unwrapNativeForEvaluation(
  wrapperBytes,
  expectedDescriptorBytes,
  prfResult,
) {
  const w = decode("native-wrapper", wrapperBytes),
    { nonce, ciphertext, ...d } = w;
  check(
    same(d, strictJson(expectedDescriptorBytes, 65536)),
    "LOCAL_CONTEXT_MISMATCH",
  );
  const kek = nativeKekForEvaluation(expectedDescriptorBytes, prfResult),
    bytes = un64(ciphertext);
  try {
    const cipher = createDecipheriv("aes-256-gcm", kek, un64(nonce));
    cipher.setAAD(aad("local-unlock", d));
    cipher.setAuthTag(bytes.subarray(-16));
    return Buffer.concat([
      cipher.update(bytes.subarray(0, -16)),
      cipher.final(),
    ]);
  } catch {
    throw new ContractError("INTEGRITY_FAILURE");
  } finally {
    sodium.memzero(kek);
  }
}
