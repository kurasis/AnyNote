import { bech32m } from "@scure/base";
import {
  sodium,
  Buffer,
  b64,
  un64,
  key,
  hkdf,
  hash,
  deviceKeys,
  randomKey,
} from "./primitives.mjs";
import {
  decodeIdentity as decode,
  encodeIdentity as encode,
  domain,
  identityDigest,
  identitySigningInput,
  wire,
  same,
} from "./codecs/identity-codec.mjs";
import {
  requireCondition as check,
  ContractError,
} from "../src/strict-json.mjs";
export { deviceKeys, randomKey };
const common = (purpose) => ({
  purpose,
  contract: "p02-identity-c1",
  protocol: "anynote",
  protocol_version: 1,
});
export async function deriveRoot(secret, contextBytes) {
  key(secret);
  const context = encode("derivation-context", contextBytes);
  const salt = un64(
    hash(Buffer.concat([domain("hkdf", "extract-salt"), context])),
  );
  const s = await hkdf(
    secret,
    salt,
    Buffer.concat([domain("hkdf", "root-signing-seed"), context]),
  );
  const e = await hkdf(
    secret,
    salt,
    Buffer.concat([domain("hkdf", "recovery-encryption-seed"), context]),
  );
  try {
    return {
      signing: sodium.crypto_sign_seed_keypair(s),
      recovery: sodium.crypto_box_seed_keypair(e),
    };
  } finally {
    sodium.memzero(s);
    sodium.memzero(e);
  }
}
export function encodeRecoverySecret(secret) {
  key(secret);
  return bech32m.encode(
    "anr",
    bech32m.toWords(Buffer.concat([Buffer.from([1]), secret])),
    90,
  );
}
export function decodeRecoverySecret(text) {
  check(
    typeof text === "string" && text.length === 63 && /^[a-z0-9]+$/.test(text),
    "INVALID_RECOVERY_ENCODING",
  );
  try {
    const r = bech32m.decode(text, 90),
      b = bech32m.fromWords(r.words);
    check(
      r.prefix === "anr" &&
        b.length === 33 &&
        b[0] === 1 &&
        bech32m.encode(r.prefix, bech32m.toWords(b), 90) === text,
      "INVALID_RECOVERY_ENCODING",
    );
    return Buffer.from(b.slice(1));
  } catch {
    throw new ContractError("INVALID_RECOVERY_ENCODING");
  }
}
export async function createIdentity(secret, contextBytes) {
  const c = decode("derivation-context", contextBytes),
    keys = await deriveRoot(secret, contextBytes);
  try {
    const body = {
      ...common("account-root-identity"),
      derivation: "hkdf-sha256-c1",
      service_id: c.service_id,
      account_id: c.account_id,
      root_signing_key: b64(keys.signing.publicKey),
      recovery_encryption_key: b64(keys.recovery.publicKey),
    };
    return encode(
      "identity",
      wire({
        body,
        signature: b64(
          sodium.crypto_sign_detached(
            identitySigningInput("identity-body", wire(body)),
            keys.signing.privateKey,
          ),
        ),
      }),
    );
  } finally {
    sodium.memzero(keys.signing.privateKey);
    sodium.memzero(keys.recovery.privateKey);
  }
}
export function verifyIdentity(identityBytes, pinBytes) {
  const i = decode("identity", identityBytes),
    p = decode("identity-pin", pinBytes);
  check(
    i.body.service_id === p.service_id &&
      i.body.account_id === p.account_id &&
      identityDigest("identity-body", wire(i.body)) === p.root_fingerprint,
    "ROOT_PIN_MISMATCH",
  );
  check(
    sodium.crypto_sign_verify_detached(
      un64(i.signature),
      identitySigningInput("identity-body", wire(i.body)),
      un64(i.body.root_signing_key),
    ),
    "INVALID_SIGNATURE",
  );
  return i;
}
export async function recoverRoot(kitBytes, pinBytes) {
  const kit = decode("kit", kitBytes),
    p = decode("identity-pin", pinBytes);
  check(
    kit.service_id === p.service_id &&
      kit.account_id === p.account_id &&
      kit.root_fingerprint === p.root_fingerprint,
    "ROOT_PIN_MISMATCH",
  );
  verifyIdentity(wire(kit.identity), pinBytes);
  const secret = decodeRecoverySecret(kit.recovery_secret);
  try {
    const context = wire({
      ...common("account-root-derivation"),
      service_id: kit.service_id,
      account_id: kit.account_id,
    });
    check(
      same(
        decode("identity", await createIdentity(secret, context)),
        kit.identity,
      ),
      "RECOVERY_IDENTITY_MISMATCH",
    );
    return await deriveRoot(secret, context);
  } finally {
    sodium.memzero(secret);
  }
}
// Expected context and issuer key MUST come from independently verified P08/P10
// policy/roster state. A decryptable box or valid signature grants no role.
export function openGrant(
  recordBytes,
  expectedContextBytes,
  issuerPublicKey,
  publicKey,
  secretKey,
) {
  key(issuerPublicKey);
  key(publicKey);
  key(secretKey);
  const r = decode("grant", recordBytes),
    c = decode("grant-context", expectedContextBytes);
  check(same(r.body.context, c), "GRANT_CONTEXT_MISMATCH");
  check(
    sodium.crypto_sign_verify_detached(
      un64(r.signature),
      identitySigningInput("grant-body", wire(r.body)),
      issuerPublicKey,
    ),
    "INVALID_SIGNATURE",
  );
  check(
    hash(Buffer.concat([domain("hash", "x25519-public-key"), publicKey])) ===
      c.recipient.encryption_key_fingerprint &&
      b64(sodium.crypto_scalarmult_base(secretKey)) === b64(publicKey),
    "RECIPIENT_KEY_MISMATCH",
  );
  let plain;
  try {
    plain = sodium.crypto_box_seal_open(
      un64(r.body.sealed_ciphertext),
      publicKey,
      secretKey,
    );
  } catch {
    throw new ContractError("INTEGRITY_FAILURE");
  }
  try {
    const p = decode("grant-plaintext", plain);
    check(same(p.context, c), "INNER_CONTEXT_MISMATCH");
    return un64(p.group_key);
  } finally {
    sodium.memzero(plain);
  }
}
export function sealGrant(contextBytes, groupKey, recipientKey, signingKey) {
  key(groupKey);
  key(recipientKey);
  key(signingKey, 64);
  const c = decode("grant-context", contextBytes);
  check(
    hash(Buffer.concat([domain("hash", "x25519-public-key"), recipientKey])) ===
      c.recipient.encryption_key_fingerprint,
    "RECIPIENT_KEY_MISMATCH",
  );
  const plain = encode(
    "grant-plaintext",
    wire({
      purpose: "group-key-plaintext",
      context: c,
      group_key: b64(groupKey),
    }),
  );
  try {
    const body = {
      context: c,
      sealed_ciphertext: b64(sodium.crypto_box_seal(plain, recipientKey)),
    };
    return encode(
      "grant",
      wire({
        body,
        signature: b64(
          sodium.crypto_sign_detached(
            identitySigningInput("grant-body", wire(body)),
            signingKey,
          ),
        ),
      }),
    );
  } finally {
    sodium.memzero(plain);
  }
}
