// Raw bytes only. Crypto validity does not establish policy/roster freshness.
import * as file from "./codecs/codec.mjs";
import * as identity from "./codecs/identity-codec.mjs";
import * as state from "./codecs/state-codec.mjs";
import { groupCodecForProfile } from "./codecs/group-codec.mjs";
import * as complete from "./codecs/protocol-codec.mjs";
import { requireCondition as check } from "../src/strict-json.mjs";
import { Buffer, sodium, b64, un64, key } from "./primitives.mjs";
const group = groupCodecForProfile("p02-group-c2");
const codecs = {
  "p02-file-c1": file.decode,
  "p02-identity-c1": identity.decodeIdentity,
  "p02-state-c1": state.stateDecode,
  "p02-group-c2": group.groupDecode,
  "p02-v1": complete.decode,
};
export function decode(profile, kind, bytes) {
  check(Object.hasOwn(codecs, profile), "UNSUPPORTED_SCHEMA");
  return codecs[profile](kind, bytes);
}
export { canonicalBytes } from "./codecs/codec.mjs";
const signable = {
  "p02-file-c1": ["header", "checkpoint"],
  "p02-identity-c1": ["identity-body", "certificate-body", "grant-body"],
  "p02-state-c1": [
    "invitation-body",
    "offer-body",
    "response-body",
    "approval-body",
    "confirmation-body",
    "possession-body",
    "event-body",
  ],
  "p02-group-c2": [
    "invitation-body",
    "acceptance-body",
    "policy-body",
    "epoch-intent-body",
    "descriptor-body",
    "epoch-commit-body",
    "history-body",
  ],
  "p02-v1": ["header", "export-footer-body"],
};
export function publicSigningBytes(profile, kind, raw) {
  check(signable[profile]?.includes(kind), "UNSUPPORTED_PURPOSE");
  const v = decode(profile, kind, raw);
  const purpose =
    profile === "p02-identity-c1"
      ? {
          "identity-body": "account-root-identity",
          "certificate-body": "provisional-device-certificate",
          "grant-body": "group-key-distribution",
        }[kind]
      : v.purpose;
  return Buffer.concat([
    Buffer.from(`AnyNote/${profile}/sign/${purpose}\0`),
    file.canonicalBytes(raw),
  ]);
}
export function signPublicFrame(profile, kind, raw, secret) {
  key(secret, 64);
  return b64(
    sodium.crypto_sign_detached(publicSigningBytes(profile, kind, raw), secret),
  );
}
export function verifyPublicFrame(profile, kind, raw, signature, publicKey) {
  key(publicKey);
  const s = un64(signature);
  check(
    s.length === 64 &&
      sodium.crypto_sign_verify_detached(
        s,
        publicSigningBytes(profile, kind, raw),
        publicKey,
      ),
    "INVALID_SIGNATURE",
  );
  return decode(profile, kind, raw);
}
export { Buffer, b64, un64, hash } from "./primitives.mjs";
export * from "./identity.mjs";
export * from "./objects.mjs";
export { nativeKek, wrapNative, unwrapNative } from "./local.mjs";
export * from "./files.mjs";
export * from "./history.mjs";
