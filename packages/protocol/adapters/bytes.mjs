// Minimal typed-byte operations used by unchanged codec predicates. Crypto and
// binary encoding are maintained libsodium/scure implementations, never polyfilled primitives.
import sodium from "libsodium-wrappers-sumo";
import { base64urlnopad, hex } from "@scure/base";
import file from "../../contracts/p02-file-c1.schema.json" with { type: "json" };
import identity from "../../contracts/p02-identity-c1.schema.json" with { type: "json" };
import state from "../../contracts/p02-state-c1.schema.json" with { type: "json" };
import group1 from "../../contracts/p02-group-c1.schema.json" with { type: "json" };
import group2 from "../../contracts/p02-group-c2.schema.json" with { type: "json" };
import complete from "../../contracts/p02-v1.schema.json" with { type: "json" };
import errors from "../../contracts/p02-errors.json" with { type: "json" };
await sodium.ready;
const encoder = new TextEncoder(),
  decoder = new TextDecoder("utf-8", { fatal: true });
export class Buffer extends Uint8Array {
  static from(value, encoding = "utf8") {
    return new Buffer(
      typeof value === "string"
        ? encoding === "base64url"
          ? base64urlnopad.decode(value)
          : encoding === "hex"
            ? hex.decode(value)
            : encoder.encode(value)
        : value,
    );
  }
  static alloc(n) {
    return new Buffer(n);
  }
  static byteLength(s) {
    return encoder.encode(s).length;
  }
  static concat(values) {
    const out = new Buffer(values.reduce((n, b) => n + b.length, 0));
    let at = 0;
    for (const b of values) {
      out.set(b, at);
      at += b.length;
    }
    return out;
  }
  equals(other) {
    return this.length === other.length && sodium.memcmp(this, other);
  }
  toString(encoding = "utf8") {
    return encoding === "base64url"
      ? base64urlnopad.encode(this)
      : encoding === "hex"
        ? hex.encode(this)
        : decoder.decode(this);
  }
  readUInt16BE(at) {
    return new DataView(
      this.buffer,
      this.byteOffset,
      this.byteLength,
    ).getUint16(at, false);
  }
  writeUInt32BE(n, at = 0) {
    new DataView(this.buffer, this.byteOffset, this.byteLength).setUint32(
      at,
      n,
      false,
    );
  }
  writeBigUInt64BE(n, at = 0) {
    new DataView(this.buffer, this.byteOffset, this.byteLength).setBigUint64(
      at,
      n,
      false,
    );
  }
  writeBigUInt64LE(n, at = 0) {
    new DataView(this.buffer, this.byteOffset, this.byteLength).setBigUint64(
      at,
      n,
      true,
    );
  }
}
export function createHash(algorithm) {
  if (algorithm !== "sha256") throw Error("UNSUPPORTED_PURPOSE");
  const state = sodium.crypto_hash_sha256_init();
  let done = false;
  const api = {
    update(b) {
      if (done) throw Error("HASH_FINALIZED");
      sodium.crypto_hash_sha256_update(
        state,
        b instanceof Uint8Array ? b : encoder.encode(b),
      );
      return api;
    },
    digest(encoding) {
      if (done) throw Error("HASH_FINALIZED");
      done = true;
      const b = Buffer.from(sodium.crypto_hash_sha256_final(state));
      return encoding ? b.toString(encoding) : b;
    },
  };
  return api;
}
const schemas = {
  "p02-file-c1": file,
  "p02-identity-c1": identity,
  "p02-state-c1": state,
  "p02-group-c1": group1,
  "p02-group-c2": group2,
  "p02-v1": complete,
  "p02-errors": errors,
};
export function readFileSync(url) {
  const match = Object.keys(schemas).find(
    (k) =>
      url.pathname.endsWith("/" + k + ".schema.json") ||
      url.pathname.endsWith("/" + k + ".json"),
  );
  if (!match) throw Error("UNSUPPORTED_SCHEMA");
  return encoder.encode(JSON.stringify(schemas[match]));
}
