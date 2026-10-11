// Project only closed PUBLIC signatures; private fixture inputs never enter PHP.
import { readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import {
  canonicalBytes as canonical,
  signingInput as fileSigning,
} from "./src/codec.mjs";
import { identitySigningInput } from "./src/identity-codec.mjs";
import { signingInput as objectSigning } from "./src/protocol-codec.mjs";
import { verifyPublicFrame } from "./adapters/core.mjs";
const root = resolve(import.meta.dirname, "../.."),
  out = join(root, "artifacts/p05");
const load = (p) => JSON.parse(readFileSync(join(out, p)));
const f = load("public-corpus.json");
if (f.purpose !== "PUBLIC_TEST_ONLY_NOT_PRODUCT_AUTHORIZATION")
  throw Error("PUBLIC_ONLY");
const objectPublic = Buffer.from(f.notes.inputs.signing_public_hex, "hex"),
  issuer = Buffer.from(
    f.identity.outputs.certificates[0].record.body.device_signing_key,
    "base64url",
  );
const sources = [];
for (const [runtime, path, nested] of [
  ["Rust", "native-output.json", true],
  ["Node", "node-peer.json", false],
  ["Chromium worker", "browser-peer.json", false],
]) {
  let v;
  try {
    v = load(path);
  } catch (e) {
    if (e.code === "ENOENT" && runtime === "Chromium worker") continue;
    throw e;
  }
  if (nested) v = v.peer;
  const frames = [...v.public_signatures];
  for (const [profile, kind, record, body, publicKey, signing] of [
    [
      "p02-v1",
      "header",
      v.bundle.envelope,
      v.bundle.envelope.header,
      objectPublic,
      objectSigning,
    ],
    [
      "p02-file-c1",
      "header",
      v.file.record.envelope,
      v.file.record.envelope.header,
      issuer,
      fileSigning,
    ],
    [
      "p02-identity-c1",
      "grant-body",
      v.grant,
      v.grant.body,
      issuer,
      identitySigningInput,
    ],
  ]) {
    const raw = Buffer.from(JSON.stringify(body));
    verifyPublicFrame(
      profile,
      kind,
      raw,
      record.signature,
      new Uint8Array(publicKey),
    );
    frames.push({
      profile,
      kind,
      raw_hex: raw.toString("hex"),
      canonical_hex: Buffer.from(canonical(raw)).toString("hex"),
      signing_hex: Buffer.from(signing(kind, raw)).toString("hex"),
      signature: record.signature,
      public_key: publicKey.toString("base64url"),
      source: "fresh-ciphertext",
    });
  }
  sources.push({ runtime, frames });
}
if (sources.length < 2) throw Error("NATIVE_AND_NODE_REQUIRED");
writeFileSync(
  join(out, "public-signatures.json"),
  JSON.stringify({
    purpose: "PUBLIC_SIGNATURE_ONLY_P05",
    sources,
    malformed: f.jcs.invalid_hex,
  }) + "\n",
);
console.log(
  JSON.stringify({
    status: "PASS",
    scope: "PUBLIC_SIGNATURE_ONLY_P05",
    sources: sources.map((s) => ({
      runtime: s.runtime,
      frames: s.frames.length,
      fresh_ciphertext_frames: 3,
    })),
  }),
);
