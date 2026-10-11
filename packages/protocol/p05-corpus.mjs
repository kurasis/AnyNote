// Build ignored PUBLIC test inputs from unchanged frozen corpora; never rewrite them.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { createHash } from "node:crypto";
import * as core from "./adapters/core.mjs";
import {
  canonicalBytes as frozenCanonical,
  signingInput as fileSigning,
} from "./src/codec.mjs";
import { identitySigningInput } from "./src/identity-codec.mjs";
import { stateSigningInput } from "./src/state-codec.mjs";
import { groupCodecForProfile as frozenGroup } from "./src/group-codec.mjs";
import { signingInput as completeSigning } from "./src/protocol-codec.mjs";
import { groupCodecForProfile } from "./adapters/codecs/group-codec.mjs";
const root = resolve(import.meta.dirname, "../..");
const load = (p) => JSON.parse(readFileSync(join(root, p)));
export function corpus() {
  const frames = [];
  const v1 = load("fixtures/protocol/p02/v1/schema-vectors.json");
  for (const [kind, v] of Object.entries(v1)) {
    const raw = Buffer.concat(
      v.byte_blocks.map((p) =>
        Buffer.from(
          readFileSync(
            join(root, "fixtures/protocol/p02/v1", p),
            "utf8",
          ).trim(),
          "hex",
        ),
      ),
    );
    core.decode("p02-v1", kind, raw);
    frames.push({
      profile: "p02-v1",
      kind,
      raw_hex: raw.toString("hex"),
      expected_hex: Buffer.from(frozenCanonical(raw)).toString("hex"),
    });
  }
  const notes = load("fixtures/protocol/p02/v1/crypto.json"),
    identity = load("fixtures/protocol/p02/identity-vectors.json");
  const file = load("fixtures/protocol/p02/vectors.json"),
    state = load("fixtures/protocol/p02/state-vectors.json"),
    group = load("fixtures/protocol/p02/group-vectors.json");
  const pools = {
    "p02-file-c1": [file, identity.outputs.file],
    "p02-identity-c1": [identity, state, notes.objects.evidence],
    "p02-state-c1": [state, notes.objects.evidence],
    "p02-group-c2": [group, notes.objects.evidence],
  };
  const candidates = [];
  const visit = (v, depth = 0) => {
    if (depth > 24) return;
    candidates.push(v);
    if (v && typeof v === "object")
      for (const x of Object.values(v)) visit(x, depth + 1);
  };
  for (const [profile, pool] of Object.entries(pools)) {
    candidates.length = 0;
    for (const p of pool) visit(p);
    const schema = load("packages/contracts/" + profile + ".schema.json");
    for (const kind of Object.keys(schema.$defs)) {
      for (const value of candidates) {
        const raw = Buffer.from(JSON.stringify(value));
        if (raw.length > 1048576) continue;
        try {
          core.decode(profile, kind, raw);
        } catch {
          continue;
        }
        frames.push({
          profile,
          kind,
          raw_hex: raw.toString("hex"),
          expected_hex: Buffer.from(frozenCanonical(raw)).toString("hex"),
        });
        break;
      }
    }
  }
  const negatives = [],
    signed = [];
  const signers = {
    "p02-file-c1": fileSigning,
    "p02-identity-c1": identitySigningInput,
    "p02-state-c1": stateSigningInput,
    "p02-group-c2": frozenGroup("p02-group-c2").groupSigningInput,
    "p02-v1": completeSigning,
  };
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
  for (const frame of frames) {
    const value = JSON.parse(Buffer.from(frame.raw_hex, "hex"));
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const invalid = { ...value, unexpected_p05_field: true };
      negatives.push({
        profile: frame.profile,
        kind: frame.kind,
        raw_hex: Buffer.from(JSON.stringify(invalid)).toString("hex"),
        reason: "closed schema unknown field",
      });
      if ("protocol_version" in value) {
        const invalid = { ...value, protocol_version: 2 };
        negatives.push({
          profile: frame.profile,
          kind: frame.kind,
          raw_hex: Buffer.from(JSON.stringify(invalid)).toString("hex"),
          reason: "unsupported version",
        });
      }
    }
    if (signable[frame.profile].includes(frame.kind))
      signed.push({
        ...frame,
        expected_signing_hex: Buffer.from(
          signers[frame.profile](frame.kind, Buffer.from(frame.raw_hex, "hex")),
        ).toString("hex"),
      });
  }
  const g = notes.objects.evidence.groups[0],
    account = notes.objects.evidence.accounts.find(
      (a) => a.identity.body.account_id === g.history.body.signer.account_id,
    );
  const history = {
    record: g.history,
    pages: g.history_pages,
    independent_digest: groupCodecForProfile("p02-group-c2").groupDigest(
      "history",
      Buffer.from(JSON.stringify(g.history)),
    ),
    signer_key:
      account.events[0].body.payload.certificate.body.device_signing_key,
  };
  return {
    purpose: "PUBLIC_TEST_ONLY_NOT_PRODUCT_AUTHORIZATION",
    jcs: load("fixtures/protocol/p05/jcs.json"),
    frames,
    negatives,
    signed,
    notes,
    identity,
    history,
    fixture_inputs: [
      "fixtures/protocol/p05/jcs.json",
      "fixtures/protocol/p02/v1/crypto.json",
      "fixtures/protocol/p02/v1/schema-vectors.json",
      "fixtures/protocol/p02/identity-vectors.json",
      "fixtures/protocol/p02/vectors.json",
      "fixtures/protocol/p02/state-vectors.json",
      "fixtures/protocol/p02/group-vectors.json",
    ].map((path) => ({
      path,
      sha256: createHash("sha256")
        .update(readFileSync(join(root, path)))
        .digest("hex"),
    })),
  };
}
if (process.argv[1] === import.meta.filename) {
  const c = corpus();
  mkdirSync(join(root, "artifacts/p05"), { recursive: true });
  writeFileSync(
    join(root, "artifacts/p05/public-corpus.json"),
    JSON.stringify(c) + "\n",
  );
  console.log(
    JSON.stringify({
      status: "PASS",
      purpose: "PUBLIC corpus preparation",
      frames: c.frames.length,
      by_profile: Object.fromEntries(
        [...new Set(c.frames.map((x) => x.profile))].map((p) => [
          p,
          c.frames.filter((x) => x.profile === p).length,
        ]),
      ),
      jcs: c.jcs.valid.length,
      malformed: c.jcs.invalid_hex.length,
    }),
  );
}
