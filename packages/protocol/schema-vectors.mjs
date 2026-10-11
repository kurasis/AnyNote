import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { common, decode, encode, digest } from "./src/protocol-codec.mjs";
import { wire } from "./src/identity-codec.mjs";
import { fixtureDir, id, seed, b64 } from "./complete-fixtures.mjs";
import { pageCommitmentForEvaluation } from "./src/sync-reference.mjs";
const names = [
  "p02-file-c1",
  "p02-identity-c1",
  "p02-state-c1",
  "p02-group-c2",
  "p02-v1",
];
const schemas = names.map((n) =>
    JSON.parse(
      readFileSync(
        new URL("../contracts/" + n + ".schema.json", import.meta.url),
      ),
    ),
  ),
  lookup = new Map(schemas.map((s) => [s.$id, s])),
  schema = schemas.at(-1);
function sample(s, root = schema) {
  if (s.$ref) {
    const [urn, path] = s.$ref.split("#/");
    const owner = urn ? lookup.get(urn) : root;
    return sample(
      path.split("/").reduce((v, k) => v[k], owner),
      owner,
    );
  }
  if ("const" in s) return s.const;
  if (s.enum) return s.enum[0];
  if (s.anyOf) {
    const nullable = s.anyOf.find((x) => x.type === "null");
    return sample(nullable ?? s.anyOf[0], root);
  }
  if (s.oneOf) return sample(s.oneOf[0], root);
  if (s.type === "object")
    return Object.fromEntries(
      (s.required ?? []).map((k) => [k, sample(s.properties[k], root)]),
    );
  if (s.type === "array")
    return Array.from({ length: s.minItems ?? 0 }, () => sample(s.items, root));
  if (s.type === "null") return null;
  if (s.type === "boolean") return false;
  if (s.type === "integer") return s.minimum ?? 1;
  if (s.type === "string") {
    if (s.format?.startsWith("base64url-")) {
      const n = Number(s.format.slice(10));
      return b64(seed("schema-" + n, Number.isFinite(n) ? n : 32));
    }
    if (s.format?.startsWith("decimal")) return "0";
    return "PUBLIC";
  }
  throw Error("UNHANDLED_SCHEMA");
}
export function examples(f) {
  const o = f.objects,
    p = o.payload,
    c = p.context,
    dict = {};
  for (const [k, s] of Object.entries(schema.$defs)) dict[k] = sample(s);
  Object.assign(dict, {
    context: c,
    payload: p,
    wrap: o.bundle.wrap,
    header: o.bundle.envelope.header,
    envelope: o.bundle.envelope,
    bundle: o.bundle,
    "local-context": o.local_plain.context,
    "local-plaintext": o.local_plain,
    "local-envelope": o.local_cipher,
    draft: o.local_plain.data,
    "argon2-parameters": o.parameters,
    "unlock-context": o.phrase_descriptor.context,
    "phrase-wrapper": o.phrase_wrapper,
    "prf-wrapper": o.prf_wrapper,
    "native-wrapper": o.native_wrapper,
    "export-evidence": o.evidence,
    "export-account-evidence": o.evidence.accounts[0],
    "export-group-evidence": o.evidence.groups[0],
    "export-epoch-evidence": o.evidence.groups[0].transitions[0].value,
    "export-header": o.header,
    "snapshot-page": o.snapshot_page,
    "snapshot-descriptor": o.header.snapshot,
    "export-selection": o.header.selection,
    "export-page": {
      ...common("export-inventory-page"),
      export_id: o.header.export_id,
      page_index: "0",
      items: [],
    },
    "export-footer-body": o.footer.body,
    "export-footer": o.footer,
    "export-key": o.export_key,
    "export-kit": o.kit,
    "export-file-record": o.file_record,
  });
  dict.outbox = {
    draft_id: id("draft"),
    attempt_id: c.operation_id,
    revision_id: c.revision_id,
    state: "SENT_UNKNOWN",
    bundle: o.bundle,
    attempt_digest: digest("bundle", wire(o.bundle)),
    receipt: null,
  };
  dict["contact-card"] = {
    service_id: c.service_id,
    account_id: o.evidence.accounts[0].pin.account_id,
    root_fingerprint: o.evidence.accounts[0].pin.root_fingerprint,
    identity: o.evidence.accounts[0].identity,
  };
  dict["export-public-group"] = {
    genesis: o.evidence.groups[0].genesis,
    genesis_pin: o.evidence.groups[0].genesis_pin,
  };
  dict["export-public-event"] = {
    kind: "epoch",
    record: o.evidence.groups[0].transitions[0].value.record,
  };
  dict.cache = {
    cached_kind: "object-bundle",
    record_bytes: b64(encode("bundle", wire(o.bundle))),
  };
  dict.transfer.direction = "export";
  dict["export-pruned-record"] = {
    record_kind: "entry",
    payload_status: "pruned",
    envelope: o.bundle.envelope,
  };
  dict.negotiation.components = [
    "p02-file-c1",
    "p02-identity-c1",
    "p02-state-c1",
    "p02-group-c2",
    "p02-v1",
  ];
  dict.error = {
    error: {
      code: "AUTH_REQUIRED",
      message_key: "error.auth_required",
      request_id: id("request"),
      retryable: false,
      details: [],
    },
  };
  dict["error-response"] = dict.error;
  dict["sync-page"] = {
    ...common("sync-page"),
    from_cursor: { generation: id("transport"), sequence: "0" },
    next_cursor: { generation: id("transport"), sequence: "0" },
    watermark: { generation: id("transport"), sequence: "0" },
    events: [],
    complete: true,
  };
  for (const [kind, value] of Object.entries(dict)) decode(kind, wire(value));
  return dict;
}
export function checkSchemaVectors() {
  const inputs = examples(
    JSON.parse(readFileSync(new URL("crypto.json", fixtureDir))),
  );
  const vectors = JSON.parse(
    readFileSync(new URL("schema-vectors.json", fixtureDir)),
  );
  if (
    Object.keys(vectors).sort().join() !=
    Object.keys(schema.$defs).sort().join()
  )
    throw Error("SCHEMA_COVERAGE_DRIFT");
  let count = 0;
  for (const [k, v] of Object.entries(vectors)) {
    const frozen = Buffer.concat(
      v.byte_blocks.map((name) => {
        if (!new RegExp("^bytes/" + k + "-[0-9]{4}\\.hex$").test(name))
          throw Error("INVALID_VECTOR_PATH");
        const hex = readFileSync(new URL(name, fixtureDir), "utf8").trim();
        if (!/^(?:[0-9a-f]{2}){1,8192}$/.test(hex))
          throw Error("INVALID_VECTOR_HEX");
        return Buffer.from(hex, "hex");
      }),
    );
    if (
      !encode(k, wire(inputs[k])).equals(frozen) ||
      digest(k, wire(inputs[k])) !== v.digest
    )
      throw Error("SCHEMA_VECTOR_DRIFT_" + k);
    count++;
  }
  return {
    status: "PASS",
    structures: count,
    scope: "FROZEN_TYPED_BYTES_NOT_UNCHECKED_AUTHORIZATION",
  };
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--write")) {
    const f = JSON.parse(readFileSync(new URL("crypto.json", fixtureDir))),
      all = {};
    mkdirSync(new URL("bytes/", fixtureDir), { recursive: true });
    for (const [k, v] of Object.entries(examples(f))) {
      const bytes = encode(k, wire(v)),
        text = bytes.toString("utf8");
      let quoted = false,
        escaped = false,
        last = 0,
        start = 0;
      const cuts = [];
      // Cut only after complete JSON values; never cut a key/value token. Each
      // PUBLIC hex block stays below upstream scanner chunk boundaries.
      for (let i = 0; i < text.length; i++) {
        const c = text[i];
        if (quoted) {
          if (escaped) escaped = false;
          else if (c === "\\") escaped = true;
          else if (c === '"') quoted = false;
        } else if (c === '"') quoted = true;
        if (!quoted && [",", "}", "]"].includes(c)) last = i + 1;
        if (
          Buffer.byteLength(text.slice(start, i + 1)) > 3500 &&
          last > start
        ) {
          cuts.push(text.slice(start, last));
          start = last;
        }
      }
      if (start < text.length) cuts.push(text.slice(start));
      const names = [];
      for (let i = 0; i < cuts.length; i++) {
        if (Buffer.byteLength(cuts[i]) > 8192)
          throw Error("FIXTURE_BLOCK_TOO_LARGE");
        const name = "bytes/" + k + "-" + String(i).padStart(4, "0") + ".hex";
        writeFileSync(
          new URL(name, fixtureDir),
          Buffer.from(cuts[i]).toString("hex") + "\n",
        );
        names.push(name);
      }
      all[k] = { byte_blocks: names, digest: digest(k, wire(v)) };
    }
    writeFileSync(
      new URL("schema-vectors.json", fixtureDir),
      JSON.stringify(all, null, 2) + "\n",
    );
  }
  console.log(JSON.stringify(checkSchemaVectors()));
}
