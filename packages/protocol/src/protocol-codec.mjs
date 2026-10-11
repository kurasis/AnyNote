// Complete v1 contract reference. No product API or platform custody claim.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import Ajv2020 from "ajv/dist/2020.js";
import { strictJson, requireCondition as check } from "./strict-json.mjs";
import { decode as fileDecode } from "./codec.mjs";
import canonicalize from "canonicalize";
const canonicalBytes = (bytes) =>
  Buffer.from(canonicalize(strictJson(bytes, 16777216)));
import { wire, same } from "./identity-codec.mjs";
const old = strictJson(
  readFileSync(
    new URL("../../contracts/p02-file-c1.schema.json", import.meta.url),
  ),
);
const identity = strictJson(
  readFileSync(
    new URL("../../contracts/p02-identity-c1.schema.json", import.meta.url),
  ),
);
const supplemental = ["p02-state-c1", "p02-group-c2"].map((n) =>
  strictJson(
    readFileSync(
      new URL("../../contracts/" + n + ".schema.json", import.meta.url),
    ),
  ),
);
const schema = strictJson(
  readFileSync(new URL("../../contracts/p02-v1.schema.json", import.meta.url)),
);
const ajv = new Ajv2020({ strict: true, ownProperties: true });
for (const size of [12, 16, 24, 32, 48, 64])
  ajv.addFormat(
    `base64url-${size}`,
    (s) =>
      typeof s === "string" &&
      Buffer.from(s, "base64url").length === size &&
      Buffer.from(s, "base64url").toString("base64url") === s,
  );
ajv.addFormat(
  "base64url-variable",
  (s) =>
    typeof s === "string" &&
    /^[A-Za-z0-9_-]*$/.test(s) &&
    Buffer.from(s, "base64url").toString("base64url") === s,
);
ajv.addFormat(
  "decimal-u63",
  (s) =>
    s.length <= 19 &&
    /^(0|[1-9][0-9]*)$/.test(s) &&
    BigInt(s) <= 9223372036854775807n,
);
for (const limit of [
  119,
  120,
  199,
  200,
  65536,
  100000,
  8388608,
  8388624,
  1000000000,
  9223372036854775807n,
])
  ajv.addFormat(
    `decimal-${limit}`,
    (s) =>
      s.length <= String(limit).length &&
      /^(0|[1-9][0-9]*)$/.test(s) &&
      BigInt(s) <= BigInt(limit),
  );
ajv.addFormat(
  "base64url-sealed",
  (s) =>
    s.length >= 64 &&
    s.length <= 5462 &&
    Buffer.from(s, "base64url").toString("base64url") === s,
);
for (const limit of [4096, 16384])
  ajv.addFormat(
    `bounded-binary-${limit}`,
    (s) =>
      s.length >= (limit === 4096 ? 64 : 24) &&
      s.length <= Math.ceil((limit * 8) / 6) &&
      Buffer.from(s, "base64url").length <= limit &&
      Buffer.from(s, "base64url").toString("base64url") === s,
  );
ajv.addSchema(old);
ajv.addSchema(identity);
for (const s of supplemental) ajv.addSchema(s);
ajv.addSchema(schema);
const errors = new Map(
  strictJson(
    readFileSync(new URL("../../contracts/p02-errors.json", import.meta.url)),
  ).errors.map((e) => [e.code, e]),
);
const validators = new Map(
  Object.keys(schema.$defs).map((k) => [
    k,
    ajv.compile({ $ref: `${schema.$id}#/$defs/${k}` }),
  ]),
);
export const common = (purpose) => ({
  contract: "p02-v1",
  protocol: "anynote",
  protocol_version: 1,
  purpose,
});
export const domain = (family, purpose) =>
  Buffer.from(`AnyNote/p02-v1/${family}/${purpose}\0`);
export function decode(kind, bytes) {
  check(validators.has(kind), "UNSUPPORTED_SCHEMA");
  const cap =
    kind.startsWith("export-") && kind.endsWith("evidence")
      ? 16777216
      : kind === "local-envelope"
        ? 6291456
        : [
              "bundle",
              "payload",
              "local-plaintext",
              "local-envelope",
              "outbox",
              "draft",
              "cache",
              "search",
              "transfer",
              "vault-secrets",
            ].includes(kind)
          ? 4194304
          : [
                "snapshot-page",
                "export-page",
                "sync-page",
                "export-public-event",
              ].includes(kind)
            ? 1048576
            : 65536;
  const v = strictJson(bytes, cap);
  check(validators.get(kind)(v), "SCHEMA_MISMATCH");
  const ordered = (a, key) => {
    for (let i = 1; i < a.length; i++)
      check(key(a[i - 1]) < key(a[i]), "UNORDERED_OR_DUPLICATE");
  };
  const c =
    kind === "context"
      ? v
      : ["header", "wrap", "payload"].includes(kind)
        ? v.context
        : kind === "envelope"
          ? v.header.context
          : kind === "bundle"
            ? v.envelope.header.context
            : null;
  if (c) {
    ordered(c.parents, (p) => p.revision_id);
    ordered(c.attachments, (a) => a.file_id + "/" + a.file_version_id);
    check(
      c.parents.every((p) => p.revision_id !== c.revision_id),
      "SELF_PARENT",
    );
    check(
      (c.object_kind === "entry") === (c.thread_id !== null),
      "THREAD_CONTEXT_MISMATCH",
    );
    if (c.object_kind !== "entry")
      check(c.attachments.length === 0, "ATTACHMENT_CONTEXT_MISMATCH");
    if (c.action === "create")
      check(c.parents.length === 0, "PARENT_CONTEXT_MISMATCH");
    else check(c.parents.length > 0, "PARENT_CONTEXT_MISMATCH");
  }
  if (kind === "payload") {
    check(canonicalBytes(bytes).length <= 2097152, "RESOURCE_LIMIT");
    ordered(v.tags, (t) => t);
    ordered(v.checklist, (i) => i.item_id);
    const tomb = c.action === "soft-delete";
    if (tomb)
      check(
        v.title === "" &&
          v.markdown === "" &&
          !v.tags.length &&
          !v.checklist.length &&
          !v.preferences.length &&
          v.summary_entry_id === null,
        "TOMBSTONE_PAYLOAD_MISMATCH",
      );
    if (c.object_kind !== "entry")
      check(
        v.markdown === "" && !v.checklist.length,
        "METADATA_PAYLOAD_MISMATCH",
      );
    if (c.object_kind === "entry")
      check(
        v.summary_entry_id === null &&
          !v.preferences.length &&
          v.metadata_kind === "content",
        "ENTRY_PAYLOAD_MISMATCH",
      );
    ordered(v.preferences, (p) => p.key + "/" + p.target_id);
    if (v.metadata_kind === "account-preferences")
      check(c.object_kind === "group-metadata", "PRIVATE_NAMESPACE_REQUIRED");
  }
  if (kind === "bundle")
    check(same(v.envelope.header.context, v.wrap.context), "CONTEXT_MISMATCH");
  if (kind === "draft") {
    decode("payload", wire(v.payload));
    check(same(v.context, v.payload.context), "LOCAL_CONTEXT_MISMATCH");
  }
  if (kind === "outbox") {
    decode("bundle", wire(v.bundle));
    const c = v.bundle.envelope.header.context;
    check(
      v.attempt_id === c.operation_id &&
        v.revision_id === c.revision_id &&
        v.attempt_digest === digest("bundle", wire(v.bundle)),
      "ATTEMPT_CONTEXT_MISMATCH",
    );
    check(
      (v.state === "COMMITTED") === (v.receipt !== null),
      "RECEIPT_STATE_MISMATCH",
    );
    if (v.receipt)
      check(
        v.receipt.operation_id === c.operation_id &&
          v.receipt.revision_id === c.revision_id &&
          v.receipt.envelope_digest ===
            digest("envelope", wire(v.bundle.envelope)),
        "RECEIPT_CONTEXT_MISMATCH",
      );
  }
  if (kind === "phrase-wrapper")
    check(v.context.method === "argon2id13", "WRAPPER_METHOD_MISMATCH");
  if (kind === "prf-wrapper")
    check(v.context.method === "webauthn-prf", "WRAPPER_METHOD_MISMATCH");
  if (kind === "native-wrapper") {
    check(
      v.context.method === "windows-webauthn-prf",
      "WRAPPER_METHOD_MISMATCH",
    );
    check(
      Buffer.from(v.tpm_name, "base64url").length === 34 &&
        Buffer.from(v.tpm_name, "base64url").readUInt16BE(0) === 11,
      "INVALID_TPM_NAME",
    );
  }
  if (kind === "local-plaintext") {
    const kinds = {
      "vault-secrets": "vault-secrets",
      draft: "draft",
      outbox: "outbox",
      session: "session-secret",
      cache: "cache",
      search: "search",
      transfer: "transfer",
    };
    check(
      validators.get(kinds[v.context.record_kind] ?? "opaque-data")?.(v.data) ??
        (Object.keys(v.data).length === 1 &&
          typeof v.data.opaque_bytes === "string"),
      "LOCAL_KIND_MISMATCH",
    );
    if (
      [
        "draft",
        "outbox",
        "cache",
        "search",
        "transfer",
        "vault-secrets",
      ].includes(v.context.record_kind)
    )
      decode(v.context.record_kind, wire(v.data));
    if (v.context.record_kind === "outbox") {
      const c = v.data.bundle.envelope.header.context;
      check(
        c.author.account_id === v.context.account_id &&
          c.author.device_id === v.context.device_id &&
          c.service_id === v.context.service_id,
        "LOCAL_CONTEXT_MISMATCH",
      );
    }
    if (v.context.record_kind === "draft")
      check(
        same(v.data.context, v.data.payload.context) &&
          v.data.context.author.account_id === v.context.account_id &&
          v.data.context.author.device_id === v.context.device_id &&
          v.data.context.service_id === v.context.service_id,
        "LOCAL_CONTEXT_MISMATCH",
      );
  }
  if (kind === "error" || kind === "error-response") {
    const known = errors.get(v.error.code);
    check(
      known &&
        known.retryable === v.error.retryable &&
        known.message_key === v.error.message_key,
      "ERROR_SEMANTICS_MISMATCH",
    );
  }
  if (kind === "negotiation")
    check(
      same(v.components, [
        "p02-file-c1",
        "p02-identity-c1",
        "p02-state-c1",
        "p02-group-c2",
        "p02-v1",
      ]),
      "UNSUPPORTED_SCHEMA",
    );
  if (kind === "export-selection") ordered(v.group_ids, (x) => x);
  if (kind === "export-pruned-record") {
    if (v.record_kind === "file-manifest")
      fileDecode("envelope", wire(v.envelope));
    else {
      decode("envelope", wire(v.envelope));
      check(
        v.envelope.header.context.object_kind === v.record_kind,
        "CONTEXT_MISMATCH",
      );
    }
  }
  if (kind === "export-file-record") {
    const e = fileDecode("envelope", wire(v.envelope)),
      w = fileDecode("wrap", wire(v.wrap));
    check(same(e.header.context, w.context), "CONTEXT_MISMATCH");
  }
  if (kind === "cache") {
    const types = {
      "object-bundle": "bundle",
      "file-record": "export-file-record",
      "public-evidence": "export-evidence",
    };
    decode(types[v.cached_kind], Buffer.from(v.record_bytes, "base64url"));
  }
  if (kind === "search")
    ordered(
      v.documents,
      (x) => x.group_id + "/" + x.object_id + "/" + x.revision_id,
    );
  if (kind === "vault-secrets")
    ordered(
      v.group_keys,
      (x) => x.group_id + "/" + x.key_epoch.padStart(19, "0"),
    );
  if (kind === "transfer") {
    ordered(v.parts, (x) => x.index.padStart(3, "0"));
    check(
      BigInt(v.progress_bytes) <= BigInt(v.source_bytes),
      "TRANSFER_PROGRESS_MISMATCH",
    );
    if (v.direction !== "export")
      check(
        v.file_id !== null && v.file_version_id !== null && v.keys !== null,
        "TRANSFER_CONTEXT_MISMATCH",
      );
  }
  if (kind === "export-page") ordered(v.items, (i) => i.path);
  if (kind === "export-key")
    check(
      (v.key_kind === "object-dek") === (v.file_data_dek === null),
      "KEY_PURPOSE_MISMATCH",
    );
  return v;
}
export const encode = (kind, bytes) =>
  canonicalBytes(wire(decode(kind, bytes)));
export const digest = (kind, bytes) =>
  createHash("sha256")
    .update(domain("hash", kind))
    .update(encode(kind, bytes))
    .digest("base64url");
export const signingInput = (kind, bytes) => {
  check(["header", "export-footer-body"].includes(kind), "UNSUPPORTED_PURPOSE");
  const v = decode(kind, bytes);
  return Buffer.concat([domain("sign", v.purpose), encode(kind, bytes)]);
};
export const aad = (purpose, value) => {
  check(
    [
      "object-payload",
      "object-key-wrap",
      "local-record",
      "local-unlock",
    ].includes(purpose),
    "UNSUPPORTED_PURPOSE",
  );
  return Buffer.concat([domain("aad", purpose), canonicalBytes(wire(value))]);
};
export const rawDigest = (bytes) =>
  createHash("sha256").update(bytes).digest("base64url");
