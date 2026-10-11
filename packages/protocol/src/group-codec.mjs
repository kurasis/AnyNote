import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import Ajv2020 from "ajv/dist/2020.js";
import { strictJson, requireCondition as check } from "./strict-json.mjs";
import { canonicalBytes } from "./codec.mjs";
import { wire } from "./identity-codec.mjs";
const names = ["p02-identity-c1", "p02-file-c1", "p02-group-c1"];
const schemas = names.map((n) =>
  strictJson(
    readFileSync(new URL(`../../contracts/${n}.schema.json`, import.meta.url)),
  ),
);
const schema = schemas[2],
  ajv = new Ajv2020({ strict: true, ownProperties: true });
for (const size of [16, 24, 32, 48, 64])
  ajv.addFormat(
    `base64url-${size}`,
    (s) =>
      s.length === Math.ceil((size * 8) / 6) &&
      /^[A-Za-z0-9_-]+$/.test(s) &&
      Buffer.from(s, "base64url").length === size &&
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
    /^[A-Za-z0-9_-]+$/.test(s) &&
    Buffer.from(s, "base64url").toString("base64url") === s &&
    Buffer.from(s, "base64url").length <= 4096,
);
for (const s of schemas) ajv.addSchema(s);
const validators = new Map(
  Object.keys(schema.$defs).map((k) => [
    k,
    ajv.compile({ $ref: `${schema.$id}#/$defs/${k}` }),
  ]),
);
export const groupCommon = (purpose) => ({
  purpose,
  contract: "p02-group-c1",
  protocol: "anynote",
  protocol_version: 1,
});
export const groupDomain = (family, purpose) =>
  Buffer.from(`AnyNote/p02-group-c1/${family}/${purpose}\0`);
export const grantOrder = (record) => {
  const c = record.body.context,
    r = c.recipient;
  return `${c.key_epoch.padStart(19, "0")}/${r.account_id}/${r.kind}/${r.device_id ?? ""}`;
};
export function groupDecode(kind, bytes) {
  check(validators.has(kind), "UNSUPPORTED_SCHEMA");
  const value = strictJson(
    bytes,
    kind === "grant-page"
      ? 1048576
      : [
            "epoch-intent",
            "epoch-intent-body",
            "epoch-commit",
            "epoch-commit-body",
          ].includes(kind)
        ? 262144
        : 65536,
  );
  check(validators.get(kind)(value), "SCHEMA_MISMATCH");
  const ordered = (list, key) => {
    for (let i = 1; i < list.length; i++)
      check(key(list[i - 1]) < key(list[i]), "UNORDERED_OR_DUPLICATE");
  };
  if (kind === "members") {
    ordered(value, (m) => m.account_id);
    check(value.filter((m) => m.role === "owner").length === 1, "OWNER_COUNT");
  }
  if (kind === "rosters") ordered(value, (r) => r.account_id);
  if (kind === "epochs")
    for (let i = 0; i < value.length; i++)
      check(value[i].key_epoch === String(i), "EPOCH_INVENTORY_MISMATCH");
  if (kind === "grant-page") ordered(value.records, grantOrder);
  return value;
}
export const groupEncode = (kind, bytes) =>
  canonicalBytes(wire(groupDecode(kind, bytes)));
export const groupSigningInput = (kind, bytes) => {
  check(kind.endsWith("-body"), "UNSUPPORTED_PURPOSE");
  const b = groupDecode(kind, bytes);
  return Buffer.concat([
    groupDomain("sign", b.purpose),
    groupEncode(kind, bytes),
  ]);
};
export const groupDigest = (kind, bytes) => {
  check(
    [
      "policy",
      "invitation",
      "acceptance",
      "epoch-intent",
      "descriptor",
      "epoch-commit",
      "history",
      "grant-page",
      "epochs",
    ].includes(kind),
    "UNSUPPORTED_PURPOSE",
  );
  return createHash("sha256")
    .update(groupDomain("hash", kind))
    .update(groupEncode(kind, bytes))
    .digest("base64url");
};
export function groupKeyCommitment(scope, key) {
  check(key instanceof Uint8Array && key.length === 32, "INVALID_KEY_LENGTH");
  groupDecode("scope", wire(scope));
  return createHash("sha256")
    .update(groupDomain("hash", "group-epoch-key"))
    .update(canonicalBytes(wire(scope)))
    .update(key)
    .digest("base64url");
}
export function grantPageCommitment(pageInputs) {
  check(
    Array.isArray(pageInputs) &&
      pageInputs.length > 0 &&
      pageInputs.length <= 1000,
    "RESOURCE_LIMIT",
  );
  check(
    pageInputs.reduce((n, b) => n + b.length, 0) <= 16777216,
    "RESOURCE_LIMIT",
  );
  const pages = pageInputs.map((b) => groupDecode("grant-page", b)),
    count = pages.reduce((n, p) => n + p.records.length, 0);
  check(count <= 330000, "RESOURCE_LIMIT");
  const f = Buffer.alloc(12);
  f.writeUInt32BE(pages.length);
  f.writeBigUInt64BE(BigInt(count), 4);
  const h = createHash("sha256")
    .update(groupDomain("hash", "grant-inventory"))
    .update(f);
  pages.forEach((p, i) => {
    check(p.page_index === String(i), "INVALID_PAGE_ORDER");
    if (i) {
      check(
        p.service_id === pages[0].service_id &&
          p.group_id === pages[0].group_id &&
          p.operation_id === pages[0].operation_id,
        "GRANT_CONTEXT_MISMATCH",
      );
      check(
        grantOrder(pages[i - 1].records.at(-1)) < grantOrder(p.records[0]),
        "UNORDERED_OR_DUPLICATE",
      );
    }
    if (i < pages.length - 1 && p.records.length < 500)
      check(
        canonicalBytes(
          wire({ ...p, records: [...p.records, pages[i + 1].records[0]] }),
        ).length > 1048576,
        "INVALID_PAGE_PACKING",
      );
    const length = Buffer.alloc(12);
    length.writeUInt32BE(i);
    length.writeUInt32BE(p.records.length, 4);
    length.writeUInt32BE(groupEncode("grant-page", pageInputs[i]).length, 8);
    h.update(length).update(
      Buffer.from(groupDigest("grant-page", pageInputs[i]), "base64url"),
    );
  });
  return {
    digest: h.digest("base64url"),
    record_count: String(count),
    page_count: String(pages.length),
  };
}
