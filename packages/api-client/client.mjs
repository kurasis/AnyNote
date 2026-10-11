// P03 Node contract boundary. Production browser/native adapters belong to P05/P06.
import { readFileSync } from "node:fs";
import Ajv2020 from "ajv/dist/2020.js";
import { strictJson, ContractError } from "../protocol/src/strict-json.mjs";
import { decode as decodeProtocol } from "../protocol/src/protocol-codec.mjs";
const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url)));
const schemas = read("../contracts/generated/runtime-schemas.json");
const definitions = read("../contracts/p02-errors.json").errors;
const ajv = new Ajv2020({ strict: true, ownProperties: true });
const formats = new Set();
function collect(v) {
  if (v && typeof v === "object") {
    if (v.format) formats.add(v.format);
    Object.values(v).forEach(collect);
  }
}
schemas.forEach(collect);
for (const format of formats) {
  ajv.addFormat(format, (value) => {
    if (typeof value !== "string") return false;
    if (format.startsWith("decimal-")) {
      const max =
        format === "decimal-u63"
          ? 9223372036854775807n
          : BigInt(format.slice(8));
      return (
        /^(0|[1-9][0-9]*)$/.test(value) &&
        value.length <= String(max).length &&
        BigInt(value) <= max
      );
    }
    const bytes = Buffer.from(value, "base64url");
    if (
      !/^[A-Za-z0-9_-]*$/.test(value) ||
      bytes.toString("base64url") !== value
    )
      return false;
    if (/^base64url-\d+$/.test(format))
      return bytes.length === Number(format.slice(10));
    if (format === "base64url-variable") return true;
    if (format === "base64url-sealed")
      return value.length >= 64 && value.length <= 5462;
    if (format.startsWith("bounded-binary-"))
      return (
        value.length >= (format.endsWith("4096") ? 64 : 24) &&
        bytes.length <= Number(format.slice(15))
      );
    throw new ContractError("UNSUPPORTED_SCHEMA");
  });
}
schemas.forEach((schema) => ajv.addSchema(schema));
for (const schema of schemas) {
  for (const key of Object.keys(schema.$defs)) ajv.compile({ $ref: schema.$id + "#/$defs/" + key });
}

const api = schemas.at(-1);
const capabilities = ajv.compile({ $ref: api.$id + "#/$defs/capabilities" });
export function decodeCapabilities(bytes, expectedService) {
  const value = strictJson(bytes, 4096);
  if (!capabilities(value)) throw new ContractError("SCHEMA_MISMATCH");
  decodeProtocol("negotiation", Buffer.from(JSON.stringify(value.negotiation)));
  if (expectedService !== undefined && value.service_id !== expectedService)
    throw new ContractError("WRONG_SERVICE");
  return value;
}
export function decodeError(bytes, status) {
  const value = decodeProtocol("error-response", bytes);
  if (bytes.length > 4096) throw new ContractError("RESOURCE_LIMIT");
  const definition = definitions.find((e) => e.code === value.error.code);
  if (
    !definition ||
    definition.local_only ||
    definition.http_status !== status ||
    definition.message_key !== value.error.message_key ||
    definition.retryable !== value.error.retryable
  )
    throw new ContractError("ERROR_MAPPING_MISMATCH");
  if (
    ["NOT_FOUND", "ACCESS_REVOKED"].includes(definition.code) &&
    value.error.details.length !== 0
  )
    throw new ContractError("EXISTENCE_DISCLOSURE");
  return value;
}
export function requireConfiguredOrigin(origin) {
  const url = new URL(origin);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    url.origin !== origin
  )
    throw new ContractError("INVALID_API_ORIGIN");
  return origin;
}
