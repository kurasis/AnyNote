import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  decodeCapabilities,
  decodeError,
  requireConfiguredOrigin,
} from "../client.mjs";
const json = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url)));
const error = (code) => {
  const e = json("../../contracts/p02-errors.json").errors.find(
    (e) => e.code === code,
  );
  return {
    error: {
      code,
      message_key: e.message_key,
      request_id: "AAAAAAAAAAAAAAAAAAAAAg",
      retryable: e.retryable,
      details: [],
    },
  };
};
const bytes = (v) => Buffer.from(JSON.stringify(v));
const cap = {
  service_id: "AAAAAAAAAAAAAAAAAAAAAQ",
  negotiation: {
    contract: "p02-v1",
    protocol: "anynote",
    protocol_version: 1,
    purpose: "protocol-negotiation",
    profile: "p02-v1",
    api_version: 1,
    wire_version: 1,
    payload_version: 1,
    local_schema: 1,
    export_version: 1,
    minimum_reader: 1,
    minimum_writer: 1,
    components: [
      "p02-file-c1",
      "p02-identity-c1",
      "p02-state-c1",
      "p02-group-c2",
      "p02-v1",
    ],
  },
  limits: {
    control_bytes: "4194304",
    page_bytes: "1048576",
    file_plaintext_bytes: "1000000000",
    global_ciphertext_bytes: "100000000000",
    group_members: 20,
  },
  features: {
    account_authentication: false,
    device_activation: false,
    content_storage: false,
    sync: false,
    file_transfer: false,
    production_ready: false,
  },
};
test("capabilities enforce independent service, complete components, unavailable features and exact versions", () => {
  assert.equal(
    decodeCapabilities(bytes(cap), cap.service_id).service_id,
    cap.service_id,
  );
  assert.throws(() => decodeCapabilities(bytes(cap), "different-service"));
  for (const mutate of [
    (v) => (v.features.production_ready = true),
    (v) => v.negotiation.components.reverse(),
    (v) => (v.negotiation.wire_version = 2),
    (v) => (v.limits.file_plaintext_bytes = "10"),
    (v) => (v.token = "unknown"),
  ]) {
    const v = structuredClone(cap);
    mutate(v);
    assert.throws(() => decodeCapabilities(bytes(v)));
  }
});
test("all 39 HTTP errors have fixed safe mappings; 3 local errors cannot masquerade as HTTP", () => {
  for (const e of json("../../contracts/p02-errors.json").errors) {
    if (e.local_only)
      assert.throws(() => decodeError(bytes(error(e.code)), 400));
    else {
      assert.equal(
        decodeError(bytes(error(e.code)), e.http_status).error.code,
        e.code,
      );
      assert.throws(() => decodeError(bytes(error(e.code)), 200));
      for (const mutation of [
        (v) => (v.error.message_key = "SQL_PASSWORD"),
        (v) => (v.error.retryable = !v.error.retryable),
        (v) => (v.error.extra = "secret"),
      ]) {
        const v = error(e.code);
        mutation(v);
        assert.throws(() => decodeError(bytes(v), e.http_status));
      }
    }
  }
});
test("raw duplicate properties, invalid UTF-8, depth/byte overflow and error existence disclosure are rejected", () => {
  assert.throws(() =>
    decodeCapabilities(Buffer.from('{"service_id":"one","service_id":"two"}')),
  );
  assert.throws(() =>
    decodeCapabilities(Buffer.from([123, 34, 255, 34, 58, 49, 125])),
  );
  assert.throws(() =>
    decodeCapabilities(Buffer.from("[".repeat(33) + "0" + "]".repeat(33))),
  );
  assert.throws(() => decodeCapabilities(Buffer.alloc(4097, 32)));
  const v = error("NOT_FOUND");
  v.error.details = [{ key: "required_bytes", value: "1" }];
  assert.throws(() => decodeError(bytes(v), 404));
});
test("configured API origin is exact HTTPS with no userinfo, path or redirect target", () => {
  assert.equal(
    requireConfiguredOrigin("https://api.anynote.test"),
    "https://api.anynote.test",
  );
  for (const v of [
    "http://api.anynote.test",
    "https://user:password@api.anynote.test",
    "https://api.anynote.test/path",
    "https://api.anynote.test/?token=x",
    "https://api.anynote.test/",
    "https://api.anynote.test#fragment",
  ])
    assert.throws(() => requireConfiguredOrigin(v));
});
test("OpenAPI local refs and operation signatures resolve; future product paths cannot be executable stubs", () => {
  const spec = json("../../contracts/generated/openapi.json");
  const visit = (v) => {
    if (v && typeof v === "object") {
      if (v.$ref) {
        assert.ok(v.$ref.startsWith("#/components/schemas/"));
        assert.ok(spec.components.schemas[v.$ref.slice(21)]);
      }
      Object.values(v).forEach(visit);
    }
  };
  visit(spec);
  const ids = new Set();
  for (const [path, methods] of Object.entries(spec.paths))
    for (const [method, op] of Object.entries(methods)) {
      assert.ok(!ids.has(op.operationId));
      ids.add(op.operationId);
      for (const parameter of op.parameters)
        assert.ok(path.includes("{" + parameter.name + "}"));
      assert.equal(op["x-implemented"], ["P06", "P08", "P09", "P10", "P11"].includes(op["x-implementation-phase"]) || ["get_capabilities", "get_health_live", "get_health_ready"].includes(op.operationId));
      if (op.operationId === "get_health_ready") assert.deepEqual(op.security, [{NativeBearer:[]}]);
      if (op["x-implemented"] && !["P06", "P08", "P09", "P10", "P11"].includes(op["x-implementation-phase"])) assert.ok(["get", "head"].includes(method));
      if (["P06", "P08", "P09", "P10", "P11"].includes(op["x-implementation-phase"])) assert.ok(op.responses["200"].content["application/json"].schema.$ref);
      assert.ok(!path.includes("/search"));
    }
  assert.equal(ids.size, 97);
});
