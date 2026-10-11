// Actual owned loopback Nginx -> FPM -> Laravel contract checks, synthetic inputs only.
import http from "node:http";
import assert from "node:assert/strict";
import { writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { decodeCapabilities, decodeError } from "./client.mjs";
const port = Number(process.argv[2] ?? 18080);
assert.ok(Number.isInteger(port) && port >= 1024 && port <= 65535);
const origin = "http://app.anynote.test:" + port;
const cases = [];
async function request(
  path,
  { method = "GET", body, headers = {}, chunked = false } = {},
) {
  return await new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port,
        path,
        method,
        headers: {
          Host: "api.anynote.test",
          Accept: "application/json",
          ...headers,
          ...(body !== undefined && !chunked
            ? { "Content-Length": Buffer.byteLength(body) }
            : {}),
        },
      },
      (res) => {
        const parts = [];
        let size = 0;
        res.on("data", (v) => {
          size += v.length;
          if (size > 8192) {
            req.destroy(new Error("Unbounded response"));
            return;
          }
          parts.push(v);
        });
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(parts),
          }),
        );
      },
    );
    req.setTimeout(10000, () => req.destroy(new Error("Owned HTTP timeout")));
    req.on("error", reject);
    if (chunked) {
      for (let i = 0; i < body.length; i += 65536)
        req.write(body.subarray(i, i + 65536));
      req.end();
    } else req.end(body);
  });
}
const first = await request("/api/v1/capabilities", {
  headers: { Origin: origin, "X-Request-ID": "synthetic-hostile-id" },
});
assert.equal(first.status, 200);
decodeCapabilities(first.body, "AAAAAAAAAAAAAAAAAAAAAQ");
assert.equal(first.headers["access-control-allow-origin"], origin);
assert.equal(first.headers["access-control-allow-credentials"], "true");
assert.notEqual(first.headers["x-request-id"], "synthetic-hostile-id");
const second = await request("/api/v1/capabilities");
assert.notEqual(first.headers["x-request-id"], second.headers["x-request-id"]);
cases.push(
  "actual-public-capabilities-service-profile-false-features-fresh-request-id",
);
const failures = [
  [
    "/api/v1/capabilities",
    { headers: { "X-AnyNote-Profile": "p02-group-c1" } },
    400,
    "UNSUPPORTED_SCHEMA",
  ],
  [
    "/api/v1/capabilities",
    { headers: { Origin: "https://hostile.anynote.test" } },
    404,
    "NOT_FOUND",
  ],
  ["/api/v1/objects/AAAAAAAAAAAAAAAAAAAAAQ/revisions", {}, 404, "NOT_FOUND"],
  ["/api/v1/objects/AAAAAAAAAAAAAAAAAAAAAg/revisions", {}, 404, "NOT_FOUND"],
  [
    "/api/v1/auth/passkeys/verify",
    {
      method: "POST",
      body: '{"credential":"synthetic"}',
      headers: { "Content-Type": "application/json" },
    },
    404,
    "NOT_FOUND",
  ],
  [
    "/api/v1/groups",
    {
      method: "POST",
      body: '{"a":1,"\\u0061":2}',
      headers: { "Content-Type": "application/json" },
    },
    400,
    "INVALID_REQUEST",
  ],
  [
    "/api/v1/groups",
    {
      method: "POST",
      body: Buffer.from([123, 34, 255, 34, 58, 49, 125]),
      headers: { "Content-Type": "application/json" },
    },
    400,
    "INVALID_REQUEST",
  ],
  [
    "/api/v1/groups",
    {
      method: "POST",
      body: '{"a":1}',
      headers: { "Content-Type": "text/plain" },
    },
    400,
    "INVALID_REQUEST",
  ],
  [
    "/api/v1/groups",
    {
      method: "POST",
      body: "{",
      headers: { "Content-Type": "application/json" },
    },
    400,
    "INVALID_REQUEST",
  ],
  [
    "/api/v1/groups",
    {
      method: "POST",
      body: Buffer.alloc(4194305, 32),
      headers: { "Content-Type": "application/json" },
    },
    413,
    "REQUEST_TOO_LARGE",
  ],
  [
    "/api/v1/groups",
    {
      method: "POST",
      body: Buffer.alloc(4194305, 32),
      chunked: true,
      headers: { "Content-Type": "application/json" },
    },
    413,
    "REQUEST_TOO_LARGE",
  ],
  [
    "/api/v1/capabilities",
    {
      method: "OPTIONS",
      headers: {
        Origin: origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "x-private-exfiltration",
      },
    },
    404,
    "NOT_FOUND",
  ],
];
for (const [path, options, status, code] of failures) {
  const r = await request(path, options);
  assert.equal(r.status, status);
  const e = decodeError(r.body, status).error;
  assert.equal(e.code, code);
  assert.equal(e.request_id, r.headers["x-request-id"]);
  assert.deepEqual(e.details, []);
  assert.ok(r.headers["cache-control"].includes("no-store"));
  assert.equal(r.headers["x-content-type-options"], "nosniff");
  if (options.headers?.Origin === "https://hostile.anynote.test")
    assert.equal(r.headers["access-control-allow-origin"], undefined);
  cases.push(
    code + ":" + (options.chunked ? "chunked" : (options.method ?? "GET")),
  );
}
const cors = await request("/api/v1/auth/passkeys/verify", {
  method: "OPTIONS",
  headers: {
    Origin: origin,
    "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers":
      "content-type,x-csrf-token,x-anynote-profile",
  },
});
assert.equal(cors.status, 204);
assert.equal(cors.headers["access-control-allow-origin"], origin);
cases.push("exact-credentialed-preflight");
const edge = await request("/api/v1/capabilities", {
  headers: { ANYNOTE_EDGE_ERROR: "request-too-large" },
});
assert.equal(edge.status, 200);
cases.push("client-cannot-forge-trusted-fastcgi-edge-error");
const hostile = "synthetic_log_boundary_9382";
const poison = await request("/api/v1/groups?title=" + hostile, {
  method: "POST",
  body: '{"title":"' + hostile + '","private_key":"synthetic"}',
  headers: {
    "Content-Type": "application/json",
    Authorization: "Bearer " + hostile,
    Cookie: "anynote_session=" + hostile,
  },
});
assert.equal(poison.status, 404);
decodeError(poison.body, 404);
const logPath = new URL("../../apps/api/storage/logs/", import.meta.url);
// The logger's owned source has only content-free JSON records; no raw log artifact is uploaded.
const { readdirSync } = await import("node:fs");
let records = 0;
for (const file of readdirSync(logPath).filter((f) =>
  /^content-free-\d{4}-\d{2}-\d{2}\.jsonl$/.test(f),
)) {
  const text = readFileSync(new URL(file, logPath), "utf8");
  assert.ok(!text.includes(hostile));
  for (const line of text.trim().split("\n").filter(Boolean)) {
    assert.ok(Buffer.byteLength(line) < 512);
    const value = JSON.parse(line);
    assert.ok(
      Object.keys(value).every((k) =>
        [
          "event",
          "status",
          "method",
          "elapsed_ms",
          "request_id",
          "route_id",
          "code",
        ].includes(k),
      ),
    );
    records++;
  }
}
assert.ok(records > 0);
cases.push(
  "persisted-content-free-logger-hostile-body-cookie-token-query-denial",
);
const inputs = [
  "packages/api-client/client.mjs",
  "packages/api-client/http-check.mjs",
  "packages/contracts/generated/manifest.json",
  "infra/dev/nginx.conf",
  "infra/dev/php/php.ini",
  "apps/api/app/Http/Middleware/ApiBoundary.php",
];
const sha256 = Object.fromEntries(
  inputs.map((p) => [
    p,
    createHash("sha256")
      .update(readFileSync(new URL("../../" + p, import.meta.url)))
      .digest("hex"),
  ]),
);
const report = {
  status: "PASS",
  scope: "P03_ACTUAL_OWNED_LOOPBACK_HTTP_NOT_PRODUCT_AUTH_OR_DEPLOYMENT",
  checks: cases.length,
  cases,
  source_commit: execFileSync("git", ["rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim(),
  source_tree_dirty: !!execFileSync("git", ["status", "--porcelain"], {
    encoding: "utf8",
  }).trim(),
  source_inputs: sha256,
  log_records_inspected: records,
};
mkdirSync(new URL("../../artifacts/p03/", import.meta.url), {
  recursive: true,
});
writeFileSync(
  new URL("../../artifacts/p03/http-contract-report.json", import.meta.url),
  JSON.stringify(report, null, 2) + "\n",
);
console.log(
  JSON.stringify({
    status: "PASS",
    checks: cases.length,
    log_records_inspected: records,
    scope: report.scope,
  }),
);
