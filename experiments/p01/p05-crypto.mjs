// Actual sandboxed Chromium/Worker + Rust + Node bridge; content-free report.
import { build } from "esbuild";
import { chromium } from "playwright-core";
import {
  existsSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  globSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { corpus } from "../../packages/protocol/p05-corpus.mjs";
import { runSuite } from "../../packages/protocol/p05-suite.mjs";
const root = resolve(import.meta.dirname, "../.."),
  out = join(root, "artifacts/p05");
mkdirSync(out, { recursive: true });
const inputPaths = [
  ...new Set([
    "experiments/p01/p05-crypto.mjs",
    "experiments/p01/package-lock.json",
    "packages/protocol/package-lock.json",
    "scripts/p05-port-codecs.py",
    ...globSync(
      [
        "packages/crypto-core/src/*.rs",
        "packages/crypto-core/Cargo.*",
        "packages/protocol/adapters/*.mjs",
        "packages/protocol/adapters/codecs/*.mjs",
        "packages/protocol/src/*.mjs",
        "packages/protocol/p05-*.mjs",
        "packages/contracts/*.schema.json",
        "packages/contracts/p02-errors.json",
      ],
      { cwd: root },
    ),
  ]),
].sort();
const sourceInputs = () =>
  inputPaths.map((path) => ({
    path,
    sha256: createHash("sha256")
      .update(readFileSync(join(root, path)))
      .digest("hex"),
  }));
const inputs = sourceInputs();
const f = corpus(),
  corpusPath = join(out, "public-corpus.json");
writeFileSync(corpusPath, JSON.stringify(f));
const native = join(
  root,
  "packages/crypto-core/target",
  process.env.P05_PROFILE ?? "debug",
  process.platform === "win32"
    ? "anynote-crypto-core.exe"
    : "anynote-crypto-core",
);
const exec = (args) => {
  const r = spawnSync(native, [corpusPath, ...args], {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  if (r.status !== 0) throw Error("NATIVE_CORPUS_FAILED");
  return JSON.parse(r.stdout);
};
const base = exec([]);
writeFileSync(join(out, "native-output.json"), JSON.stringify(base));
const node = await runSuite(f, base.peer);
writeFileSync(join(out, "node-peer.json"), JSON.stringify(node.peer));
const fromNode = exec([
  "--peer",
  join(out, "node-peer.json"),
  ...(process.argv.includes("--large") ? ["--large"] : []),
]);
const strip = ({ peer, ...metadata }) => metadata;
const report = {
  purpose: "P05 actual crypto interoperability and bounded resources",
  status: "PENDING",
  source_commit: spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: root,
    encoding: "utf8",
  }).stdout.trim(),
  source_tree_dirty:
    spawnSync("git", ["status", "--porcelain"], {
      cwd: root,
      encoding: "utf8",
    }).stdout.trim() !== "",
  physical_acceptance: false,
  inputs,
  fixture_inputs: f.fixture_inputs,
  native: strip(fromNode),
  node: strip(node),
  browser: { status: "NOT_RUN" },
};
const scratch = mkdtempSync(join(tmpdir(), "anynote-p05-browser-"));
for (const [name, entry] of Object.entries({
  "test-worker.js": "packages/protocol/p05-worker.mjs",
  "crypto-worker.js": "packages/protocol/adapters/worker.mjs",
  "client.js": "packages/protocol/adapters/worker-client.mjs",
}))
  await build({
    entryPoints: [join(root, entry)],
    outfile: join(scratch, name),
    bundle: true,
    platform: "browser",
    format: "esm",
    target: ["chrome120", "safari18"],
    logLevel: "silent",
  });
const server = createServer((req, res) => {
  const name = {
    "/test-worker.js": "test-worker.js",
    "/crypto-worker.js": "crypto-worker.js",
    "/client.js": "client.js",
  }[req.url];
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", name ? "text/javascript" : "text/html");
  res.end(
    name
      ? readFileSync(join(scratch, name))
      : "<!doctype html><title>PUBLIC P05 integration</title>",
  );
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
let context;
try {
  context = await chromium.launchPersistentContext(join(scratch, "profile"), {
    executablePath:
      process.env.CHROMIUM_EXECUTABLE ??
      ["/usr/bin/google-chrome", "/usr/bin/chromium"].find(existsSync) ??
      "/usr/bin/google-chrome",
    headless: true,
    chromiumSandbox: true,
  });
  const page = await context.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  const session = await context.browser().newBrowserCDPSession();
  let aggregateRss = 0;
  const sample = async () => {
    try {
      const { processInfo } = await session.send("SystemInfo.getProcessInfo");
      let sum = 0;
      for (const p of processInfo) {
        try {
          const x = readFileSync(`/proc/${p.id}/status`, "utf8").match(
            /^VmRSS:\s+(\d+)/m,
          );
          if (x) sum += Number(x[1]);
        } catch {}
      }
      aggregateRss = Math.max(aggregateRss, sum);
    } catch {}
  };
  const poll = setInterval(sample, 250);
  await sample();
  let result;
  try {
    result = await page.evaluate(
      async ({ f, peer, large }) => {
        const { CryptoWorker } = await import("/client.js");
        let ticks = 0,
          maxLag = 0,
          last = performance.now();
        const timer = setInterval(() => {
          const n = performance.now();
          maxLag = Math.max(maxLag, n - last - 50);
          last = n;
          ticks++;
        }, 50);
        const worker = new Worker("/test-worker.js", { type: "module" });
        await new Promise((resolve, reject) => {
          worker.onmessage = (e) => e.data.status === "READY" && resolve();
          worker.onerror = () => reject(Error("WORKER_INIT_FAILED"));
        });
        const call = (r) =>
          new Promise((resolve, reject) => {
            const deadline = setTimeout(
              () => reject(Error("WORKER_TIMEOUT")),
              600000,
            );
            worker.onmessage = (e) => {
              clearTimeout(deadline);
              resolve(e.data);
            };
            worker.onerror = () => {
              clearTimeout(deadline);
              reject(Error("WORKER_FAILED"));
            };
            worker.postMessage(r);
          });
        const client = new CryptoWorker("/crypto-worker.js");
        let rpc = 0;
        try {
          const suite = await call({ op: "suite", f, peer });
          if (suite.status !== "PASS") throw Error("SUITE_FAILED");
          const encoded = new TextEncoder().encode(
            JSON.stringify(f.notes.objects.parameters),
          );
          const phrase = client.call("phraseKek", [
            f.notes.inputs.phrase,
            encoded,
          ]);
          await new Promise((r) => setTimeout(r, 0));
          try {
            await client.call("phraseKek", [f.notes.inputs.phrase, encoded]);
            throw Error("ACCEPTED_CONCURRENT_RPC");
          } catch (e) {
            if (e.message !== "WORKER_BUSY") throw e;
          }
          rpc++;
          const kek = await phrase;
          if (
            Array.from(kek, (b) => b.toString(16).padStart(2, "0")).join("") !==
            f.notes.expected.phrase_kek_hex
          )
            throw Error("RPC_KDF_BYTES");
          kek.fill(0);
          rpc++;
          try {
            await client.call("notAnOperation", []);
            throw Error("ACCEPTED_UNKNOWN_RPC");
          } catch (e) {
            if (e.message !== "INVALID_WORKER_REQUEST") throw e;
          }
          rpc++;
          const sizes = large
              ? [0, 1, 8388607, 8388608, 8388609, 1000000000]
              : [0, 1, 8388609],
            files = [];
          for (const size of sizes) {
            const file = await call({ op: "large", f, size });
            if (file.status !== "PASS") throw Error("FILE_FAILED");
            files.push(file);
          }
          return {
            suite,
            files,
            rpc_checks: rpc,
            ui: { ticks, max_timer_lag_ms: Math.round(Math.max(0, maxLag)) },
          };
        } finally {
          client.close();
          worker.terminate();
          clearInterval(timer);
        }
      },
      { f, peer: base.peer, large: process.argv.includes("--large") },
    );
  } finally {
    clearInterval(poll);
    await sample();
  }
  writeFileSync(
    join(out, "browser-peer.json"),
    JSON.stringify(result.suite.peer),
  );
  const fromBrowser = exec(["--peer", join(out, "browser-peer.json")]);
  report.browser = {
    status: "PASS",
    ...strip(result.suite),
    files: result.files,
    rpc_checks: result.rpc_checks,
    ui: result.ui,
    version: context.browser().version(),
    sandbox: true,
    peak_sampled_aggregate_process_rss_kib: aggregateRss,
    rss_definition:
      "sum of Chromium process RSS sampled every 250 ms; shared pages may be counted more than once; not a hard memory ceiling",
  };
  report.browser_to_native = strip(fromBrowser);
  report.status = "PASS";
} catch (e) {
  if (
    process.argv.includes("--allow-cloud-sandbox-block") &&
    /No usable sandbox|Operation not permitted|Failed to move to new namespace|SUID sandbox helper binary/.test(
      e.message,
    )
  ) {
    report.browser = {
      status: "BLOCKED",
      reason:
        "Cloud sandbox unavailable; mandatory hosted Chromium check remains required",
    };
    report.status = "BLOCKED";
  } else {
    report.status = "FAIL";
    throw e;
  }
} finally {
  await context?.close();
  await new Promise((r) => server.close(r));
  rmSync(scratch, { recursive: true, force: true });
  writeFileSync(
    join(out, "crypto-report.json"),
    JSON.stringify(report, null, 2) + "\n",
  );
}
if (JSON.stringify(sourceInputs()) !== JSON.stringify(inputs))
  throw Error("SOURCE_CHANGED_DURING_CHECK");
console.log(
  JSON.stringify({
    status: report.status,
    native: report.native,
    node: report.node,
    browser: report.browser,
    browser_to_native: report.browser_to_native,
  }),
);
