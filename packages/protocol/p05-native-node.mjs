// Portable public cross-runtime runner, including actual Windows/MSVC execution.
import { corpus } from "./p05-corpus.mjs";
import { runSuite } from "./p05-suite.mjs";
import { writeFileSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
const root = resolve(import.meta.dirname, "../.."),
  out = join(root, "artifacts/p05");
mkdirSync(out, { recursive: true });
const f = corpus(),
  path = join(out, "public-corpus.json");
writeFileSync(path, JSON.stringify(f));
const exe = join(
  root,
  "packages/crypto-core/target",
  process.env.P05_PROFILE ?? "debug",
  process.platform === "win32"
    ? "anynote-crypto-core.exe"
    : "anynote-crypto-core",
);
const run = (args) => {
  const x = spawnSync(exe, [path, ...args], {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  if (x.status !== 0) throw Error("NATIVE_CORPUS_FAILED");
  return JSON.parse(x.stdout);
};
const native = run([]);
writeFileSync(join(out, "native-output.json"), JSON.stringify(native));
const node = await runSuite(f, native.peer);
writeFileSync(join(out, "node-peer.json"), JSON.stringify(node.peer));
const back = run(["--peer", join(out, "node-peer.json")]);
const strip = ({ peer, ...x }) => x;
const report = {
  status: "PASS",
  purpose: "P05 actual native/Node PUBLIC interoperability",
  platform: process.platform,
  source_commit: spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: root,
    encoding: "utf8",
  }).stdout.trim(),
  source_tree_dirty:
    spawnSync("git", ["status", "--porcelain"], {
      cwd: root,
      encoding: "utf8",
    }).stdout.trim() !== "",
  native: strip(back),
  node: strip(node),
  fixture_inputs: f.fixture_inputs,
  physical_acceptance: false,
};
writeFileSync(
  join(
    out,
    process.platform === "win32"
      ? "windows-report.json"
      : "native-node-report.json",
  ),
  JSON.stringify(report, null, 2) + "\n",
);
console.log(JSON.stringify(report));
