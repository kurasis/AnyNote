// PUBLIC integration harness only; never bundled as an application endpoint.
import { runSuite } from "./p05-suite.mjs";
import { FileWriter, FileReader, b64, Buffer } from "./adapters/core.mjs";
import { sodium } from "./adapters/primitives.mjs";
const wire = (x) => Buffer.from(JSON.stringify(x));
async function large(f, size) {
  const started = performance.now(),
    chunk = 8388608;
  const root = await navigator.storage.getDirectory(),
    name = "p05-" + crypto.randomUUID();
  const dir = await root.getDirectoryHandle(name, { create: true });
  const id = f.identity,
    ctx = wire(id.outputs.file_context),
    key = Uint8Array.from({ length: 32 }, (_, i) => (144 + i) % 256),
    issuer = sodium.crypto_sign_seed_keypair(
      Buffer.from(id.input.device_signing_seed_hex, "hex"),
    );
  const w = new FileWriter(ctx, size);
  let reader,
    parts = 0;
  try {
    for (let at = 0; at < size; at += chunk) {
      let plain = sodium.randombytes_buf(Math.min(chunk, size - at));
      const encrypted = w.encryptNext(plain);
      sodium.memzero(plain);
      plain = null;
      const handle = await dir.getFileHandle(String(parts), { create: true }),
        out = await handle.createWritable();
      try {
        await out.write(encrypted);
      } finally {
        await out.close();
      }
      parts++;
    }
    const record = w.finish(
      "PUBLIC synthetic.bin",
      "application/octet-stream",
      key,
      issuer.privateKey,
    );
    reader = new FileReader(wire(record), key, issuer.publicKey, ctx);
    for (let n = 0; n < parts; n++) {
      const handle = await dir.getFileHandle(String(n)),
        file = await handle.getFile(),
        cipher = new Uint8Array(await file.arrayBuffer());
      const plain = reader.decryptNext(cipher);
      sodium.memzero(plain);
    }
    if (!reader.finish().complete) throw Error("INCOMPLETE_FILE");
    return {
      status: "PASS",
      plaintext_bytes: size,
      chunks: parts,
      max_plain_chunk_bytes: chunk,
      elapsed_ms: Math.round(performance.now() - started),
      storage: "owned OPFS ciphertext only",
      wasm_heap_bytes: sodium.libsodium?.HEAPU8?.buffer.byteLength ?? null,
      physical_acceptance: false,
    };
  } finally {
    w.close();
    reader?.close();
    sodium.memzero(key);
    sodium.memzero(issuer.privateKey);
    await root.removeEntry(name, { recursive: true });
  }
}
let busy = false;
self.onmessage = async ({ data: r }) => {
  if (busy) {
    postMessage({ status: "FAIL", code: "WORKER_BUSY" });
    return;
  }
  busy = true;
  try {
    if (r.f?.purpose !== "PUBLIC_TEST_ONLY_NOT_PRODUCT_AUTHORIZATION")
      throw Error("PUBLIC_ONLY");
    const result =
      r.op === "suite"
        ? await runSuite(r.f, r.peer)
        : r.op === "large"
          ? await large(r.f, r.size)
          : null;
    if (!result) throw Error("INVALID_OPERATION");
    postMessage(result);
  } catch {
    postMessage({ status: "FAIL", code: "P05_WORKER_TEST_FAILURE" });
  } finally {
    busy = false;
  }
};
postMessage({ status: "READY" });
