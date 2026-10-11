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
  const timings = {
    source_ms: 0,
    encrypt_ms: 0,
    persist_ms: 0,
    decrypt_verify_ms: 0,
  };
  let reader,
    parts = 0;
  try {
    for (let at = 0; at < size; at += chunk) {
      let before = performance.now();
      // P01 measured the wrapper's per-byte entropy bridge: use maintained
      // Web Crypto in <=64 KiB requests for bulk PUBLIC test source only.
      // Content keys/nonces continue to use libsodium's CSPRNG factories.
      let plain = new Uint8Array(Math.min(chunk, size - at));
      for (let offset = 0; offset < plain.length; offset += 65536)
        crypto.getRandomValues(
          plain.subarray(offset, Math.min(offset + 65536, plain.length)),
        );
      timings.source_ms += performance.now() - before;
      before = performance.now();
      const encrypted = w.encryptNext(plain);
      sodium.memzero(plain);
      plain = null;
      timings.encrypt_ms += performance.now() - before;
      before = performance.now();
      const handle = await dir.getFileHandle(String(parts), { create: true }),
        io = await handle.createSyncAccessHandle();
      try {
        let offset = 0;
        while (offset < encrypted.length) {
          const n = io.write(encrypted.subarray(offset), { at: offset });
          if (n <= 0) throw Error("INCOMPLETE_STORAGE_WRITE");
          offset += n;
        }
        io.flush();
      } finally {
        io.close();
      }
      parts++;
      timings.persist_ms += performance.now() - before;
      if (parts % 30 === 0)
        postMessage({ status: "PROGRESS", stage: "encrypted", chunks: parts });
    }
    const record = w.finish(
      "PUBLIC synthetic.bin",
      "application/octet-stream",
      key,
      issuer.privateKey,
    );
    reader = new FileReader(wire(record), key, issuer.publicKey, ctx);
    for (let n = 0; n < parts; n++) {
      const before = performance.now();
      const handle = await dir.getFileHandle(String(n)),
        io = await handle.createSyncAccessHandle();
      const cipher = new Uint8Array(Math.min(chunk, size - n * chunk) + 16);
      try {
        if (io.getSize() !== cipher.length) throw Error("INVALID_CHUNK_LENGTH");
        let offset = 0;
        while (offset < cipher.length) {
          const read = io.read(cipher.subarray(offset), { at: offset });
          if (read <= 0) throw Error("INCOMPLETE_STORAGE_READ");
          offset += read;
        }
      } finally {
        io.close();
      }
      const plain = reader.decryptNext(cipher);
      sodium.memzero(plain);
      timings.decrypt_verify_ms += performance.now() - before;
      if ((n + 1) % 30 === 0)
        postMessage({ status: "PROGRESS", stage: "verified", chunks: n + 1 });
    }
    if (!reader.finish().complete) throw Error("INCOMPLETE_FILE");
    return {
      status: "PASS",
      plaintext_bytes: size,
      chunks: parts,
      max_plain_chunk_bytes: chunk,
      elapsed_ms: Math.round(performance.now() - started),
      timings_ms: Object.fromEntries(
        Object.entries(timings).map(([key, value]) => [key, Math.round(value)]),
      ),
      storage:
        "owned OPFS ciphertext only; bounded sync access, no Blob/File accumulation",
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
  } catch (e) {
    // Test names are fixed PUBLIC corpus labels; never include rejected input.
    postMessage({
      status: "FAIL",
      code:
        e.code ??
        (e.message?.startsWith("P05_TEST_FAILURE:")
          ? e.message.slice(0, 160)
          : "P05_WORKER_TEST_FAILURE"),
    });
  } finally {
    busy = false;
  }
};
postMessage({ status: "READY" });
