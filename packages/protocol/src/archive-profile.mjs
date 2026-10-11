// Strict uncompressed USTAR profile; never extracts files or interprets archive paths.
import { requireCondition as check } from "./strict-json.mjs";
export const ARCHIVE_LIMIT = 100000000000n + 16n * 1024n * 1024n * 1024n;
export const generatedPath = (path) =>
  /^(export-header\.json|export-footer\.json|identity\/evidence\.json|identity\/accounts\/[A-Za-z0-9_-]{22}\/(?:identity\.json|roster\/[0-9]{8}\.json)|identity\/groups\/[A-Za-z0-9_-]{22}\/(?:genesis\.json|history\/checkpoint\.json|history\/pages\/[0-9]{8}\.json|journal\/[0-9]{8}\.json|grants\/[A-Za-z0-9_-]{22}\/[0-9]{8}\.json)|records\/[A-Za-z0-9_-]{22}\.json|keys\/[A-Za-z0-9_-]{22}\.json|files\/[A-Za-z0-9_-]{22}\/[0-9]{8}\.bin|(?:inventory|snapshots)\/[0-9]{8}\.json)$/.test(
    path,
  ) && path.length <= 100;
export function entryCap(path) {
  return path.startsWith("files/")
    ? 8388624
    : path === "identity/evidence.json"
      ? 16777216
      : path.startsWith("identity/")
        ? 1048576
        : path.startsWith("records/")
          ? 4194304
          : path.startsWith("inventory/") || path.startsWith("snapshots/")
            ? 1048576
            : 65536;
}
function octal(n, width) {
  const s = n.toString(8);
  check(s.length <= width - 1, "RESOURCE_LIMIT");
  return s.padStart(width - 1, "0") + "\0";
}
export function archiveHeader(path, size) {
  check(generatedPath(path), "UNSAFE_ARCHIVE_PATH");
  check(
    Number.isSafeInteger(size) && size >= 0 && size <= entryCap(path),
    "RESOURCE_LIMIT",
  );
  const b = Buffer.alloc(512);
  b.write(path);
  b.write(octal(384, 8), 100);
  b.write(octal(0, 8), 108);
  b.write(octal(0, 8), 116);
  b.write(octal(size, 12), 124);
  b.write(octal(0, 12), 136);
  b.fill(32, 148, 156);
  b[156] = 48;
  b.write("ustar\0", 257);
  b.write("00", 263);
  const sum = b.reduce((a, v) => a + v, 0);
  b.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return b;
}
export async function* encodeArchiveForEvaluation(entries) {
  let total = 0n,
    count = 0;
  const seen = new Set();
  for (const { path, bytes } of entries) {
    check(bytes instanceof Uint8Array, "RAW_BYTES_REQUIRED");
    check(!seen.has(path), "DUPLICATE_ARCHIVE_PATH");
    seen.add(path);
    check(++count <= 4008003, "RESOURCE_LIMIT");
    const header = archiveHeader(path, bytes.length),
      pad = (512 - (bytes.length % 512)) % 512;
    total += BigInt(512 + bytes.length + pad);
    check(total + 1024n <= ARCHIVE_LIMIT, "RESOURCE_LIMIT");
    yield header;
    yield bytes;
    if (pad) yield Buffer.alloc(pad);
  }
  yield Buffer.alloc(1024);
}
// Bounded fixture collector, not a product 100 GB memory implementation.
export async function collectArchiveForEvaluation(entries) {
  let size = 0;
  const out = [];
  for await (const b of encodeArchiveForEvaluation(entries)) {
    size += b.length;
    check(size <= 16777216, "EVALUATION_RESOURCE_LIMIT");
    out.push(b);
  }
  return Buffer.concat(out);
}
export async function decodeArchiveForEvaluation(stream, visit) {
  let stash = Buffer.alloc(0),
    offset = 0,
    observed = 0n,
    count = 0,
    ended = false;
  const seen = new Set();
  const iterator = stream[Symbol.asyncIterator]();
  async function read(n) {
    check(n <= 16777216, "RESOURCE_LIMIT");
    while (stash.length - offset < n) {
      const r = await iterator.next();
      check(!r.done, "EXPORT_TRUNCATED");
      check(
        r.value instanceof Uint8Array && r.value.length <= 16777216,
        "RESOURCE_LIMIT",
      );
      observed += BigInt(r.value.length);
      check(observed <= ARCHIVE_LIMIT, "RESOURCE_LIMIT");
      stash = Buffer.concat([stash.subarray(offset), r.value]);
      offset = 0;
    }
    const b = stash.subarray(offset, offset + n);
    offset += n;
    return b;
  }
  while (!ended) {
    const h = Buffer.from(await read(512));
    if (h.every((v) => v === 0)) {
      check(
        (await read(512)).every((v) => v === 0),
        "INVALID_ARCHIVE_END",
      );
      ended = true;
      break;
    }
    const zero = h.indexOf(0, 0);
    check(zero > 0 && zero <= 100, "UNSAFE_ARCHIVE_PATH");
    const path = h.subarray(0, zero).toString("ascii");
    check(generatedPath(path), "UNSAFE_ARCHIVE_PATH");
    check(!seen.has(path), "DUPLICATE_ARCHIVE_PATH");
    seen.add(path);
    check(++count <= 4008003, "RESOURCE_LIMIT");
    const oct = h.subarray(124, 136).toString("ascii");
    check(/^[0-7]{11}\0$/.test(oct), "INVALID_ARCHIVE_HEADER");
    const size = parseInt(oct, 8);
    check(size <= entryCap(path), "RESOURCE_LIMIT");
    check(h.equals(archiveHeader(path, size)), "INVALID_ARCHIVE_HEADER");
    const bytes = Buffer.from(await read(size));
    const pad = (512 - (size % 512)) % 512;
    check(
      (await read(pad)).every((v) => v === 0),
      "INVALID_ARCHIVE_PADDING",
    );
    await visit({ path, bytes });
  }
  check(offset === stash.length, "TRAILING_ARCHIVE_DATA");
  for (;;) {
    const r = await iterator.next();
    if (r.done) break;
    check(
      r.value instanceof Uint8Array && r.value.length === 0,
      "TRAILING_ARCHIVE_DATA",
    );
  }
  return { entries: count, observed_bytes: String(observed) };
}
