// Dedicated-worker adapter. One bounded operation; no persisted keys or user logs.
import {
  sealObject,
  openObject,
  sealLocal,
  openLocal,
  phraseKek,
  prfKek,
  wrapLocalKey,
  unwrapLocalKey,
} from "./objects.mjs";
import { nativeKek, wrapNative, unwrapNative } from "./local.mjs";
import { sodium } from "./primitives.mjs";
import { ContractError } from "../src/strict-json.mjs";
const operations = {
  sealObject,
  openObject,
  sealLocal,
  openLocal,
  phraseKek,
  prfKek,
  wrapLocalKey,
  unwrapLocalKey,
  nativeKek,
  wrapNative,
  unwrapNative,
};
let busy = false;
const clean = (x) => {
  if (x instanceof Uint8Array) sodium.memzero(x);
  else if (Array.isArray(x)) x.forEach(clean);
};
self.onmessage = async ({ data: r }) => {
  let valid =
    r &&
    Object.keys(r).sort().join(",") === "args,id,op,version" &&
    r.version === 1 &&
    Number.isSafeInteger(r.id) &&
    r.id > 0 &&
    Object.hasOwn(operations, r.op) &&
    Array.isArray(r.args) &&
    r.args.length <= 6;
  if (valid) {
    let bytes = 0;
    for (const a of r.args) {
      if (a instanceof Uint8Array) bytes += a.byteLength;
      else if (typeof a === "string")
        bytes += new TextEncoder().encode(a).length;
      else valid = false;
    }
    valid &&= bytes <= 8388608;
  }
  if (!valid || busy) {
    clean(r?.args);
    postMessage({
      version: 1,
      id: Number.isSafeInteger(r?.id) ? r.id : 0,
      error: busy ? "WORKER_BUSY" : "INVALID_WORKER_REQUEST",
    });
    return;
  }
  busy = true;
  try {
    const result = await operations[r.op](...r.args);
    postMessage({ version: 1, id: r.id, result });
    clean(result);
  } catch (e) {
    postMessage({
      version: 1,
      id: r.id,
      error: e instanceof ContractError ? e.code : "CRYPTO_FAILURE",
    });
  } finally {
    clean(r.args);
    busy = false;
  }
};
// Vendor initialization has completed and the listener exists before input is sent.
postMessage({ version: 1, status: "READY" });
