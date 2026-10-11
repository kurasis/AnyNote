// Deterministic contract model. No HTTP auth, SQL durability or global freshness.
import { createHash } from "node:crypto";
import { requireCondition as check } from "./strict-json.mjs";
import { wire, same } from "./identity-codec.mjs";
import {
  common,
  decode,
  encode,
  digest,
  domain,
  rawDigest,
} from "./protocol-codec.mjs";
const pins = new WeakMap();
export function mutationLedgerForEvaluation(cursorBytes, authorize) {
  const token = Object.freeze({ scope: "SYNTHETIC_ATOMIC_MODEL" });
  check(typeof authorize === "function", "AUTHORIZER_REQUIRED");
  pins.set(token, {
    cursor: decode("cursor", cursorBytes),
    authorize,
    receipts: new Map(),
    revisions: new Map(),
    heads: new Map(),
    events: [],
    quarantine: false,
  });
  return token;
}
function state(t) {
  check(pins.has(t), "LEDGER_PROOF_REQUIRED");
  return pins.get(t);
}
function observedFrame(bundle) {
  const header = bundle.envelope.header;
  const ciphertext = Buffer.from(bundle.ciphertext, "base64url");
  check(
    String(ciphertext.length) === header.ciphertext_bytes &&
      rawDigest(ciphertext) === header.ciphertext_digest,
    "CIPHERTEXT_MISMATCH",
  );
  check(
    digest("wrap", wire(bundle.wrap)) === header.key_wrap_digest,
    "KEY_WRAP_MISMATCH",
  );
}
export function commitMutationForEvaluation(t, bundleBytes) {
  const s = state(t);
  check(!s.quarantine, "RESTORE_QUARANTINE");
  const b = decode("bundle", bundleBytes),
    c = b.envelope.header.context,
    scope =
      c.author.account_id + "/" + c.author.device_id + "/" + c.operation_id;
  const d = digest("bundle", bundleBytes),
    old = s.receipts.get(scope),
    revision = s.revisions.get(c.revision_id);
  // Reconcile an already committed operation under current read authorization.
  // Its old policy/roster precondition is not a fresh publication precondition.
  // The trusted callback must bind the actual current requester, not the author
  // named by untrusted request bytes. No account/session authentication is simulated here.
  s.authorize(encode("envelope", wire(b.envelope)), {
    operation: old || revision ? "reconcile" : "publish",
  });
  observedFrame(b);
  if (old) {
    check(old.attempt_digest === d, "IDEMPOTENCY_MISMATCH");
    return structuredClone(old.receipt);
  }
  if (revision) {
    check(
      revision.attempt_digest === d && revision.scope === scope,
      "REVISION_ID_CONFLICT",
    );
    return structuredClone(revision.receipt);
  }
  const object = c.group_id + "/" + c.object_kind + "/" + c.object_id,
    heads = s.heads.get(object) ?? new Map();
  check(
    c.parents.length === heads.size &&
      c.parents.every((p) => heads.get(p.revision_id) === p.envelope_digest),
    "STALE_REVISION",
  );
  check(BigInt(s.cursor.sequence) < 9223372036854775807n, "RESOURCE_LIMIT");
  const cursor = {
      ...s.cursor,
      sequence: String(BigInt(s.cursor.sequence) + 1n),
    },
    receipt = {
      ...common("mutation-receipt"),
      operation_id: c.operation_id,
      revision_id: c.revision_id,
      envelope_digest: digest("envelope", wire(b.envelope)),
      status: "COMMITTED",
      cursor,
    };
  decode("receipt", wire(receipt));
  const event = {
    event_id: c.operation_id,
    sequence: cursor.sequence,
    group_id: c.group_id,
    object_kind: c.object_kind,
    object_id: c.object_id,
    revision_id: c.revision_id,
    digest: receipt.envelope_digest,
  };
  // All admission completes before this synchronous mutation boundary.
  s.cursor = cursor;
  s.heads.set(object, new Map([[c.revision_id, receipt.envelope_digest]]));
  const row = { attempt_digest: d, receipt, scope };
  s.receipts.set(scope, row);
  s.revisions.set(c.revision_id, row);
  s.events.push(event);
  return structuredClone(receipt);
}
export function expireReceiptsForEvaluation(t) {
  state(t).receipts.clear();
}
export function reconcileAttemptForEvaluation(t, outboxBytes) {
  const s = state(t),
    o = decode("outbox", outboxBytes),
    c = o.bundle.envelope.header.context;
  check(
    o.attempt_id === c.operation_id &&
      o.revision_id === c.revision_id &&
      o.attempt_digest === digest("bundle", wire(o.bundle)),
    "ATTEMPT_CONTEXT_MISMATCH",
  );
  s.authorize(encode("envelope", wire(o.bundle.envelope)), {
    operation: "reconcile",
  });
  observedFrame(o.bundle);
  const r = s.revisions.get(o.revision_id);
  if (r) {
    check(r.attempt_digest === o.attempt_digest, "REVISION_ID_CONFLICT");
    return { state: "COMMITTED", receipt: structuredClone(r.receipt) };
  }
  return {
    state: "SENT_UNKNOWN",
    action: "RETRY_IDENTICAL_BYTES_WITH_PRECONDITIONS",
  };
}
export function restoreTransportForEvaluation(t, generation) {
  const s = state(t);
  decode("cursor", wire({ generation, sequence: "0" }));
  check(generation !== s.cursor.generation, "TRANSPORT_GENERATION_REUSE");
  s.cursor = { generation, sequence: "0" };
  s.quarantine = true;
  s.receipts.clear();
  return {
    state: "RESTORE_QUARANTINE",
    restored_sessions: "ALL_REVOKED_REQUIRED_IN_PRODUCT",
  };
}
export function validateSyncPageForEvaluation(bytes, expectedCursorBytes) {
  const p = decode("sync-page", bytes),
    expected = decode("cursor", expectedCursorBytes);
  check(same(p.from_cursor, expected), "SYNC_CURSOR_EXPIRED");
  check(
    p.next_cursor.generation === expected.generation &&
      p.watermark.generation === expected.generation,
    "SYNC_CURSOR_EXPIRED",
  );
  let n = BigInt(expected.sequence);
  for (const e of p.events) {
    check(BigInt(e.sequence) === ++n, "SYNC_GAP");
  }
  check(
    BigInt(p.next_cursor.sequence) === n &&
      n <= BigInt(p.watermark.sequence) &&
      (!p.complete || n === BigInt(p.watermark.sequence)),
    "SYNC_WATERMARK_MISMATCH",
  );
  return p;
}
export function pageCommitmentForEvaluation(family, pageBytes) {
  check(
    ["snapshot", "export"].includes(family) &&
      Array.isArray(pageBytes) &&
      pageBytes.length <= 8000,
    "RESOURCE_LIMIT",
  );
  check(
    pageBytes.reduce((n, b) => n + b.length, 0) <= 16777216,
    "EVALUATION_RESOURCE_LIMIT",
  );
  const kind = family + "-page",
    pages = pageBytes.map((b) => decode(kind, b)),
    total = pages.reduce((n, p) => n + p.items.length, 0);
  check(total <= 4000000, "RESOURCE_LIMIT");
  const framing = Buffer.alloc(12);
  framing.writeUInt32BE(pages.length);
  framing.writeBigUInt64BE(BigInt(total), 4);
  const h = createHash("sha256")
    .update(domain("hash", family + "-inventory"))
    .update(framing);
  let last = "";
  for (let i = 0; i < pages.length; i++) {
    const p = pages[i];
    check(
      p.page_index === String(i) &&
        p[family + "_id"] === pages[0][family + "_id"],
      "INVALID_PAGE_ORDER",
    );
    check(p.items.length > 0, "EMPTY_PAGE");
    for (const item of p.items) {
      const k =
        family === "export"
          ? item.path
          : item.group_id +
            "/" +
            item.object_kind +
            "/" +
            item.object_id +
            "/" +
            item.revision_id;
      check(k > last, "UNORDERED_OR_DUPLICATE");
      last = k;
    }
    if (i < pages.length - 1 && p.items.length < 500) {
      let combined = wire({ ...p, items: [...p.items, pages[i + 1].items[0]] });
      check(combined.length > 1048576, "INVALID_PAGE_PACKING");
    }
    const f = Buffer.alloc(12);
    f.writeUInt32BE(i);
    f.writeUInt32BE(p.items.length, 4);
    f.writeUInt32BE(encode(kind, pageBytes[i]).length, 8);
    h.update(f).update(Buffer.from(digest(kind, pageBytes[i]), "base64url"));
  }
  return {
    inventory_digest: h.digest("base64url"),
    page_count: String(pages.length),
    item_count: String(total),
  };
}
export function verifySnapshotForEvaluation(
  descriptorBytes,
  pageBytes,
  now,
  authorize,
) {
  const d = decode("snapshot-descriptor", descriptorBytes);
  check(
    typeof now === "bigint" &&
      now >= BigInt(d.created_at) &&
      now < BigInt(d.expires_at),
    "SNAPSHOT_EXPIRED",
  );
  const lease = BigInt(d.expires_at) - BigInt(d.created_at);
  check(
    lease > 0n &&
      lease <= BigInt(d.snapshot_purpose === "resync" ? 1800000 : 86400000),
    "INVALID_LEASE",
  );
  check(typeof authorize === "function", "AUTHORIZER_REQUIRED");
  authorize(d);
  for (const b of pageBytes) {
    const p = decode("snapshot-page", b);
    check(p.snapshot_id === d.snapshot_id, "SNAPSHOT_CONTEXT_MISMATCH");
    authorize(d, p);
  }
  const c = pageCommitmentForEvaluation("snapshot", pageBytes);
  check(
    c.page_count === d.page_count &&
      c.item_count === d.item_count &&
      c.inventory_digest === d.inventory_digest,
    "SNAPSHOT_INCOMPLETE",
  );
  return {
    state: "COMPLETE_SNAPSHOT",
    inventory: pageBytes.flatMap((b) => decode("snapshot-page", b).items),
    watermark: d.watermark,
    preserve: "OUTBOX_AND_INDEPENDENT_SECURITY_PINS",
  };
}
export class LocalFenceForEvaluation {
  #generation = 0;
  #unlocked = false;
  unlock() {
    this.#unlocked = true;
    return ++this.#generation;
  }
  capture() {
    check(this.#unlocked, "LOCKED");
    return this.#generation;
  }
  accept(generation) {
    check(this.#unlocked && generation === this.#generation, "STALE");
  }
  lock() {
    this.#unlocked = false;
    this.#generation++;
    return {
      plaintext: "DISCARD_REQUIRED",
      persisted_outbox: "KEEP_ENCRYPTED",
    };
  }
}
