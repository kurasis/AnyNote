import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import sodium from "libsodium-wrappers-sumo";
import { wire, same } from "../src/identity-codec.mjs";
import {
  common,
  decode,
  encode,
  digest,
  rawDigest,
  aad,
  signingInput,
} from "../src/protocol-codec.mjs";
import * as crypto from "../src/object-crypto.mjs";
import * as sync from "../src/sync-reference.mjs";
import {
  sceneForEvaluation,
  fixtureDir,
  seed,
  id,
  b64,
  checkCompleteFixture,
} from "../complete-fixtures.mjs";
import { checkSchemaVectors } from "../schema-vectors.mjs";
import {
  archiveHeader,
  collectArchiveForEvaluation,
  decodeArchiveForEvaluation,
  ARCHIVE_LIMIT,
} from "../src/archive-profile.mjs";
import {
  verifyExportForEvaluation,
  ageForEvaluation,
  makeExportForEvaluation,
} from "../src/export-reference.mjs";
import { verifyRootIdentity } from "../src/identity-crypto.mjs";
import {
  newRosterForEvaluation,
  applyRosterEventForEvaluation,
} from "../src/roster.mjs";
import { groupCodecForProfile } from "../src/group-codec.mjs";
await sodium.ready;
const f = JSON.parse(readFileSync(new URL("crypto.json", fixtureDir))),
  o = f.objects,
  raw = (s) => Buffer.from(s, "hex"),
  copy = (x) => structuredClone(x);
const fail = (fn, code) => assert.throws(fn, (e) => e.code === code);
const reject = (fn, code) => assert.rejects(fn, (e) => e.code === code);
const encrypt = (s, p) =>
  crypto.encryptObjectForEvaluation(
    wire(p),
    s.keys.get(p.context.policy.key_epoch),
    s.accounts[
      p.context.author.account_id === s.author(0).account_id
        ? 0
        : p.context.author.account_id === s.author(1).account_id
          ? 1
          : 2
    ].current.device.signing.privateKey,
  );
test("complete frozen note/local/native bytes and independent age engines recover cross-account history and a file", async () => {
  assert.equal((await checkCompleteFixture(f)).status, "PASS");
  assert.ok(checkSchemaVectors().structures >= 40);
});
for (const field of [
  "service_id",
  "group_id",
  "object_id",
  "revision_id",
  "operation_id",
  "thread_id",
])
  test("signed object binds " + field, () => {
    const b = copy(o.bundle);
    b.envelope.header.context[field] = id("changed-" + field);
    b.wrap.context[field] = b.envelope.header.context[field];
    fail(
      () =>
        crypto.verifyObjectForEvaluation(
          wire(b),
          raw(f.inputs.signing_public_hex),
          wire(b.envelope.header.context),
        ),
      "SIGNATURE_INVALID",
    );
  });
for (const field of ["nonce", "ciphertext_digest", "key_wrap_digest"])
  test("header signature binds " + field, () => {
    const b = copy(o.bundle);
    b.envelope.header[field] = b64(
      seed("changed", field === "nonce" ? 24 : 32),
    );
    fail(
      () =>
        crypto.verifyObjectForEvaluation(
          wire(b),
          raw(f.inputs.signing_public_hex),
          wire(o.payload.context),
        ),
      "SIGNATURE_INVALID",
    );
  });
test("note/key-wrap ciphertext replacement never falls back to plaintext", () => {
  for (const which of ["ciphertext", "wrap"]) {
    const b = copy(o.bundle);
    if (which === "ciphertext")
      b.ciphertext = b64(Buffer.from("plaintext imitation"));
    else b.wrap.ciphertext = b64(seed("changed-wrap", 48));
    fail(
      () =>
        crypto.decryptObjectForEvaluation(
          wire(b),
          raw(f.inputs.group_key_hex),
          raw(f.inputs.signing_public_hex),
          wire(o.payload.context),
        ),
      which === "ciphertext" ? "CIPHERTEXT_MISMATCH" : "KEY_WRAP_MISMATCH",
    );
  }
});
test("wrong object DEK or group G rejects authentic framing", () => {
  fail(
    () =>
      crypto.decryptObjectForEvaluation(
        wire(o.bundle),
        seed("wrong-G"),
        raw(f.inputs.signing_public_hex),
        wire(o.payload.context),
      ),
    "INTEGRITY_FAILURE",
  );
  fail(
    () =>
      crypto.decryptExportedObjectForEvaluation(
        wire(o.bundle),
        seed("wrong-DEK"),
        raw(f.inputs.signing_public_hex),
        wire(o.payload.context),
      ),
    "INTEGRITY_FAILURE",
  );
});
test("fresh revision encryptions use different actual CSPRNG DEKs and nonces", () => {
  const s = sceneForEvaluation(),
    p = s.payload(),
    a = encrypt(s, p),
    b = encrypt(s, p);
  assert.notEqual(a.ciphertext, b.ciphertext);
  assert.notEqual(a.wrap.nonce, b.wrap.nonce);
  assert.notEqual(a.envelope.header.nonce, b.envelope.header.nonce);
});
test("full 2 MiB canonical plaintext bound works above old 1 MiB parser limit", () => {
  const p = copy(o.payload),
    empty = encode("payload", wire({ ...p, markdown: "" })).length;
  p.markdown = "x".repeat(2097152 - empty);
  assert.equal(encode("payload", wire(p)).length, 2097152);
  p.markdown += "x";
  fail(() => decode("payload", wire(p)), "RESOURCE_LIMIT");
});
test("Unicode scalar title bounds, well formed UTF-8 and no duplicate fields", () => {
  const p = copy(o.payload);
  p.title = "😀".repeat(256);
  decode("payload", wire(p));
  p.title += "😀";
  fail(() => decode("payload", wire(p)), "SCHEMA_MISMATCH");
  fail(
    () => decode("context", Buffer.from('{"x":1,"x":2}')),
    "DUPLICATE_PROPERTY",
  );
  fail(() => decode("payload", Buffer.from([0xc0, 0xaf])), "INVALID_UTF8");
});
for (const change of [
  "unknown",
  "version",
  "thread",
  "self-parent",
  "attachments",
  "tags",
  "metadata",
  "tombstone",
])
  test("typed note rejects " + change, () => {
    const p = copy(o.payload);
    let code = "SCHEMA_MISMATCH";
    switch (change) {
      case "unknown":
        p.context.unknown = true;
        break;
      case "version":
        p.context.payload_schema = 2;
        break;
      case "thread":
        p.context.thread_id = null;
        code = "THREAD_CONTEXT_MISMATCH";
        break;
      case "self-parent":
        p.context.action = "update";
        p.context.parents = [
          {
            revision_id: p.context.revision_id,
            envelope_digest: b64(seed("digest")),
          },
        ];
        code = "SELF_PARENT";
        break;
      case "attachments":
        p.context.attachments = Array(101).fill({
          file_id: id("attachment"),
          file_version_id: id("version"),
          envelope_digest: b64(seed("digest")),
        });
        break;
      case "tags":
        p.tags = ["z", "a"];
        code = "UNORDERED_OR_DUPLICATE";
        break;
      case "metadata":
        p.metadata_kind = "account-preferences";
        code = "ENTRY_PAYLOAD_MISMATCH";
        break;
      case "tombstone":
        p.context.action = "soft-delete";
        p.context.parents = [
          {
            revision_id: id("parent"),
            envelope_digest: b64(seed("parent-digest")),
          },
        ];
        code = "TOMBSTONE_PAYLOAD_MISMATCH";
        break;
    }
    fail(() => decode("payload", wire(p)), code);
  });
test("reader cannot write; editor cannot edit group metadata; fake private handles rejected", () => {
  const s = sceneForEvaluation();
  for (const [kind, index, code] of [
    ["entry", 2, "WRITER_REQUIRED"],
    ["group-metadata", 1, "OWNER_REQUIRED"],
  ]) {
    const b = encrypt(s, s.payload(kind, index));
    fail(
      () => s.g.checkCurrentObjectForEvaluation(s.group, wire(b.envelope)),
      code,
    );
  }
  fail(
    () => s.g.checkCurrentObjectForEvaluation({}, wire(o.bundle.envelope)),
    "GROUP_PROOF_REQUIRED",
  );
});
test("note history preserves tombstone and restore parent closure without promoting forged ancient signatures", () => {
  const s = sceneForEvaluation(),
    initial = encrypt(s, s.payload());
  s.g.observeAcceptedObjectForEvaluation(s.group, wire(initial.envelope));
  const parent = {
    revision_id: initial.envelope.header.context.revision_id,
    envelope_digest: digest("envelope", wire(initial.envelope)),
  };
  const tomb = encrypt(s, s.payload("entry", 1, "soft-delete", [parent]));
  s.g.observeAcceptedObjectForEvaluation(s.group, wire(tomb.envelope));
  assert.equal(
    s.g.checkHistoricalObjectForEvaluation(
      s.group,
      wire(tomb.envelope),
      s.sender(2),
    ).payload_availability,
    "tombstone",
  );
  const restored = encrypt(
    s,
    s.payload("entry", 1, "restore", [
      {
        revision_id: tomb.envelope.header.context.revision_id,
        envelope_digest: digest("envelope", wire(tomb.envelope)),
      },
    ]),
  );
  s.g.observeAcceptedObjectForEvaluation(s.group, wire(restored.envelope));
  assert.equal(s.g.observedHistoryRecordsForEvaluation(s.group).length, 3);
  const unknown = encrypt(s, s.payload("entry", 1, "create", [], "forged-old"));
  fail(
    () =>
      s.g.checkHistoricalObjectForEvaluation(
        s.group,
        wire(unknown.envelope),
        s.sender(2),
      ),
    "UNANCHORED_HISTORY",
  );
});
test("same-object parents cannot substitute a different object or object kind", () => {
  const s = sceneForEvaluation(),
    a = encrypt(s, s.payload());
  s.g.observeAcceptedObjectForEvaluation(s.group, wire(a.envelope));
  const parent = {
    revision_id: a.envelope.header.context.revision_id,
    envelope_digest: digest("envelope", wire(a.envelope)),
  };
  const b = encrypt(s, s.payload("thread", 1, "update", [parent], "different"));
  fail(
    () => s.g.observeAcceptedObjectForEvaluation(s.group, wire(b.envelope)),
    "MISSING_OR_WRONG_ANCESTOR",
  );
});
test("decrypted account preferences require actual private group, with current owner authority", () => {
  const s = sceneForEvaluation(),
    p = s.payload("group-metadata", 0);
  p.metadata_kind = "account-preferences";
  const b = encrypt(s, p);
  s.g.observeAcceptedObjectForEvaluation(s.group, wire(b.envelope));
  fail(
    () =>
      s.g.decryptAuthorizedGroupObjectForEvaluation(
        s.group,
        wire(b),
        s.keys.get(p.context.policy.key_epoch),
        s.sender(0),
      ),
    "PRIVATE_NAMESPACE_REQUIRED",
  );
});
for (const field of [
  "service_id",
  "account_id",
  "device_id",
  "profile_id",
  "record_id",
  "record_kind",
])
  test("local ciphertext cannot be transplanted across " + field, () => {
    const c = copy(o.local_plain.context);
    c[field] = field === "record_kind" ? "cache" : id("changed-" + field);
    fail(
      () =>
        crypto.decryptLocalForEvaluation(
          wire(o.local_cipher),
          raw(f.inputs.local_key_hex),
          wire(c),
        ),
      "LOCAL_CONTEXT_MISMATCH",
    );
  });
test("local L is fresh, wrong L and tag reject, root secret excluded from everyday record schema", () => {
  fail(
    () =>
      crypto.decryptLocalForEvaluation(
        wire(o.local_cipher),
        seed("wrong-L"),
        wire(o.local_plain.context),
      ),
    "INTEGRITY_FAILURE",
  );
  const e = copy(o.local_cipher),
    bytes = Buffer.from(e.ciphertext, "base64url");
  bytes[0] ^= 1;
  e.ciphertext = b64(bytes);
  fail(
    () =>
      crypto.decryptLocalForEvaluation(
        wire(e),
        raw(f.inputs.local_key_hex),
        wire(e.context),
      ),
    "INTEGRITY_FAILURE",
  );
  const p = copy(o.local_plain);
  p.data.root_secret = b64(seed("R"));
  fail(() => decode("local-plaintext", wire(p)), "SCHEMA_MISMATCH");
});
test("Argon2 rejects weaker/excessive profiles before allocation and admits exactly one pending job", async () => {
  for (const [key, value] of [
    ["memlimit", 67108863],
    ["memlimit", 268435457],
    ["opslimit", 2],
    ["opslimit", 11],
  ])
    await reject(
      () =>
        crypto.phraseKekForEvaluation(
          f.inputs.phrase,
          wire({ ...o.parameters, [key]: value }),
        ),
      "SCHEMA_MISMATCH",
    );
  await reject(
    () => crypto.phraseKekForEvaluation("short words", wire(o.parameters)),
    "STRONG_PHRASE_REQUIRED",
  );
  const job = crypto.phraseKekForEvaluation(
    f.inputs.phrase,
    wire(o.parameters),
  );
  await reject(
    () => crypto.phraseKekForEvaluation(f.inputs.phrase, wire(o.parameters)),
    "KDF_BUSY",
  );
  await job;
});
test("wrappers bind full typed descriptors and reject wrong phrase/PRF/credential", () => {
  const d = copy(o.prf_descriptor);
  d.credential_id = b64(seed("wrong-credential"));
  const key = crypto.prfKekForEvaluation(
    wire(d.context),
    d.credential_id,
    Buffer.from(d.prf_salt, "base64url"),
    raw(f.inputs.prf_result_hex),
  );
  fail(
    () =>
      crypto.unwrapLocalKeyForEvaluation(
        "prf-wrapper",
        wire(o.prf_wrapper),
        wire(d),
        key,
      ),
    "LOCAL_CONTEXT_MISMATCH",
  );
  fail(
    () =>
      crypto.unwrapLocalKeyForEvaluation(
        "phrase-wrapper",
        wire(o.phrase_wrapper),
        wire(o.phrase_descriptor),
        seed("wrong-phrase-KEK"),
      ),
    "INTEGRITY_FAILURE",
  );
  fail(
    () =>
      crypto.wrapLocalKeyForEvaluation(
        "prf-wrapper",
        Buffer.from('{"x":1,"x":1}'),
        seed("L"),
        seed("KEK"),
      ),
    "DUPLICATE_PROPERTY",
  );
});
test("native candidate AES-GCM byte wrapper binds machine/TPM, never claims a physical unlock", () => {
  const d = copy(o.native_descriptor);
  d.machine_binding_id = id("other-machine");
  fail(
    () =>
      crypto.unwrapNativeForEvaluation(
        wire(o.native_wrapper),
        wire(d),
        raw(f.inputs.prf_result_hex),
      ),
    "LOCAL_CONTEXT_MISMATCH",
  );
  fail(
    () =>
      crypto.unwrapNativeForEvaluation(
        wire(o.native_wrapper),
        wire(o.native_descriptor),
        seed("wrong-PRF"),
      ),
    "INTEGRITY_FAILURE",
  );
});
test("lock generation drops stale pending results, preserves encrypted outbox", () => {
  const fence = new sync.LocalFenceForEvaluation();
  fence.unlock();
  const n = fence.capture();
  assert.equal(fence.lock().persisted_outbox, "KEEP_ENCRYPTED");
  fail(() => fence.accept(n), "STALE");
  fence.unlock();
  fail(() => fence.accept(n), "STALE");
  fence.accept(fence.capture());
});
test("stable attempt returns same receipt after response loss and receipt expiry; stale forks require explicit merge", () => {
  const s = sceneForEvaluation(),
    b = encrypt(s, s.payload()),
    ledger = sync.mutationLedgerForEvaluation(
      wire({ generation: id("generation"), sequence: "0" }),
      (bytes) => s.g.checkCurrentObjectForEvaluation(s.group, bytes),
    );
  const receipt = sync.commitMutationForEvaluation(ledger, wire(b));
  assert.equal(receipt.cursor.sequence, "1");
  assert.deepEqual(sync.commitMutationForEvaluation(ledger, wire(b)), receipt);
  sync.expireReceiptsForEvaluation(ledger);
  assert.deepEqual(sync.commitMutationForEvaluation(ledger, wire(b)), receipt);
  const outbox = {
    draft_id: id("stable-draft"),
    attempt_id: b.envelope.header.context.operation_id,
    revision_id: b.envelope.header.context.revision_id,
    state: "SENT_UNKNOWN",
    bundle: b,
    attempt_digest: digest("bundle", wire(b)),
    receipt: null,
  };
  assert.equal(
    sync.reconcileAttemptForEvaluation(ledger, wire(outbox)).state,
    "COMMITTED",
  );
  const changed = encrypt(s, s.payload());
  fail(
    () => sync.commitMutationForEvaluation(ledger, wire(changed)),
    "REVISION_ID_CONFLICT",
  );
  const stale = encrypt(s, s.payload("entry", 1, "create", []));
  stale.envelope.header.context.operation_id = id("other-op");
  fail(
    () => sync.commitMutationForEvaluation(ledger, wire(stale)),
    "CONTEXT_MISMATCH",
  );
  const p = s.payload("entry", 1, "update", [
    {
      revision_id: receipt.revision_id,
      envelope_digest: receipt.envelope_digest,
    },
  ]);
  p.context.operation_id = id("update-op");
  sync.commitMutationForEvaluation(ledger, wire(encrypt(s, p)));
  const fork = s.payload("entry", 1, "update", [
    {
      revision_id: receipt.revision_id,
      envelope_digest: receipt.envelope_digest,
    },
  ]);
  fork.context.revision_id = id("fork-version");
  fork.context.operation_id = id("fork-op");
  fail(
    () => sync.commitMutationForEvaluation(ledger, wire(encrypt(s, fork))),
    "STALE_REVISION",
  );
});
test("sync cursor is generation-scoped, contiguous, bounded and complete only at watermark", () => {
  const generation = id("generation"),
    from = { generation, sequence: "0" },
    p = {
      ...common("sync-page"),
      from_cursor: from,
      next_cursor: { generation, sequence: "1" },
      watermark: { generation, sequence: "1" },
      events: [
        {
          event_id: id("event"),
          sequence: "1",
          group_id: id("group"),
          object_kind: "entry",
          object_id: id("note"),
          revision_id: id("revision"),
          digest: b64(seed("digest")),
        },
      ],
      complete: true,
    };
  sync.validateSyncPageForEvaluation(wire(p), wire(from));
  const gap = copy(p);
  gap.events[0].sequence = "2";
  fail(
    () => sync.validateSyncPageForEvaluation(wire(gap), wire(from)),
    "SYNC_GAP",
  );
  p.watermark.sequence = "2";
  fail(
    () => sync.validateSyncPageForEvaluation(wire(p), wire(from)),
    "SYNC_WATERMARK_MISMATCH",
  );
  p.from_cursor.generation = id("restore");
  fail(
    () => sync.validateSyncPageForEvaluation(wire(p), wire(from)),
    "SYNC_CURSOR_EXPIRED",
  );
});
test("snapshot reauthorizes every page; incomplete/revoked/expired snapshot cannot purge or replace local state", () => {
  const p = {
      ...common("snapshot-page"),
      snapshot_id: id("snapshot"),
      page_index: "0",
      items: [
        {
          group_id: id("group"),
          object_kind: "entry",
          object_id: id("note"),
          revision_id: id("revision"),
          envelope_digest: b64(seed("digest")),
          payload_status: "retained",
        },
      ],
    },
    commit = sync.pageCommitmentForEvaluation("snapshot", [wire(p)]),
    d = { ...o.header.snapshot, ...commit };
  let calls = 0;
  assert.equal(
    sync.verifySnapshotForEvaluation(wire(d), [wire(p)], 10001n, () => calls++)
      .state,
    "COMPLETE_SNAPSHOT",
  );
  assert.equal(calls, 2);
  fail(
    () => sync.verifySnapshotForEvaluation(wire(d), [], 10001n, () => {}),
    "SNAPSHOT_INCOMPLETE",
  );
  fail(
    () =>
      sync.verifySnapshotForEvaluation(wire(d), [wire(p)], 10001n, () => {
        throw Object.assign(Error(), { code: "ACCESS_REVOKED" });
      }),
    "ACCESS_REVOKED",
  );
  fail(
    () =>
      sync.verifySnapshotForEvaluation(wire(d), [wire(p)], 86410000n, () => {}),
    "SNAPSHOT_EXPIRED",
  );
});
test("restore changes transport generation and quarantines all mutations; cannot silently trust restored security state", () => {
  const s = sceneForEvaluation(),
    ledger = sync.mutationLedgerForEvaluation(
      wire({ generation: id("generation"), sequence: "0" }),
      () => {},
    );
  assert.equal(
    sync.restoreTransportForEvaluation(ledger, id("new-generation")).state,
    "RESTORE_QUARANTINE",
  );
  fail(
    () =>
      sync.commitMutationForEvaluation(ledger, wire(encrypt(s, s.payload()))),
    "RESTORE_QUARANTINE",
  );
});
test("new 20-member profile accepts exact default, rejects 21 and does not reinterpret old 10-member bytes", () => {
  const c2 = groupCodecForProfile("p02-group-c2"),
    c1 = groupCodecForProfile("p02-group-c1"),
    members = Array.from({ length: 20 }, (_, i) => ({
      account_id: id("account-" + i),
      root_fingerprint: b64(seed("root-" + i)),
      role: i === 0 ? "owner" : "reader",
    })).sort((a, b) => (a.account_id < b.account_id ? -1 : 1));
  assert.equal(c2.groupDecode("members", wire(members)).length, 20);
  fail(() => c1.groupDecode("members", wire(members)), "SCHEMA_MISMATCH");
  members.push({
    account_id: id("account-21"),
    root_fingerprint: b64(seed("root-21")),
    role: "reader",
  });
  fail(() => c2.groupDecode("members", wire(members)), "SCHEMA_MISMATCH");
  const record = o.evidence.groups[0].genesis;
  fail(() => c1.groupDecode("policy", wire(record)), "SCHEMA_MISMATCH");
  assert.notEqual(
    c1.groupDomain("sign", "group-policy-event").toString("hex"),
    c2.groupDomain("sign", "group-policy-event").toString("hex"),
  );
});
const stream = (bytes) =>
  (async function* () {
    for (let i = 0; i < bytes.length; i += 71) yield bytes.subarray(i, i + 71);
  })();
test("strict USTAR bytes reject path traversal, links, PAX, size tricks, padding, truncation, duplicate and trailing data", async () => {
  const good = await collectArchiveForEvaluation([
    { path: "export-header.json", bytes: Buffer.from("{}") },
  ]);
  assert.equal(
    (await decodeArchiveForEvaluation(stream(good), () => {})).entries,
    1,
  );
  for (const [name, change, code] of [
    [
      "path",
      (b) => {
        b.write("../escape");
      },
      "UNSAFE_ARCHIVE_PATH",
    ],
    [
      "link",
      (b) => {
        b[156] = 50;
      },
      "INVALID_ARCHIVE_HEADER",
    ],
    [
      "pax",
      (b) => {
        b[156] = 120;
      },
      "INVALID_ARCHIVE_HEADER",
    ],
    [
      "checksum",
      (b) => {
        b[148] ^= 1;
      },
      "INVALID_ARCHIVE_HEADER",
    ],
    [
      "padding",
      (b) => {
        b[515] = 1;
      },
      "INVALID_ARCHIVE_PADDING",
    ],
  ]) {
    const bad = Buffer.from(good);
    change(bad);
    await reject(() => decodeArchiveForEvaluation(stream(bad), () => {}), code);
  }
  await reject(
    () => decodeArchiveForEvaluation(stream(good.subarray(0, -1)), () => {}),
    "EXPORT_TRUNCATED",
  );
  await reject(
    () =>
      decodeArchiveForEvaluation(
        stream(Buffer.concat([good, Buffer.from("extra")])),
        () => {},
      ),
    "TRAILING_ARCHIVE_DATA",
  );
  await reject(
    () =>
      collectArchiveForEvaluation([
        { path: "export-header.json", bytes: Buffer.from("{}") },
        { path: "export-header.json", bytes: Buffer.from("{}") },
      ]),
    "DUPLICATE_ARCHIVE_PATH",
  );
  assert.equal(ARCHIVE_LIMIT, 117179869184n);
});
for (const provider of ["age", "rage"])
  test(
    "actual " +
      provider +
      " rejects wrong export identity, bit flip and authenticated-stream truncation",
    async () => {
      const bytes = readFileSync(new URL("rust.age", fixtureDir)),
        wrong = o.kit.export_identity.replace(
          /.$/,
          o.kit.export_identity.endsWith("A") ? "B" : "A",
        );
      await reject(
        () => ageForEvaluation(provider, "decrypt", bytes, wrong),
        "EXPORT_INTEGRITY_FAILURE",
      );
      const bad = Buffer.from(bytes);
      bad[bad.length - 20] ^= 1;
      await reject(
        () => ageForEvaluation(provider, "decrypt", bad, o.kit.export_identity),
        "EXPORT_INTEGRITY_FAILURE",
      );
      await reject(
        () =>
          ageForEvaluation(
            provider,
            "decrypt",
            bytes.subarray(0, -1),
            o.kit.export_identity,
          ),
        "EXPORT_INTEGRITY_FAILURE",
      );
    },
  );
test("outer age success cannot upgrade forged identity, missing footer, changed inventory or absent independent pin", async () => {
  const ageBytes = readFileSync(new URL("rust.age", fixtureDir)),
    kit = copy(o.kit);
  kit.independent_group_pins = [];
  await reject(
    () => verifyExportForEvaluation(ageBytes, wire(kit)),
    "INDEPENDENT_HISTORY_REQUIRED",
  );
  const tar = await ageForEvaluation(
      "age",
      "decrypt",
      ageBytes,
      o.kit.export_identity,
    ),
    entries = [];
  await decodeArchiveForEvaluation(stream(tar), (e) => entries.push(e));
  for (const which of ["footer", "inventory", "identity"]) {
    const changed = entries.map((x) => ({
      path: x.path,
      bytes: Buffer.from(x.bytes),
    }));
    if (which === "footer") changed.pop();
    if (which === "inventory") {
      const i = changed.find((e) => e.path.startsWith("inventory/")),
        v = JSON.parse(i.bytes);
      v.items[0].digest = b64(seed("forged"));
      i.bytes = encode("export-page", wire(v));
    }
    if (which === "identity") {
      const i = changed.find((e) => e.path === "identity/evidence.json"),
        v = JSON.parse(i.bytes);
      v.accounts[0].identity.signature = b64(seed("forged", 64));
      i.bytes = encode("export-evidence", wire(v));
    }
    const altered = await ageForEvaluation(
        "age",
        "encrypt",
        await collectArchiveForEvaluation(changed),
        f.inputs.recipient,
      ),
      newKit = { ...o.kit, archive_sha256: rawDigest(altered) };
    await assert.rejects(
      () => verifyExportForEvaluation(altered, wire(newKit)),
      (e) =>
        [
          "EXPORT_TRUNCATED",
          "EXPORT_INVENTORY_MISMATCH",
          "SIGNATURE_INVALID",
        ].includes(e.code),
    );
  }
});
test("frozen authorization decisions require pinned current policy, role, roster and original signature", () => {
  const s = sceneForEvaluation();
  const expectedPolicy = o.bundle.envelope.header.context.policy; // Live synthetic scene uses independent fresh keys; import exact frozen signed epochs instead.
  const ev = o.evidence.groups[0],
    g = s.g,
    accounts = o.evidence.accounts.map((a) => {
      const identity = verifyRootIdentity(wire(a.identity), wire(a.pin)),
        roster = newRosterForEvaluation(identity);
      for (const e of a.events) applyRosterEventForEvaluation(roster, wire(e));
      return { identity, roster };
    }),
    token = g.newGroupForEvaluation(
      wire(ev.genesis),
      wire(ev.genesis_pin),
      accounts,
    );
  for (let i = 0; i < ev.transitions.length; i++) {
    const t = ev.transitions[i];
    g.replayGroupEpochForEvaluation(
      token,
      wire(t.value.record),
      t.value.pages.map(wire),
    );
    if (i === 0) g.startFreshHistoryObservationForEvaluation(token);
  }
  for (const v of o.authorization_cases) {
    if (v.expected === "ACCEPT_CURRENT")
      assert.equal(
        g.checkCurrentObjectForEvaluation(token, wire(v.envelope))
          .group_authorization,
        "VERIFIED_CURRENT_WRITER",
      );
    else
      fail(
        () => g.checkCurrentObjectForEvaluation(token, wire(v.envelope)),
        v.expected,
      );
  }
});
test("errors have fixed HTTP/retry semantics and exact component negotiation fails closed", () => {
  const error = {
    error: {
      code: "INTEGRITY_FAILURE",
      message_key: "error.integrity_failure",
      request_id: id("request"),
      retryable: false,
      details: [],
    },
  };
  decode("error", wire(error));
  error.error.retryable = true;
  fail(() => decode("error", wire(error)), "ERROR_SEMANTICS_MISMATCH");
  const n = {
    ...common("protocol-negotiation"),
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
  };
  decode("negotiation", wire(n));
  n.components[3] = "p02-group-c1";
  fail(() => decode("negotiation", wire(n)), "UNSUPPORTED_SCHEMA");
});
test("empty export uses standard age, signed footer and independent kit without invented group authority", async () => {
  const { publicDevice } = await import("../state-fixtures.mjs"),
    evidence = { accounts: [o.evidence.accounts[0]], groups: [] },
    snapshot = {
      ...o.header.snapshot,
      page_count: "0",
      item_count: "0",
      inventory_digest: sync.pageCommitmentForEvaluation("snapshot", [])
        .inventory_digest,
    },
    header = {
      ...o.header,
      snapshot,
      selection: {
        include_history: false,
        include_trash: false,
        group_ids: [],
      },
    };
  const plain = await makeExportForEvaluation(
      wire(header),
      [
        {
          path: "identity/evidence.json",
          kind: "identity",
          bytes: encode("export-evidence", wire(evidence)),
        },
      ],
      wire(o.footer.body.signer),
      publicDevice(0).signing.privateKey,
    ),
    age = await ageForEvaluation(
      "age",
      "encrypt",
      plain.tar,
      f.inputs.recipient,
    ),
    kit = {
      ...o.kit,
      archive_sha256: rawDigest(age),
      independent_group_pins: [],
    };
  const result = await verifyExportForEvaluation(age, wire(kit), "rage");
  assert.equal(result.live_destination_mutations, 0);
  assert.deepEqual(result.recovered, []);
  assert.deepEqual(result.recoveredFiles, []);
});
test("actual pinned 20-account admission covers all retained epochs and recipients in multiple bounded signed pages", async () => {
  const { fixtureBase, registerFixture } = await import(
      "../state-fixtures.mjs"
    ),
    { createIdentity, deriveRoot, rootFingerprint } = await import(
      "../src/identity-crypto.mjs"
    ),
    { EvaluationAuthority } = await import("../src/evaluation-authority.mjs");
  const s = sceneForEvaluation();
  for (let i = 3; i < 20; i++) {
    const context = {
        ...fixtureBase().v.input.context,
        account_id: id("member-" + i),
      },
      secret = seed("member-R-" + i),
      identityBytes = createIdentity(secret, wire(context)),
      pin = {
        service_id: context.service_id,
        account_id: context.account_id,
        root_fingerprint: rootFingerprint(identityBytes),
      },
      identity = verifyRootIdentity(identityBytes, wire(pin)),
      roster = newRosterForEvaluation(identity),
      account = {
        identity,
        root: deriveRoot(secret, wire(context)),
        roster,
        server: new EvaluationAuthority(roster),
        now: 10000n,
        v: { outputs: { identity: JSON.parse(identityBytes), pin } },
      };
    account.current = registerFixture(account, i);
    s.accounts.push(account);
    s.g.registerRelatedAccountForEvaluation(s.group, { identity, roster });
    s.admit(i, "reader");
  }
  assert.equal(s.g.groupDetails(s.group).members.length, 20);
  assert.equal(s.g.groupDetails(s.group).epochs.length, 20);
  assert.equal(s.g.groupGrantRecordsForEvaluation(s.group).length, 800);
  const final = s.transitions.at(-1).value;
  assert.ok(final.pages.length >= 2);
  for (const p of final.pages) {
    assert.ok(p.records.length <= 500);
    assert.ok(wire(p).length <= 1048576);
  }
  const last = s.transitions.at(-1).value.record.body.policy;
  const overflow = structuredClone(last.body.members);
  overflow.push({
    account_id: id("twenty-first"),
    root_fingerprint: b64(seed("root-twenty-first")),
    role: "reader",
  });
  overflow.sort((a, b) => (a.account_id < b.account_id ? -1 : 1));
  fail(() => s.codec.groupDecode("members", wire(overflow)), "SCHEMA_MISMATCH");
});
test("paginated public evidence restores the same offline cross-account note/file without an unbounded metadata document", async () => {
  const { publicEvidenceEntriesForEvaluation } = await import(
      "../src/export-evidence.mjs"
    ),
    { publicDevice } = await import("../state-fixtures.mjs");
  const bytes = readFileSync(new URL("rust.age", fixtureDir)),
    tar = await ageForEvaluation(
      "age",
      "decrypt",
      bytes,
      o.kit.export_identity,
    ),
    entries = [];
  await decodeArchiveForEvaluation(stream(tar), (x) => entries.push(x));
  const data = entries
    .slice(1, -1)
    .filter(
      (x) =>
        !x.path.startsWith("inventory/") && x.path !== "identity/evidence.json",
    )
    .map((x) => ({
      path: x.path,
      bytes: x.bytes,
      kind: x.path.startsWith("records/")
        ? "record"
        : x.path.startsWith("keys/")
          ? "key"
          : x.path.startsWith("snapshots/")
            ? "source-snapshot"
            : "chunk",
    }));
  data.push(...publicEvidenceEntriesForEvaluation(wire(o.evidence)));
  const exported = await makeExportForEvaluation(
      wire(o.header),
      data,
      wire(o.footer.body.signer),
      publicDevice(0).signing.privateKey,
    ),
    age = await ageForEvaluation(
      "rage",
      "encrypt",
      exported.tar,
      f.inputs.recipient,
    ),
    kit = { ...o.kit, archive_sha256: rawDigest(age) },
    result = await verifyExportForEvaluation(age, wire(kit), "age");
  assert.deepEqual(result.recovered, [o.payload]);
  assert.equal(
    result.recoveredFiles[0].bytes.toString("hex"),
    o.file_plain_hex,
  );
  assert.equal(result.live_destination_mutations, 0);
});
for (const provider of ["age", "rage"])
  test(
    provider + " rejects trailing bytes after authenticated age final chunk",
    async () => {
      const bytes = readFileSync(new URL("rust.age", fixtureDir));
      await reject(
        () =>
          ageForEvaluation(
            provider,
            "decrypt",
            Buffer.concat([bytes, Buffer.from("extra")]),
            o.kit.export_identity,
          ),
        "EXPORT_INTEGRITY_FAILURE",
      );
    },
  );
test("all local record kinds have closed schemas; cached bytes and transfer resume cannot bypass their typed context", () => {
  const cache = {
    cached_kind: "object-bundle",
    record_bytes: b64(encode("bundle", wire(o.bundle))),
  };
  decode("cache", wire(cache));
  cache.cached_kind = "file-record";
  fail(() => decode("cache", wire(cache)), "SCHEMA_MISMATCH");
  const record = copy(o.local_plain);
  record.context.record_kind = "session";
  fail(() => decode("local-plaintext", wire(record)), "LOCAL_KIND_MISMATCH");
  const transfer = {
    transfer_id: id("transfer"),
    direction: "download",
    group_id: o.payload.context.group_id,
    file_id: id("file"),
    file_version_id: id("file-version"),
    upload_id: null,
    state: "PAUSED",
    source_bytes: "10",
    source_sha256: b64(seed("source")),
    progress_bytes: "11",
    parts: [],
    keys: {
      manifest_dek: b64(seed("manifest")),
      file_data_dek: b64(seed("file")),
      nonce_prefix: b64(seed("prefix", 16)),
    },
  };
  fail(() => decode("transfer", wire(transfer)), "TRANSFER_PROGRESS_MISMATCH");
  transfer.progress_bytes = "0";
  transfer.keys = null;
  fail(() => decode("transfer", wire(transfer)), "TRANSFER_CONTEXT_MISMATCH");
});
test("lost-response reconciliation remains readable after writer role loss, but current removal denies even a retained receipt", () => {
  const s = sceneForEvaluation(),
    bundle = encrypt(s, s.payload()),
    requester = s.sender(1),
    authorize = (bytes, { operation }) => {
      const members = s.g.groupDetails(s.group).members;
      if (
        !members.some(
          (m) =>
            m.account_id === requester.account_id &&
            m.root_fingerprint === requester.root_fingerprint,
        )
      )
        throw Object.assign(Error(), { code: "ACCESS_REVOKED" });
      assert.equal(
        JSON.parse(bytes).header.context.author.account_id,
        requester.account_id,
      );
      s.g.groupSenderForEvaluation(
        s.group,
        requester.account_id,
        requester.device_id,
        "receive-group-key",
      );
      if (operation === "publish")
        return s.g.checkCurrentObjectForEvaluation(s.group, bytes);
    },
    ledger = sync.mutationLedgerForEvaluation(
      wire({ generation: id("generation"), sequence: "0" }),
      authorize,
    ),
    receipt = sync.commitMutationForEvaluation(ledger, wire(bundle));
  const policy = s.build.policyForEvaluation(
    s.group,
    "role",
    s.sender(),
    s.owner.current.device.signing.privateKey,
    { target_account_id: requester.account_id, role: "reader" },
  );
  s.g.applyGroupPolicyForEvaluation(s.group, policy, 10000n);
  assert.deepEqual(
    sync.commitMutationForEvaluation(ledger, wire(bundle)),
    receipt,
  );
  sync.expireReceiptsForEvaluation(ledger);
  assert.deepEqual(
    sync.commitMutationForEvaluation(ledger, wire(bundle)),
    receipt,
  );
  const removal = s.build.policyForEvaluation(
    s.group,
    "remove",
    s.sender(),
    s.owner.current.device.signing.privateKey,
    { target_account_id: requester.account_id },
  );
  s.g.applyGroupPolicyForEvaluation(s.group, removal, 10000n);
  fail(
    () => sync.commitMutationForEvaluation(ledger, wire(bundle)),
    "ACCESS_REVOKED",
  );
});
test("server-visible ciphertext and key-wrap commitments are checked before a mutation can receive a committed receipt", () => {
  const s = sceneForEvaluation(),
    bundle = encrypt(s, s.payload()),
    ledger = sync.mutationLedgerForEvaluation(
      wire({ generation: id("generation"), sequence: "0" }),
      (bytes) => s.g.checkCurrentObjectForEvaluation(s.group, bytes),
    ),
    bad = copy(bundle);
  const cipher = Buffer.from(bad.ciphertext, "base64url");
  cipher[0] ^= 1;
  bad.ciphertext = b64(cipher);
  fail(
    () => sync.commitMutationForEvaluation(ledger, wire(bad)),
    "CIPHERTEXT_MISMATCH",
  );
  const wrap = copy(bundle);
  wrap.wrap.ciphertext = b64(seed("wrong-wrap", 48));
  fail(
    () => sync.commitMutationForEvaluation(ledger, wire(wrap)),
    "KEY_WRAP_MISMATCH",
  );
  assert.equal(
    sync.commitMutationForEvaluation(ledger, wire(bundle)).cursor.sequence,
    "1",
  );
});
