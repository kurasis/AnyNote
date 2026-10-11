// PUBLIC bounded synthetic export reference. No plaintext disk staging or live import.
import { assemblePublicEvidenceForEvaluation } from "./export-evidence.mjs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import sodium from "libsodium-wrappers-sumo";
import { requireCondition as check, strictJson } from "./strict-json.mjs";
import { wire, same } from "./identity-codec.mjs";
import {
  decode,
  encode,
  digest,
  rawDigest,
  signingInput,
  common,
} from "./protocol-codec.mjs";
import {
  collectArchiveForEvaluation,
  decodeArchiveForEvaluation,
  generatedPath,
} from "./archive-profile.mjs";
import {
  pageCommitmentForEvaluation,
  verifySnapshotForEvaluation,
} from "./sync-reference.mjs";
import {
  verifyRootIdentity,
  certificateDetails,
  identityDetails,
  senderForCertificate,
} from "./identity-crypto.mjs";
import {
  newRosterForEvaluation,
  applyRosterEventForEvaluation,
  rosterScope,
  rosterDetails,
  activeCertificateForEvaluation,
} from "./roster.mjs";
import { groupStateForProfile } from "./group-state.mjs";
await sodium.ready;
const dir = fileURLToPath(
  new URL("../../../.local/p02-tools/", import.meta.url),
);
export async function ageForEvaluation(provider, mode, input, identity) {
  check(
    ["age", "rage"].includes(provider) && ["encrypt", "decrypt"].includes(mode),
    "UNSUPPORTED_PROVIDER",
  );
  check(input.length <= 16777216, "EVALUATION_RESOURCE_LIMIT");
  const args =
    mode === "encrypt" ? ["-r", identity] : ["-d", "-i", "/dev/fd/3"];
  const command = mode === "decrypt" ? "bash" : dir + provider;
  const commandArgs =
    mode === "decrypt"
      ? [
          "-c",
          'exec "$1" -d -i <(cat <&3)',
          "anynote-public-age",
          dir + provider,
        ]
      : args;
  const child = spawn(command, commandArgs, {
    env: { ...process.env, LANG: "en_US.UTF-8" },
    stdio: ["pipe", "pipe", "pipe", mode === "decrypt" ? "pipe" : "ignore"],
  });
  const out = [];
  let size = 0;
  child.stdout.on("data", (b) => {
    size += b.length;
    if (size > 16777216) child.kill();
    else out.push(b);
  });
  child.stderr.resume();
  child.stdin.on("error", () => {});
  child.stdin.end(input);
  if (mode === "decrypt") {
    child.stdio[3].on("error", () => {});
    child.stdio[3].end(identity + "\n");
  }
  const status = await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", resolve);
  });
  check(size <= 16777216, "EVALUATION_RESOURCE_LIMIT");
  check(
    status === 0,
    mode === "encrypt" ? "AGE_ENCRYPTION_FAILED" : "EXPORT_INTEGRITY_FAILURE",
  );
  return Buffer.concat(out);
}
export async function makeExportForEvaluation(
  headerBytes,
  items,
  signerBytes,
  signingKey,
) {
  const header = decode("export-header", headerBytes);
  check(
    signingKey instanceof Uint8Array && signingKey.length === 64,
    "INVALID_KEY_LENGTH",
  );
  const sorted = [...items].sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  );
  check(
    sorted.every(
      (x) =>
        generatedPath(x.path) &&
        !x.path.startsWith("inventory/") &&
        !x.path.startsWith("export-"),
    ),
    "UNSAFE_ARCHIVE_PATH",
  );
  const pages = [];
  for (let i = 0; i < sorted.length; i += 500) {
    const batch = sorted.slice(i, i + 500).map((x) => ({
      path: x.path,
      kind: x.kind,
      size: String(x.bytes.length),
      digest: rawDigest(x.bytes),
    }));
    pages.push(
      encode(
        "export-page",
        wire({
          ...common("export-inventory-page"),
          export_id: header.export_id,
          page_index: String(pages.length),
          items: batch,
        }),
      ),
    );
  }
  const commitment = pageCommitmentForEvaluation("export", pages),
    body = {
      ...common("export-footer"),
      export_id: header.export_id,
      header_digest: digest("export-header", headerBytes),
      ...commitment,
      total_item_bytes: String(sorted.reduce((n, x) => n + x.bytes.length, 0)),
      signer: strictJson(signerBytes, 65536),
    };
  const footer = encode(
    "export-footer",
    wire({
      body,
      signature: Buffer.from(
        sodium.crypto_sign_detached(
          signingInput("export-footer-body", wire(body)),
          signingKey,
        ),
      ).toString("base64url"),
    }),
  );
  const entries = [
    { path: "export-header.json", bytes: encode("export-header", headerBytes) },
    ...sorted.map(({ path, bytes }) => ({ path, bytes })),
    ...pages.map((bytes, i) => ({
      path: "inventory/" + String(i).padStart(8, "0") + ".json",
      bytes,
    })),
    { path: "export-footer.json", bytes: footer },
  ];
  return {
    tar: await collectArchiveForEvaluation(entries),
    footer: decode("export-footer", footer),
    pages,
  };
}
function evidenceForEvaluation(bytes, kit) {
  const e = decode("export-evidence", bytes),
    g = groupStateForProfile("p02-group-c2");
  const accounts = e.accounts.map((a) => {
    const identity = verifyRootIdentity(wire(a.identity), wire(a.pin)),
      roster = newRosterForEvaluation(identity);
    for (const event of a.events)
      applyRosterEventForEvaluation(roster, wire(event));
    return { identity, roster };
  });
  const exporter = accounts.find(
    (a) =>
      identityDetails(a.identity).fingerprint === kit.exporter_root_fingerprint,
  );
  check(
    exporter && same(rosterDetails(exporter.roster).head, kit.exporter_roster),
    "EXPORT_IDENTITY_MISMATCH",
  );
  const groups = new Map();
  for (const ev of e.groups) {
    const pin = kit.independent_group_pins.find(
      (p) => p.group_id === ev.genesis_pin.group_id,
    );
    check(
      pin && pin.genesis_digest === ev.genesis_pin.genesis_digest,
      "INDEPENDENT_HISTORY_REQUIRED",
    );
    const token = g.newGroupForEvaluation(
      wire(ev.genesis),
      wire(ev.genesis_pin),
      accounts,
    );
    for (const step of ev.transitions) {
      if (step.kind === "epoch")
        g.replayGroupEpochForEvaluation(
          token,
          wire(step.value.record),
          step.value.pages.map(wire),
        );
      else g.applyGroupPolicyForEvaluation(token, wire(step.value));
    }
    g.importPinnedGroupHistoryForEvaluation(
      token,
      wire(ev.history),
      ev.history_pages.map(wire),
      wire(pin.history),
    );
    g.verifyGroupStatePinForEvaluation(
      token,
      wire({
        service_id: ev.genesis_pin.service_id,
        group_id: pin.group_id,
        policy: pin.policy,
        epoch: pin.epoch,
        history: pin.history,
      }),
    );
    groups.set(pin.group_id, token);
  }
  return { g, accounts, exporter, groups };
}
export async function verifyExportForEvaluation(
  ageBytes,
  kitBytes,
  provider = "age",
) {
  const kit = decode("export-kit", kitBytes);
  check(rawDigest(ageBytes) === kit.archive_sha256, "ARCHIVE_DIGEST_MISMATCH");
  const tar = await ageForEvaluation(
      provider,
      "decrypt",
      ageBytes,
      kit.export_identity,
    ),
    entries = [];
  // All decrypted keys remain provisional in bounded memory; there is no filesystem extraction.
  await decodeArchiveForEvaluation(
    (async function* () {
      for (let i = 0; i < tar.length; i += 65536)
        yield tar.subarray(i, i + 65536);
    })(),
    (x) => entries.push(x),
  );
  check(
    entries[0]?.path === "export-header.json" &&
      entries.at(-1)?.path === "export-footer.json",
    "EXPORT_TRUNCATED",
  );
  const header = decode("export-header", entries[0].bytes),
    footer = decode("export-footer", entries.at(-1).bytes),
    body = footer.body;
  check(
    header.snapshot.snapshot_purpose === "export" &&
      header.snapshot.account_id === header.account_id &&
      header.snapshot.device_id === body.signer.device_id,
    "EXPORT_CONTEXT_MISMATCH",
  );
  check(
    header.export_id === kit.export_id &&
      body.export_id === kit.export_id &&
      header.root_fingerprint === kit.exporter_root_fingerprint,
    "EXPORT_CONTEXT_MISMATCH",
  );
  const evidenceBytes = assemblePublicEvidenceForEvaluation(entries);
  const proofs = evidenceForEvaluation(evidenceBytes, kit),
    signer = body.signer;
  check(
    identityDetails(proofs.exporter.identity).body.account_id ===
      header.account_id &&
      identityDetails(proofs.exporter.identity).body.service_id ===
        header.service_id,
    "EXPORT_IDENTITY_MISMATCH",
  );
  const account = proofs.accounts.find(
    (a) => rosterScope(a.roster).account_id === signer.account_id,
  );
  check(account === proofs.exporter, "EXPORT_SIGNER_MISMATCH");
  const exporterCertificate = activeCertificateForEvaluation(
      account.roster,
      signer.device_id,
      "sign-content",
    ),
    verifiedSender = senderForCertificate(
      exporterCertificate,
      rosterDetails(account.roster).head,
    ),
    expected = {
      account_id: verifiedSender.account_id,
      device_id: verifiedSender.device_id,
      root_fingerprint: verifiedSender.root_fingerprint,
      recovery_generation: verifiedSender.recovery_generation,
      roster: verifiedSender.roster_head,
    };
  check(same(expected, signer), "EXPORT_SIGNER_MISMATCH");
  const publicKey = Buffer.from(
    certificateDetails(exporterCertificate).body.device_signing_key,
    "base64url",
  );
  check(
    sodium.crypto_sign_verify_detached(
      Buffer.from(footer.signature, "base64url"),
      signingInput("export-footer-body", wire(body)),
      publicKey,
    ),
    "EXPORT_SIGNATURE_INVALID",
  );
  check(
    body.header_digest === digest("export-header", entries[0].bytes),
    "EXPORT_HEADER_MISMATCH",
  );
  const pageEntries = entries.filter((e) => e.path.startsWith("inventory/")),
    pages = pageEntries.map((e) => e.bytes),
    c = pageCommitmentForEvaluation("export", pages);
  check(
    c.inventory_digest === body.inventory_digest &&
      c.page_count === body.page_count &&
      c.item_count === body.item_count,
    "EXPORT_INVENTORY_MISMATCH",
  );
  const items = entries
      .slice(1, -1)
      .filter((e) => !e.path.startsWith("inventory/")),
    listed = pages.flatMap((b) => decode("export-page", b).items);
  check(
    items.length === listed.length &&
      items.reduce((n, x) => n + BigInt(x.bytes.length), 0n) ===
        BigInt(body.total_item_bytes),
    "EXPORT_INVENTORY_MISMATCH",
  );
  const expectedOrder = [
    "export-header.json",
    ...listed.map((x) => x.path),
    ...pages.map((_, i) => "inventory/" + String(i).padStart(8, "0") + ".json"),
    "export-footer.json",
  ];
  check(
    same(
      entries.map((e) => e.path),
      expectedOrder,
    ),
    "EXPORT_ORDER_MISMATCH",
  );
  const keys = new Map();
  for (let i = 0; i < items.length; i++) {
    const item = items[i],
      row = listed[i];
    check(
      row.path === item.path &&
        row.digest === rawDigest(item.bytes) &&
        row.size === String(item.bytes.length),
      "EXPORT_ITEM_MISMATCH",
    );
    const expectedKind = item.path.startsWith("identity/")
      ? "identity"
      : item.path.startsWith("records/")
        ? "record"
        : item.path.startsWith("keys/")
          ? "key"
          : item.path.startsWith("snapshots/")
            ? "source-snapshot"
            : "chunk";
    check(row.kind === expectedKind, "EXPORT_KIND_MISMATCH");
    if (row.kind === "key") {
      const key = decode("export-key", item.bytes);
      check(
        key.revision_id === item.path.split("/")[1].slice(0, -5) &&
          !keys.has(key.revision_id),
        "EXPORT_KEY_MISMATCH",
      );
      keys.set(key.revision_id, key);
    }
  }
  const sourcePages = items
    .filter((x) => x.path.startsWith("snapshots/"))
    .map((x) => x.bytes);
  const snapshot = verifySnapshotForEvaluation(
    wire(header.snapshot),
    sourcePages,
    BigInt(header.created_at),
    () => {},
  );
  const expectedSnapshots = sourcePages.map(
    (_, i) => "snapshots/" + String(i).padStart(8, "0") + ".json",
  );
  check(
    same(
      items.filter((x) => x.path.startsWith("snapshots/")).map((x) => x.path),
      expectedSnapshots,
    ),
    "INVALID_PAGE_ORDER",
  );
  const sourceIndex = new Map(
    snapshot.inventory.map((x) => [x.revision_id, x]),
  );
  check(
    sourceIndex.size === snapshot.inventory.length,
    "DUPLICATE_REVISION_ID",
  );
  const recovered = [],
    recoveredFiles = [],
    usedChunks = new Set();
  for (const item of items.filter((e) => e.path.startsWith("records/"))) {
    const raw = strictJson(item.bytes, 4194304),
      pruned = raw.payload_status === "pruned",
      isFile = raw.record_kind === "file-manifest",
      bundle = decode(
        pruned
          ? "export-pruned-record"
          : isFile
            ? "export-file-record"
            : "bundle",
        item.bytes,
      ),
      context = bundle.envelope.header.context,
      group = proofs.groups.get(context.group_id);
    check(
      group && header.selection.group_ids.includes(context.group_id),
      "EXPORT_SELECTION_MISMATCH",
    );
    const revision = isFile ? context.file_version_id : context.revision_id,
      object = isFile ? context.file_id : context.object_id,
      k = keys.get(revision),
      source = sourceIndex.get(revision);
    check(
      source &&
        source.group_id === context.group_id &&
        source.object_id === object &&
        source.object_kind ===
          (isFile ? "file-manifest" : context.object_kind) &&
        source.envelope_digest ===
          (isFile
            ? (await import("./codec.mjs")).envelopeDigest(
                wire(bundle.envelope),
              )
            : digest("envelope", wire(bundle.envelope))) &&
        source.payload_status ===
          (pruned
            ? "pruned"
            : context.action === "soft-delete"
              ? "tombstone"
              : "retained"),
      "EXPORT_SOURCE_MISMATCH",
    );
    sourceIndex.delete(revision);
    check(
      header.selection.include_trash || source.payload_status !== "tombstone",
      "EXPORT_SELECTION_MISMATCH",
    );
    if (!header.selection.include_history) {
      const history = proofs.g.observedHistoryRecordsForEvaluation(group);
      check(
        !history.some((r) => r.parents.some((p) => p.revision_id === revision)),
        "EXPORT_SELECTION_MISMATCH",
      );
    }
    if (pruned) {
      check(!k, "EXPORT_KEY_MISMATCH");
      if (isFile)
        proofs.g.checkHistoricalFileForEvaluation(
          group,
          wire(bundle.envelope),
          verifiedSender,
        );
      else
        proofs.g.checkHistoricalObjectForEvaluation(
          group,
          wire(bundle.envelope),
          verifiedSender,
        );
      continue;
    }
    check(
      k &&
        k.key_kind === (isFile ? "manifest-and-file-deks" : "object-dek") &&
        k.service_id === context.service_id &&
        k.group_id === context.group_id &&
        k.object_id === object &&
        item.path === "records/" + revision + ".json",
      "EXPORT_KEY_MISMATCH",
    );
    if (isFile) {
      const authority = proofs.g.checkHistoricalFileForEvaluation(
        group,
        wire(bundle.envelope),
        verifiedSender,
      );
      const chunks = [];
      for (
        let i = 0;
        i < Number(bundle.envelope.header.framing.chunk_count);
        i++
      ) {
        const path =
            "files/" + revision + "/" + String(i).padStart(8, "0") + ".bin",
          chunk = items.find((e) => e.path === path);
        check(chunk, "EXPORT_CHUNK_MISSING");
        chunks.push(chunk.bytes);
        usedChunks.add(path);
      }
      const { decryptExportedFileForEvaluation } = await import(
        "../export-file.mjs"
      );
      recoveredFiles.push(
        decryptExportedFileForEvaluation(
          bundle,
          chunks,
          k,
          authority.certificate,
        ),
      );
    } else {
      const authority = proofs.g.checkHistoricalObjectForEvaluation(
        group,
        wire(bundle.envelope),
        verifiedSender,
      );
      const { decryptExportedObjectForEvaluation } = await import(
        "./object-crypto.mjs"
      );
      recovered.push(
        decryptExportedObjectForEvaluation(
          item.bytes,
          Buffer.from(k.object_dek, "base64url"),
          Buffer.from(
            certificateDetails(authority.certificate).body.device_signing_key,
            "base64url",
          ),
          wire(context),
        ),
      );
    }
    keys.delete(revision);
  }
  check(
    items
      .filter((e) => e.path.startsWith("files/"))
      .every((e) => usedChunks.has(e.path)),
    "EXPORT_UNUSED_CHUNK",
  );
  check(sourceIndex.size === 0, "EXPORT_SOURCE_INCOMPLETE");
  check(keys.size === 0, "EXPORT_UNUSED_KEY");
  return {
    status: "VERIFIED_OFFLINE_SYNTHETIC",
    header,
    recovered,
    recoveredFiles,
    live_destination_mutations: 0,
    import_policy: "NEW_PRIVATE_GROUP_FRESH_IDS_KEYS_CURRENT_EPOCH_REQUIRED",
    tar,
  };
}
