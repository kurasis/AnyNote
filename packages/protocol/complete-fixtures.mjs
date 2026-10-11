// Development-only PUBLIC fixture writer; normal checks never rewrite vectors.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import sodium from "libsodium-wrappers-sumo";
import { wire, same } from "./src/identity-codec.mjs";
import {
  common,
  decode,
  encode,
  digest,
  aad,
  rawDigest,
  signingInput,
} from "./src/protocol-codec.mjs";
import {
  encryptObjectForEvaluation,
  decryptObjectForEvaluation,
  encryptLocalForEvaluation,
  decryptLocalForEvaluation,
  phraseKekForEvaluation,
  prfKekForEvaluation,
  wrapLocalKeyForEvaluation,
  unwrapLocalKeyForEvaluation,
  wrapNativeForEvaluation,
  nativeKekForEvaluation,
  unwrapNativeForEvaluation,
} from "./src/object-crypto.mjs";
import { groupBase, groupAccount } from "./group-fixtures.mjs";
import { groupStateForProfile } from "./src/group-state.mjs";
import { groupBuildersForProfile } from "./src/group-builders.mjs";
import { groupCodecForProfile } from "./src/group-codec.mjs";
import {
  rosterScope,
  rosterDetails,
  rosterEvents,
  activeCertificateForEvaluation,
} from "./src/roster.mjs";
import { stateDecode } from "./src/state-codec.mjs";
import { prepareEvaluationFile } from "./evaluation-file.mjs";
import {
  identityDetails,
  senderForCertificate,
} from "./src/identity-crypto.mjs";
import { pageCommitmentForEvaluation } from "./src/sync-reference.mjs";
import {
  makeExportForEvaluation,
  ageForEvaluation,
  verifyExportForEvaluation,
} from "./src/export-reference.mjs";
await sodium.ready;
export const fixtureDir = new URL(
  "../../fixtures/protocol/p02/v1/",
  import.meta.url,
);
export const b64 = (b) => Buffer.from(b).toString("base64url");
export const seed = (label, n = 32) =>
  createHash("sha512")
    .update("PUBLIC ANYNOTE P02 v1 " + label)
    .digest()
    .subarray(0, n);
export const id = (label) => b64(seed(label, 16));
export function sceneForEvaluation() {
  const accounts = [0, 1, 2].map(groupAccount),
    owner = accounts[0],
    g = groupStateForProfile("p02-group-c2"),
    build = groupBuildersForProfile("p02-group-c2", g),
    codec = groupCodecForProfile("p02-group-c2");
  const sender = (i = 0) =>
    g.groupSenderForEvaluation(
      group,
      rosterScope(accounts[i].roster).account_id,
      accounts[i].current.device.body.device_id,
    );
  const signer = () =>
    senderForCertificate(
      activeCertificateForEvaluation(
        owner.roster,
        owner.current.device.body.device_id,
      ),
      rosterDetails(owner.roster).head,
    );
  const genesis = build.genesisForEvaluation(
    identityDetails(owner.identity).body.service_id,
    id("group"),
    signer(),
    "shared",
    owner.current.device.signing.privateKey,
  );
  const pin = {
    service_id: rosterScope(owner.roster).service_id,
    group_id: id("group"),
    owner_account_id: rosterScope(owner.roster).account_id,
    owner_root_fingerprint: rosterScope(owner.roster).root_fingerprint,
    genesis_digest: codec.groupDigest("policy", genesis),
  };
  const group = g.newGroupForEvaluation(
      genesis,
      wire(pin),
      accounts.map((a) => ({ identity: a.identity, roster: a.roster })),
    ),
    keys = new Map(),
    transitions = [];
  function epoch(reason = "genesis", policy = null) {
    const n = String(
        g.groupDetails(group).epoch
          ? BigInt(g.groupDetails(group).epoch.version) + 1n
          : 0n,
      ),
      key = seed("group-key-" + n);
    keys.set(n, key);
    const intent = build.epochIntentForEvaluation(
      group,
      reason,
      sender(),
      owner.current.device.signing.privateKey,
      key,
      g.groupRostersForEvaluation(group, policy, 10000n),
      10000n,
      policy,
    );
    g.beginGroupEpochForEvaluation(group, intent, policy, 10000n);
    const pages = build.grantPagesForEvaluation(
      group,
      intent,
      keys,
      owner.current.device.signing.privateKey,
      owner.roster,
      10000n,
      policy,
    );
    for (const p of pages) g.stageGroupGrantPageForEvaluation(group, p, 10000n);
    const commit = build.epochCommitForEvaluation(
      group,
      intent,
      pages,
      owner.current.device.signing.privateKey,
      policy,
    );
    g.finalizeGroupEpochForEvaluation(group, commit, 10000n);
    transitions.push({
      kind: "epoch",
      value: {
        record: codec.groupDecode("epoch-commit", commit),
        pages: pages.map((p) => codec.groupDecode("grant-page", p)),
      },
    });
  }
  epoch();
  g.startFreshHistoryObservationForEvaluation(group);
  const author = (i) => ({
    account_id: rosterScope(accounts[i].roster).account_id,
    root_fingerprint: rosterScope(accounts[i].roster).root_fingerprint,
    device_id: accounts[i].current.device.body.device_id,
    recovery_generation: rosterDetails(accounts[i].roster).generation,
    roster: rosterDetails(accounts[i].roster).head,
  });
  function payload(
    kind = "entry",
    i = 1,
    action = "create",
    parents = [],
    label = "note",
  ) {
    const context = {
      ...common("object-context"),
      service_id: pin.service_id,
      group_id: pin.group_id,
      object_kind: kind,
      object_id: id(label),
      revision_id: id(label + "-" + action),
      operation_id: id(label + "-" + action + "-op"),
      thread_id: kind === "entry" ? id("thread") : null,
      action,
      author: author(i),
      policy: g.groupPolicyReference(group),
      parents,
      attachments: [],
      payload_schema: 1,
      archived: false,
    };
    return {
      ...common("object-plaintext"),
      context,
      title: action === "soft-delete" ? "" : "PUBLIC " + kind,
      tags: action === "soft-delete" ? [] : ["public", "test"],
      markdown:
        kind === "entry" && action !== "soft-delete"
          ? "# Public note\nNo real user content."
          : "",
      checklist: [],
      summary_entry_id: null,
      metadata_kind: "content",
      preferences: [],
    };
  }
  function admit(index, role) {
    const target = accounts[index],
      invite = build.invitationForGroupEvaluation(
        group,
        sender(),
        rosterScope(target.roster),
        role,
        owner.current.device.signing.privateKey,
        10000n,
      );
    g.stageInvitationForEvaluation(group, invite, 10000n);
    g.acceptInvitationForEvaluation(
      group,
      build.acceptanceForGroupEvaluation(
        invite,
        sender(index),
        target.current.device.signing.privateKey,
      ),
      10000n,
    );
    epoch(
      "admission",
      build.admissionPolicyForEvaluation(
        group,
        sender(),
        owner.current.device.signing.privateKey,
      ),
    );
  }
  admit(1, "editor");
  admit(2, "reader");
  return {
    g,
    build,
    codec,
    accounts,
    owner,
    group,
    genesis,
    pin,
    sender,
    author,
    payload,
    keys,
    transitions,
    epoch,
    admit,
  };
}
export async function writeCompleteFixtures() {
  mkdirSync(fixtureDir, { recursive: true });
  const s = sceneForEvaluation(),
    p = s.payload(),
    inputs = {
      objectKey: seed("object-dek"),
      nonce: seed("note-nonce", 24),
      wrapNonce: seed("wrap-nonce", 24),
    },
    groupKey = s.keys.get(p.context.policy.key_epoch);
  const bundle = encryptObjectForEvaluation(
    wire(p),
    groupKey,
    s.accounts[1].current.device.signing.privateKey,
    inputs,
  );
  s.g.observeAcceptedObjectForEvaluation(s.group, wire(bundle.envelope));
  const authorizationCases = [];
  for (const [name, payload, expected] of [
    ["editor-entry", p, "ACCEPT_CURRENT"],
    ["reader-entry", s.payload("entry", 2), "WRITER_REQUIRED"],
    ["editor-group-metadata", s.payload("group-metadata", 1), "OWNER_REQUIRED"],
    ["owner-group-metadata", s.payload("group-metadata", 0), "ACCEPT_CURRENT"],
  ]) {
    const index =
      payload.context.author.account_id === s.author(0).account_id
        ? 0
        : payload.context.author.account_id === s.author(1).account_id
          ? 1
          : 2;
    const value = encryptObjectForEvaluation(
      wire(payload),
      groupKey,
      s.accounts[index].current.device.signing.privateKey,
    );
    authorizationCases.push({ name, envelope: value.envelope, expected });
  }
  const altered = structuredClone(bundle.envelope);
  altered.signature = b64(seed("wrong-signature", 64));
  authorizationCases.push({
    name: "signature-replacement",
    envelope: altered,
    expected: "SIGNATURE_INVALID",
  });
  const stale = structuredClone(bundle.envelope);
  stale.header.context.policy.membership.version = "0";
  authorizationCases.push({
    name: "stale-policy",
    envelope: stale,
    expected: "POLICY_OR_EPOCH_CHANGED",
  });
  const badRoster = structuredClone(bundle.envelope);
  badRoster.header.context.author.roster.version = "8";
  authorizationCases.push({
    name: "stale-roster",
    envelope: badRoster,
    expected: "ROSTER_CHANGED",
  });
  const filePlain = Buffer.from(
      "PUBLIC offline file recovered without uploader keys",
    ),
    fileKeys = {
      groupKey,
      fileKey: seed("file-dek"),
      manifestKey: seed("manifest-dek"),
      wrapNonce: seed("file-wrap-nonce", 24),
      manifestNonce: seed("file-manifest-nonce", 24),
      noncePrefix: seed("file-prefix", 16),
    },
    fileContext = {
      protocol: "anynote",
      protocol_version: 1,
      contract: "p02-file-c1",
      service_id: s.pin.service_id,
      group_id: s.pin.group_id,
      file_id: id("file"),
      file_version_id: id("file-version"),
      operation_id: id("file-operation"),
      author: s.author(1),
      policy: s.g.groupPolicyReference(s.group),
      parents: [],
      file_format: "xchacha20poly1305-chunks-c1",
      manifest_schema: 1,
    };
  const file = prepareEvaluationFile(
    wire(fileContext),
    filePlain,
    fileKeys,
    s.accounts[1].current.device.signing.privateKey,
  );
  s.g.observeAcceptedFileForEvaluation(s.group, wire(file.envelope));
  const fileRecord = {
      record_kind: "file-manifest",
      envelope: file.envelope,
      wrap: file.wrap,
      manifest_ciphertext: file.manifest_ciphertext,
    },
    fileExportKey = {
      ...common("export-selected-key"),
      service_id: s.pin.service_id,
      group_id: s.pin.group_id,
      object_id: fileContext.file_id,
      revision_id: fileContext.file_version_id,
      key_kind: "manifest-and-file-deks",
      object_dek: b64(fileKeys.manifestKey),
      file_data_dek: b64(fileKeys.fileKey),
    };
  const pages = s.build.historyPagesForEvaluation(s.group),
    history = s.build.historyForEvaluation(
      s.group,
      s.sender(),
      s.owner.current.device.signing.privateKey,
      pages,
    );
  s.g.endorseGroupHistoryForEvaluation(
    s.group,
    history,
    pages,
    s.g.independentHistoryWitnessForEvaluation(s.group),
  );
  const localContext = {
    ...common("local-record"),
    ...{
      service_id: p.context.service_id,
      account_id: p.context.author.account_id,
      device_id: p.context.author.device_id,
    },
    profile_id: id("profile"),
    record_id: id("draft-record"),
    record_kind: "draft",
    local_schema: 1,
  };
  const localPlain = {
      ...common("local-record-plaintext"),
      context: localContext,
      data: { draft_id: id("draft"), context: p.context, payload: p },
    },
    localKey = seed("local-L"),
    localCipher = encryptLocalForEvaluation(
      wire(localPlain),
      localKey,
      seed("local-nonce", 24),
    );
  const unlockContext = {
      ...common("local-unlock"),
      service_id: localContext.service_id,
      account_id: localContext.account_id,
      device_id: localContext.device_id,
      profile_id: localContext.profile_id,
      wrapper_id: id("phrase-wrapper"),
      method: "argon2id13",
    },
    parameters = {
      algorithm: "argon2id13",
      salt: b64(seed("argon-salt", 16)),
      opslimit: 3,
      memlimit: 67108864,
    },
    phrase = "public synthetic silver meadow orbit lantern";
  const phraseKek = await phraseKekForEvaluation(phrase, wire(parameters)),
    phraseDescriptor = { context: unlockContext, parameters },
    phraseWrapper = wrapLocalKeyForEvaluation(
      "phrase-wrapper",
      wire(phraseDescriptor),
      localKey,
      phraseKek,
      seed("phrase-nonce", 24),
    );
  const prfContext = {
      ...unlockContext,
      wrapper_id: id("prf-wrapper"),
      method: "webauthn-prf",
    },
    credentialId = b64(seed("credential", 32)),
    prfSalt = seed("prf-salt"),
    prfResult = seed("prf-result"),
    prfKek = prfKekForEvaluation(
      wire(prfContext),
      credentialId,
      prfSalt,
      prfResult,
    ),
    prfDescriptor = {
      context: prfContext,
      credential_id: credentialId,
      prf_salt: b64(prfSalt),
    },
    prfWrapper = wrapLocalKeyForEvaluation(
      "prf-wrapper",
      wire(prfDescriptor),
      localKey,
      prfKek,
      seed("prf-nonce", 24),
    );
  const evidence = {
    accounts: s.accounts.map((a) => ({
      identity: identityDetails(a.identity),
      pin: a.v.outputs.pin,
      events: rosterEvents(a.roster).map((e) => stateDecode("event", e)),
    })),
    groups: [
      {
        genesis: s.codec.groupDecode("policy", s.genesis),
        genesis_pin: s.pin,
        transitions: s.transitions,
        history: s.codec.groupDecode("history", history),
        history_pages: pages.map((b) => JSON.parse(b)),
      },
    ],
  };
  // Public identityDetails contains verifier metadata; archive stores only the exact signed identity record.
  evidence.accounts.forEach(
    (a, i) => (a.identity = s.accounts[i].v.outputs.identity),
  );
  const snapshot = {
    ...common("snapshot-descriptor"),
    snapshot_id: id("snapshot"),
    account_id: s.author(0).account_id,
    device_id: s.author(0).device_id,
    snapshot_purpose: "export",
    watermark: { generation: id("transport"), sequence: "1" },
    created_at: "10000",
    expires_at: "86410000",
    page_count: "0",
    item_count: "0",
    inventory_digest: pageCommitmentForEvaluation("snapshot", [])
      .inventory_digest,
  };
  const snapshotPage = {
    ...common("snapshot-page"),
    snapshot_id: snapshot.snapshot_id,
    page_index: "0",
    items: s.g
      .observedHistoryRecordsForEvaluation(s.group)
      .map((r) => ({
        group_id: s.pin.group_id,
        object_kind: r.object_kind,
        object_id: r.object_id,
        revision_id: r.revision_id,
        envelope_digest: r.envelope_digest,
        payload_status: r.payload_status,
      }))
      .sort((a, b) =>
        a.object_kind + "/" + a.object_id + "/" + a.revision_id <
        b.object_kind + "/" + b.object_id + "/" + b.revision_id
          ? -1
          : 1,
      ),
  };
  Object.assign(
    snapshot,
    pageCommitmentForEvaluation("snapshot", [wire(snapshotPage)]),
  );
  const header = {
    ...common("export-header"),
    export_id: id("export"),
    service_id: p.context.service_id,
    account_id: s.author(0).account_id,
    root_fingerprint: s.author(0).root_fingerprint,
    snapshot,
    selection: {
      include_history: true,
      include_trash: true,
      group_ids: [s.pin.group_id],
    },
    created_at: "10000",
    outer_format: "age-v1-X25519",
    archive_format: "ustar-anynote-v1",
  };
  const exportKey = {
    ...common("export-selected-key"),
    service_id: p.context.service_id,
    group_id: p.context.group_id,
    object_id: p.context.object_id,
    revision_id: p.context.revision_id,
    key_kind: "object-dek",
    object_dek: b64(inputs.objectKey),
    file_data_dek: null,
  };
  const items = [
    {
      path: "identity/evidence.json",
      kind: "identity",
      bytes: encode("export-evidence", wire(evidence)),
    },
    {
      path: "records/" + p.context.revision_id + ".json",
      kind: "record",
      bytes: encode("bundle", wire(bundle)),
    },
    {
      path: "keys/" + p.context.revision_id + ".json",
      kind: "key",
      bytes: encode("export-key", wire(exportKey)),
    },
  ];
  items.push(
    {
      path: "snapshots/00000000.json",
      kind: "source-snapshot",
      bytes: encode("snapshot-page", wire(snapshotPage)),
    },
    {
      path: "records/" + fileContext.file_version_id + ".json",
      kind: "record",
      bytes: encode("export-file-record", wire(fileRecord)),
    },
    {
      path: "keys/" + fileContext.file_version_id + ".json",
      kind: "key",
      bytes: encode("export-key", wire(fileExportKey)),
    },
    {
      path: "files/" + fileContext.file_version_id + "/00000000.bin",
      kind: "chunk",
      bytes: Buffer.from(file.chunks[0], "base64url"),
    },
  );
  const result = await makeExportForEvaluation(
    wire(header),
    items,
    wire(s.author(0)),
    s.owner.current.device.signing.privateKey,
  );
  const { spawnSync } = await import("node:child_process");
  const generated = spawnSync(
    fileURLToPath(
      new URL("../../.local/p02-tools/age-keygen", import.meta.url),
    ),
    [],
    { encoding: "utf8" },
  );
  if (generated.status !== 0) throw Error("PUBLIC_KEYGEN_FAILED");
  const identity = generated.stdout
      .split("\n")
      .find((l) => l.startsWith("AGE-SECRET-KEY-")),
    recipient =
      generated.stdout.match(/public key: (age1\w+)/i)?.[1] ??
      generated.stderr.match(/Public key: (age1\w+)/i)?.[1];
  const ageBytes = await ageForEvaluation(
      "rage",
      "encrypt",
      result.tar,
      recipient,
    ),
    ageGo = await ageForEvaluation("age", "encrypt", result.tar, recipient),
    d = s.g.groupDetails(s.group);
  const kit = {
    ...common("export-recovery-document"),
    export_id: header.export_id,
    archive_sha256: rawDigest(ageBytes),
    export_identity: identity,
    exporter_root_fingerprint: header.root_fingerprint,
    exporter_roster: s.author(0).roster,
    independent_group_pins: [
      {
        group_id: d.scope.group_id,
        genesis_digest: s.pin.genesis_digest,
        policy: d.policy,
        epoch: d.epoch,
        history: d.history,
      },
    ],
  };
  const nativeDescriptor = {
      context: {
        ...unlockContext,
        wrapper_id: id("native-wrapper"),
        method: "windows-webauthn-prf",
      },
      provider: "windows-hello-webauthn-prf-tpm",
      provider_format: 1,
      credential_id: credentialId,
      prf_salt: b64(prfSalt),
      tpm_name: b64(Buffer.concat([Buffer.from([0, 11]), seed("tpm-name")])),
      tpm_public_sha256: b64(seed("tpm-public")),
      machine_binding_id: id("machine"),
    },
    nativeWrapper = wrapNativeForEvaluation(
      wire(nativeDescriptor),
      localKey,
      prfResult,
      seed("native-nonce", 12),
    );
  const fixture = {
    status: "PUBLIC_SYNTHETIC_ONLY_NOT_PLATFORM_AUTH_OR_PRODUCT_SQL",
    inputs: {
      group_key_hex: groupKey.toString("hex"),
      object_key_hex: inputs.objectKey.toString("hex"),
      signing_secret_hex: Buffer.from(
        s.accounts[1].current.device.signing.privateKey,
      ).toString("hex"),
      signing_public_hex: Buffer.from(
        s.accounts[1].current.device.signing.publicKey,
      ).toString("hex"),
      nonce_hex: inputs.nonce.toString("hex"),
      wrap_nonce_hex: inputs.wrapNonce.toString("hex"),
      local_key_hex: localKey.toString("hex"),
      local_nonce_hex: seed("local-nonce", 24).toString("hex"),
      phrase,
      prf_result_hex: prfResult.toString("hex"),
      recipient,
    },
    objects: {
      payload: p,
      bundle,
      local_plain: localPlain,
      local_cipher: decode("local-envelope", localCipher),
      parameters,
      phrase_descriptor: phraseDescriptor,
      phrase_wrapper: decode("phrase-wrapper", phraseWrapper),
      prf_descriptor: prfDescriptor,
      prf_wrapper: decode("prf-wrapper", prfWrapper),
      evidence,
      header,
      export_key: exportKey,
      footer: result.footer,
      kit,
      snapshot_page: snapshotPage,
      file_record: fileRecord,
      file_export_key: fileExportKey,
      file_plain_hex: filePlain.toString("hex"),
      file_chunk_hex: Buffer.from(file.chunks[0], "base64url").toString("hex"),
      authorization_cases: authorizationCases,
      native_descriptor: nativeDescriptor,
      native_wrapper: decode("native-wrapper", nativeWrapper),
    },
    expected: {
      payload_hex: encode("payload", wire(p)).toString("hex"),
      local_plain_hex: encode("local-plaintext", wire(localPlain)).toString(
        "hex",
      ),
      phrase_kek_hex: Buffer.from(phraseKek).toString("hex"),
      prf_kek_hex: Buffer.from(prfKek).toString("hex"),
      native_kek_hex: Buffer.from(
        nativeKekForEvaluation(wire(nativeDescriptor), prfResult),
      ).toString("hex"),
      tar_sha256: rawDigest(result.tar),
      rust_age_sha256: rawDigest(ageBytes),
      go_age_sha256: rawDigest(ageGo),
    },
  };
  writeFileSync(
    new URL("crypto.json", fixtureDir),
    JSON.stringify(fixture, null, 2) + "\n",
  );
  writeFileSync(new URL("rust.age", fixtureDir), ageBytes);
  writeFileSync(new URL("go.age", fixtureDir), ageGo);
  await checkCompleteFixture(fixture);
  return fixture;
}
export async function checkCompleteFixture(f) {
  const x = f.inputs,
    o = f.objects,
    raw = (s) => Buffer.from(s, "hex");
  const fresh = encryptObjectForEvaluation(
    wire(o.payload),
    raw(x.group_key_hex),
    raw(x.signing_secret_hex),
    {
      objectKey: raw(x.object_key_hex),
      nonce: raw(x.nonce_hex),
      wrapNonce: raw(x.wrap_nonce_hex),
    },
  );
  if (!same(fresh, o.bundle)) throw Error("OBJECT_VECTOR_DRIFT");
  if (
    encode(
      "payload",
      wire(
        decryptObjectForEvaluation(
          wire(o.bundle),
          raw(x.group_key_hex),
          raw(x.signing_public_hex),
          wire(o.payload.context),
        ),
      ),
    ).toString("hex") !== f.expected.payload_hex
  )
    throw Error("OBJECT_DECRYPT_DRIFT");
  if (
    !same(
      decryptLocalForEvaluation(
        wire(o.local_cipher),
        raw(x.local_key_hex),
        wire(o.local_plain.context),
      ),
      o.local_plain,
    )
  )
    throw Error("LOCAL_VECTOR_DRIFT");
  if (
    !same(
      decode(
        "local-envelope",
        encryptLocalForEvaluation(
          wire(o.local_plain),
          raw(x.local_key_hex),
          raw(x.local_nonce_hex),
        ),
      ),
      o.local_cipher,
    )
  )
    throw Error("LOCAL_ENCRYPT_DRIFT");
  const phraseKek = await phraseKekForEvaluation(x.phrase, wire(o.parameters));
  if (Buffer.from(phraseKek).toString("hex") !== f.expected.phrase_kek_hex)
    throw Error("ARGON_VECTOR_DRIFT");
  const prfKek = prfKekForEvaluation(
    wire(o.prf_descriptor.context),
    o.prf_descriptor.credential_id,
    Buffer.from(o.prf_descriptor.prf_salt, "base64url"),
    raw(x.prf_result_hex),
  );
  if (Buffer.from(prfKek).toString("hex") !== f.expected.prf_kek_hex)
    throw Error("PRF_VECTOR_DRIFT");
  for (const kind of ["phrase", "prf"])
    if (
      Buffer.from(
        unwrapLocalKeyForEvaluation(
          kind + "-wrapper",
          wire(o[kind + "_wrapper"]),
          wire(o[kind + "_descriptor"]),
          kind === "phrase" ? phraseKek : prfKek,
        ),
      ).toString("hex") !== x.local_key_hex
    )
      throw Error("LOCAL_KEY_UNWRAP_DRIFT");
  for (const [file, provider] of [
    ["rust.age", "age"],
    ["go.age", "rage"],
  ]) {
    const bytes = readFileSync(new URL(file, fixtureDir)),
      kit = { ...o.kit, archive_sha256: rawDigest(bytes) };
    const result = await verifyExportForEvaluation(bytes, wire(kit), provider);
    if (
      !same(result.recovered, [o.payload]) ||
      result.recoveredFiles[0].bytes.toString("hex") !== o.file_plain_hex ||
      rawDigest(result.tar) !== f.expected.tar_sha256
    )
      throw Error("OFFLINE_EXPORT_DRIFT");
  }
  if (
    Buffer.from(
      nativeKekForEvaluation(wire(o.native_descriptor), raw(x.prf_result_hex)),
    ).toString("hex") !== f.expected.native_kek_hex ||
    unwrapNativeForEvaluation(
      wire(o.native_wrapper),
      wire(o.native_descriptor),
      raw(x.prf_result_hex),
    ).toString("hex") !== x.local_key_hex
  )
    throw Error("NATIVE_BYTE_VECTOR_DRIFT");
  return {
    status: "PASS",
    scope: "PUBLIC_NOTE_LOCAL_AND_INDEPENDENT_RUST_GO_AGE_FIXTURES",
    actual_account_auth_SQL_and_platform_custody: "NOT_IMPLEMENTED",
  };
}
if (process.argv[1] === fileURLToPath(import.meta.url))
  console.log(
    JSON.stringify(
      await checkCompleteFixture(
        process.argv.includes("--write")
          ? await writeCompleteFixtures()
          : JSON.parse(readFileSync(new URL("crypto.json", fixtureDir))),
      ),
    ),
  );
