import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import sodium from "libsodium-wrappers-sumo";
import { wire } from "./src/identity-codec.mjs";
import {
  createIdentity,
  verifyRootIdentity,
  identityDetails,
  deriveRoot,
  senderForCertificate,
} from "./src/identity-crypto.mjs";
import * as roster from "./src/roster.mjs";
import { EvaluationAuthority } from "./src/evaluation-authority.mjs";
import {
  fixtureBase,
  registerFixture,
  publicDevice,
  prepareEnrollment,
  activateFixture,
} from "./state-fixtures.mjs";
import { publicSeed } from "./crypto-vectors.mjs";
import * as g from "./src/group-state.mjs";
import * as build from "./src/group-builders.mjs";
import { groupDecode, groupDigest } from "./src/group-codec.mjs";
import { stateDecode } from "./src/state-codec.mjs";
import {
  prepareEvaluationFile,
  decryptEvaluationFile,
} from "./evaluation-file.mjs";
import * as enroll from "./src/enrollment.mjs";
await sodium.ready;
const b64 = (b) => Buffer.from(b).toString("base64url");
export const groupFixturePath = new URL(
  "../../fixtures/protocol/p02/group-vectors.json",
  import.meta.url,
);
export function groupAccount(index) {
  if (index === 0) {
    const a = fixtureBase();
    a.current = registerFixture(a, 0);
    return a;
  }
  const owner = fixtureBase(),
    context = {
      ...owner.v.input.context,
      account_id: b64(publicSeed(32 + index * 32).slice(0, 16)),
    },
    secret = publicSeed(index === 1 ? 80 : 160),
    identityBytes = createIdentity(secret, wire(context)),
    detail = JSON.parse(identityBytes);
  const pin = {
      service_id: context.service_id,
      account_id: context.account_id,
      root_fingerprint: awaitFingerprint(identityBytes),
    },
    identity = verifyRootIdentity(identityBytes, wire(pin)),
    root = deriveRoot(secret, wire(context)),
    r = roster.newRosterForEvaluation(identity);
  const a = {
    identity,
    root,
    roster: r,
    server: new EvaluationAuthority(r),
    now: 10000n,
    v: { outputs: { identity: detail, pin } },
  };
  a.current = registerFixture(a, index * 4);
  return a;
}
// Fingerprint API avoids an unchecked server pin in the public fixture builder.
import { rootFingerprint as awaitFingerprint } from "./src/identity-crypto.mjs";
export function groupBase(kind = "shared") {
  const accounts = [0, 1, 2].map(groupAccount),
    owner = accounts[0],
    sender = senderForCertificate(
      roster.activeCertificateForEvaluation(
        owner.roster,
        owner.current.device.body.device_id,
      ),
      roster.rosterDetails(owner.roster).head,
    );
  const genesis = build.genesisForEvaluation(
    identityDetails(owner.identity).body.service_id,
    b64(publicSeed(220).slice(0, 16)),
    sender,
    kind,
    owner.current.device.signing.privateKey,
  );
  const pin = {
    service_id: identityDetails(owner.identity).body.service_id,
    group_id: b64(publicSeed(220).slice(0, 16)),
    owner_account_id: sender.account_id,
    owner_root_fingerprint: sender.root_fingerprint,
    genesis_digest: groupDigest("policy", genesis),
  };
  const group = g.newGroupForEvaluation(
    genesis,
    wire(pin),
    accounts.map((a) => ({ identity: a.identity, roster: a.roster })),
  );
  return { accounts, group, genesis, pin, now: 10000n, keys: new Map() };
}
export const currentSender = (base, index, capability = "sign-content") => {
  const a = base.accounts[index];
  return g.groupSenderForEvaluation(
    base.group,
    roster.rosterScope(a.roster).account_id,
    a.current.device.body.device_id,
    capability,
  );
};
export function prepareGroupEpoch(
  base,
  reason = "optional",
  actorIndex = 0,
  policyBytes = null,
  keys = base.keys,
) {
  const account = base.accounts[actorIndex],
    d = g.groupDetails(base.group),
    next = String(d.epoch ? BigInt(d.epoch.version) + 1n : 0n),
    key = publicSeed(120 + Number(next) * 7);
  keys.set(next, key);
  const intent = build.epochIntentForEvaluation(
    base.group,
    reason,
    currentSender(base, actorIndex, "distribute-group-key"),
    account.current.device.signing.privateKey,
    key,
    g.groupRostersForEvaluation(base.group, policyBytes, base.now),
    base.now,
    policyBytes,
  );
  g.beginGroupEpochForEvaluation(base.group, intent, policyBytes, base.now);
  const pages = build.grantPagesForEvaluation(
    base.group,
    intent,
    keys,
    account.current.device.signing.privateKey,
    account.roster,
    base.now,
    policyBytes,
  );
  for (const p of pages)
    g.stageGroupGrantPageForEvaluation(base.group, p, base.now);
  const commit = build.epochCommitForEvaluation(
    base.group,
    intent,
    pages,
    account.current.device.signing.privateKey,
    policyBytes,
  );
  return { intent, pages, commit, policy: policyBytes };
}
export function activateGroupEpoch(base, prepared) {
  return g.finalizeGroupEpochForEvaluation(
    base.group,
    prepared.commit,
    base.now,
  );
}
export function admitGroupAccount(base, index, role = "reader") {
  const owner = base.accounts[0],
    target = base.accounts[index],
    invite = build.invitationForGroupEvaluation(
      base.group,
      currentSender(base, 0),
      roster.rosterScope(target.roster),
      role,
      owner.current.device.signing.privateKey,
      base.now,
    );
  g.stageInvitationForEvaluation(base.group, invite, base.now);
  const accept = build.acceptanceForGroupEvaluation(
    invite,
    currentSender(base, index),
    target.current.device.signing.privateKey,
  );
  g.acceptInvitationForEvaluation(base.group, accept, base.now);
  const policy = build.admissionPolicyForEvaluation(
      base.group,
      currentSender(base, 0),
      owner.current.device.signing.privateKey,
    ),
    prepared = prepareGroupEpoch(base, "admission", 0, policy);
  activateGroupEpoch(base, prepared);
  return { ...prepared, invite, accept };
}
export function closeGroupHistory(base, index = 0) {
  const pages = build.historyPagesForEvaluation(base.group),
    record = build.historyForEvaluation(
      base.group,
      currentSender(base, index),
      base.accounts[index].current.device.signing.privateKey,
      pages,
    ),
    witness = g.independentHistoryWitnessForEvaluation(base.group);
  g.endorseGroupHistoryForEvaluation(base.group, record, pages, witness);
  return { record, pages };
}
export function fileForGroup(base, index = 1, idIndex = 180) {
  const sender = currentSender(base, index),
    d = g.groupDetails(base.group),
    context = {
      protocol: "anynote",
      protocol_version: 1,
      contract: "p02-file-c1",
      ...d.scope,
      file_id: b64(publicSeed(idIndex).slice(0, 16)),
      file_version_id: b64(publicSeed(idIndex + 1).slice(0, 16)),
      operation_id: build.randomGroupOperation(),
      author: {
        account_id: sender.account_id,
        device_id: sender.device_id,
        root_fingerprint: sender.root_fingerprint,
        recovery_generation: sender.recovery_generation,
        roster: sender.roster_head,
      },
      policy: g.groupPolicyReference(base.group),
      parents: [],
      file_format: "xchacha20poly1305-chunks-c1",
      manifest_schema: 1,
    };
  const plaintext = Buffer.from(
      "PUBLIC group authorized file before writer removal",
    ),
    bundle = prepareEvaluationFile(
      wire(context),
      plaintext,
      {
        groupKey: base.keys.get(context.policy.key_epoch),
        fileKey: publicSeed(200),
        manifestKey: publicSeed(201),
        wrapNonce: publicSeed(202).slice(0, 24),
        manifestNonce: publicSeed(203).slice(0, 24),
        noncePrefix: publicSeed(204).slice(0, 16),
      },
      base.accounts[index].current.device.signing.privateKey,
    );
  return { bundle, plaintext };
}
export function writeGroupFixture() {
  const b = groupBase(),
    accounts = b.accounts.map((a) => ({
      identity: a.v.outputs.identity,
      pin: a.v.outputs.pin,
      events: roster.rosterEvents(a.roster).map((e) => stateDecode("event", e)),
    })),
    steps = [];
  const add = (kind, input) =>
    steps.push({ kind, ...input, expected: g.groupDetails(b.group) });
  const epoch = (p) => {
    activateGroupEpoch(b, p);
    add("epoch", {
      record: groupDecode("epoch-commit", p.commit),
      pages: p.pages.map((p) => groupDecode("grant-page", p)),
    });
  };
  const history = (index = 0) => {
    const h = closeGroupHistory(b, index);
    add("history", {
      record: groupDecode("history", h.record),
      pages: h.pages.map((p) => JSON.parse(p)),
    });
  };
  epoch(prepareGroupEpoch(b, "genesis"));
  g.startFreshHistoryObservationForEvaluation(b.group);
  add("fresh-history", {});
  for (const [index, role] of [
    [1, "editor"],
    [2, "reader"],
  ]) {
    const p = admitGroupAccount(b, index, role);
    add("epoch", {
      record: groupDecode("epoch-commit", p.commit),
      pages: p.pages.map((p) => groupDecode("grant-page", p)),
    });
  }
  const file = fileForGroup(b);
  g.observeAcceptedFileForEvaluation(b.group, wire(file.bundle.envelope));
  add("file", {
    bundle: file.bundle,
    plaintext_hex: file.plaintext.toString("hex"),
  });
  history();
  const policy = (action, payload, index = 0, incomingKey = null) => {
    const p = build.policyForEvaluation(
      b.group,
      action,
      currentSender(b, index),
      b.accounts[index].current.device.signing.privateKey,
      payload,
      incomingKey,
    );
    g.applyGroupPolicyForEvaluation(b.group, p, b.now);
    add("policy", { record: groupDecode("policy", p) });
  };
  policy("role", {
    target_account_id: roster.rosterScope(b.accounts[1].roster).account_id,
    role: "reader",
  });
  history();
  const reader = b.accounts[2],
    pair = prepareEnrollment(reader, reader.current, 9);
  activateFixture(reader, pair);
  add("account-event", {
    account_index: 2,
    record: stateDecode("event", pair.event),
  });
  epoch(prepareGroupEpoch(b, "roster-maintenance", 2));
  history();
  policy("remove", {
    target_account_id: roster.rosterScope(b.accounts[1].roster).account_id,
  });
  history();
  epoch(prepareGroupEpoch(b, "member-removal"));
  policy(
    "transfer",
    { incoming_signer: currentSender(b, 2) },
    0,
    reader.current.device.signing.privateKey,
  );
  policy("archive", {}, 2);
  policy("unarchive", {}, 2);
  const newDevice = publicDevice(10),
    session = reader.server.authenticateForEvaluation(b.now),
    challenge = reader.server.issueChallenge(
      session,
      "reset",
      wire(newDevice.body),
      b.now,
    ),
    reset = enroll.rootEventForEvaluation(
      reader.roster,
      challenge,
      newDevice,
      reader.root.signing.privateKey,
    );
  reader.server.submitRootTransition(session, reset, b.now);
  reader.current = { device: newDevice, session };
  add("account-event", {
    account_index: 2,
    record: stateDecode("event", reset),
  });
  epoch(prepareGroupEpoch(b, "roster-maintenance"));
  history();
  const result = {
    status: "PUBLIC_SYNTHETIC_KEYS_OBSERVATION_NEVER_PRODUCT_ACCOUNT_AUTH",
    contract: "p02-group-c1",
    public_account_seed_profile:
      "owner prior identity; account1 R seed80/account64/device4; account2 R seed160/account96/device8; all PUBLIC",
    public_epoch_seed_profile: "bytes (120 + 7*epoch)..+31; PUBLIC ONLY",
    inputs: {
      accounts,
      genesis: groupDecode("policy", b.genesis),
      genesis_pin: b.pin,
      steps,
    },
    outputs: {
      final_pin: {
        ...g.groupDetails(b.group).scope,
        policy: g.groupDetails(b.group).policy,
        epoch: g.groupDetails(b.group).epoch,
        history: g.groupDetails(b.group).history,
      },
      historical_file_step: 4,
    },
  };
  writeFileSync(groupFixturePath, JSON.stringify(result, null, 2) + "\n");
  return result;
}
export function checkGroupFixture(f) {
  const accounts = f.inputs.accounts.map((a) => {
    const identity = verifyRootIdentity(wire(a.identity), wire(a.pin)),
      r = roster.newRosterForEvaluation(identity);
    for (const event of a.events)
      roster.applyRosterEventForEvaluation(r, wire(event));
    return { identity, roster: r };
  });
  const group = g.newGroupForEvaluation(
      wire(f.inputs.genesis),
      wire(f.inputs.genesis_pin),
      accounts,
    ),
    statistics = {
      epochs: 0,
      grants: 0,
      policies: 1,
      checkpoints: 0,
      files: 0,
    };
  for (const step of f.inputs.steps) {
    if (step.kind === "epoch") {
      g.replayGroupEpochForEvaluation(
        group,
        wire(step.record),
        step.pages.map(wire),
      );
      statistics.epochs++;
      if (step.record.body.policy) statistics.policies++;
      statistics.grants += step.pages.reduce((n, p) => n + p.records.length, 0);
    } else if (step.kind === "policy") {
      g.applyGroupPolicyForEvaluation(group, wire(step.record));
      statistics.policies++;
    } else if (step.kind === "account-event")
      roster.applyRosterEventForEvaluation(
        accounts[step.account_index].roster,
        wire(step.record),
      );
    else if (step.kind === "fresh-history")
      g.startFreshHistoryObservationForEvaluation(group);
    else if (step.kind === "file") {
      g.observeAcceptedFileForEvaluation(group, wire(step.bundle.envelope));
      statistics.files++;
    } else if (step.kind === "history") {
      g.endorseGroupHistoryForEvaluation(
        group,
        wire(step.record),
        step.pages.map(wire),
        g.independentHistoryWitnessForEvaluation(group),
      );
      statistics.checkpoints++;
    } else throw Error("UNSUPPORTED_FIXTURE_STEP");
    if (JSON.stringify(g.groupDetails(group)) !== JSON.stringify(step.expected))
      throw Error("GROUP_STATE_FIXTURE_DRIFT_" + step.kind);
  }
  g.verifyGroupStatePinForEvaluation(group, wire(f.outputs.final_pin));
  const file = f.inputs.steps.find((s) => s.kind === "file"),
    a = accounts[0],
    device = publicDevice(0),
    sender = g.groupSenderForEvaluation(
      group,
      roster.rosterScope(a.roster).account_id,
      device.body.device_id,
    ),
    epoch = file.bundle.envelope.header.context.policy.key_epoch;
  const record = g.groupGrantRecordsForEvaluation(group).find((r) => {
    const c = JSON.parse(r).body.context;
    return (
      c.key_epoch === epoch &&
      c.recipient.kind === "device" &&
      c.recipient.account_id === sender.account_id
    );
  });
  const key = g.openAuthorizedGroupKeyForEvaluation(
      group,
      record,
      sender,
      device.encryption.publicKey,
      device.encryption.privateKey,
    ),
    historical = g.checkHistoricalFileForEvaluation(
      group,
      wire(file.bundle.envelope),
      sender,
    ),
    plain = decryptEvaluationFile(
      file.bundle,
      key,
      historical.certificate,
      wire(file.bundle.envelope.header.context),
    );
  if (plain.toString("hex") !== file.plaintext_hex)
    throw Error("HISTORICAL_FILE_DRIFT");
  sodium.memzero(key);
  sodium.memzero(plain);
  return {
    status: "PASS",
    ...statistics,
    historical_file_bytes: Buffer.from(file.plaintext_hex, "hex").length,
    group_authorization: "VERIFIED_PINNED_CANDIDATE_STATE",
    history: "INDEPENDENT_BOUNDARY",
    account_authentication_and_SQL: "NOT_IMPLEMENTED",
  };
}
if (process.argv[1] === fileURLToPath(import.meta.url))
  console.log(
    JSON.stringify(
      checkGroupFixture(
        process.argv.includes("--write")
          ? writeGroupFixture()
          : JSON.parse(readFileSync(groupFixturePath)),
      ),
    ),
  );
