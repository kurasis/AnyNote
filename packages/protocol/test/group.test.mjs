import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import sodium from "libsodium-wrappers-sumo";
import { ContractError } from "../src/strict-json.mjs";
import { wire } from "../src/identity-codec.mjs";
import {
  groupDecode as decode,
  groupDigest as digest,
  groupSigningInput,
  groupKeyCommitment,
  grantPageCommitment,
} from "../src/group-codec.mjs";
import * as g from "../src/group-state.mjs";
import * as b from "../src/group-builders.mjs";
import * as r from "../src/roster.mjs";
import * as e from "../src/enrollment.mjs";
import { stateDecode } from "../src/state-codec.mjs";
import {
  publicDevice,
  prepareEnrollment,
  activateFixture,
} from "../state-fixtures.mjs";
import {
  groupBase,
  currentSender,
  prepareGroupEpoch,
  activateGroupEpoch,
  admitGroupAccount,
  closeGroupHistory,
  fileForGroup,
  groupFixturePath,
  checkGroupFixture,
} from "../group-fixtures.mjs";
await sodium.ready;
const fail = (fn, code) =>
  assert.throws(
    fn,
    (x) => x instanceof ContractError && (!code || x.code === code),
  );
const copy = structuredClone,
  b64 = (b) => Buffer.from(b).toString("base64url");
function base(kind = "shared") {
  const a = groupBase(kind);
  activateGroupEpoch(a, prepareGroupEpoch(a, "genesis"));
  g.startFreshHistoryObservationForEvaluation(a.group);
  return a;
}
function shared() {
  const a = base();
  admitGroupAccount(a, 1, "editor");
  admitGroupAccount(a, 2, "reader");
  return a;
}
const signChanged = (kind, bytes, change, key) => {
  const record = decode(kind, bytes);
  change(record.body);
  return g.signGroupRecord(
    kind,
    wire(record.body),
    key,
    record.cosignature ?? null,
  );
};
const issuer = (a, i = 0) => a.accounts[i].current.device.signing.privateKey;
const applyPolicy = (a, action, payload = {}, i = 0, incoming = null) =>
  g.applyGroupPolicyForEvaluation(
    a.group,
    b.policyForEvaluation(
      a.group,
      action,
      currentSender(a, i),
      issuer(a, i),
      payload,
      incoming,
    ),
    a.now,
  );
function stagedInvitation(a, index = 1, role = "reader") {
  const invite = b.invitationForGroupEvaluation(
    a.group,
    currentSender(a, 0),
    r.rosterScope(a.accounts[index].roster),
    role,
    issuer(a),
    a.now,
  );
  g.stageInvitationForEvaluation(a.group, invite, a.now);
  const accept = b.acceptanceForGroupEvaluation(
    invite,
    currentSender(a, index),
    issuer(a, index),
  );
  return { invite, accept };
}
function readerGrant(a, epoch = "2", i = 2) {
  const sender = currentSender(a, i);
  return g.groupGrantRecordsForEvaluation(a.group).find((raw) => {
    const c = JSON.parse(raw).body.context;
    return (
      c.key_epoch === epoch &&
      c.recipient.kind === "device" &&
      c.recipient.account_id === sender.account_id &&
      c.recipient.device_id === sender.device_id
    );
  });
}

test("frozen public group inputs reproduce complete policy, epoch, history and file paths", () => {
  const result = checkGroupFixture(JSON.parse(readFileSync(groupFixturePath)));
  assert.equal(result.epochs, 6);
  assert.equal(result.grants, 105);
  assert.equal(result.policies, 8);
  assert.equal(result.checkpoints, 5);
});
test("genesis requires independent root/group digest pin and an active owner certificate", () => {
  const a = groupBase(),
    pin = copy(a.pin);
  pin.genesis_digest = b64(new Uint8Array(32));
  fail(
    () =>
      g.newGroupForEvaluation(
        a.genesis,
        wire(pin),
        a.accounts.map((x) => ({ identity: x.identity, roster: x.roster })),
      ),
    "GENESIS_PIN_MISMATCH",
  );
  fail(
    () => g.groupDetails({ group_authorization: "VERIFIED" }),
    "GROUP_PROOF_REQUIRED",
  );
  assert.equal(g.groupDetails(a.group).write_state, "KEYS_PENDING");
});
test("genesis cannot smuggle an administrator or extra initial member", () => {
  const a = groupBase(),
    changed = signChanged(
      "policy",
      a.genesis,
      (x) =>
        x.members.push({
          account_id: r.rosterScope(a.accounts[1].roster).account_id,
          root_fingerprint: r.rosterScope(a.accounts[1].roster)
            .root_fingerprint,
          role: "reader",
        }),
      issuer(a),
    );
  const pin = { ...a.pin, genesis_digest: digest("policy", changed) };
  fail(() =>
    g.newGroupForEvaluation(
      changed,
      wire(pin),
      a.accounts.map((x) => ({ identity: x.identity, roster: x.roster })),
    ),
  );
});
test("acceptance keeps membership/key access pending until exact complete grant activation", () => {
  const a = base(),
    p = stagedInvitation(a);
  assert.equal(g.groupDetails(a.group).members.length, 1);
  const target = currentSender(a, 1);
  fail(
    () =>
      g.openAuthorizedGroupKeyForEvaluation(
        a.group,
        g.groupGrantRecordsForEvaluation(a.group)[0],
        target,
        a.accounts[1].current.device.encryption.publicKey,
        a.accounts[1].current.device.encryption.privateKey,
      ),
    "ACCESS_REVOKED",
  );
  g.acceptInvitationForEvaluation(a.group, p.accept, a.now);
  const policy = b.admissionPolicyForEvaluation(
    a.group,
    currentSender(a, 0),
    issuer(a),
  );
  fail(
    () => g.applyGroupPolicyForEvaluation(a.group, policy, a.now),
    "ADMISSION_REQUIRES_COMPLETE_GRANTS",
  );
  const epoch = prepareGroupEpoch(a, "admission", 0, policy);
  assert.equal(g.groupDetails(a.group).members.length, 1);
  activateGroupEpoch(a, epoch);
  assert.equal(g.groupDetails(a.group).members.length, 2);
});
for (const field of [
  "target_root_fingerprint",
  "target_account_id",
  "role",
  "policy",
  "full_retained_history",
  "expires_at",
])
  test(`invitation rejects relay substitution of ${field}`, () => {
    const a = base(),
      target = r.rosterScope(a.accounts[1].roster),
      raw = b.invitationForGroupEvaluation(
        a.group,
        currentSender(a, 0),
        target,
        "reader",
        issuer(a),
        a.now,
      ),
      i = decode("invitation", raw);
    if (field === "role") i.body.role = "editor";
    else if (field === "policy") i.body.policy.version = "99";
    else if (field === "full_retained_history")
      i.body.full_retained_history = false;
    else if (field === "expires_at") i.body.expires_at = "0";
    else
      i.body[field] = b64(
        new Uint8Array(field === "target_account_id" ? 16 : 32),
      );
    fail(() => g.stageInvitationForEvaluation(a.group, wire(i), a.now));
    assert.equal(g.groupDetails(a.group).pending, null);
  });
test("validly signed wrong target root and expired invitation still fail", () => {
  const a = base(),
    raw = b.invitationForGroupEvaluation(
      a.group,
      currentSender(a, 0),
      r.rosterScope(a.accounts[1].roster),
      "reader",
      issuer(a),
      a.now,
    ),
    changed = signChanged(
      "invitation",
      raw,
      (x) => (x.target_root_fingerprint = b64(new Uint8Array(32))),
      issuer(a),
    );
  fail(
    () => g.stageInvitationForEvaluation(a.group, changed, a.now),
    "TARGET_ROOT_MISMATCH",
  );
  fail(
    () => g.stageInvitationForEvaluation(a.group, raw, a.now + 172800000n),
    "EXPIRED_OR_OUT_OF_RANGE",
  );
});
test("acceptance binds exact target, signed invite, policy and explicit full history", () => {
  const a = base(),
    p = stagedInvitation(a),
    wrong = b.acceptanceForGroupEvaluation(
      p.invite,
      currentSender(a, 2),
      issuer(a, 2),
    );
  fail(
    () => g.acceptInvitationForEvaluation(a.group, wrong, a.now),
    "INVITATION_CONTEXT_MISMATCH",
  );
  const changed = signChanged(
    "acceptance",
    p.accept,
    (x) => (x.invitation_digest = b64(new Uint8Array(32))),
    issuer(a, 1),
  );
  fail(
    () => g.acceptInvitationForEvaluation(a.group, changed, a.now),
    "INVITATION_CONTEXT_MISMATCH",
  );
});
test("only one transition can be pending; target decline is terminal", () => {
  const a = base(),
    p = stagedInvitation(a),
    second = b.invitationForGroupEvaluation(
      a.group,
      currentSender(a, 0),
      r.rosterScope(a.accounts[2].roster),
      "reader",
      issuer(a),
      a.now,
    );
  fail(
    () => g.stageInvitationForEvaluation(a.group, second, a.now),
    "TRANSITION_ALREADY_PENDING",
  );
  fail(
    () =>
      g.cancelGroupTransitionForEvaluation(
        a.group,
        currentSender(a, 2),
        decode("invitation", p.invite).body.operation_id,
        a.now,
      ),
    "CANCEL_NOT_AUTHORIZED",
  );
  g.cancelGroupTransitionForEvaluation(
    a.group,
    currentSender(a, 1),
    decode("invitation", p.invite).body.operation_id,
    a.now,
  );
  fail(
    () => g.stageInvitationForEvaluation(a.group, p.invite, a.now),
    "OPERATION_REPLAY",
  );
});
test("readers receive group keys and can decrypt current writer content without write privilege", () => {
  const a = shared(),
    reader = currentSender(a, 2),
    device = a.accounts[2].current.device,
    key = g.openAuthorizedGroupKeyForEvaluation(
      a.group,
      readerGrant(a),
      reader,
      device.encryption.publicKey,
      device.encryption.privateKey,
    ),
    file = fileForGroup(a, 1);
  assert.deepEqual(
    g.decryptAuthorizedGroupFileForEvaluation(
      a.group,
      file.bundle,
      key,
      reader,
    ),
    file.plaintext,
  );
  const readerFile = fileForGroup(a, 2);
  fail(
    () =>
      g.checkCurrentFileForEvaluation(
        a.group,
        wire(readerFile.bundle.envelope),
      ),
    "WRITER_REQUIRED",
  );
  sodium.memzero(key);
});
test("readers cannot change roles, admit members, transfer ownership or request optional rekey", () => {
  const a = shared(),
    other = r.rosterScope(a.accounts[1].roster).account_id;
  fail(
    () =>
      applyPolicy(a, "role", { target_account_id: other, role: "reader" }, 2),
    "OWNER_REQUIRED",
  );
  const invite = b.invitationForGroupEvaluation(
    a.group,
    currentSender(a, 2),
    r.rosterScope(a.accounts[1].roster),
    "reader",
    issuer(a, 2),
    a.now,
  );
  fail(
    () => g.stageInvitationForEvaluation(a.group, invite, a.now),
    "OWNER_REQUIRED",
  );
  fail(
    () => prepareGroupEpoch(a, "optional", 2),
    "OPTIONAL_REKEY_NOT_AUTHORIZED",
  );
});
test("reader performs mandatory roster maintenance while history remains blocked for writer closure", () => {
  const a = shared(),
    file = fileForGroup(a);
  g.observeAcceptedFileForEvaluation(a.group, wire(file.bundle.envelope));
  closeGroupHistory(a);
  const reader = a.accounts[2],
    p = prepareEnrollment(reader, reader.current, 9);
  activateFixture(reader, p);
  assert.equal(g.groupDetails(a.group).write_state, "REKEY_REQUIRED");
  activateGroupEpoch(a, prepareGroupEpoch(a, "roster-maintenance", 2));
  assert.equal(g.groupDetails(a.group).write_state, "HISTORY_CLOSURE_REQUIRED");
  const pages = b.historyPagesForEvaluation(a.group),
    record = b.historyForEvaluation(
      a.group,
      currentSender(a, 2),
      issuer(a, 2),
      pages,
    );
  fail(
    () =>
      g.endorseGroupHistoryForEvaluation(
        a.group,
        record,
        pages,
        g.independentHistoryWitnessForEvaluation(a.group),
      ),
    "WRITER_REQUIRED",
  );
  closeGroupHistory(a);
  assert.equal(g.groupDetails(a.group).write_state, "WRITABLE");
});
test("removal denies access immediately and requires fresh epoch plus historical closure", () => {
  const a = shared(),
    file = fileForGroup(a);
  g.observeAcceptedFileForEvaluation(a.group, wire(file.bundle.envelope));
  closeGroupHistory(a);
  const before = readerGrant(a),
    removed = currentSender(a, 2),
    device = a.accounts[2].current.device;
  applyPolicy(a, "remove", { target_account_id: removed.account_id });
  assert.equal(g.groupDetails(a.group).write_state, "REKEY_REQUIRED");
  fail(
    () =>
      g.openAuthorizedGroupKeyForEvaluation(
        a.group,
        before,
        removed,
        device.encryption.publicKey,
        device.encryption.privateKey,
      ),
    "ACCESS_REVOKED",
  );
  activateGroupEpoch(a, prepareGroupEpoch(a, "member-removal"));
  assert.equal(g.groupDetails(a.group).write_state, "HISTORY_CLOSURE_REQUIRED");
  closeGroupHistory(a);
  assert.equal(g.groupDetails(a.group).write_state, "WRITABLE");
});
test("editor downgrade stops writes despite possession of the old valid group key", () => {
  const a = shared(),
    old = fileForGroup(a);
  g.observeAcceptedFileForEvaluation(a.group, wire(old.bundle.envelope));
  applyPolicy(a, "role", {
    target_account_id: currentSender(a, 1).account_id,
    role: "reader",
  });
  closeGroupHistory(a);
  const fresh = fileForGroup(a, 1);
  fail(
    () => g.checkCurrentFileForEvaluation(a.group, wire(fresh.bundle.envelope)),
    "WRITER_REQUIRED",
  );
  assert.equal(
    g.checkHistoricalFileForEvaluation(
      a.group,
      wire(old.bundle.envelope),
      currentSender(a, 2),
    ).history_authorization,
    "VERIFIED_INDEPENDENT_BOUNDARY",
  );
});
for (const field of [
  "service_id",
  "group_id",
  "expected_policy",
  "membership",
  "rosters",
  "retained_epochs",
  "key_commitment",
])
  test(`signed epoch intent cannot substitute ${field}`, () => {
    const a = shared(),
      p = prepareGroupEpoch(a),
      changed = signChanged(
        "epoch-intent",
        p.intent,
        (x) => {
          if (field === "service_id" || field === "group_id")
            x[field] = b64(new Uint8Array(16));
          else if (field === "expected_policy" || field === "membership")
            x[field].version = "99";
          else if (field === "rosters") x.rosters[0].roster.version = "99";
          else if (field === "retained_epochs") x.retained_epochs = [];
          else
            x.key_commitment = a.keys.get("2")
              ? groupKeyCommitment(
                  g.groupDetails(a.group).scope,
                  a.keys.get("2"),
                )
              : b64(new Uint8Array(32));
        },
        issuer(a),
      );
    fail(() =>
      g.expectedGroupGrantsForEvaluation(a.group, changed, null, a.now),
    );
  });
test("partial grant pages never activate membership or mutate the epoch", () => {
  const a = base(),
    p = stagedInvitation(a);
  g.acceptInvitationForEvaluation(a.group, p.accept, a.now);
  const policy = b.admissionPolicyForEvaluation(
      a.group,
      currentSender(a, 0),
      issuer(a),
    ),
    epoch = prepareGroupEpoch(a, "admission", 0, policy),
    page = decode("grant-page", epoch.pages[0]);
  page.records.pop();
  const pages = [wire(page)],
    commit = b.epochCommitForEvaluation(
      a.group,
      epoch.intent,
      pages,
      issuer(a),
      policy,
    ),
    before = g.groupDetails(a.group);
  // Replay verifies complete coverage independently of a staged page map.
  fail(
    () => g.replayGroupEpochForEvaluation(a.group, commit, pages),
    "RECIPIENT_COVERAGE_MISMATCH",
  );
  assert.deepEqual(g.groupDetails(a.group), before);
});
test("extra, duplicate and wrong-epoch grants fail complete derived coverage", () => {
  const a = shared(),
    p = prepareGroupEpoch(a),
    page = decode("grant-page", p.pages[0]);
  for (const variant of ["extra", "duplicate", "wrong-epoch"]) {
    const bad = copy(page);
    if (variant === "extra") bad.records.push(copy(bad.records[0]));
    if (variant === "duplicate") bad.records[1] = copy(bad.records[0]);
    if (variant === "wrong-epoch")
      bad.records[0].body.context.epoch_digest = b64(new Uint8Array(32));
    fail(() => {
      const pages = [wire(bad)],
        commit = b.epochCommitForEvaluation(
          a.group,
          p.intent,
          pages,
          issuer(a),
        );
      g.replayGroupEpochForEvaluation(a.group, commit, pages);
    });
  }
});
test("signed structurally complete wrong keys cause explicit repair after unwrap", () => {
  const a = shared(),
    keys = new Map(a.keys),
    next = String(BigInt(g.groupDetails(a.group).epoch.version) + 1n),
    p = prepareGroupEpoch(a),
    wrong = new Uint8Array(32);
  keys.set(next, wrong);
  const pages = b.grantPagesForEvaluation(
      a.group,
      p.intent,
      keys,
      issuer(a),
      a.accounts[0].roster,
      a.now,
    ),
    commit = b.epochCommitForEvaluation(a.group, p.intent, pages, issuer(a));
  g.replayGroupEpochForEvaluation(a.group, commit, pages);
  const reader = currentSender(a, 2),
    device = a.accounts[2].current.device;
  fail(
    () =>
      g.openAuthorizedGroupKeyForEvaluation(
        a.group,
        readerGrant(a, next),
        reader,
        device.encryption.publicKey,
        device.encryption.privateKey,
      ),
    "KEY_REPAIR_REQUIRED",
  );
});
test("any relevant roster advance rejects final CAS, even when the actor was not revoked", () => {
  const a = shared(),
    p = prepareGroupEpoch(a),
    before = g.groupDetails(a.group).epoch,
    reader = a.accounts[2],
    pair = prepareEnrollment(reader, reader.current, 9);
  activateFixture(reader, pair);
  fail(() => activateGroupEpoch(a, p), "POLICY_OR_ROSTER_CHANGED");
  assert.deepEqual(g.groupDetails(a.group).epoch, before);
});
test("owner policy head advance invalidates staging and fresh key commitment cannot be reused", () => {
  const a = shared(),
    p = prepareGroupEpoch(a),
    body = decode("epoch-intent", p.intent).body;
  applyPolicy(a, "archive");
  fail(() => activateGroupEpoch(a, p), "TRANSITION_REQUIRED");
  const reuse = b.epochIntentForEvaluation(
    a.group,
    "optional",
    currentSender(a, 0),
    issuer(a),
    a.keys.get(body.next_epoch),
    g.groupRostersForEvaluation(a.group),
    a.now,
  );
  fail(
    () => g.beginGroupEpochForEvaluation(a.group, reuse, null, a.now),
    "FRESH_KEY_REQUIRED",
  );
});
test("explicit staging cancel burns the next key across changed operation IDs", () => {
  const a = shared(),
    p = prepareGroupEpoch(a);
  g.cancelGroupTransitionForEvaluation(
    a.group,
    currentSender(a, 0),
    decode("epoch-intent", p.intent).body.operation_id,
    a.now,
  );
  const raw = b.epochIntentForEvaluation(
    a.group,
    "optional",
    currentSender(a, 0),
    issuer(a),
    a.keys.get("3"),
    g.groupRostersForEvaluation(a.group),
    a.now,
  );
  fail(
    () => g.beginGroupEpochForEvaluation(a.group, raw, null, a.now),
    "FRESH_KEY_REQUIRED",
  );
});
test("final epoch receipt is idempotent only for the same signed commitment", () => {
  const a = shared(),
    p = prepareGroupEpoch(a),
    result = activateGroupEpoch(a, p);
  assert.deepEqual(
    g.finalizeGroupEpochForEvaluation(a.group, p.commit, a.now),
    result,
  );
  const changed = signChanged(
    "epoch-commit",
    p.commit,
    (x) => (x.descriptor.body.inventory_digest = b64(new Uint8Array(32))),
    issuer(a),
  );
  fail(
    () => g.finalizeGroupEpochForEvaluation(a.group, changed, a.now),
    "OPERATION_ID_CONFLICT",
  );
});
test("live stage expiry and regressed time fail without epoch activation", () => {
  const a = shared(),
    p = prepareGroupEpoch(a),
    before = g.groupDetails(a.group).epoch;
  fail(
    () => g.finalizeGroupEpochForEvaluation(a.group, p.commit, a.now + 600000n),
    "EXPIRED_OR_OUT_OF_RANGE",
  );
  assert.deepEqual(g.groupDetails(a.group).epoch, before);
  fail(
    () => g.finalizeGroupEpochForEvaluation(a.group, p.commit, a.now),
    "INVALID_OR_REGRESSED_CLOCK",
  );
});
test("immutable page retry preserves data while a changed same-index page fails", () => {
  const a = shared(),
    p = prepareGroupEpoch(a);
  assert.equal(
    g.stageGroupGrantPageForEvaluation(a.group, p.pages[0], a.now).state,
    "STAGED_IDEMPOTENT",
  );
  const page = decode("grant-page", p.pages[0]);
  page.records[0].signature = b64(new Uint8Array(64));
  fail(
    () => g.stageGroupGrantPageForEvaluation(a.group, wire(page), a.now),
    "PAGE_ID_CONFLICT",
  );
  activateGroupEpoch(a, p);
});
test("private group sharing and routine owner transfer remain forbidden", () => {
  const a = base("private");
  const invite = b.invitationForGroupEvaluation(
    a.group,
    currentSender(a, 0),
    r.rosterScope(a.accounts[1].roster),
    "reader",
    issuer(a),
    a.now,
  );
  fail(
    () => g.stageInvitationForEvaluation(a.group, invite, a.now),
    "INVITATION_NOT_ALLOWED",
  );
  const archive = b.policyForEvaluation(
    a.group,
    "archive",
    currentSender(a, 0),
    issuer(a),
  );
  const p = signChanged(
    "policy",
    archive,
    (x) => {
      x.action = "transfer";
      x.payload = { incoming_signer: currentSender(a, 1) };
    },
    issuer(a),
  );
  fail(
    () => g.applyGroupPolicyForEvaluation(a.group, p, a.now),
    "PRIVATE_TRANSFER_FORBIDDEN",
  );
});
test("ownership transfer requires both active identities and exactly one resulting owner", () => {
  const a = shared(),
    payload = { incoming_signer: currentSender(a, 2) },
    missing = b.policyForEvaluation(
      a.group,
      "transfer",
      currentSender(a, 0),
      issuer(a),
      payload,
    );
  fail(
    () => g.applyGroupPolicyForEvaluation(a.group, missing, a.now),
    "INCOMING_OWNER_REQUIRED",
  );
  const raw = b.policyForEvaluation(
    a.group,
    "transfer",
    currentSender(a, 0),
    issuer(a),
    payload,
    issuer(a, 2),
  );
  g.applyGroupPolicyForEvaluation(a.group, raw, a.now);
  assert.equal(
    g.groupDetails(a.group).members.find((m) => m.role === "owner").account_id,
    payload.incoming_signer.account_id,
  );
  fail(() => applyPolicy(a, "archive"), "OWNER_REQUIRED");
  applyPolicy(a, "archive", {}, 2);
});
test("archive denies new content but permits reads, removal, maintenance and unarchive", () => {
  const a = shared(),
    file = fileForGroup(a);
  g.observeAcceptedFileForEvaluation(a.group, wire(file.bundle.envelope));
  closeGroupHistory(a);
  applyPolicy(a, "archive");
  fail(
    () => g.checkCurrentFileForEvaluation(a.group, wire(file.bundle.envelope)),
    "ARCHIVED",
  );
  assert.equal(
    g.checkHistoricalFileForEvaluation(
      a.group,
      wire(file.bundle.envelope),
      currentSender(a, 2),
    ).history_authorization,
    "VERIFIED_INDEPENDENT_BOUNDARY",
  );
  applyPolicy(a, "remove", {
    target_account_id: currentSender(a, 1).account_id,
  });
  closeGroupHistory(a);
  activateGroupEpoch(a, prepareGroupEpoch(a, "member-removal"));
  assert.equal(g.groupDetails(a.group).write_state, "ARCHIVED");
  applyPolicy(a, "unarchive");
  assert.equal(g.groupDetails(a.group).write_state, "WRITABLE");
});
test("history closure cannot omit an independently observed revision", () => {
  const a = shared(),
    file = fileForGroup(a);
  g.observeAcceptedFileForEvaluation(a.group, wire(file.bundle.envelope));
  const record = b.historyForEvaluation(
      a.group,
      currentSender(a, 0),
      issuer(a),
      [],
    ),
    before = g.groupDetails(a.group);
  fail(
    () =>
      g.endorseGroupHistoryForEvaluation(
        a.group,
        record,
        [],
        g.independentHistoryWitnessForEvaluation(a.group),
      ),
    "HISTORY_COMPLETENESS_MISMATCH",
  );
  assert.deepEqual(g.groupDetails(a.group), before);
});
test("a newly forged backdated signature remains unanchored after writer removal", () => {
  const a = shared(),
    file = fileForGroup(a);
  g.observeAcceptedFileForEvaluation(a.group, wire(file.bundle.envelope));
  closeGroupHistory(a);
  applyPolicy(a, "remove", {
    target_account_id: currentSender(a, 1).account_id,
  });
  const forged = copy(file.bundle.envelope);
  forged.header.context.file_version_id = b64(new Uint8Array(16));
  importSignFile(forged, issuer(a, 1));
  fail(
    () =>
      g.checkHistoricalFileForEvaluation(
        a.group,
        wire(forged),
        currentSender(a, 2),
      ),
    "UNANCHORED_HISTORY",
  );
  assert.equal(
    g.checkHistoricalFileForEvaluation(
      a.group,
      wire(file.bundle.envelope),
      currentSender(a, 2),
    ).history_authorization,
    "VERIFIED_INDEPENDENT_BOUNDARY",
  );
});
import { signingInput as fileSigningInput } from "../src/codec.mjs";
function importSignFile(envelope, key) {
  envelope.signature = b64(
    sodium.crypto_sign_detached(
      fileSigningInput("header", wire(envelope.header)),
      key,
    ),
  );
}
test("unwitnessed clients cannot create historical trust from unchecked server rows", () => {
  const a = shared(),
    file = fileForGroup(a);
  fail(
    () =>
      g.checkHistoricalFileForEvaluation(
        a.group,
        wire(file.bundle.envelope),
        currentSender(a, 2),
      ),
    "UNANCHORED_HISTORY",
  );
  fail(
    () =>
      g.endorseGroupHistoryForEvaluation(
        a.group,
        b.historyForEvaluation(a.group, currentSender(a, 0), issuer(a), []),
        [],
        { known_history: true },
      ),
    "INDEPENDENT_HISTORY_REQUIRED",
  );
  fail(
    () => g.startFreshHistoryObservationForEvaluation(a.group),
    "INDEPENDENT_HISTORY_REQUIRED",
  );
});
test("history checkpoint requires exact current signer, descriptor/context and sequence", () => {
  const a = shared(),
    file = fileForGroup(a);
  g.observeAcceptedFileForEvaluation(a.group, wire(file.bundle.envelope));
  const pages = b.historyPagesForEvaluation(a.group),
    record = b.historyForEvaluation(
      a.group,
      currentSender(a, 0),
      issuer(a),
      pages,
    ),
    w = g.independentHistoryWitnessForEvaluation(a.group);
  for (const field of ["sequence", "descriptor_signature", "signer"]) {
    const wrong = signChanged(
      "history",
      record,
      (x) => {
        if (field === "sequence") x.sequence = "2";
        else if (field === "signer") x.signer = currentSender(a, 2);
        else x.descriptor_signature = b64(new Uint8Array(64));
      },
      issuer(a),
    );
    fail(() => g.endorseGroupHistoryForEvaluation(a.group, wrong, pages, w));
  }
  g.endorseGroupHistoryForEvaluation(a.group, record, pages, w);
  fail(
    () => g.endorseGroupHistoryForEvaluation(a.group, record, pages, w),
    "HISTORY_CHANGED",
  );
});
for (const kind of [
  "policy",
  "invitation",
  "acceptance",
  "epoch-intent",
  "grant-page",
  "descriptor",
  "epoch-commit",
  "history",
  "state-pin",
])
  test(`${kind} rejects duplicate/escaped JSON keys, invalid Unicode, extra fields and byte overflow`, () => {
    fail(
      () => decode(kind, Buffer.from('{"a":1,"\\u0061":2}')),
      "DUPLICATE_PROPERTY",
    );
    fail(() => decode(kind, Buffer.from('"\\ud800"')), "INVALID_UNICODE");
    fail(() => decode(kind, wire({ extra: true })), "SCHEMA_MISMATCH");
    const max =
      kind === "grant-page"
        ? 1048576
        : ["epoch-intent", "epoch-commit"].includes(kind)
          ? 262144
          : 65536;
    fail(() => decode(kind, Buffer.alloc(max + 1)), "RESOURCE_LIMIT");
  });
test("new client needs an independently pinned checkpoint, not the same server history head", () => {
  const fixture = JSON.parse(readFileSync(groupFixturePath));
  // Use frozen accounts/genesis, replay only the signature/coverage chain before its first closure.
  const accounts = fixture.inputs.accounts.map((input) => {
    const identity = verifyRootIdentity(wire(input.identity), wire(input.pin)),
      roster = r.newRosterForEvaluation(identity);
    for (const event of input.events)
      r.applyRosterEventForEvaluation(roster, wire(event));
    return { identity, roster };
  });
  const group = g.newGroupForEvaluation(
      wire(fixture.inputs.genesis),
      wire(fixture.inputs.genesis_pin),
      accounts,
    ),
    history = fixture.inputs.steps.find((s) => s.kind === "history");
  for (const step of fixture.inputs.steps) {
    if (step === history) break;
    if (step.kind === "epoch")
      g.replayGroupEpochForEvaluation(
        group,
        wire(step.record),
        step.pages.map(wire),
      );
  }
  const file = fixture.inputs.steps.find((s) => s.kind === "file"),
    readerAccount = accounts[2],
    reader = g.groupSenderForEvaluation(
      group,
      r.rosterScope(readerAccount.roster).account_id,
      publicDevice(8).body.device_id,
    );
  fail(
    () =>
      g.checkHistoricalFileForEvaluation(
        group,
        wire(file.bundle.envelope),
        reader,
      ),
    "UNANCHORED_HISTORY",
  );
  const head = {
      version: history.record.body.sequence,
      digest: digest("history", wire(history.record)),
    },
    bad = { ...head, digest: b64(new Uint8Array(32)) };
  fail(
    () =>
      g.importPinnedGroupHistoryForEvaluation(
        group,
        wire(history.record),
        history.pages.map(wire),
        wire(bad),
      ),
    "HISTORY_PIN_MISMATCH",
  );
  g.importPinnedGroupHistoryForEvaluation(
    group,
    wire(history.record),
    history.pages.map(wire),
    wire(head),
  );
  assert.equal(
    g.checkHistoricalFileForEvaluation(
      group,
      wire(file.bundle.envelope),
      reader,
    ).history_authorization,
    "VERIFIED_INDEPENDENT_BOUNDARY",
  );
});
import { verifyRootIdentity } from "../src/identity-crypto.mjs";
test("root reset revokes every old recipient, preserves independent history and demands new grants", () => {
  const a = shared(),
    file = fileForGroup(a);
  g.observeAcceptedFileForEvaluation(a.group, wire(file.bundle.envelope));
  closeGroupHistory(a);
  const account = a.accounts[2],
    old = currentSender(a, 2),
    record = readerGrant(a),
    device = publicDevice(10),
    session = account.server.authenticateForEvaluation(a.now),
    challenge = account.server.issueChallenge(
      session,
      "reset",
      wire(device.body),
      a.now,
    ),
    event = e.rootEventForEvaluation(
      account.roster,
      challenge,
      device,
      account.root.signing.privateKey,
    );
  account.server.submitRootTransition(session, event, a.now);
  account.current = { device, session };
  fail(
    () =>
      g.openAuthorizedGroupKeyForEvaluation(
        a.group,
        record,
        old,
        publicDevice(8).encryption.publicKey,
        publicDevice(8).encryption.privateKey,
      ),
    "DEVICE_NOT_ACTIVE",
  );
  assert.equal(g.groupDetails(a.group).write_state, "REKEY_REQUIRED");
  activateGroupEpoch(a, prepareGroupEpoch(a, "roster-maintenance"));
  assert.equal(g.groupDetails(a.group).write_state, "HISTORY_CLOSURE_REQUIRED");
  closeGroupHistory(a);
  assert.equal(g.groupDetails(a.group).write_state, "WRITABLE");
  assert.equal(
    g.checkHistoricalFileForEvaluation(
      a.group,
      wire(file.bundle.envelope),
      currentSender(a, 2),
    ).history_authorization,
    "VERIFIED_INDEPENDENT_BOUNDARY",
  );
});
test("full-history admission cannot proceed while independently observed new history is not closed", () => {
  const a = base(),
    file = fileForGroup(a, 0);
  g.observeAcceptedFileForEvaluation(a.group, wire(file.bundle.envelope));
  const p = stagedInvitation(a);
  g.acceptInvitationForEvaluation(a.group, p.accept, a.now);
  const policy = b.admissionPolicyForEvaluation(
    a.group,
    currentSender(a, 0),
    issuer(a),
  );
  fail(
    () => prepareGroupEpoch(a, "admission", 0, policy),
    "INDEPENDENT_HISTORY_REQUIRED",
  );
});
test("independent final state pin rejects known policy/epoch rollback and malformed pin", () => {
  const a = shared(),
    d = g.groupDetails(a.group),
    pin = { ...d.scope, policy: d.policy, epoch: d.epoch, history: d.history };
  g.verifyGroupStatePinForEvaluation(a.group, wire(pin));
  const bad = copy(pin);
  bad.epoch.version = "0";
  fail(
    () => g.verifyGroupStatePinForEvaluation(a.group, wire(bad)),
    "GROUP_PIN_MISMATCH",
  );
  fail(
    () =>
      g.verifyGroupStatePinForEvaluation(
        a.group,
        Buffer.from('{"policy":1,"policy":2}'),
      ),
    "DUPLICATE_PROPERTY",
  );
});
test("fresh epoch-key generation uses distinct 32-byte library CSPRNG outputs", () => {
  const x = b.freshEpochKeyForEvaluation(),
    y = b.freshEpochKeyForEvaluation();
  assert.equal(x.length, 32);
  assert.equal(y.length, 32);
  assert.notDeepEqual(x, y);
  sodium.memzero(x);
  sodium.memzero(y);
});
test("admission requires closure of observations newer than the last checkpoint", () => {
  const a = base(),
    first = fileForGroup(a, 0, 180);
  g.observeAcceptedFileForEvaluation(a.group, wire(first.bundle.envelope));
  closeGroupHistory(a);
  const second = fileForGroup(a, 0, 190);
  g.observeAcceptedFileForEvaluation(a.group, wire(second.bundle.envelope));
  const p = stagedInvitation(a);
  g.acceptInvitationForEvaluation(a.group, p.accept, a.now);
  const policy = b.admissionPolicyForEvaluation(
    a.group,
    currentSender(a, 0),
    issuer(a),
  );
  fail(
    () => prepareGroupEpoch(a, "admission", 0, policy),
    "INDEPENDENT_HISTORY_REQUIRED",
  );
});
test("expiry or a relevant head advance retires staging and burns exposed key material", () => {
  const a = shared(),
    p = prepareGroupEpoch(a);
  assert.equal(
    g.reconcileGroupTransitionForEvaluation(a.group, a.now + 600000n).state,
    "EXPIRED",
  );
  assert.equal(g.groupDetails(a.group).pending, null);
  fail(
    () => activateGroupEpoch({ ...a, now: a.now + 600000n }, p),
    "TRANSITION_REQUIRED",
  );
  const other = shared(),
    q = prepareGroupEpoch(other),
    account = other.accounts[2],
    pair = prepareEnrollment(account, account.current, 9);
  activateFixture(account, pair);
  assert.equal(
    g.reconcileGroupTransitionForEvaluation(other.group, other.now).state,
    "STALE_HEAD",
  );
  const intent = b.epochIntentForEvaluation(
    other.group,
    "roster-maintenance",
    currentSender(other, 0),
    issuer(other),
    other.keys.get("3"),
    g.groupRostersForEvaluation(other.group),
    other.now,
  );
  fail(
    () => g.beginGroupEpochForEvaluation(other.group, intent, null, other.now),
    "FRESH_KEY_REQUIRED",
  );
});

test("grant inventory supports two greedily packed pages and rejects cross-page disorder", () => {
  // Serialization framing only: cloned records are not claimed as valid signatures.
  const a = shared(),
    raw = prepareGroupEpoch(a),
    template = decode("grant-page", raw.pages[0]);
  const records = Array.from({ length: 501 }, (_, i) => {
    const record = copy(template.records[0]);
    record.body.context.key_epoch = String(i);
    record.body.sealed_ciphertext = b64(new Uint8Array(48));
    return record;
  });
  const pages = [
    wire({ ...template, page_index: "0", records: records.slice(0, 500) }),
    wire({ ...template, page_index: "1", records: records.slice(500) }),
  ];
  assert.deepEqual(
    { ...grantPageCommitment(pages), digest: "omitted" },
    { digest: "omitted", record_count: "501", page_count: "2" },
  );
  fail(() => grantPageCommitment([pages[1], pages[0]]), "INVALID_PAGE_ORDER");
  fail(
    () =>
      grantPageCommitment([
        wire({ ...template, page_index: "0", records: records.slice(0, 499) }),
        wire({ ...template, page_index: "1", records: records.slice(499) }),
      ]),
    "INVALID_PAGE_PACKING",
  );
  fail(
    () =>
      grantPageCommitment([
        pages[0],
        wire({ ...template, page_index: "1", records: [records[499]] }),
      ]),
    "UNORDERED_OR_DUPLICATE",
  );
});

test("history operation IDs cannot be reused across distinct signed checkpoints", () => {
  const a = shared();
  closeGroupHistory(a);
  const history = b.historyForEvaluation(
    a.group,
    currentSender(a, 0),
    issuer(a),
    b.historyPagesForEvaluation(a.group),
  );
  const reused = signChanged(
    "history",
    history,
    (body) => (body.operation_id = JSON.parse(a.genesis).body.operation_id),
    issuer(a),
  );
  fail(
    () =>
      g.endorseGroupHistoryForEvaluation(
        a.group,
        reused,
        b.historyPagesForEvaluation(a.group),
        g.independentHistoryWitnessForEvaluation(a.group),
      ),
    "OPERATION_REPLAY",
  );
});

test("a new client cannot write until independently known history is established", () => {
  const a = groupBase();
  activateGroupEpoch(a, prepareGroupEpoch(a, "genesis"));
  assert.equal(g.groupDetails(a.group).write_state, "UNANCHORED_HISTORY");
  fail(
    () => g.checkCurrentFileForEvaluation(a.group, new Uint8Array()),
    "UNANCHORED_HISTORY",
  );
  g.startFreshHistoryObservationForEvaluation(a.group);
  assert.equal(g.groupDetails(a.group).write_state, "WRITABLE");
});
