// Synthetic client builders; randomness uses libsodium, never server key creation.
import sodium from "libsodium-wrappers-sumo";
import { requireCondition as check } from "./strict-json.mjs";
import { wire } from "./identity-codec.mjs";
import {
  certificateDetails,
  sealGroupKeyForEvaluation,
} from "./identity-crypto.mjs";
import { rosterScope, activeCertificateForEvaluation } from "./roster.mjs";
import {
  decode as fileDecode,
  inventoryCommitment,
  signingInput as fileSigningInput,
} from "./codec.mjs";
import {
  groupCommon as common,
  groupDecode as decode,
  groupDigest as digest,
  groupSigningInput as signing,
  groupKeyCommitment,
  grantOrder,
  grantPageCommitment,
} from "./group-codec.mjs";
import * as g from "./group-state.mjs";
await sodium.ready;
const b64 = (b) => Buffer.from(b).toString("base64url");
export const randomGroupOperation = () => b64(sodium.randombytes_buf(16));
export const freshEpochKeyForEvaluation = () => sodium.randombytes_buf(32);
const sorted = (members) =>
  members.sort((a, b) =>
    a.account_id < b.account_id ? -1 : a.account_id > b.account_id ? 1 : 0,
  );
export function genesisForEvaluation(serviceId, groupId, owner, kind, key) {
  return g.signGroupRecord(
    "policy",
    wire({
      ...common("group-policy-event"),
      service_id: serviceId,
      group_id: groupId,
      operation_id: randomGroupOperation(),
      action: "genesis",
      version: "0",
      predecessor: null,
      signer: owner,
      members: [
        {
          account_id: owner.account_id,
          root_fingerprint: owner.root_fingerprint,
          role: "owner",
        },
      ],
      payload: { group_kind: kind },
    }),
    key,
  );
}
export function policyForEvaluation(
  group,
  action,
  signer,
  key,
  payload = {},
  incomingKey = null,
) {
  const d = g.groupDetails(group),
    members = structuredClone(d.members);
  let result = members;
  if (action === "remove")
    result = members.filter((m) => m.account_id !== payload.target_account_id);
  if (action === "role") {
    const m = members.find((m) => m.account_id === payload.target_account_id);
    check(m, "TARGET_MEMBER_REQUIRED");
    m.role = payload.role;
  }
  if (action === "transfer") {
    const m = members.find(
      (m) => m.account_id === payload.incoming_signer.account_id,
    );
    check(m, "TARGET_MEMBER_REQUIRED");
    members.find((m) => m.role === "owner").role = "editor";
    m.role = "owner";
  }
  const body = {
    ...common("group-policy-event"),
    ...d.scope,
    operation_id: randomGroupOperation(),
    action,
    version: String(BigInt(d.policy.version) + 1n),
    predecessor: d.policy,
    signer,
    members: sorted(result),
    payload,
  };
  const cosignature = incomingKey
    ? b64(
        sodium.crypto_sign_detached(
          signing("policy-body", wire(body)),
          incomingKey,
        ),
      )
    : null;
  return g.signGroupRecord("policy", wire(body), key, cosignature);
}
export function invitationForGroupEvaluation(
  group,
  signer,
  target,
  role,
  key,
  now,
) {
  const d = g.groupDetails(group);
  return g.signGroupRecord(
    "invitation",
    wire({
      ...common("group-invitation"),
      ...d.scope,
      operation_id: randomGroupOperation(),
      policy: d.policy,
      signer,
      target_account_id: target.account_id,
      target_root_fingerprint: target.root_fingerprint,
      role,
      full_retained_history: true,
      nonce: b64(sodium.randombytes_buf(32)),
      expires_at: String(now + 172800000n),
    }),
    key,
  );
}
export function acceptanceForGroupEvaluation(invitationBytes, signer, key) {
  const i = decode("invitation", invitationBytes);
  return g.signGroupRecord(
    "acceptance",
    wire({
      ...common("group-invitation-acceptance"),
      service_id: i.body.service_id,
      group_id: i.body.group_id,
      operation_id: i.body.operation_id,
      invitation_digest: digest("invitation", invitationBytes),
      policy: i.body.policy,
      signer,
      full_retained_history: true,
    }),
    key,
  );
}
export function admissionPolicyForEvaluation(group, signer, key) {
  const d = g.groupDetails(group),
    p = g.pendingTransitionForEvaluation(group),
    i = p.invitation.body;
  return g.signGroupRecord(
    "policy",
    wire({
      ...common("group-policy-event"),
      ...d.scope,
      operation_id: i.operation_id,
      action: "admit",
      version: String(BigInt(d.policy.version) + 1n),
      predecessor: d.policy,
      signer,
      members: sorted([
        ...d.members,
        {
          account_id: i.target_account_id,
          root_fingerprint: i.target_root_fingerprint,
          role: i.role,
        },
      ]),
      payload: { invitation: p.invitation, acceptance: p.acceptance },
    }),
    key,
  );
}
export function epochIntentForEvaluation(
  group,
  reason,
  signer,
  key,
  epochKey,
  rosters,
  now,
  policyBytes = null,
) {
  const d = g.groupDetails(group),
    policy = policyBytes ? decode("policy", policyBytes) : null;
  return g.signGroupRecord(
    "epoch-intent",
    wire({
      ...common("group-epoch-intent"),
      ...d.scope,
      operation_id: policy?.body.operation_id ?? randomGroupOperation(),
      reason,
      expected_policy: d.policy,
      membership: policy
        ? {
            version: policy.body.version,
            digest: digest("policy", policyBytes),
          }
        : d.policy,
      previous_epoch: d.epoch,
      next_epoch: String(d.epoch ? BigInt(d.epoch.version) + 1n : 0n),
      retained_epochs: d.epochs,
      key_commitment: groupKeyCommitment(d.scope, epochKey),
      rosters,
      history_checkpoint_digest: d.history_checkpoint_digest,
      signer,
      expires_at: String(now + 600000n),
    }),
    key,
  );
}
export function grantPagesForEvaluation(
  group,
  intentBytes,
  epochKeys,
  signingKey,
  issuerRoster,
  now,
  policyBytes = null,
) {
  const intent = decode("epoch-intent", intentBytes),
    expected = g.expectedGroupGrantsForEvaluation(
      group,
      intentBytes,
      policyBytes,
      now,
    ),
    cert = activeCertificateForEvaluation(
      issuerRoster,
      intent.body.signer.device_id,
      "distribute-group-key",
    );
  const records = expected
    .map(({ context, recipient_public_key }) => {
      check(epochKeys.has(context.key_epoch), "EPOCH_KEY_REQUIRED");
      return JSON.parse(
        sealGroupKeyForEvaluation(
          wire(context),
          epochKeys.get(context.key_epoch),
          Buffer.from(recipient_public_key, "base64url"),
          signingKey,
          cert,
        ),
      );
    })
    .sort((a, b) =>
      grantOrder(a) < grantOrder(b)
        ? -1
        : grantOrder(a) > grantOrder(b)
          ? 1
          : 0,
    );
  const pages = [];
  let batch = [];
  const make = (records) => ({
    ...common("group-grant-page"),
    service_id: intent.body.service_id,
    group_id: intent.body.group_id,
    operation_id: intent.body.operation_id,
    page_index: String(pages.length),
    records,
  });
  for (const record of records) {
    if (
      batch.length &&
      (batch.length === 500 || wire(make([...batch, record])).length > 1048576)
    ) {
      pages.push(wire(make(batch)));
      batch = [];
    }
    batch.push(record);
  }
  if (batch.length) pages.push(wire(make(batch)));
  return pages;
}
export function epochCommitForEvaluation(
  group,
  intentBytes,
  pageInputs,
  key,
  policyBytes = null,
) {
  const intent = decode("epoch-intent", intentBytes),
    d = g.groupDetails(group),
    c = grantPageCommitment(pageInputs),
    row = {
      key_epoch: intent.body.next_epoch,
      epoch_digest: digest("epoch-intent", intentBytes),
      key_commitment: intent.body.key_commitment,
    };
  const descriptor = g.signGroupRecord(
    "descriptor",
    wire({
      ...common("group-grant-descriptor"),
      ...d.scope,
      operation_id: intent.body.operation_id,
      intent_digest: digest("epoch-intent", intentBytes),
      membership: intent.body.membership,
      inventory_digest: c.digest,
      record_count: c.record_count,
      page_count: c.page_count,
      epoch_inventory_digest: digest("epochs", wire([...d.epochs, row])),
      signer: intent.body.signer,
    }),
    key,
  );
  return g.signGroupRecord(
    "epoch-commit",
    wire({
      ...common("group-epoch-commit"),
      ...d.scope,
      operation_id: intent.body.operation_id,
      policy: policyBytes ? decode("policy", policyBytes) : null,
      intent,
      descriptor: decode("descriptor", descriptor),
    }),
    key,
  );
}
export function historyPagesForEvaluation(group) {
  const d = g.groupDetails(group),
    records = g.observedHistoryRecordsForEvaluation(group),
    pages = [];
  let batch = [];
  const make = (records) => ({
    purpose: "history-inventory-page",
    contract: "p02-file-c1",
    version: 1,
    ...d.scope,
    page_index: String(pages.length),
    records,
  });
  for (const record of records) {
    if (
      batch.length &&
      (batch.length === 500 || wire(make([...batch, record])).length > 1048576)
    ) {
      pages.push(wire(make(batch)));
      batch = [];
    }
    batch.push(record);
  }
  if (batch.length) pages.push(wire(make(batch)));
  return pages;
}
export function historyForEvaluation(group, signer, key, pages) {
  const d = g.groupDetails(group),
    commitment = inventoryCommitment(pages),
    descriptor = {
      purpose: "history-checkpoint",
      contract: "p02-file-c1",
      version: 1,
      ...d.scope,
      predecessor_checkpoint_digest: d.history_checkpoint_digest,
      closed_policy: g.groupPolicyReference(group),
      closed_rosters: d.rosters,
      record_count: commitment.record_count,
      page_count: commitment.page_count,
      inventory_digest: commitment.digest,
      signer: {
        account_id: signer.account_id,
        device_id: signer.device_id,
        root_fingerprint: signer.root_fingerprint,
        recovery_generation: signer.recovery_generation,
        roster: signer.roster_head,
      },
    };
  fileDecode("checkpoint", wire(descriptor));
  const descriptorSignature = b64(
    sodium.crypto_sign_detached(
      fileSigningInput("checkpoint", wire(descriptor)),
      key,
    ),
  );
  return g.signGroupRecord(
    "history",
    wire({
      ...common("group-history-checkpoint"),
      ...d.scope,
      operation_id: randomGroupOperation(),
      sequence: String(d.history ? BigInt(d.history.version) + 1n : 0n),
      predecessor: d.history,
      descriptor,
      descriptor_signature: descriptorSignature,
      signer,
    }),
    key,
  );
}
