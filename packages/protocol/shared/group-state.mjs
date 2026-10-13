// Generated portable frozen group predicates. Durable custody and independent anchors are separate.
import {stateDigest as stateDigestForCustody} from "../adapters/codecs/state-codec.mjs";
const decryptEvaluationFile = () => { throw Error("FILES_PHASE_REQUIRED"); };
// Isolated pinned-client evaluation, not account auth, SQL or physical custody.
import {openObject as decryptObjectForEvaluation} from "../adapters/core.mjs";
import {sodium,Buffer} from "../adapters/primitives.mjs";
import { requireCondition as check, ContractError } from "../src/strict-json.mjs";
import {
  wire,
  same,
  decodeIdentity,
  identityDigest,
} from "../adapters/codecs/identity-codec.mjs";
import {
  identityDetails,
  certificateDetails,
  senderForCertificate,
  verifyDistributionSignature,
  openGroupKeyForEvaluation,
} from "../devices/proofs.mjs";
import {
  rosterScope,
  rosterDetails,
  rosterEvents,
  activeCertificateForEvaluation,
  replayRosterForEvaluation,
  activeRecipientForRosterEvaluation,
  recoveryRecipientForRosterEvaluation,
} from "../devices/roster.mjs";
import {
  decode as fileDecode,
  signingInput as fileSigningInput,
  checkpointDigest,
  checkCheckpoint,
  envelopeDigest,
} from "../adapters/codecs/codec.mjs";
import { groupCodecForProfile } from "../adapters/codecs/group-codec.mjs";
import {
  decode as objectDecode,
  digest as objectDigest,
  signingInput as objectSigningInput,
} from "../adapters/codecs/protocol-codec.mjs";
await sodium.ready;
export function groupStateForProfile(profile = "p02-group-c1") {
  const {
    groupDecode: decode,
    groupEncode: encode,
    groupDigest: digest,
    groupSigningInput: signing,
    groupKeyCommitment,
    grantPageCommitment,
    grantOrder,
  } = groupCodecForProfile(profile);
  const maxMembers = profile === "p02-group-c2" ? 20 : 10;
  const groups = new WeakMap(),
    witnesses = new WeakMap(),
    b64 = (b) => Buffer.from(b).toString("base64url"),
    un64 = (s) => Buffer.from(s, "base64url");
  function state(token) {
    check(groups.has(token), "GROUP_PROOF_REQUIRED");
    return groups.get(token);
  }
  const scope = (s) => ({ service_id: s.serviceId, group_id: s.groupId });
  function matchScope(s, b) {
    check(
      b.service_id === s.serviceId && b.group_id === s.groupId,
      "GROUP_CONTEXT_MISMATCH",
    );
  }
  function time(s, now) {
    if (now !== null) {
      check(
        typeof now === "bigint" &&
          now >= s.lastNow &&
          now <= 9223372036854775807n,
        "INVALID_OR_REGRESSED_CLOCK",
      );
      s.lastNow = now;
    }
  }
  function expiry(s, expires, now, max = 600000n) {
    time(s, now);
    if (now !== null)
      check(
        BigInt(expires) > now && BigInt(expires) - now <= max,
        "EXPIRED_OR_OUT_OF_RANGE",
      );
  }
  function evidence(s, accountId) {
    const e = s.accounts.get(accountId);
    check(e, "PINNED_ACCOUNT_REQUIRED");
    return e;
  }
  function actor(s, sender, capability = "sign-content") {
    const e = evidence(s, sender.account_id),
      cert = activeCertificateForEvaluation(
        e.roster,
        sender.device_id,
        capability,
      ),
      r = rosterDetails(e.roster);
    check(same(sender, senderForCertificate(cert, r.head)), "ROSTER_CHANGED");
    return cert;
  }
  function role(s, sender, members = s.members) {
    const member = members.find((m) => m.account_id === sender.account_id);
    check(
      member && member.root_fingerprint === sender.root_fingerprint,
      "ACCESS_REVOKED",
    );
    return member.role;
  }
  function owner(s, sender) {
    check(role(s, sender) === "owner", "OWNER_REQUIRED");
    return actor(s, sender);
  }
  function signGroupRecord(kind, bodyBytes, key, cosignature = null) {
    check(key instanceof Uint8Array && key.length === 64, "INVALID_KEY_LENGTH");
    const body = decode(kind + "-body", bodyBytes);
    const record = {
      body,
      signature: b64(
        sodium.crypto_sign_detached(signing(kind + "-body", wire(body)), key),
      ),
    };
    if (kind === "policy") record.cosignature = cosignature;
    return encode(kind, wire(record));
  }
  function signature(kind, record, cert) {
    const key = certificateDetails(cert).body.device_signing_key;
    check(
      sodium.crypto_sign_verify_detached(
        un64(record.signature),
        signing(kind + "-body", wire(record.body)),
        un64(key),
      ),
      "SIGNATURE_INVALID",
    );
  }
  const policyHead = (bytes) => {
    const p = decode("policy", bytes);
    return { version: p.body.version, digest: digest("policy", bytes) };
  };
  function rosterAnchors(s, members = s.members) {
    return members.map((m) => {
      const e = evidence(s, m.account_id),
        r = rosterDetails(e.roster),
        rs = rosterScope(e.roster);
      check(
        rs.root_fingerprint === m.root_fingerprint &&
          rs.service_id === s.serviceId &&
          r.head,
        "PINNED_ACCOUNT_MISMATCH",
      );
      return {
        account_id: m.account_id,
        root_fingerprint: m.root_fingerprint,
        recovery_generation: r.generation,
        roster: r.head,
      };
    });
  }
  // ASCII IDs must use protocol lexical ordering, independent of locale.
  const sortMembers = (members) =>
    members.sort((a, b) =>
      a.account_id < b.account_id ? -1 : a.account_id > b.account_id ? 1 : 0,
    );
  function anchors(s, members = s.members) {
    const result = rosterAnchors(s, members);
    result.sort((a, b) =>
      a.account_id < b.account_id ? -1 : a.account_id > b.account_id ? 1 : 0,
    );
    decode("rosters", wire(result));
    return result;
  }
  function addEvidence(s, account) {
    check(
      s.accounts.size < (profile === "p02-group-c2" ? 200 : 20),
      "RESOURCE_LIMIT",
    );
    const i = identityDetails(account.identity),
      r = rosterScope(account.roster);
    check(
      i.body.service_id === s.serviceId &&
        r.service_id === s.serviceId &&
        i.body.account_id === r.account_id &&
        i.fingerprint === r.root_fingerprint,
      "PINNED_ACCOUNT_MISMATCH",
    );
    check(!s.accounts.has(r.account_id), "DUPLICATE_ACCOUNT");
    s.accounts.set(r.account_id, {
      identity: account.identity,
      roster: account.roster,
    });
  }
  function newGroupForEvaluation(genesisBytes, pinBytes, accountProofs) {
    const genesis = decode("policy", genesisBytes),
      pin = decode("genesis-pin", pinBytes),
      b = genesis.body;
    check(
      Array.isArray(accountProofs) &&
        accountProofs.length > 0 &&
        accountProofs.length <= (profile === "p02-group-c2" ? 200 : 20),
      "RESOURCE_LIMIT",
    );
    const s = {
      serviceId: b.service_id,
      groupId: b.group_id,
      accounts: new Map(),
      members: [],
      kind: null,
      archived: false,
      policy: null,
      policies: new Map(),
      policyRecords: [],
      epoch: null,
      epochs: [],
      epochRecords: [],
      grants: [],
      grantIntent: null,
      grantIssuer: null,
      history: null,
      historyRequired: false,
      removalRekey: false,
      pending: null,
      historyCount: 0,
      terminal: new Set(),
      burned: new Set(),
      operations: new Set(),
      receipts: new Map(),
      lastNow: 0n,
      journalBytes: 0,
      accepted: new Map(),
      observedBytes: 0,
      historyKnown: false,
    };
    for (const account of accountProofs) addEvidence(s, account);
    check(
      b.action === "genesis" &&
        b.version === "0" &&
        b.predecessor === null &&
        genesis.cosignature === null,
      "INVALID_GENESIS",
    );
    matchScope(s, pin);
    decode("members", wire(b.members));
    check(
      b.members.length === 1 &&
        b.members[0].role === "owner" &&
        b.members[0].account_id === pin.owner_account_id &&
        b.members[0].root_fingerprint === pin.owner_root_fingerprint,
      "OWNER_CONTEXT_MISMATCH",
    );
    check(
      b.signer.account_id === pin.owner_account_id &&
        b.signer.root_fingerprint === pin.owner_root_fingerprint &&
        digest("policy", genesisBytes) === pin.genesis_digest,
      "GENESIS_PIN_MISMATCH",
    );
    const cert = actor(s, b.signer);
    signature("policy", genesis, cert);
    s.kind = b.payload.group_kind;
    s.members = b.members;
    const token = Object.freeze({
      scope: "PINNED_GROUP_EVALUATION",
      account_authentication: "NOT_IMPLEMENTED",
    });
    groups.set(token, s);
    applyPolicy(s, genesisBytes, genesis);
    return token;
  }
  function registerRelatedAccountForEvaluation(token, account) {
    addEvidence(state(token), account);
  }
  function budget(s, bytes) {
    check(
      s.policyRecords.length + s.epochRecords.length + s.historyCount < 1000 &&
        s.journalBytes + bytes.length <= 16777216,
      "RESOURCE_LIMIT",
    );
  }
  function applyPolicy(s, bytes, p) {
    s.members = p.body.members;
    s.policy = policyHead(bytes);
    s.policies.set(s.policy.digest, {
      head: structuredClone(s.policy),
      members: structuredClone(s.members),
    });
    s.policyRecords.push(Buffer.from(bytes));
    s.journalBytes += bytes.length;
    s.operations.add(p.body.operation_id);
  }
  function retirePending(s) {
    if (s.pending) {
      s.terminal.add(s.pending.operationId);
      if (s.pending.intent) s.burned.add(s.pending.intent.body.key_commitment);
      s.pending = null;
    }
  }
  function groupDetails(token) {
    const s = state(token),
      changed = !!s.epoch && !same(anchors(s), s.epoch.rosters);
    let writeState = s.archived
      ? "ARCHIVED"
      : !s.epoch
        ? "KEYS_PENDING"
        : s.removalRekey || changed
          ? "REKEY_REQUIRED"
          : !s.historyKnown
            ? "UNANCHORED_HISTORY"
            : s.historyRequired
              ? "HISTORY_CLOSURE_REQUIRED"
              : "WRITABLE";
    return {
      scope: scope(s),
      kind: s.kind,
      members: structuredClone(s.members),
      policy: structuredClone(s.policy),
      epoch: s.epoch ? structuredClone(s.epoch.head) : null,
      epochs: structuredClone(s.epochs),
      rosters: anchors(s),
      history: s.history ? structuredClone(s.history.head) : null,
      history_checkpoint_digest: s.history?.descriptorDigest ?? null,
      write_state: writeState,
      pending: s.pending
        ? { operation_id: s.pending.operationId, phase: s.pending.phase }
        : null,
      group_authorization: "VERIFIED_FROM_PINNED_CANDIDATE_STATE",
      account_authentication_and_durable_transactions: "NOT_IMPLEMENTED",
      history_observation: s.historyKnown
        ? "SIMULATED_LOCAL_OR_INDEPENDENT_PIN"
        : "UNANCHORED",
    };
  }
  function groupPolicyReference(token) {
    const s = state(token);
    check(s.epoch, "KEYS_PENDING");
    return {
      membership: structuredClone(s.policy),
      key_epoch: s.epoch.head.version,
      epoch_digest: s.epoch.intentDigest,
      history_checkpoint_digest: s.history?.descriptorDigest ?? null,
    };
  }
  function groupSenderForEvaluation(
    token,
    accountId,
    deviceId,
    capability = "sign-content",
  ) {
    const s = state(token),
      r = evidence(s, accountId).roster;
    return senderForCertificate(
      activeCertificateForEvaluation(r, deviceId, capability),
      rosterDetails(r).head,
    );
  }
  function invitationValid(s, record, now) {
    const b = record.body;
    matchScope(s, b);
    check(s.kind === "shared" && !s.archived, "INVITATION_NOT_ALLOWED");
    check(same(b.policy, s.policy), "POLICY_CHANGED");
    const cert = owner(s, b.signer);
    signature("invitation", record, cert);
    check(
      !s.members.some((m) => m.account_id === b.target_account_id),
      "ALREADY_MEMBER",
    );
    const target = rosterScope(evidence(s, b.target_account_id).roster);
    check(
      target.root_fingerprint === b.target_root_fingerprint,
      "TARGET_ROOT_MISMATCH",
    );
    expiry(s, b.expires_at, now, 172800000n);
  }
  function acceptanceValid(s, invitation, record) {
    const b = record.body;
    matchScope(s, b);
    check(
      b.operation_id === invitation.body.operation_id &&
        b.invitation_digest === digest("invitation", wire(invitation)) &&
        same(b.policy, s.policy) &&
        b.signer.account_id === invitation.body.target_account_id &&
        b.signer.root_fingerprint === invitation.body.target_root_fingerprint,
      "INVITATION_CONTEXT_MISMATCH",
    );
    signature("acceptance", record, actor(s, b.signer));
  }
  function stageInvitationForEvaluation(token, bytes, now) {
    const s = state(token),
      r = decode("invitation", bytes);
    check(typeof now === "bigint", "INVALID_CLOCK");
    invitationValid(s, r, now);
    reconcileGroupTransitionForEvaluation(token, now);
    check(!s.pending, "TRANSITION_ALREADY_PENDING");
    check(
      !s.operations.has(r.body.operation_id) &&
        !s.terminal.has(r.body.operation_id),
      "OPERATION_REPLAY",
    );
    check(
      s.members.length < maxMembers && s.terminal.size < 4096,
      "RESOURCE_LIMIT",
    );
    s.pending = {
      operationId: r.body.operation_id,
      phase: "INVITED",
      invitation: r,
      acceptance: null,
      intent: null,
      policy: null,
      pages: new Map(),
      pageBytes: 0,
    };
    return { membership: "INVITED", group_key_access: false };
  }
  function acceptInvitationForEvaluation(token, bytes, now) {
    const s = state(token);
    check(typeof now === "bigint", "INVALID_CLOCK");
    check(s.pending?.phase === "INVITED", "INVITATION_REQUIRED");
    invitationValid(s, s.pending.invitation, now);
    const a = decode("acceptance", bytes);
    acceptanceValid(s, s.pending.invitation, a);
    s.pending.acceptance = a;
    s.pending.phase = "ACCEPTED_PENDING_GRANTS";
    return { membership: "ACCEPTED_PENDING_GRANTS", group_key_access: false };
  }
  function pendingTransitionForEvaluation(token) {
    const s = state(token);
    check(s.pending, "TRANSITION_REQUIRED");
    return structuredClone({
      invitation: s.pending.invitation ?? null,
      acceptance: s.pending.acceptance ?? null,
      intent: s.pending.intent ?? null,
      policy: s.pending.policy ?? null,
    });
  }
  function cancelGroupTransitionForEvaluation(token, sender, operationId, now) {
    const s = state(token);
    check(typeof now === "bigint", "INVALID_CLOCK");
    time(s, now);
    actor(s, sender);
    check(
      s.pending && s.pending.operationId === operationId,
      "TRANSITION_REQUIRED",
    );
    const p = s.pending;
    check(
      roleOrNull(s, sender) === "owner" ||
        (p.intent && same(p.intent.body.signer, sender)) ||
        (p.invitation &&
          p.invitation.body.target_account_id === sender.account_id),
      "CANCEL_NOT_AUTHORIZED",
    );
    retirePending(s);
    return { state: "CANCELLED", key_reuse_forbidden: true };
  }
  function roleOrNull(s, sender) {
    return (
      s.members.find(
        (m) =>
          m.account_id === sender.account_id &&
          m.root_fingerprint === sender.root_fingerprint,
      )?.role ?? null
    );
  }
  function validatePolicy(s, bytes, now, admission = false) {
    const p = decode("policy", bytes),
      b = p.body;
    matchScope(s, b);
    decode("members", wire(b.members));
    check(
      b.action !== "genesis" &&
        same(b.predecessor, s.policy) &&
        b.version === String(BigInt(s.policy.version) + 1n),
      "POLICY_CHANGED",
    );
    check(!s.operations.has(b.operation_id), "OPERATION_REPLAY");
    const cert = owner(s, b.signer);
    signature("policy", p, cert);
    let members = structuredClone(s.members),
      loss = false;
    if (b.action === "admit") {
      check(admission, "ADMISSION_REQUIRES_COMPLETE_GRANTS");
      invitationValid(s, b.payload.invitation, now);
      acceptanceValid(s, b.payload.invitation, b.payload.acceptance);
      const i = b.payload.invitation.body;
      check(b.operation_id === i.operation_id, "INVITATION_CONTEXT_MISMATCH");
      members.push({
        account_id: i.target_account_id,
        root_fingerprint: i.target_root_fingerprint,
        role: i.role,
      });
    } else if (b.action === "remove") {
      const m = members.find(
        (m) => m.account_id === b.payload.target_account_id,
      );
      check(m && m.role !== "owner", "INVALID_MEMBER_REMOVAL");
      members = members.filter(
        (m) =>
          m !==
          members.find((x) => x.account_id === b.payload.target_account_id),
      );
      loss = true;
    } else if (b.action === "role") {
      const m = members.find(
        (m) => m.account_id === b.payload.target_account_id,
      );
      check(
        m && m.role !== "owner" && m.role !== b.payload.role,
        "INVALID_ROLE_CHANGE",
      );
      loss = m.role === "editor" && b.payload.role === "reader";
      m.role = b.payload.role;
    } else if (b.action === "archive")
      check(!s.archived, "ARCHIVE_STATE_MISMATCH");
    else if (b.action === "unarchive")
      check(s.archived, "ARCHIVE_STATE_MISMATCH");
    else if (b.action === "transfer") {
      check(s.kind === "shared", "PRIVATE_TRANSFER_FORBIDDEN");
      const incoming = b.payload.incoming_signer,
        m = members.find(
          (m) =>
            m.account_id === incoming.account_id &&
            m.root_fingerprint === incoming.root_fingerprint,
        );
      check(
        m && m.role !== "owner" && p.cosignature,
        "INCOMING_OWNER_REQUIRED",
      );
      const incomingCert = actor(s, incoming);
      check(
        sodium.crypto_sign_verify_detached(
          un64(p.cosignature),
          signing("policy-body", wire(b)),
          un64(certificateDetails(incomingCert).body.device_signing_key),
        ),
        "SIGNATURE_INVALID",
      );
      members.find((m) => m.role === "owner").role = "editor";
      m.role = "owner";
    }
    if (b.action !== "transfer")
      check(p.cosignature === null, "UNEXPECTED_COSIGNATURE");
    sortMembers(members);
    decode("members", wire(members));
    check(same(members, b.members), "MEMBERSHIP_RESULT_MISMATCH");
    budget(s, bytes);
    return { record: p, loss };
  }
  function applyGroupPolicyForEvaluation(token, bytes, now = null) {
    const s = state(token);
    time(s, now);
    const v = validatePolicy(s, bytes, now);
    retirePending(s);
    applyPolicy(s, bytes, v.record);
    if (v.record.body.action === "archive") s.archived = true;
    if (v.record.body.action === "unarchive") s.archived = false;
    if (v.record.body.action === "remove") s.removalRekey = true;
    if (v.loss) s.historyRequired = true;
    return groupDetails(token);
  }
  function validateIntent(s, intentBytes, policyBytes, now) {
    if(policyBytes && decode("policy", policyBytes).body.action === "genesis"){check(!s.epoch && same(decode("policy", policyBytes),decode("policy",s.policyRecords[0])),"INVALID_GENESIS");policyBytes=null;}
    const intent = decode("epoch-intent", intentBytes),
      b = intent.body;
    matchScope(s, b);
    expiry(s, b.expires_at, now);
    check(
      same(b.expected_policy, s.policy) &&
        same(b.previous_epoch, s.epoch?.head ?? null),
      "POLICY_OR_EPOCH_CHANGED",
    );
    check(
      b.next_epoch ===
        String(s.epoch ? BigInt(s.epoch.head.version) + 1n : 0n) &&
        same(b.retained_epochs, s.epochs),
      "EPOCH_INVENTORY_MISMATCH",
    );
    decode("epochs", wire(b.retained_epochs));
    check(
      !s.burned.has(b.key_commitment) &&
        !s.epochs.some((e) => e.key_commitment === b.key_commitment),
      "FRESH_KEY_REQUIRED",
    );
    check(
      (!s.operations.has(b.operation_id) || (b.reason === "genesis" && !s.epoch && decode("policy",s.policyRecords[0]).body.operation_id === b.operation_id)) &&
        !s.terminal.has(b.operation_id) &&
        s.terminal.size < 4096,
      "OPERATION_REPLAY",
    );
    let members = s.members,
      target = s.policy,
      policy = null;
    if (policyBytes) {
      const v = validatePolicy(s, policyBytes, now, true);
      check(
        v.record.body.action === "admit" &&
          v.record.body.operation_id === b.operation_id,
        "INVITATION_CONTEXT_MISMATCH",
      );
      policy = v.record;
      members = policy.body.members;
      target = policyHead(policyBytes);
      check(b.reason === "admission", "INVALID_EPOCH_REASON");
    }
    check(
      same(b.membership, target) &&
        same(b.rosters, anchors(s, members)) &&
        b.history_checkpoint_digest === (s.history?.descriptorDigest ?? null),
      "POLICY_OR_ROSTER_CHANGED",
    );
    const cert = actor(s, b.signer, "distribute-group-key"),
      r = role(s, b.signer);
    signature("epoch-intent", intent, cert);
    const changed = !!s.epoch && !same(anchors(s), s.epoch.rosters);
    if (b.reason === "genesis")
      check(!s.epoch && r === "owner" && !policy, "INVALID_EPOCH_REASON");
    else if (b.reason === "admission") {
      check(policy && r === "owner" && !s.archived, "OWNER_REQUIRED");
      if (now !== null)
        check(
          s.historyKnown &&
            !s.historyRequired &&
            (!s.accepted.size ||
              s.history?.record.body.descriptor.record_count ===
                String(s.accepted.size)),
          "INDEPENDENT_HISTORY_REQUIRED",
        );
    } else if (b.reason === "member-removal")
      check(
        s.removalRekey && r !== "reader" && !policy,
        "WRITER_MAINTENANCE_REQUIRED",
      );
    else if (b.reason === "roster-maintenance")
      check(
        s.epoch && changed && !s.removalRekey && !policy,
        "MANDATORY_ROSTER_MAINTENANCE_REQUIRED",
      );
    else
      check(
        s.epoch && !changed && !s.removalRekey && r !== "reader" && !policy,
        "OPTIONAL_REKEY_NOT_AUTHORIZED",
      );
    const row = {
        key_epoch: b.next_epoch,
        epoch_digest: digest("epoch-intent", intentBytes),
        key_commitment: b.key_commitment,
      },
      epochs = [...s.epochs, row];
    check(epochs.length <= 1000, "RESOURCE_LIMIT");
    return { intent, policy, members, cert, epochs, target };
  }
  function beginGroupEpochForEvaluation(
    token,
    intentBytes,
    policyBytes = null,
    now = null,
  ) {
    const s = state(token);
    check(typeof now === "bigint", "INVALID_CLOCK");
    reconcileGroupTransitionForEvaluation(token, now);
    const v = validateIntent(s, intentBytes, policyBytes, now),
      op = v.intent.body.operation_id;
    if (v.policy) {
      check(
        s.pending?.phase === "ACCEPTED_PENDING_GRANTS" &&
          s.pending.operationId === op &&
          same(s.pending.invitation, v.policy.body.payload.invitation) &&
          same(s.pending.acceptance, v.policy.body.payload.acceptance),
        "ACCEPTED_INVITATION_REQUIRED",
      );
    } else check(!s.pending, "TRANSITION_ALREADY_PENDING");
    s.pending = {
      ...(s.pending ?? {}),
      operationId: op,
      phase: "STAGING",
      intent: v.intent,
      policy: v.policy,
      pages: new Map(),
      pageBytes: 0,
    };
    return { state: "STAGING", live_epoch_changed: false };
  }
  function stageGroupGrantPageForEvaluation(token, bytes, now) {
    const s = state(token),
      p = s.pending;
    check(typeof now === "bigint", "INVALID_CLOCK");
    check(p?.phase === "STAGING", "TRANSITION_REQUIRED");
    validateIntent(s, wire(p.intent), p.policy ? wire(p.policy) : null, now);
    const page = decode("grant-page", bytes);
    matchScope(s, page);
    check(
      page.operation_id === p.operationId && BigInt(page.page_index) < 1000n,
      "GRANT_CONTEXT_MISMATCH",
    );
    const prior = p.pages.get(page.page_index);
    if (prior) {
      check(
        encode("grant-page", prior).equals(encode("grant-page", bytes)),
        "PAGE_ID_CONFLICT",
      );
      return { state: "STAGED_IDEMPOTENT" };
    }
    check(p.pageBytes + bytes.length <= 16777216, "RESOURCE_LIMIT");
    p.pages.set(page.page_index, Buffer.from(bytes));
    p.pageBytes += bytes.length;
    return { state: "STAGED", live_epoch_changed: false };
  }
  function recipients(s, members) {
    const result = [];
    for (const m of members) {
      const e = evidence(s, m.account_id),
        r = rosterDetails(e.roster);
      for (const d of r.devices)
        if (d.status === "ACTIVE")
          result.push({
            context: activeRecipientForRosterEvaluation(e.roster, d.device_id),
            key: certificateDetails(
              activeCertificateForEvaluation(e.roster, d.device_id),
            ).body.device_encryption_key,
          });
      result.push({
        context: recoveryRecipientForRosterEvaluation(e.roster),
        key: identityDetails(e.identity).body.recovery_encryption_key,
      });
    }
    return result;
  }
  function grantContext(s, v, epoch, recipient) {
    return {
      purpose: "group-key-distribution",
      contract: "p02-identity-c1",
      protocol: "anynote",
      protocol_version: 1,
      ...scope(s),
      key_epoch: epoch.key_epoch,
      epoch_digest: epoch.epoch_digest,
      membership_head: v.target,
      operation_id: v.intent.body.operation_id,
      issuer: v.intent.body.signer,
      recipient,
    };
  }
  function expectedGroupGrantsForEvaluation(
    token,
    intentBytes,
    policyBytes = null,
    now = null,
  ) {
    const s = state(token),
      v = validateIntent(s, intentBytes, policyBytes, now),
      rs = recipients(s, v.members);
    check(v.epochs.length * rs.length <= 330000, "RESOURCE_LIMIT");
    return v.epochs.flatMap((e) =>
      rs.map((r) => ({
        context: grantContext(s, v, e, r.context),
        recipient_public_key: r.key,
      })),
    );
  }
  function validateCommit(s, bytes, pageInputs, now) {
    const c = decode("epoch-commit", bytes),
      b = c.body;
    matchScope(s, b);
    const v = validateIntent(
      s,
      wire(b.intent),
      b.policy ? wire(b.policy) : null,
      now,
    );
    check(
      b.operation_id === v.intent.body.operation_id,
      "GRANT_CONTEXT_MISMATCH",
    );
    signature("epoch-commit", c, v.cert);
    const descriptor = b.descriptor,
      d = descriptor.body;
    matchScope(s, d);
    signature("descriptor", descriptor, v.cert);
    const commitment = grantPageCommitment(pageInputs);
    check(
      d.operation_id === b.operation_id &&
        d.intent_digest === digest("epoch-intent", wire(b.intent)) &&
        same(d.membership, v.target) &&
        same(d.signer, b.intent.body.signer) &&
        d.inventory_digest === commitment.digest &&
        d.record_count === commitment.record_count &&
        d.page_count === commitment.page_count &&
        d.epoch_inventory_digest === digest("epochs", wire(v.epochs)),
      "GRANT_DESCRIPTOR_MISMATCH",
    );
    const rs = recipients(s, v.members);
    check(
      Number(d.record_count) === v.epochs.length * rs.length,
      "RECIPIENT_COVERAGE_MISMATCH",
    );
    const expected = new Map();
    for (const e of v.epochs)
      for (const r of rs) {
        const ctx = grantContext(s, v, e, r.context);
        expected.set(identityDigest("grant-context", wire(ctx)), ctx);
      }
    const records = [];
    for (const input of pageInputs) {
      const page = decode("grant-page", input);
      matchScope(s, page);
      check(page.operation_id === b.operation_id, "GRANT_CONTEXT_MISMATCH");
      for (const r of page.records) {
        const k = identityDigest("grant-context", wire(r.body.context));
        check(expected.has(k), "RECIPIENT_COVERAGE_MISMATCH");
        verifyDistributionSignature(wire(r), wire(expected.get(k)), v.cert);
        expected.delete(k);
        records.push(r);
      }
    }
    check(expected.size === 0, "RECIPIENT_COVERAGE_MISMATCH");
    check(
      s.policyRecords.length +
        s.epochRecords.length +
        s.historyCount +
        (v.policy ? 2 : 1) <=
        1000,
      "RESOURCE_LIMIT",
    );
    budget(s, v.policy ? Buffer.concat([bytes, wire(v.policy)]) : bytes);
    return { ...v, commit: c, records };
  }
  function commitEpoch(s, bytes, v) {
    if (
      v.intent.body.reason === "roster-maintenance" &&
      s.epoch &&
      !same(s.epoch.rosters, v.intent.body.rosters) &&
      !same(
        s.history?.record.body.descriptor.closed_rosters ?? null,
        v.intent.body.rosters,
      )
    )
      s.historyRequired = true;
    if (v.policy) applyPolicy(s, wire(v.policy), v.policy);
    s.epochs = v.epochs;
    s.epoch = {
      head: {
        version: v.intent.body.next_epoch,
        digest: digest("epoch-commit", bytes),
      },
      intentDigest: digest("epoch-intent", wire(v.intent)),
      rosters: structuredClone(v.intent.body.rosters),
    };
    s.epochRecords.push(Buffer.from(bytes));
    s.journalBytes += bytes.length;
    s.operations.add(v.intent.body.operation_id);
    s.grants = v.records;
    s.grantIntent = v.intent;
    s.grantIssuer = v.cert;
    s.removalRekey = false;
    s.pending = null;
  }
  function finalizeGroupEpochForEvaluation(token, bytes, now) {
    const s = state(token);
    check(typeof now === "bigint", "INVALID_CLOCK");
    time(s, now);
    const c = decode("epoch-commit", bytes),
      op = c.body.operation_id,
      cached = s.receipts.get(op);
    if (cached) {
      check(
        cached.digest === digest("epoch-commit", bytes),
        "OPERATION_ID_CONFLICT",
      );
      return structuredClone(cached.result);
    }
    const p = s.pending;
    check(
      p?.phase === "STAGING" &&
        p.operationId === op &&
        same(p.intent, c.body.intent) &&
        same(p.policy, c.body.policy),
      "TRANSITION_REQUIRED",
    );
    const pageInputs = [...p.pages]
      .sort((a, b) => Number(a[0]) - Number(b[0]))
      .map(([, bytes]) => bytes);
    const v = validateCommit(s, bytes, pageInputs, now);
    commitEpoch(s, bytes, v);
    const result = {
      state: "ACTIVATED",
      head: structuredClone(s.epoch.head),
      membership: structuredClone(s.policy),
      ciphertext_key_contents: "NOT_SERVER_VERIFIABLE",
      durable_transaction: "NOT_IMPLEMENTED",
    };
    s.receipts.set(op, { digest: digest("epoch-commit", bytes), result });
    return structuredClone(result);
  }
  function replayGroupEpochForEvaluation(token, bytes, pageInputs) {
    const s = state(token),
      v = validateCommit(s, bytes, pageInputs, null);
    commitEpoch(s, bytes, v);
    return groupDetails(token);
  }
  function verifyGroupStatePinForEvaluation(token, pinBytes) {
    const s = state(token),
      p = decode("state-pin", pinBytes);
    matchScope(s, p);
    check(
      same(p.policy, s.policy) &&
        same(p.epoch, s.epoch?.head ?? null) &&
        same(p.history, s.history?.head ?? null),
      "GROUP_PIN_MISMATCH",
    );
    return { group_authorization: "VERIFIED_FROM_PINNED_CANDIDATE_STATE" };
  }
  function groupGrantRecordsForEvaluation(token) {
    return state(token).grants.map((r) => encodeIdentityGrant(r));
  }
  const encodeIdentityGrant = (r) => wire(decodeIdentity("grant", wire(r)));
  function openAuthorizedGroupKeyForEvaluation(
    token,
    recordBytes,
    sender,
    publicKey,
    privateKey,
  ) {
    const s = state(token);
    role(s, sender);
    actor(s, sender, "receive-group-key");
    check(s.grantIntent, "KEYS_PENDING");
    check(same(anchors(s), s.grantIntent.body.rosters), "ROSTER_CHANGED");
    const record = decodeIdentity("grant", recordBytes),
      actual = s.grants.find(
        (r) =>
          identityDigest("grant", wire(r)) ===
          identityDigest("grant", recordBytes),
      );
    check(actual, "ACCEPTED_GRANT_REQUIRED");
    const recipient = record.body.context.recipient;
    check(
      recipient.account_id === sender.account_id &&
        (recipient.kind !== "device" ||
          recipient.device_id === sender.device_id),
      "RECIPIENT_ACCESS_MISMATCH",
    );
    const key = openGroupKeyForEvaluation(
        recordBytes,
        wire(record.body.context),
        s.grantIssuer,
        publicKey,
        privateKey,
      ),
      epoch = s.epochs.find(
        (e) => e.key_epoch === record.body.context.key_epoch,
      );
    if (groupKeyCommitment(scope(s), key) !== epoch.key_commitment) {
      sodium.memzero(key);
      throw new ContractError("KEY_REPAIR_REQUIRED");
    }
    return key;
  }
  function checkCurrentFileForEvaluation(token, bytes) {
    const s = state(token);
    check(
      groupDetails(token).write_state === "WRITABLE",
      groupDetails(token).write_state,
    );
    const env = fileDecode("envelope", bytes),
      c = env.header.context;
    matchScope(s, c);
    check(
      same(c.policy, groupPolicyReference(token)),
      "POLICY_OR_EPOCH_CHANGED",
    );
    const author = c.author,
      e = evidence(s, author.account_id),
      r = rosterDetails(e.roster),
      cert = activeCertificateForEvaluation(
        e.roster,
        author.device_id,
        "sign-content",
      );
    check(
      role(s, {
        account_id: author.account_id,
        root_fingerprint: author.root_fingerprint,
      }) !== "reader",
      "WRITER_REQUIRED",
    );
    const detail = certificateDetails(cert);
    check(
      author.root_fingerprint === detail.body.root_fingerprint &&
        author.recovery_generation === detail.body.recovery_generation &&
        same(author.roster, r.head),
      "ROSTER_CHANGED",
    );
    check(
      sodium.crypto_sign_verify_detached(
        un64(env.signature),
        fileSigningInput("header", wire(env.header)),
        un64(detail.body.device_signing_key),
      ),
      "SIGNATURE_INVALID",
    );
    return {
      group_authorization: "VERIFIED_CURRENT_WRITER",
      certificate: cert,
      envelope: env,
    };
  }
  function startFreshHistoryObservationForEvaluation(token) {
    const s = state(token);
    check(
      s.policy.version === "0" &&
        s.epoch?.head.version === "0" &&
        !s.history &&
        !s.accepted.size,
      "INDEPENDENT_HISTORY_REQUIRED",
    );
    s.historyKnown = true;
    return { scope: "SIMULATED_LOCAL_FRESH_GENESIS_OBSERVATION" };
  }
  function observeAcceptedFileForEvaluation(token, bytes) {
    const s = state(token);
    check(s.historyKnown, "UNANCHORED_HISTORY");
    const result = checkCurrentFileForEvaluation(token, bytes),
      e = result.envelope,
      c = e.header.context,
      d = envelopeDigest(bytes),
      prior = s.accepted.get(c.file_version_id);
    if (prior) {
      check(prior.record.envelope_digest === d, "REVISION_ID_CONFLICT");
      return { state: "OBSERVED_IDEMPOTENT" };
    }
    check(
      s.accepted.size < 100000 && s.observedBytes + bytes.length <= 16777216,
      "RESOURCE_LIMIT",
    );
    for (const parent of c.parents) {
      const p = s.accepted.get(parent.revision_id);
      check(
        p &&
          p.record.object_kind === "file-manifest" &&
          p.record.object_id === c.file_id &&
          p.record.envelope_digest === parent.envelope_digest,
        "MISSING_OR_WRONG_ANCESTOR",
      );
    }
    const record = {
      object_kind: "file-manifest",
      object_id: c.file_id,
      revision_id: c.file_version_id,
      envelope_digest: d,
      parents: c.parents,
      payload_status: "retained",
    };
    s.accepted.set(c.file_version_id, { record, envelope: Buffer.from(bytes) });
    s.observedBytes += bytes.length;
    return {
      state: "OBSERVED",
      scope: "SIMULATED_LOCAL_ACCEPTANCE_NOT_DURABLE_SERVER_COMMIT",
    };
  }
  function independentHistoryWitnessForEvaluation(token) {
    const s = state(token);
    check(s.historyKnown, "UNANCHORED_HISTORY");
    const handle = Object.freeze({
      scope: "INDEPENDENT_LOCAL_HISTORY_SNAPSHOT",
    });
    witnesses.set(handle, {
      group: token,
      records: new Map(
        [...s.accepted].map(([id, v]) => [id, structuredClone(v.record)]),
      ),
    });
    return handle;
  }
  function observedHistoryRecordsForEvaluation(token) {
    const s = state(token);
    check(s.historyKnown, "UNANCHORED_HISTORY");
    return [...s.accepted.values()]
      .map((v) => structuredClone(v.record))
      .sort((a, b) =>
        a.revision_id < b.revision_id
          ? -1
          : a.revision_id > b.revision_id
            ? 1
            : 0,
      );
  }
  function verifyHistory(s, bytes, pageInputs, closurePolicy) {
    check(
      Array.isArray(pageInputs) &&
        pageInputs.length <= 200 &&
        pageInputs.reduce((n, b) => n + b.length, 0) <= 16777216,
      "RESOURCE_LIMIT",
    );
    const h = decode("history", bytes),
      b = h.body;
    check(!s.operations.has(b.operation_id), "OPERATION_REPLAY");
    matchScope(s, b);
    const cert = actor(s, b.signer);
    check(role(s, b.signer) !== "reader", "WRITER_REQUIRED");
    signature("history", h, cert);
    const d = b.descriptor;
    matchScope(s, d);
    check(
      same(d.closed_policy, closurePolicy) &&
        same(d.closed_rosters, anchors(s)),
      "HISTORY_CONTEXT_MISMATCH",
    );
    const sender = b.signer,
      author = {
        account_id: sender.account_id,
        device_id: sender.device_id,
        root_fingerprint: sender.root_fingerprint,
        recovery_generation: sender.recovery_generation,
        roster: sender.roster_head,
      };
    check(same(d.signer, author), "HISTORY_CONTEXT_MISMATCH");
    check(
      sodium.crypto_sign_verify_detached(
        un64(b.descriptor_signature),
        fileSigningInput("checkpoint", wire(d)),
        un64(certificateDetails(cert).body.device_signing_key),
      ),
      "SIGNATURE_INVALID",
    );
    checkCheckpoint(wire(d), pageInputs, d.predecessor_checkpoint_digest);
    return {
      history: h,
      records: pageInputs.flatMap(
        (p) => fileDecode("checkpoint-page", p).records,
      ),
    };
  }
  function endorseGroupHistoryForEvaluation(token, bytes, pageInputs, witness) {
    const s = state(token);
    check(
      witnesses.has(witness) && witnesses.get(witness).group === token,
      "INDEPENDENT_HISTORY_REQUIRED",
    );
    const h = decode("history", bytes);
    check(
      same(h.body.predecessor, s.history?.head ?? null) &&
        h.body.sequence ===
          String(s.history ? BigInt(s.history.head.version) + 1n : 0n) &&
        h.body.descriptor.predecessor_checkpoint_digest ===
          (s.history?.descriptorDigest ?? null),
      "HISTORY_CHANGED",
    );
    const v = verifyHistory(s, bytes, pageInputs, groupPolicyReference(token)),
      w = witnesses.get(witness).records;
    check(
      v.records.length === w.size && w.size === s.accepted.size,
      "HISTORY_COMPLETENESS_MISMATCH",
    );
    for (const record of v.records)
      check(
        w.has(record.revision_id) &&
          s.accepted.has(record.revision_id) &&
          same(record, w.get(record.revision_id)) &&
          same(record, s.accepted.get(record.revision_id).record),
        "HISTORY_COMPLETENESS_MISMATCH",
      );
    budget(s, bytes);
    retirePending(s);
    s.history = {
      head: { version: h.body.sequence, digest: digest("history", bytes) },
      descriptorDigest: checkpointDigest(wire(h.body.descriptor)),
      record: v.history,
    };
    s.journalBytes += bytes.length;
    s.historyCount++;
    s.operations.add(h.body.operation_id);
    s.historyRequired = false;
    return {
      state: "HISTORY_CLOSED",
      known_completeness: "VERIFIED_LOCAL_WITNESS",
      global_freshness: "NOT_PROVEN",
    };
  }
  function importPinnedGroupHistoryForEvaluation(
    token,
    bytes,
    pageInputs,
    independentHeadBytes,
  ) {
    const s = state(token),
      h = decode("history", bytes),
      head = decode("head", independentHeadBytes);
    check(
      same(head, {
        version: h.body.sequence,
        digest: digest("history", bytes),
      }),
      "HISTORY_PIN_MISMATCH",
    );
    check(
      !s.history && !s.historyKnown && !s.accepted.size,
      "HISTORY_ALREADY_KNOWN",
    );
    const closed = h.body.descriptor.closed_policy;
    check(
      same(closed.membership, s.policy) &&
        s.epoch &&
        closed.key_epoch === s.epoch.head.version &&
        closed.epoch_digest === s.epoch.intentDigest,
      "HISTORY_CONTEXT_MISMATCH",
    );
    const v = verifyHistory(s, bytes, pageInputs, closed);
    budget(s, bytes);
    for (const record of v.records)
      s.accepted.set(record.revision_id, { record, envelope: null });
    s.history = {
      head,
      descriptorDigest: checkpointDigest(wire(h.body.descriptor)),
      record: v.history,
    };
    s.historyKnown = true;
    s.journalBytes += bytes.length;
    s.historyCount++;
    s.operations.add(h.body.operation_id);
    s.historyRequired = false;
    return {
      state: "PINNED_HISTORY_IMPORTED",
      scope: "INDEPENDENT_OOB_PIN_NOT_SAME_SERVER",
    };
  }
  function checkHistoricalFileForEvaluation(token, bytes, reader) {
    const s = state(token);
    role(s, reader);
    actor(s, reader, "receive-group-key");
    const env = fileDecode("envelope", bytes),
      c = env.header.context;
    matchScope(s, c);
    const record = s.accepted.get(c.file_version_id)?.record;
    check(
      s.historyKnown &&
        record &&
        record.envelope_digest === envelopeDigest(bytes),
      "UNANCHORED_HISTORY",
    );
    check(
      record.object_kind === "file-manifest" &&
        record.object_id === c.file_id &&
        same(record.parents, c.parents),
      "HISTORY_CONTEXT_MISMATCH",
    );
    const snapshot = s.policies.get(c.policy.membership.digest),
      members = snapshot?.members;
    check(
      snapshot &&
        same(snapshot.head, c.policy.membership) &&
        members.some(
          (m) =>
            m.account_id === c.author.account_id &&
            m.root_fingerprint === c.author.root_fingerprint &&
            m.role !== "reader",
        ),
      "HISTORICAL_WRITER_REQUIRED",
    );
    const e = evidence(s, c.author.account_id),
      events = rosterEvents(e.roster),
      index = Number(c.author.roster.version);
    check(index < events.length, "HISTORICAL_ROSTER_REQUIRED");
    const historical = replayRosterForEvaluation(
        e.identity,
        events.slice(0, index + 1),
        wire(c.author.roster),
      ),
      cert = activeCertificateForEvaluation(
        historical,
        c.author.device_id,
        "sign-content",
      ),
      d = certificateDetails(cert);
    check(
      d.body.root_fingerprint === c.author.root_fingerprint &&
        d.body.recovery_generation === c.author.recovery_generation,
      "HISTORICAL_ROSTER_REQUIRED",
    );
    check(
      sodium.crypto_sign_verify_detached(
        un64(env.signature),
        fileSigningInput("header", wire(env.header)),
        un64(d.body.device_signing_key),
      ),
      "SIGNATURE_INVALID",
    );
    return {
      certificate: cert,
      history_authorization: "VERIFIED_INDEPENDENT_BOUNDARY",
      payload_availability: record.payload_status,
      global_freshness: "NOT_PROVEN",
    };
  }
  function groupRostersForEvaluation(token, policyBytes = null, now = null) {
    const s = state(token),
      members = policyBytes
        ? validatePolicy(s, policyBytes, now, true).record.body.members
        : s.members;
    return anchors(s, members);
  }
  function decryptAuthorizedGroupFileForEvaluation(
    token,
    bundle,
    key,
    reader,
    historical = false,
  ) {
    const s = state(token);
    role(s, reader);
    actor(s, reader, "receive-group-key");
    const env = fileDecode("envelope", wire(bundle.envelope)),
      epoch = s.epochs.find(
        (e) => e.key_epoch === env.header.context.policy.key_epoch,
      );
    check(
      epoch &&
        epoch.epoch_digest === env.header.context.policy.epoch_digest &&
        groupKeyCommitment(scope(s), key) === epoch.key_commitment,
      "KEY_REPAIR_REQUIRED",
    );
    const proof = historical
      ? checkHistoricalFileForEvaluation(token, wire(env), reader)
      : checkCurrentFileForEvaluation(token, wire(env));
    return decryptEvaluationFile(
      bundle,
      key,
      proof.certificate,
      wire(env.header.context),
    );
  }

  function reconcileGroupTransitionForEvaluation(token, now) {
    const s = state(token);
    check(typeof now === "bigint", "INVALID_CLOCK");
    time(s, now);
    const p = s.pending;
    if (!p) return { state: "NONE" };
    const deadline = p.intent?.body.expires_at ?? p.invitation.body.expires_at;
    if (BigInt(deadline) <= now) {
      retirePending(s);
      return { state: "EXPIRED", new_keys_required: true };
    }
    let stale = false;
    if (p.intent) {
      const b = p.intent.body,
        members = p.policy?.body.members ?? s.members;
      stale =
        !same(b.expected_policy, s.policy) ||
        !same(b.previous_epoch, s.epoch?.head ?? null) ||
        !same(b.rosters, anchors(s, members));
    } else {
      const i = p.invitation.body;
      stale =
        !same(i.policy, s.policy) ||
        !same(
          i.signer.roster_head,
          rosterDetails(evidence(s, i.signer.account_id).roster).head,
        );
      if (p.acceptance)
        stale =
          stale ||
          !same(
            p.acceptance.body.signer.roster_head,
            rosterDetails(
              evidence(s, p.acceptance.body.signer.account_id).roster,
            ).head,
          );
    }
    if (stale) {
      retirePending(s);
      return { state: "STALE_HEAD", new_keys_required: true };
    }
    return { state: p.phase };
  }

  function checkCurrentObjectForEvaluation(token, bytes) {
    const s = state(token),
      env = objectDecode("envelope", bytes),
      c = env.header.context;
    check(
      groupDetails(token).write_state === "WRITABLE",
      groupDetails(token).write_state,
    );
    matchScope(s, c);
    check(
      same(c.policy, groupPolicyReference(token)),
      "POLICY_OR_EPOCH_CHANGED",
    );
    const a = c.author,
      e = evidence(s, a.account_id),
      r = rosterDetails(e.roster);
    const cert = activeCertificateForEvaluation(
        e.roster,
        a.device_id,
        "sign-content",
      ),
      d = certificateDetails(cert);
    const writerRole = role(s, {
      account_id: a.account_id,
      root_fingerprint: a.root_fingerprint,
    });
    check(writerRole !== "reader", "WRITER_REQUIRED");
    if (c.object_kind === "group-metadata")
      check(writerRole === "owner", "OWNER_REQUIRED");
    check(
      a.root_fingerprint === d.body.root_fingerprint &&
        a.recovery_generation === d.body.recovery_generation &&
        same(a.roster, r.head),
      "ROSTER_CHANGED",
    );
    check(
      sodium.crypto_sign_verify_detached(
        un64(env.signature),
        objectSigningInput("header", wire(env.header)),
        un64(d.body.device_signing_key),
      ),
      "SIGNATURE_INVALID",
    );
    return {
      group_authorization: "VERIFIED_CURRENT_WRITER",
      certificate: cert,
      envelope: env,
    };
  }
  function observeAcceptedObjectForEvaluation(token, bytes) {
    const s = state(token);
    check(s.historyKnown, "UNANCHORED_HISTORY");
    const result = checkCurrentObjectForEvaluation(token, bytes),
      c = result.envelope.header.context,
      d = objectDigest("envelope", bytes),
      prior = s.accepted.get(c.revision_id);
    if (prior) {
      check(prior.record.envelope_digest === d, "REVISION_ID_CONFLICT");
      return { state: "OBSERVED_IDEMPOTENT" };
    }
    check(
      s.accepted.size < 100000 && s.observedBytes + bytes.length <= 16777216,
      "RESOURCE_LIMIT",
    );
    for (const parent of c.parents) {
      const p = s.accepted.get(parent.revision_id);
      check(
        p &&
          p.record.object_kind === c.object_kind &&
          p.record.object_id === c.object_id &&
          p.record.envelope_digest === parent.envelope_digest,
        "MISSING_OR_WRONG_ANCESTOR",
      );
    }
    const record = {
      object_kind: c.object_kind,
      object_id: c.object_id,
      revision_id: c.revision_id,
      envelope_digest: d,
      parents: c.parents,
      payload_status: c.action === "soft-delete" ? "tombstone" : "retained",
    };
    s.accepted.set(c.revision_id, { record, envelope: Buffer.from(bytes) });
    s.observedBytes += bytes.length;
    return {
      state: "OBSERVED",
      scope: "SIMULATED_LOCAL_ACCEPTANCE_NOT_DURABLE_SERVER_COMMIT",
    };
  }
  function checkHistoricalObjectForEvaluation(token, bytes, reader) {
    const s = state(token);
    role(s, reader);
    actor(s, reader, "receive-group-key");
    const env = objectDecode("envelope", bytes),
      c = env.header.context;
    matchScope(s, c);
    const record = s.accepted.get(c.revision_id)?.record;
    check(
      s.historyKnown &&
        record &&
        record.envelope_digest === objectDigest("envelope", bytes),
      "UNANCHORED_HISTORY",
    );
    check(
      record.object_kind === c.object_kind &&
        record.object_id === c.object_id &&
        same(record.parents, c.parents),
      "HISTORY_CONTEXT_MISMATCH",
    );
    const snapshot = s.policies.get(c.policy.membership.digest),
      m = snapshot?.members.find(
        (m) =>
          m.account_id === c.author.account_id &&
          m.root_fingerprint === c.author.root_fingerprint,
      );
    check(
      snapshot &&
        same(snapshot.head, c.policy.membership) &&
        m &&
        m.role !== "reader" &&
        (c.object_kind !== "group-metadata" || m.role === "owner"),
      "HISTORICAL_WRITER_REQUIRED",
    );
    const e = evidence(s, c.author.account_id),
      events = rosterEvents(e.roster),
      index = Number(c.author.roster.version);
    check(index < events.length, "HISTORICAL_ROSTER_REQUIRED");
    const h = replayRosterForEvaluation(
        e.identity,
        events.slice(0, index + 1),
        wire(c.author.roster),
      ),
      cert = activeCertificateForEvaluation(
        h,
        c.author.device_id,
        "sign-content",
      ),
      d = certificateDetails(cert);
    check(
      d.body.root_fingerprint === c.author.root_fingerprint &&
        d.body.recovery_generation === c.author.recovery_generation,
      "HISTORICAL_ROSTER_REQUIRED",
    );
    check(
      sodium.crypto_sign_verify_detached(
        un64(env.signature),
        objectSigningInput("header", wire(env.header)),
        un64(d.body.device_signing_key),
      ),
      "SIGNATURE_INVALID",
    );
    return {
      certificate: cert,
      history_authorization: "VERIFIED_INDEPENDENT_BOUNDARY",
      payload_availability: record.payload_status,
      global_freshness: "NOT_PROVEN",
    };
  }

  function decryptAuthorizedGroupObjectForEvaluation(
    token,
    bundleBytes,
    groupKey,
    reader,
  ) {
    const bundle = objectDecode("bundle", bundleBytes),
      authority = checkHistoricalObjectForEvaluation(
        token,
        wire(bundle.envelope),
        reader,
      ),
      cert = certificateDetails(authority.certificate);
    const payload = decryptObjectForEvaluation(
      bundleBytes,
      groupKey,
      un64(cert.body.device_signing_key),
      wire(bundle.envelope.header.context),
    );
    if (payload.metadata_kind === "account-preferences")
      check(state(token).kind === "private", "PRIVATE_NAMESPACE_REQUIRED");
    return payload;
  }
  // These entry points are internal to the fenced custody workflow, never page IPC.
  function custodyAccount(token, account) {
    const s=state(token),r=rosterScope(account.roster),old=s.accounts.get(r.account_id);
    if(!old){addEvidence(s,account);return;}
    const known=rosterScope(old.roster);
    check(same(known,r),'PINNED_ACCOUNT_MISMATCH');
    const before=rosterDetails(old.roster).head,after=rosterDetails(account.roster).head;
    check(BigInt(after.version)>=BigInt(before.version),'ROLLBACK_QUARANTINE');
    const events=rosterEvents(account.roster).map(e=>JSON.parse(new TextDecoder().decode(e)));
    check(identityDigest('identity-body',wire(identityDetails(account.identity).body))===known.root_fingerprint,'ROOT_PIN_MISMATCH');
    check(events.some(e=>e.body.version===before.version && stateDigestForCustody('event',wire(e))===before.digest),'ROLLBACK_QUARANTINE');
    s.accounts.set(r.account_id,{identity:account.identity,roster:account.roster});
  }
  function custodyHistory(token, bytes, pages, independentHead, knownHeads) {
    const s=state(token),h=decode('history',bytes),previous=s.history?.head??null;
    check(same(h.body.predecessor,previous) && h.body.sequence===String(previous?BigInt(previous.version)+1n:0n) && h.body.descriptor.predecessor_checkpoint_digest===(s.history?.descriptorDigest??null),'HISTORY_CHANGED');
    const v=verifyHistory(s,bytes,pages,groupPolicyReference(token));
    const head={version:h.body.sequence,digest:digest('history',bytes)};
    const anchored=same(head,independentHead)||knownHeads.some(x=>same(x,head))||s.historyKnown;
    for(const record of v.records){const old=s.accepted.get(record.revision_id);if(old)check(same(old.record,record),'HISTORY_COMPLETENESS_MISMATCH');}
    for(const [id]of s.accepted)check(v.records.some(x=>x.revision_id===id),'HISTORY_COMPLETENESS_MISMATCH');
    s.accepted=new Map(v.records.map(record=>[record.revision_id,{record,envelope:null}]));
    s.history={head,descriptorDigest:checkpointDigest(wire(h.body.descriptor)),record:h};s.historyKnown=anchored;s.historyRequired=false;s.historyCount++;s.operations.add(h.body.operation_id);
  }
  function custodyWitnesses(token, records) {
    const s=state(token);check(s.historyKnown,'UNANCHORED_HISTORY');
    for(const record of records){const old=s.accepted.get(record.revision_id);check(!old||same(old.record,record),'REVISION_ID_CONFLICT');s.accepted.set(record.revision_id,{record,envelope:null});}
  }

  return Object.freeze({
    custodyAccount,custodyHistory,custodyWitnesses,
    decryptAuthorizedGroupObjectForEvaluation,
    signGroupRecord,
    newGroupForEvaluation,
    registerRelatedAccountForEvaluation,
    groupDetails,
    groupPolicyReference,
    groupSenderForEvaluation,
    stageInvitationForEvaluation,
    acceptInvitationForEvaluation,
    pendingTransitionForEvaluation,
    cancelGroupTransitionForEvaluation,
    applyGroupPolicyForEvaluation,
    beginGroupEpochForEvaluation,
    stageGroupGrantPageForEvaluation,
    expectedGroupGrantsForEvaluation,
    finalizeGroupEpochForEvaluation,
    replayGroupEpochForEvaluation,
    verifyGroupStatePinForEvaluation,
    groupGrantRecordsForEvaluation,
    openAuthorizedGroupKeyForEvaluation,
    checkCurrentFileForEvaluation,
    startFreshHistoryObservationForEvaluation,
    observeAcceptedFileForEvaluation,
    independentHistoryWitnessForEvaluation,
    observedHistoryRecordsForEvaluation,
    endorseGroupHistoryForEvaluation,
    importPinnedGroupHistoryForEvaluation,
    checkHistoricalFileForEvaluation,
    groupRostersForEvaluation,
    decryptAuthorizedGroupFileForEvaluation,
    reconcileGroupTransitionForEvaluation,
    checkCurrentObjectForEvaluation,
    observeAcceptedObjectForEvaluation,
    checkHistoricalObjectForEvaluation,
  });
}
export const {
  decryptAuthorizedGroupObjectForEvaluation,
  signGroupRecord,
  newGroupForEvaluation,
  registerRelatedAccountForEvaluation,
  groupDetails,
  groupPolicyReference,
  groupSenderForEvaluation,
  stageInvitationForEvaluation,
  acceptInvitationForEvaluation,
  pendingTransitionForEvaluation,
  cancelGroupTransitionForEvaluation,
  applyGroupPolicyForEvaluation,
  beginGroupEpochForEvaluation,
  stageGroupGrantPageForEvaluation,
  expectedGroupGrantsForEvaluation,
  finalizeGroupEpochForEvaluation,
  replayGroupEpochForEvaluation,
  verifyGroupStatePinForEvaluation,
  groupGrantRecordsForEvaluation,
  openAuthorizedGroupKeyForEvaluation,
  checkCurrentFileForEvaluation,
  startFreshHistoryObservationForEvaluation,
  observeAcceptedFileForEvaluation,
  independentHistoryWitnessForEvaluation,
  observedHistoryRecordsForEvaluation,
  endorseGroupHistoryForEvaluation,
  importPinnedGroupHistoryForEvaluation,
  checkHistoricalFileForEvaluation,
  groupRostersForEvaluation,
  decryptAuthorizedGroupFileForEvaluation,
  reconcileGroupTransitionForEvaluation,
  checkCurrentObjectForEvaluation,
  observeAcceptedObjectForEvaluation,
  checkHistoricalObjectForEvaluation,
} = groupStateForProfile();
