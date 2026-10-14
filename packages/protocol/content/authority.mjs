// Independent public identity and historical authority verification; no API or local vault.
import {requireCondition as check} from '../src/strict-json.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {decode} from '../adapters/codecs/protocol-codec.mjs';
import {verifyRootIdentity,identityDetails} from '../devices/proofs.mjs';
import {newRosterForEvaluation,applyRosterEventForEvaluation,rosterDetails} from '../devices/roster.mjs';
import {strictJson} from '../src/strict-json.mjs';
import {contentValue} from './client.mjs';
import {replayGroup,groupApi} from '../shared/proof.mjs';
import {groupStateForProfile} from '../shared/group-state.mjs';
import {historicalSnapshot,verifiedSnapshot} from '../devices/client.mjs';
import {stateDigest} from '../adapters/codecs/state-codec.mjs';
export function verifyPortableEvidence(bytes, kit) {
  const raw=strictJson(bytes,16777216),extended=raw.profile==='p13-public-proof-v1';
  const e = extended?contentValue('portable-evidence',raw):decode("export-evidence", bytes),
    g = extended?groupApi:groupStateForProfile("p02-group-c2");
  const accounts = e.accounts.map((input) => {
    const a=extended?{identity:input.snapshot.identity,pin:input.pins,events:input.snapshot.events}:input;
    const identity = verifyRootIdentity(wire(a.identity), wire(a.pin)),
      roster = newRosterForEvaluation(identity);
    for (const event of a.events)
      applyRosterEventForEvaluation(roster, wire(event));
    const snapshot={identity:a.identity,events:a.events,head:rosterDetails(roster).head,generation:rosterDetails(roster).generation};
    return { identity, roster, snapshot, pin:a.pin };
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
  if(extended){
    for(const proof of e.groups){const pin=kit.independent_group_pins.find(p=>p.group_id===proof.pin.group_id);check(pin&&pin.genesis_digest===proof.pin.genesis_digest&&same(pin.history,proof.pin.history),'INDEPENDENT_HISTORY_REQUIRED');
      const verified=replayGroup(proof);g.verifyGroupStatePinForEvaluation(verified.token,wire({service_id:proof.pin.service_id,group_id:pin.group_id,policy:pin.policy,epoch:pin.epoch,history:pin.history}));check(!groups.has(pin.group_id),'DUPLICATE_GROUP');groups.set(pin.group_id,verified.token);
    }
    return {g,accounts,exporter,groups};
  }
  for (const ev of e.groups) {
    const pin = kit.independent_group_pins.find(
      (p) => p.group_id === ev.genesis_pin.group_id,
    );
    check(
      pin && pin.genesis_digest === ev.genesis_pin.genesis_digest,
      "INDEPENDENT_HISTORY_REQUIRED",
    );
    const historical=new Map(accounts.map(a=>[a.pin.account_id,historicalSnapshot(a.snapshot,a.pin,{version:'0',digest:stateDigest('event',wire(a.snapshot.events[0]))})]));
    const advance=(account_id,head)=>{const a=accounts.find(a=>a.pin.account_id===account_id);check(a,'PINNED_ACCOUNT_REQUIRED');const value=historicalSnapshot(a.snapshot,a.pin,head);historical.set(account_id,value);return value;};
    advance(ev.genesis.body.signer.account_id,ev.genesis.body.signer.roster_head);
    const token = g.newGroupForEvaluation(
      wire(ev.genesis),
      wire(ev.genesis_pin),
      [...historical.values()],
    );
    const sender=r=>g.custodyAccount(token,advance(r.account_id,r.roster??r.roster_head));
    for (const step of ev.transitions) {
      if (step.kind === "epoch") {
        const b=step.value.record.body;for(const r of b.intent.body.rosters)sender(r);sender(b.intent.body.signer);
        if(b.policy?.body.action==='admit'){sender(b.policy.body.signer);sender(b.policy.body.payload.acceptance.body.signer);}
        g.replayGroupEpochForEvaluation(
          token,
          wire(step.value.record),
          step.value.pages.map(wire),
        );
      }else{sender(step.value.body.signer);if(step.value.body.action==='transfer')sender(step.value.body.payload.incoming_signer);g.applyGroupPolicyForEvaluation(token, wire(step.value));}
    }
    for(const r of ev.history.body.descriptor.closed_rosters)sender(r);sender(ev.history.body.signer);
    g.importPinnedGroupHistoryForEvaluation(
      token,
      wire(ev.history),
      ev.history_pages.map(wire),
      wire(pin.history),
    );
    for(const a of accounts)g.custodyAccount(token,verifiedSnapshot(a.snapshot,a.pin));
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
