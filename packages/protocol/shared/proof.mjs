// Public proof replay is subordinate to independent pins and protected local witnesses.
import {groupStateForProfile} from './group-state.mjs';
import {groupBuildersForProfile} from './group-builders.mjs';
import {groupCodecForProfile} from '../adapters/codecs/group-codec.mjs';
import {verifiedSnapshot,historicalSnapshot} from '../devices/client.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {stateDigest} from '../adapters/codecs/state-codec.mjs';
import {ensure} from '../vault/store.mjs';
import {sharedValue} from './client.mjs';
const codec=groupCodecForProfile('p02-group-c2');
export const groupApi=groupStateForProfile('p02-group-c2'),groupBuilders=groupBuildersForProfile('p02-group-c2',groupApi);
export const groupCodec=codec;
export function replayGroup(proof,{ownPins=null,known=null,witnesses=[],localGenesis=false}={}){
 sharedValue('adopt-request',proof);const {pin,journal,accounts}=proof;
 ensure(pin.group_id===journal.group_id && journal.genesis.group_id===pin.group_id && pin.service_id===journal.genesis.commit.body.service_id,'CONTEXT_MISMATCH');
 const source=new Map();
 for(const account of accounts){const p=account.pins,s=account.snapshot;ensure(p.service_id===pin.service_id&&!source.has(p.account_id),'PINNED_ACCOUNT_MISMATCH');verifiedSnapshot(s,p,known?.accounts.find(x=>x.pins.account_id===p.account_id)?.snapshot.head??null);source.set(p.account_id,account);}
 if(ownPins){const own=source.get(ownPins.account_id);ensure(own&&same(own.pins,ownPins),'ROOT_PIN_MISMATCH');}
 const owner=source.get(pin.owner_account_id);ensure(owner?.pins.root_fingerprint===pin.owner_root_fingerprint,'ROOT_PIN_MISMATCH');
 const head=(kind,r)=>({version:r.body.version??r.body.sequence,digest:codec.groupDigest(kind,wire(r))});
 const genesis=journal.genesis.commit.body.policy;
 ensure(pin.genesis_digest===codec.groupDigest('policy',wire(genesis)),'GENESIS_PIN_MISMATCH');
 if(known){ensure(same({...known.pin,history:null},{...pin,history:null})&&(!known.pin.history||pin.history&&BigInt(pin.history.version)>=BigInt(known.pin.history.version)),'ROLLBACK_QUARANTINE');ensure(journal.events.length>=known.journal.events.length&&known.journal.events.every((e,n)=>same(e,journal.events[n])),'ROLLBACK_QUARANTINE');}
 const initial=accounts.map(a=>historicalSnapshot(a.snapshot,a.pins,{version:'0',digest:stateDigest('event',wire(a.snapshot.events[0]))}));
 const byId=new Map(accounts.map((a,n)=>[a.pins.account_id,initial[n]]));
 const advance=(account_id,roster)=>{const a=source.get(account_id);ensure(a,'PINNED_ACCOUNT_REQUIRED');const p=historicalSnapshot(a.snapshot,a.pins,roster);byId.set(account_id,p);return p;};
 advance(genesis.body.signer.account_id,genesis.body.signer.roster_head);
 const token=groupApi.newGroupForEvaluation(wire(genesis),wire({service_id:pin.service_id,group_id:pin.group_id,owner_account_id:pin.owner_account_id,owner_root_fingerprint:pin.owner_root_fingerprint,genesis_digest:pin.genesis_digest}),[...byId.values()]);
 const step=r=>groupApi.custodyAccount(token,advance(r.account_id,r.roster??r.roster_head));
 const epoch=(commit,pages)=>{const b=commit.body;for(const r of b.intent.body.rosters)step(r);step(b.intent.body.signer);if(b.policy?.body.action==='admit'){step(b.policy.body.signer);step(b.policy.body.payload.acceptance.body.signer);}groupApi.replayGroupEpochForEvaluation(token,wire(commit),pages.map(wire));};
 epoch(journal.genesis.commit,journal.genesis.pages);
 if(localGenesis||known && known.pin.owner_account_id===ownPins?.account_id && known.journal.events.length===0)groupApi.startFreshHistoryObservationForEvaluation(token);
 const knownHeads=(known?.journal.events??[]).filter(e=>e.kind==='history').map(e=>head('history',e.history));
 let independentSeen=pin.history===null;
 for(let index=0;index<journal.events.length;index++){
  if(known && index===known.journal.events.length)for(const a of known.accounts)groupApi.custodyAccount(token,verifiedSnapshot(a.snapshot,a.pins));
  const e=journal.events[index];
  if(e.kind==='policy'){step(e.policy.body.signer);if(e.policy.body.action==='transfer')step(e.policy.body.payload.incoming_signer);groupApi.applyGroupPolicyForEvaluation(token,wire(e.policy));}
  else if(e.kind==='epoch')epoch(e.commit,e.pages);
  else{for(const r of e.history.body.descriptor.closed_rosters)step(r);step(e.history.body.signer);groupApi.custodyHistory(token,wire(e.history),e.pages.map(wire),pin.history,knownHeads);if(same(head('history',e.history),pin.history))independentSeen=true;}
 }
 ensure(independentSeen,'HISTORY_PIN_MISMATCH');
 for(const a of accounts)groupApi.custodyAccount(token,verifiedSnapshot(a.snapshot,a.pins));
 const details=groupApi.groupDetails(token);
 if(witnesses.length && details.write_state!=='UNANCHORED_HISTORY')groupApi.custodyWitnesses(token,witnesses);
 return {token,details:groupApi.groupDetails(token),policy:groupApi.groupPolicyReference(token),accounts:source,proofs:byId};
}
export function genesisPin(evidence){const p=evidence.commit.body.policy;return {version:1,service_id:p.body.service_id,group_id:p.body.group_id,owner_account_id:p.body.members[0].account_id,owner_root_fingerprint:p.body.members[0].root_fingerprint,genesis_digest:codec.groupDigest('policy',wire(p)),history:null};}
