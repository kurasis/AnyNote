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
