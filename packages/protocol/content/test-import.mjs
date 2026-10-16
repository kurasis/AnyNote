// State-machine regressions with the actual frozen authenticated archive.
// This does not replace the real API/Worker/incompressible-gigabyte acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {ProtectedImport} from './import.mjs';
import {sodium,b64} from '../adapters/primitives.mjs';

const corpus=JSON.parse(readFileSync(new URL('../../../fixtures/protocol/p02/v1/crypto.json',import.meta.url))).objects;
const source=new Blob([readFileSync(new URL('../../../fixtures/protocol/p02/v1/rust.age',import.meta.url))]);
const ident=()=>b64(sodium.randombytes_buf(16));

async function pausedAfterPrivateCreation(){
  const rows=new Map(),member={account_id:corpus.header.account_id,root_fingerprint:corpus.header.root_fingerprint,role:'owner'};
  const initial={mode:'new-private',group_id:null,members:[member]};
  const created={group_id:ident(),policy:structuredClone(corpus.payload.context.policy),members:[member]};
  const jobs={async saveJob(id,kind,value){assert.equal(kind,'import-state');rows.set(id,structuredClone(value));},async job(id,kind){assert.equal(kind,'import-state');return structuredClone(rows.get(id));}};
  const make=destination=>new ProtectedImport({jobs,destination,scope:{},apply(){assert.fail('This confirmation regression must not publish');}});
  const first=make(async group=>structuredClone(group?created:initial));
  const plan=await first.begin({source,kit:structuredClone(corpus.kit)});
  await first.confirm(plan.audience_digest);
  // A real group-create receipt changes only the resolved destination in the
  // protected job. Model the durable boundary before any file publication.
  const retained=rows.get(plan.import_id);retained.destination=structuredClone(created);retained.state='PAUSED';
  first.close();
  return {rows,jobs,created,plan,make};
}

test('resume after private group creation requires the freshly displayed audience token',async()=>{
  const f=await pausedAfterPrivateCreation(),resumed=f.make(async()=>structuredClone(f.created));
  try{
    const preview=await resumed.begin({source,kit:structuredClone(corpus.kit),import_id:f.plan.import_id});
    assert.equal(preview.live_destination_mutations,0);
    assert.equal(preview.preview.destination.group_id,f.created.group_id);
    assert.notEqual(preview.audience_digest,f.plan.audience_digest);
    await assert.rejects(()=>resumed.confirm(f.plan.audience_digest),/COPY_CONFIRMATION_REQUIRED/);
    assert.equal((await resumed.confirm(preview.audience_digest)).state,'IMPORTING');
  }finally{resumed.close();}
});

test('a destination change after the resumed preview cannot publish or replace the retained job',async()=>{
  const f=await pausedAfterPrivateCreation();let current=structuredClone(f.created);
  const resumed=f.make(async()=>structuredClone(current));
  try{
    const preview=await resumed.begin({source,kit:structuredClone(corpus.kit),import_id:f.plan.import_id});
    const before=structuredClone(f.rows.get(f.plan.import_id));
    current.members.push({account_id:ident(),root_fingerprint:corpus.header.root_fingerprint,role:'reader'});
    await assert.rejects(()=>resumed.confirm(preview.audience_digest),/COPY_CONFIRMATION_REQUIRED/);
    assert.deepEqual(f.rows.get(f.plan.import_id),before);
  }finally{resumed.close();}
});
