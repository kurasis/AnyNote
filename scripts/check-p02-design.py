#!/usr/bin/env python3
"""Read-only validation of the complete design registry and immutable baseline bytes."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    registry=json.loads((ROOT/'packages/contracts/p02-v1.registry.json').read_text())
    assert registry['profile']=='p02-v1' and registry['production_use']=='BLOCKED_PENDING_QUALIFIED_REVIEW'
    for row in registry['components']:
        schema=json.loads((ROOT/row['schema']).read_text())
        assert row['schema_id']==schema['$id'] and row['structures']==list(schema['$defs'])
    for row in registry['frozen_inputs']:
        assert hashlib.sha256((ROOT/row['path']).read_bytes()).hexdigest()==row['sha256'], 'Frozen contract/input drift: '+row['path']
    expected={x['path']for x in registry['frozen_inputs'] if '/v1/' in x['path']}
    actual={str(p.relative_to(ROOT))for p in (ROOT/'fixtures/protocol/p02/v1').rglob('*')if p.is_file()}
    assert actual==expected, 'Missing/extra complete fixture bytes'
    review=json.loads((ROOT/'packages/contracts/p02-review.json').read_text())
    assert review['qualified_review']=='TRACKED_NOT_BOOKED' and review['reviewer'] is None and review['report'] is None
    assert review['security_sensitive_production_use']=='BLOCKED_UNTIL_QUALIFIED_REVIEW_AND_REMEDIATION'
    error=json.loads((ROOT/'packages/contracts/p02-errors.json').read_text())
    required='SESSION_DEVICE_PROOF_REQUIRED RECOVERY_GENERATION_CONFLICT TRANSITION_EXPIRED SNAPSHOT_EXPIRED REKEY_RESTART_REQUIRED UNANCHORED_HISTORY EXPORT_TRUNCATED KEYS_PENDING HISTORY_CLOSURE_REQUIRED ROSTER_CHANGED POLICY_CHANGED INTEGRITY_FAILURE RESTORE_QUARANTINE RESOURCE_LIMIT INSUFFICIENT_STORAGE ACCESS_REVOKED'.split()
    codes=[x['code']for x in error['errors']];assert len(set(codes))==len(codes) and set(required)<=set(codes)
    assert all(x['retryable']==(x['retry_action']=='bounded-backoff') for x in error['errors'])
    assert all((x['http_status'] is None)==x['local_only']for x in error['errors'])
    vectors=json.loads((ROOT/'fixtures/protocol/p02/v1/schema-vectors.json').read_text())
    assert set(vectors)==set(json.loads((ROOT/'packages/contracts/p02-v1.schema.json').read_text())['$defs'])
    print(json.dumps({'status':'PASS','components':len(registry['components']),'structures':len(vectors),'frozen_inputs':len(registry['frozen_inputs']),'errors':len(codes),'qualified_review':'TRACKED_NOT_BOOKED_NOT_RUN','production':'BLOCKED'}))
if __name__=='__main__':main()
