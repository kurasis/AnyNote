#!/usr/bin/env python3
"""Verify actual P16 raw acceptance semantics after ZIP/Git-blob audit."""
import hashlib,json,sys,zipfile
from pathlib import Path
folder=Path(sys.argv[1]);output=Path(sys.argv[2]);a=json.loads((folder/'audit-receipt.json').read_text());phase_only=sys.argv[3:]==['--phase-only'];assert not sys.argv[3:] or phase_only
assert a['status']=='VERIFIED' and a['cohort_status_when_downloaded'] in (['PASS','PENDING'] if phase_only else ['PASS'])
def report(artifact,name):
 found=[r for r in a['reports'] if r['artifact_name']==artifact and r['member'].endswith(name)];assert len(found)==1
 row=found[0]
 with zipfile.ZipFile(folder/(str(row['artifact_id'])+'.zip')) as z:raw=z.read(row['member'])
 assert hashlib.sha256(raw).hexdigest()==row['sha256'];return json.loads(raw)
ops=report('p16-operations-report','operations-report.json');cap=report('p16-capacity-report','capacity-report.json');neg=report('p16-operations-report','archive-negative-report.json')
for r in [ops,cap,neg]:assert r['status']=='PASS' and r['source_commit']==a['candidate_head'] and r['source_tree_dirty'] is False
h=ops['runtime_permissions']['operator_health'];assert h['status']=='ready' and all(h['components'][k] for k in ['database','queue','scheduler']) and h['free_bytes']>max(10737418240,h['total_bytes']*.1)
assert ops['plaintext_bytes']==1000000000 and len(ops['source_sha256'])==64 and ops['source_sha256']==ops['recovered_sha256']
assert ops['api_image_source']['source_commit']==a['candidate_head'] and ops['api_image_source']['source_tree_dirty'] is False
for k in ['protected_admin_mtls_and_recent_role_verified','restored_generation_changed','existing_client_restore_quarantine_and_old_cursor_preserved','encrypted_draft_and_immutable_outbox_bytes_preserved','old_credentials_and_unreconciled_security_blocked','fresh_identity_group_and_file_copy_verified','accel_delivery_verified','api_isolation_verified','missing_recovery_secret_no_admin_decryption','modified_recovery_ciphertext_refused_before_output']:assert ops[k] is True,k
assert ops['storage_faults']['status']=='PASS' and ops['storage_faults']['physical_tmpfs_bytes']==8388608 and ops['storage_faults']['actual_enospc_observed']
assert ops['interrupted_backup']['status']=='PASS' and ops['interrupted_backup']['actual_partial_age_bytes_observed']>=65536 and ops['interrupted_backup']['no_final_archive_or_signature']
assert ops['concurrent_writes']['acknowledged']>0 and ops['offline_network_used'] is False and ops['security_checkpoint_matches_latest'] is False
assert neg['tests_run']>=10 and neg['failures']==neg['errors']==neg['skipped']==0
assert cap['accounts']==10 and cap['active_devices']==50 and cap['retained_signed_revisions_inserted']==100000 and cap['actual_history_rows_read']==100001 and cap['actual_authenticated_http_history_pages']==1001
assert cap['bulk_fixture_installed']['quota_journal_consistent']
assert cap['every_client_record_encrypted_signed_and_opened'] and cap['every_server_bundle_signature_verified'] and cap['http_publication_requests_for_bulk']==0
assert cap['logical_100gb_inventory']==cap['physical_100gb_fixture']=='NOT_RUN'
for role in ['operations','capacity']:
 src=report('p16-'+role+'-report',role+'-source-report.json');assert src['status']=='PASS' and src['role']==role and src['source_commit']==a['candidate_head'] and src['source_tree']==a['candidate_tree']
r={'purpose':'P16 raw acceptance semantics after exact Git-blob and ZIP verification','status':'PASS','ordinary_cohort_status_when_verified':a['cohort_status_when_downloaded'],'aggregate_acceptance':a['cohort_status_when_downloaded']=='PASS','source_commit':a['candidate_head'],'source_tree':a['candidate_tree'],'plaintext_bytes':ops['plaintext_bytes'],'full_sha256':ops['source_sha256'],'operations_checks':ops['checks'],'archive_negative_tests':neg['tests_run'],'accounts':cap['accounts'],'active_devices':cap['active_devices'],'retained_signed_revisions_inserted':cap['retained_signed_revisions_inserted'],'actual_authenticated_http_history_pages':cap['actual_authenticated_http_history_pages'],'actual_history_rows_read':cap['actual_history_rows_read'],'backup_elapsed_ms':ops['backup_elapsed_ms'],'rto_offline_content_seconds':ops['rto_offline_content_seconds'],'rto_drill_seconds':ops['rto_drill_seconds'],'http_page_latency_ms':cap['http_page_latency_ms'],'physical_100gb_fixture':'NOT_RUN','physical_acceptance':False,'independent_security_review':'NOT_RUN','production_deployed':False}
output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
