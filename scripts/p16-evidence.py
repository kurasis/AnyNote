#!/usr/bin/env python3
"""Exact-source P16 acceptance, never promotes development bytes to a full pass."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1]
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT)
role=sys.argv[1];assert role in ['operations','capacity']
head=git('rev-parse','HEAD').decode().strip();assert not git('status','--porcelain'),'Dirty source is not final acceptance'
path=ROOT/f'artifacts/p16/{role}-report.json';report=json.loads(path.read_text());assert report['status']=='PASS' and report['source_commit']==head and report['source_tree_dirty'] is False
if role=='operations':
    negative_path=ROOT/'artifacts/p16/archive-negative-report.json';negative=json.loads(negative_path.read_text())
    assert negative['status']=='PASS' and negative['source_commit']==head and negative['source_tree_dirty'] is False and negative['tests_run']>=10 and negative['failures']==negative['errors']==negative['skipped']==0
    assert report['plaintext_bytes']==1000000000
    assert report['api_image_source']['source_commit']==head and report['api_image_source']['source_tree_dirty'] is False
    assert len(report['source_sha256'])==64 and report['source_sha256']==report['recovered_sha256']
    for name in ['protected_admin_mtls_and_recent_role_verified','restored_generation_changed','existing_client_restore_quarantine_and_old_cursor_preserved','encrypted_draft_and_immutable_outbox_bytes_preserved','old_credentials_and_unreconciled_security_blocked','fresh_identity_group_and_file_copy_verified','accel_delivery_verified','api_isolation_verified','missing_recovery_secret_no_admin_decryption','modified_recovery_ciphertext_refused_before_output']:assert report[name] is True,name
    assert report['storage_faults']['status']=='PASS' and report['storage_faults']['physical_tmpfs_bytes']==8388608 and report['storage_faults']['actual_enospc_observed'] is True
    assert report['interrupted_backup']['status']=='PASS' and report['interrupted_backup']['actual_partial_age_bytes_observed']>=65536 and report['interrupted_backup']['no_final_archive_or_signature']
    assert report['concurrent_writes']['acknowledged']>0 and report['offline_network_used'] is False
    assert report['security_checkpoint_matches_latest'] is False
    assert report['incident_drill']['altered_pwa_release_refused'] is True
    assert report['cleanup']['committed_reference_preserved'] is True
else:
    assert report['accounts']==10 and report['active_devices']==50 and report['retained_signed_revisions_inserted']==100000
    assert report['every_client_record_encrypted_signed_and_opened'] and report['every_server_bundle_signature_verified']
    assert report['actual_history_rows_read']==100001 and report['actual_authenticated_http_history_pages']==1001
    assert report['bulk_fixture_installed']['quota_journal_consistent']
    assert report['physical_100gb_fixture']=='NOT_RUN' and report['logical_100gb_inventory']=='NOT_RUN'
paths=sorted(p for p in git('ls-files','-z').decode().split('\0') if p and not p.startswith(('docs/evidence/','artifacts/')))
raw_reports={role:{'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}}
if role=='operations':raw_reports['archive-negative']={'path':str(negative_path.relative_to(ROOT)),'sha256':hashlib.sha256(negative_path.read_bytes()).hexdigest()}
receipt={'purpose':'P16 exact-source executed operations acceptance','status':'PASS','role':role,'source_commit':head,'source_tree':git('rev-parse','HEAD^{tree}').decode().strip(),'source_tree_dirty':False,'timestamp':datetime.now(timezone.utc).isoformat(),'reports':raw_reports,'inputs':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in paths],'physical_acceptance':False,'production_deployed':False,'independent_review':'NOT_RUN'}
(ROOT/f'artifacts/p16/{role}-source-report.json').write_text(json.dumps(receipt,indent=2)+'\n')
print('PASS: P16',role,'actual acceptance;',len(paths),'exact Git input bytes; no 100GB/physical/production claim')
