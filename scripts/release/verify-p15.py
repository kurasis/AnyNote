#!/usr/bin/env python3
"""Independently audit public P15 ZIP receipts against actual Git object bytes."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
head, browser_meta_path, browser_zip, webkit_meta_path, webkit_zip, output_path = sys.argv[1:]

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)

assert git('rev-parse', head).decode().strip() == head and len(head) == 40
tree = git('rev-parse', head+'^{tree}').decode().strip()
tracked = git('ls-tree', '-r', '-z', '--name-only', head).decode().split('\0')
expected = sorted(p for p in tracked if p and not p.startswith(('docs/evidence/', 'artifacts/')))

def archive(meta_path, path):
    meta = json.loads(Path(meta_path).read_text())
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    assert meta['digest'] == 'sha256:'+digest, 'API/ZIP digest mismatch'
    assert meta['expired'] is False
    z = zipfile.ZipFile(path)
    return z, {'id': meta['id'], 'name': meta['name'], 'zip_sha256': digest}

def member(z, suffix):
    names = [n for n in z.namelist() if n == suffix or n.endswith('/'+suffix)]
    assert len(names) == 1, 'Missing or ambiguous ZIP member: '+suffix
    return z.read(names[0])

def provenance(report):
    assert report['source_commit'] == head
    assert report['source_tree'] == tree and report['source_tree_dirty'] is False
    inputs = report['inputs']
    paths = [r['path'] for r in inputs]
    assert len(paths) == len(set(paths)) and sorted(paths) == expected, 'Incomplete/duplicate source-input array'
    for row in inputs:
        actual = hashlib.sha256(git('show', head+':'+row['path'])).hexdigest()
        assert actual == row['sha256'], 'Git input mismatch: '+row['path']
    return len(paths)

bz, bmeta = archive(browser_meta_path, browser_zip)
wz, wmeta = archive(webkit_meta_path, webkit_zip)
source_raw = member(bz, 'p15/source-report.json')
source = json.loads(source_raw)
assert source['status'] == 'PASS' and source['physical_acceptance'] is False
inputs = provenance(source)
browser_raw = member(bz, 'p10/browser-report.json')
assert hashlib.sha256(browser_raw).hexdigest() == source['reports']['browser']['sha256']
browser = json.loads(browser_raw)
assert browser['status'] == 'PASS' and browser['source_commit'] == head
assert browser['source_tree_dirty'] is False and browser['chromium_sandbox'] is True
assert browser['p12_files']['gigabyte_bytes'] == 1000000000
pwa = browser['p15_pwa']
assert pwa['status'] == 'PASS' and pwa['physical_acceptance'] is False
assert pwa['plaintext_bytes'] == pwa['recovered_bytes'] == pwa['imported_bytes'] == 1000000000
assert len(pwa['source_sha256']) == 64
assert pwa['source_sha256'] == pwa['recovered_sha256'] == pwa['imported_sha256']
required = {
    'P15_IMPORTED_DESTINATION_FULL_DOWNLOAD_HASH',
    'P15_NEW_WORKER_WAITS_FOR_CONTROLLED_WINDOW',
    'P15_UPDATE_STARTS_WITH_ACTUAL_CONTROLLED_WINDOW',
    'P15_ACTUAL_ACTIVATION_AFTER_LAST_WINDOW_CLOSES',
    'P15_UPDATE_RETAINS_LATEST_ENCRYPTED_DRAFT',
    'P15_LOCK_CLEARS_DECRYPTED_DESTINATION_TITLES',
    'P15_IMPORT_PAUSE_PRESERVES_PROTECTED_PROGRESS',
    'P15_PAGE_DESTRUCTION_RETAINS_EXACT_IMPORT_JOB',
    'P15_KEYBOARD_VIEWPORT_VISIBLE_SAVE_STATE',
    'P15_REAL_MANIFEST_MEDIA_TYPE',
    'P15_UNANCHORED_EXPORT_DENIED_BEFORE_DOWNLOAD',
    'P15_ACTIVATION_PRESERVES_EXACT_ENCRYPTED_OUTBOX_BYTES',
    'P15_POST_UPDATE_RECONCILES_EXACT_OLD_RECEIPT',
    'P15_OLD_RECEIPT_ARRIVES_AFTER_ACTIVATION',
    'P15_OLD_RECEIPT_DOES_NOT_RETIRE_NEWER_DRAFT',
}
assert required <= set(pwa['checks'])
assert pwa['update_lifecycle']['before']['controlledByActive'] is True
assert pwa['update_lifecycle']['waiting']['controlledByActive'] is True
assert pwa['update_lifecycle']['waiting']['active']=='activated' and pwa['update_lifecycle']['waiting']['waiting']=='installed'
assert pwa['old_receipt_verified_after_activation'] is True
assert pwa['old_receipt_verified_after_update'] is True and pwa['retained_outbox_records'] > 0
storage=browser['p15_storage']
assert storage['status']=='PASS' and storage['physical_acceptance'] is False
assert storage['forced_origin_quota_bytes']==1 and storage['retained_draft_records']>0
assert storage['failed_operation'] in ['writer-admission','draft-update']
assert storage['browser_pid']!=storage['previous_browser_pid']
assert browser['p15_storage_preflight']['status']=='PASS'
assert storage['observed_error'] in ['INSUFFICIENT_STORAGE','STORAGE_FAILURE','STORAGE_ABORTED']
assert 'P15_NO_SPACE_RECOVERY_REOPENS_LAST_ACKNOWLEDGED_TEXT' in storage['checks']
assert pwa['process_memory']['samples'] > 1 and pwa['process_memory']['processes']
assert any(a['role'] == 'dedicated-worker' and a['samples'] > 1 for a in pwa['v8_memory']['agents'])
webkit_raw = member(wz, 'webkit-report.json')
webkit = json.loads(webkit_raw)
assert webkit['status'] == 'PASS' and webkit['physical_acceptance'] is False
assert provenance(webkit) == inputs
assert 'REAL_MANIFEST_MEDIA_TYPE' in webkit['checks']
receipt = {
    'purpose': 'Independent P15 public ZIP, complete source-array and Git-blob verification',
    'status': 'PASS', 'source_commit': head, 'source_tree': tree,
    'verified_git_inputs_per_receipt': inputs,
    'artifacts': [bmeta, wmeta],
    'reports': {
        'browser': hashlib.sha256(browser_raw).hexdigest(),
        'source': hashlib.sha256(source_raw).hexdigest(),
        'webkit': hashlib.sha256(webkit_raw).hexdigest(),
    },
    'chromium_version': browser['browser_version'], 'webkit_version': webkit['browser_version'],
    'pwa_checks': pwa['checks'], 'webkit_checks': webkit['checks'],
    'plaintext_bytes': pwa['plaintext_bytes'], 'full_sha256': pwa['source_sha256'],
    'physical_acceptance': False, 'independent_security_review': 'NOT_RUN',
}
Path(output_path).write_text(json.dumps(receipt, indent=2)+'\n')
print('PASS: API ZIP digests, complete source-input arrays and',inputs,'Git blobs per receipt; real full-hash gigabyte/update/recovery checks')
