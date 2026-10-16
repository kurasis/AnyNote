#!/usr/bin/env python3
"""Require actual clean-source PWA receipts; bind every tracked input byte."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


head = git('rev-parse', 'HEAD').decode().strip()
assert not git('status', '--porcelain'), 'Refuse dirty source acceptance'
path = ROOT / 'artifacts/p10/browser-report.json'
browser = json.loads(path.read_text())
assert browser['status'] == 'PASS' and browser['source_commit'] == head
assert browser['source_tree_dirty'] is False and browser['chromium_sandbox'] is True
assert browser['p12_files']['gigabyte_bytes'] == 1000000000
pwa = browser['p15_pwa']
assert pwa['status'] == 'PASS' and pwa['physical_acceptance'] is False
assert pwa['plaintext_bytes'] == pwa['recovered_bytes'] == 1000000000
assert pwa['imported_bytes'] == 1000000000
assert len(pwa['source_sha256']) == 64
assert pwa['source_sha256'] == pwa['recovered_sha256'] == pwa['imported_sha256']
assert pwa['old_receipt_verified_after_update'] is True
assert pwa['old_receipt_verified_after_activation'] is True
assert len(pwa['updated_attempt_id']) == 22 and len(pwa['original_update_request_sha256']) == 64
assert pwa['retained_outbox_records'] > 0 and len(pwa['outbox_before_after_sha256']) == 64
storage = browser['p15_storage']
assert storage['status'] == 'PASS' and storage['physical_acceptance'] is False
assert storage['forced_origin_quota_bytes'] == 1 and storage['retained_draft_records'] > 0
assert storage['failed_operation'] in ['writer-admission', 'draft-update']
assert storage['browser_pid'] != storage['previous_browser_pid']
assert browser['p15_storage_preflight']['status'] == 'PASS'
assert browser['p15_lock_race']['status'] == 'PASS'
assert browser['p15_lock_race']['scenarios'] == 2
assert browser['p15_lock_race']['actual_authenticated_responses'] is True
assert storage['observed_error'] in ['INSUFFICIENT_STORAGE', 'STORAGE_FAILURE', 'STORAGE_ABORTED']
assert pwa['memory']['samples'] > 1
assert pwa['process_memory']['samples'] > 1 and pwa['process_memory']['processes']
assert any(agent['role'] == 'dedicated-worker' and agent['samples'] > 1
           for agent in pwa['v8_memory']['agents'])
paths = sorted(p for p in git('ls-files', '-z').decode().split('\0')
               if p and not p.startswith(('docs/evidence/', 'artifacts/')))
inputs = [{'path': p, 'sha256': hashlib.sha256((ROOT / p).read_bytes()).hexdigest()}
          for p in paths]
report = {
    'purpose': 'P15 exact-source shipped PWA software acceptance', 'status': 'PASS',
    'source_commit': head, 'source_tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
    'source_tree_dirty': False, 'timestamp': datetime.now(timezone.utc).isoformat(),
    'reports': {'browser': {'path': str(path.relative_to(ROOT)),
                            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}},
    'inputs': inputs, 'physical_acceptance': False, 'independent_review': 'NOT_RUN',
}
output = ROOT / 'artifacts/p15'
output.mkdir(parents=True, exist_ok=True)
(output / 'source-report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: P15 real gigabyte, cache/update/lifecycle and process/Worker memory receipt;', len(inputs), 'tracked input bytes')
