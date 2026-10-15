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
assert len(pwa['source_sha256']) == 64
assert pwa['memory']['samples'] > 1
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
