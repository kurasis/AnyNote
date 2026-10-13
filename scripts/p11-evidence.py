#!/usr/bin/env python3
"""Exact-source receipt for executed P11 software; never a physical/audit acceptance."""
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
role = sys.argv[1]
assert role in ['linux', 'windows'] and (role == 'windows') == (sys.platform == 'win32')
def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()
assert not git('status', '--porcelain'), 'Software receipt requires clean source'
result = subprocess.run(['cargo', 'test', '--manifest-path', 'packages/vault-native/Cargo.toml', '--locked', '--all-features', '-j', '4', '--', '--test-threads=1'], cwd=ROOT, check=True, text=True, encoding='utf-8', capture_output=True)
assert 'staged_sync_cursor_is_atomic_and_restore_regression_keeps_drafts ... ok' in result.stdout
paths = git('ls-files').splitlines()
prefixes = ('packages/', 'apps/', 'scripts/', 'infra/', 'experiments/p01/', '.github/workflows/')
report = {'purpose': 'P11 staged synchronization software source receipt', 'status': 'PASS', 'role': role, 'source_commit': git('rev-parse', 'HEAD'), 'source_tree': git('rev-parse', 'HEAD^{tree}'), 'source_tree_dirty': False, 'timestamp': datetime.now(timezone.utc).isoformat(), 'physical_acceptance': False, 'independent_review': 'NOT_RUN', 'inputs': [{'path': p, 'sha256': hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in paths if p.startswith(prefixes)]}
if role == 'linux':
    http = json.loads((ROOT/'artifacts/p11/http-report.json').read_text())
    assert http['status'] == 'PASS' and http['source_commit'] == report['source_commit'] and not http['source_tree_dirty']
    report['http_checks'] = http['checks']
(ROOT/'artifacts/p11').mkdir(parents=True, exist_ok=True)
(ROOT/'artifacts/p11/source-report.json').write_text(json.dumps(report, indent=2)+'\n')
print('PASS: P11 source receipt', role, len(report['inputs']), 'raw inputs')
