#!/usr/bin/env python3
"""Exact executed source receipt; public metadata only, no physical/audit inference."""
import hashlib, json, subprocess, sys
from pathlib import Path
from datetime import datetime, timezone
ROOT = Path(__file__).resolve().parents[1]
role = sys.argv[1]
assert role in ['linux', 'windows'] and (role == 'windows') == (sys.platform == 'win32')
def git(*args): return subprocess.check_output(['git', *args], cwd=ROOT)
head = git('rev-parse', 'HEAD').decode().strip()
assert not git('status', '--porcelain'), 'Source must be clean before a final receipt'
native = subprocess.run(['cargo', 'test', '--manifest-path', 'packages/content-native/Cargo.toml', '--locked', '-j', '4', '--', '--test-threads=1'], cwd=ROOT, capture_output=True, text=True, encoding='utf-8', check=True)
assert native.stdout.count('2 passed; 0 failed; 0 ignored') == 2
assert 'authenticated_native_filename_index_never_exports_keys_and_survives_reopen ... ok' in native.stdout
assert 'real_native_search_verifies_signed_content_encrypts_tokens_and_fences_lock_and_source_change ... ok' in native.stdout
reports = {}
if role == 'windows':
    value = json.loads((ROOT / 'artifacts/p13/gigabyte-development.json').read_text())
    assert value['status'] == 'PASS' and value['source_commit'] == head and not value['source_tree_dirty']
    assert value['plaintext_bytes'] == 1000000000 and value['independent_age_reader'] == 'Rust age 0.12.1/MSVC'
    reports['gigabyte'] = {'path': 'artifacts/p13/gigabyte-development.json', 'sha256': hashlib.sha256((ROOT / 'artifacts/p13/gigabyte-development.json').read_bytes()).hexdigest()}
if role == 'linux':
    for name, path in [('authority', 'artifacts/p13/authority-report.json'), ('http', 'artifacts/p13/http-development-report.json'), ('gigabyte', 'artifacts/p13/gigabyte-development.json'), ('preview', 'artifacts/p13/preview-probe.json'), ('browser', 'artifacts/p10/browser-report.json')]:
        value = json.loads((ROOT / path).read_text())
        assert value['status'] == 'PASS' and value['source_commit'] == head and not value.get('source_tree_dirty', False)
        reports[name] = {'sha256': hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), 'path': path}
    assert json.loads((ROOT / reports['browser']['path']).read_text())['p13_content']['status'] == 'PASS'
paths = sorted(p for p in git('ls-files', '-z').decode().split('\0') if p and not p.startswith(('docs/evidence/', 'artifacts/')))
inputs = [{'path': p, 'sha256': hashlib.sha256((ROOT / p).read_bytes()).hexdigest()} for p in paths]
report = {'purpose': 'P13 exact-source executed software receipt', 'status': 'PASS', 'role': role, 'source_commit': head, 'source_tree': git('rev-parse', 'HEAD^{tree}').decode().strip(), 'source_tree_dirty': False, 'timestamp': datetime.now(timezone.utc).isoformat(), 'native_content_tests': 4, 'reports': reports, 'inputs': inputs, 'physical_acceptance': False, 'independent_review': 'NOT_RUN'}
(ROOT / 'artifacts/p13').mkdir(exist_ok=True, parents=True)
(ROOT / 'artifacts/p13/source-report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: P13 exact-source', role, len(inputs), 'tracked inputs; hardware/review gates remain separate')
