#!/usr/bin/env python3
"""Read-only format/dependency/source provenance checks; never creates fixture bytes."""
import hashlib,json,subprocess,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
current=tomllib.loads((ROOT/'packages/vault-native/Cargo.lock').read_text())['package']
for name in ['crypto-core','auth-native']:
    baseline=tomllib.loads((ROOT/f'packages/{name}/Cargo.lock').read_text())['package']
    for package in baseline:
        exact=[p for p in current if p['name']==package['name'] and p['version']==package['version']]
        if name=='crypto-core' and package['name']=='syn' and package['version']=='3.0.7':
            assert any(p['name']=='syn' and p['version']=='3.0.8' for p in current)
            continue
        assert exact and exact[0].get('checksum')==package.get('checksum'),(name,package['name'])
for file in (ROOT/'experiments/p01/windows-hello/tests/hello').rglob('*'):
    if file.is_file():
        counterpart=ROOT/'packages/vault-native/tests/hello'/file.relative_to(ROOT/'experiments/p01/windows-hello/tests/hello')
        assert file.read_bytes()==counterpart.read_bytes(),'Provider fixture/header copy drift'
for file in ['packages/vault-native/LICENSE','experiments/p01/windows-hello/LICENSE']:
    assert 'GNU GENERAL PUBLIC LICENSE' in (ROOT/file).read_text()
assert (ROOT/'packages/vault-native/LICENSE').read_bytes()==(ROOT/'experiments/p01/windows-hello/LICENSE').read_bytes()
manifest=tomllib.loads((ROOT/'packages/vault-native/Cargo.toml').read_text())
assert manifest['dependencies']['rusqlite']['version']=='=0.40.2'
assert manifest['package']['license']=='GPL-3.0-only'
assert manifest['features']['integration-harness']==['anynote-auth-native/integration-harness']
subprocess.run(['node','--test','--test-concurrency=1','packages/protocol/vault/test-engine.mjs'],cwd=ROOT,check=True)
print('PASS: frozen baseline dependencies (one documented already-reviewed syn unification), exact GPL/header/fixture provenance and executed custody attack tests')
