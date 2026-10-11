"""One explicit P04 lock extension, never a general frozen-input drift exception."""
import hashlib
import json
from pathlib import Path

ADDED = {'opis/json-schema':'2.6.0','opis/string':'2.1.0','opis/uri':'1.1.0','truschery/kanon':'v1.0.1'}

def verify(root: Path):
    receipt = json.loads((root/'packages/contracts/p04-compatibility.json').read_text())
    assert receipt['version']==1 and receipt['phase']=='P04' and receipt['path']=='apps/api/composer.lock'
    assert receipt['baseline_path']=='docs/reference/p02/composer-p02.lock'
    baseline=root/receipt['baseline_path'];current=root/receipt['path']
    assert hashlib.sha256(baseline.read_bytes()).hexdigest()==receipt['baseline_sha256']
    registry=json.loads((root/'packages/contracts/p02-v1.registry.json').read_text())
    row=next(r for r in registry['frozen_inputs'] if r['path']==receipt['path'])
    assert receipt['baseline_sha256']==row['sha256']
    assert hashlib.sha256((root/'packages/contracts/p02-v1.registry.json').read_bytes()).hexdigest()==receipt['predecessor_registry_sha256']
    assert hashlib.sha256(current.read_bytes()).hexdigest()==receipt['current_sha256']
    old=json.loads(baseline.read_bytes());new=json.loads(current.read_bytes())
    def packages(lock):return {p['name']:p for k in ['packages','packages-dev'] for p in lock[k]}
    a=packages(old);b=packages(new)
    assert all(n in b and b[n]==p for n,p in a.items()),'An existing package record changed'
    added={n:b[n]['version'] for n in b.keys()-a.keys()}
    assert added==ADDED and receipt['added_packages']==ADDED,'Unreviewed dependency addition/version'
    assert len(a)==99 and len(b)==103
    return {receipt['path']:baseline}
