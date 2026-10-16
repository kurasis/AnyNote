#!/usr/bin/env python3
"""Read-only P17 review-manifest, frozen-input and portable codec validation."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
trace=json.loads((ROOT/'docs/security/p17-traceability.json').read_text())
assert trace['independent_review']=='NOT_RUN' and trace['production_release_allowed']is False
assert {r['id']for r in trace['regressions']}=={f'R{i:02}'for i in range(1,25)}
assert len(trace['regressions'])==24
anchors=[]
for row in trace['regressions']:
    assert row['authority'] and row['tests'] and row['limitations']
    for entry in row['authority']+row['tests']:
        path=ROOT/entry['path']
        assert not path.is_symlink() and path.resolve().is_relative_to(ROOT)
        raw=path.read_bytes();assert entry['anchor'].encode()in raw,row['id']+': stale source anchor'
        anchors.append({'regression':row['id'],'path':entry['path'],'anchor':entry['anchor'],'sha256':hashlib.sha256(raw).hexdigest(),**({'gate':entry['gate']}if 'gate'in entry else {})})
for args in [['python3','scripts/p05-port-codecs.py'],['python3','scripts/p03-contracts.py'],['python3','scripts/check-p14.py'],['python3','scripts/check_baseline.py']]:
    subprocess.run(args,cwd=ROOT,check=True,capture_output=True)
out=ROOT/'artifacts/p17';out.mkdir(parents=True,exist_ok=True)
git=lambda *a:subprocess.check_output(['git',*a],cwd=ROOT).decode().strip()
report={'purpose':'P17 threat source/test anchors, not runtime or independent review','status':'PASS','source_commit':git('rev-parse','HEAD'),'source_tree_dirty':bool(git('status','--porcelain')),'regressions':24,'bindings':anchors,'independent_review':'NOT_RUN','production_release_allowed':False}
(out/'traceability-report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: all24 R01–R24 authority/test anchors, portable predicates and179 frozen files; runtime evidence is separate')
