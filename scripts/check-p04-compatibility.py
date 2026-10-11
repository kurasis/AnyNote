#!/usr/bin/env python3
"""Prove the one explicit lock extension and reject actual baseline/current tampering."""
import hashlib,json,shutil,tempfile
from pathlib import Path
from p04_compatibility import verify
ROOT=Path(__file__).resolve().parents[1]
verify(ROOT)
paths=['packages/contracts/p04-compatibility.json','packages/contracts/p02-v1.registry.json','docs/reference/p02/composer-p02.lock','apps/api/composer.lock']
with tempfile.TemporaryDirectory(prefix='p04-compatibility-',dir='/tmp') as directory:
    root=Path(directory)
    for path in paths:
        target=root/path;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/path,target)
    verify(root)
    for mode in ['baseline-bytes','existing-package','added-version','extra-package']:
        p=root/'apps/api/composer.lock';original=p.read_bytes();receipt=root/'packages/contracts/p04-compatibility.json';original_receipt=receipt.read_bytes()
        baseline=root/'docs/reference/p02/composer-p02.lock';original_baseline=baseline.read_bytes()
        if mode=='baseline-bytes':baseline.write_bytes(original_baseline+b'\n')
        else:
            value=json.loads(original)
            if mode=='existing-package':value['packages'][0]['version']='9.9.9'
            elif mode=='added-version':next(p for p in value['packages'] if p['name']=='opis/json-schema')['version']='2.6.1'
            else:value['packages'].append({'name':'synthetic/unreviewed','version':'1.0.0'})
            p.write_text(json.dumps(value));r=json.loads(original_receipt);r['current_sha256']=hashlib.sha256(p.read_bytes()).hexdigest();receipt.write_text(json.dumps(r))
        try:verify(root)
        except AssertionError:pass
        else:raise RuntimeError('Unreviewed lock drift accepted: '+mode)
        p.write_bytes(original);baseline.write_bytes(original_baseline);receipt.write_bytes(original_receipt)
    verify(root)
print('PASS: frozen P02 lock, 99 unchanged records/four explicit additions; four genuine tamper negatives')
