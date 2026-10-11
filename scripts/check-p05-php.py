#!/usr/bin/env python3
"""Feed the owned PHP runtime a projected PUBLIC signature-only corpus."""
import hashlib,importlib.util,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'artifacts/p05'
sources=[]
for runtime,path,peer in [('Rust','native-output.json',True),('Node','node-peer.json',False),('Chromium worker','browser-peer.json',False)]:
    p=OUT/path
    if p.exists():
        v=json.loads(p.read_text());v=v['peer'] if peer else v
        sources.append({'runtime':runtime,'frames':v['public_signatures']})
assert len(sources)>=2,'Native and Node public signatures required'
jcs=json.loads((ROOT/'fixtures/protocol/p05/jcs.json').read_text())
value={'purpose':'PUBLIC_SIGNATURE_ONLY_P05','sources':sources,'malformed':jcs['invalid_hex']}
path=OUT/'public-signatures.json';path.write_text(json.dumps(value)+'\n')
spec=importlib.util.spec_from_file_location('p05_owned_stack',ROOT/'scripts/dev-stack.py');stack=importlib.util.module_from_spec(spec);spec.loader.exec_module(stack);stack.initialize()
x=json.loads(stack.compose('run','--rm','--no-deps','-v',f'{ROOT}:/reference:ro','php','php','/reference/scripts/check-p05-php.php','/reference/artifacts/p05/public-signatures.json',capture=True))
assert x['status']=='PASS' and x['php']==json.loads((ROOT/'infra/dev/versions.json').read_text())['php']
x['source_commit']=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip();x['source_tree_dirty']=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT));x['public_input_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
(OUT/'php-report.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
