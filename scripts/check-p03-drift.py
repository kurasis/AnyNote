#!/usr/bin/env python3
"""Real changed-output/input negatives in isolated temporary copies; never rewrite source."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('contracts', ROOT/'scripts/p03-contracts.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
products,manifest=module.outputs()
def verify():
    generated,_=module.outputs()
    return all((module.ROOT/path).read_bytes()==content.encode() for path,content in generated.items())
assert verify(), 'Actual generated sources drift'
negatives=['packages/contracts/generated/protocol.d.ts','apps/api/app/Generated/Dtos.php','packages/contracts/generated/openapi.json','packages/contracts/generated/runtime-schemas.json','packages/contracts/generated/manifest.json','packages/contracts/p03-api.schema.json','packages/contracts/p02-errors.json','packages/protocol/src/protocol-codec.mjs','packages/api-client/client.mjs']
with tempfile.TemporaryDirectory(prefix='anynote-p03-drift-',dir='/tmp') as temp:
    temp=Path(temp)
    for path in set(products)|{r['path'] for r in manifest['inputs']}:
        target=temp/path;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/path,target)
    module.ROOT=temp
    assert verify()
    for path in negatives:
        p=temp/path;before=p.read_bytes()
        if path.endswith('.json'):
            value=json.loads(before)
            if path.endswith('p02-errors.json'):value['errors'][0]['http_status']=401
            elif path.endswith('p03-api.schema.json'):value['$defs']['liveness']['properties']['status']['const']='incorrect'
            elif isinstance(value,list):value.append({'synthetic_drift':True})
            else:value['synthetic_drift']=True
            p.write_text(json.dumps(value))
        else:p.write_bytes(before+b'\n// synthetic drift\n')
        assert not verify(), 'Changed contract accepted: '+path
        p.write_bytes(before)
    assert verify()
print(json.dumps({'status':'PASS','changed_input_output_negatives':len(negatives),'repository_mutations':0}))
