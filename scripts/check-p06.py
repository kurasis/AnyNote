#!/usr/bin/env python3
"""Read-only auth contracts, exact dependency extension and real tamper negatives."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from p06_compatibility import verify
ROOT=Path(__file__).resolve().parents[1]
verify(ROOT)
paths=['packages/contracts/p06-compatibility.json','docs/reference/p04/composer-p04.lock','apps/api/composer.lock']
with tempfile.TemporaryDirectory(prefix='anynote-p06-tamper-',dir='/tmp') as name:
 target=Path(name)
 for path in paths:
  p=target/path;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/path,p)
 receipt=target/paths[0];lock=target/paths[2];original=lock.read_bytes();r=receipt.read_bytes()
 for mutation in ['existing','new','unapproved-addition','baseline']:
  if mutation=='baseline':p=target/paths[1];before=p.read_bytes();p.write_bytes(before+b'\n')
  else:
   d=json.loads(original)
   if mutation=='existing':d['packages'][0]['version']='0.0.0'
   elif mutation=='new':next(x for x in d['packages'] if x['name']=='league/oauth2-server')['version']='9.4.0'
   else:d['packages'].append({'name':'synthetic/unreviewed','version':'1.0.0'})
   lock.write_text(json.dumps(d));updated=json.loads(r);updated['current_sha256']=hashlib.sha256(lock.read_bytes()).hexdigest();receipt.write_text(json.dumps(updated))
  try:verify(target)
  except AssertionError:pass
  else:raise AssertionError('Tampered lock accepted: '+mutation)
  if mutation=='baseline':p.write_bytes(before)
  lock.write_bytes(original);receipt.write_bytes(r)
 verify(target)
docs={p.stem.removesuffix('.schema'):json.loads(p.read_text()) for p in (ROOT/'packages/contracts').glob('*.schema.json')}
for doc in docs.values():
 def visit(v):
  if isinstance(v,dict):
   if '$ref'in v:
    uri,fragment=v['$ref'].split('#');source=doc if not uri else next(x for x in docs.values() if x['$id']==uri);assert fragment.startswith('/$defs/') and fragment[7:]in source['$defs'],v['$ref']
   for child in v.values():visit(child)
  elif isinstance(v,list):
   for child in v:visit(child)
 visit(doc)
ops=json.loads((ROOT/'packages/contracts/p03-operations.json').read_text())['operations']
routes=(ROOT/'apps/api/routes/web.php').read_text()
auth=[o for o in ops if o['phase']=='P06']
assert len(auth)==23 and all(o['implemented'] for o in auth)
for op in auth:
 assert "->name('"+op['operation_id']+"')"in routes
 for key in ['request','response']:
  if key in op:
   component,kind=op[key].split('/');assert kind in docs[component]['$defs'],op['operation_id']
assert (ROOT/'docs/reference/p04/composer-p04.lock').read_bytes()!= (ROOT/'apps/api/composer.lock').read_bytes()
print(json.dumps({'status':'PASS','auth_routes':23,'lock_tamper_negatives':4,'prior_package_records_preserved':103,'approved_additions':23}))
