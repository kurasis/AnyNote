#!/usr/bin/env python3
"""Freeze only the additive P13 browser package; default invocation is read-only."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
folder=ROOT/'packages/content-browser'
lock=json.loads((folder/'package-lock.json').read_text())
packages=[]
for path,value in lock['packages'].items():
    if not path:continue
    packages.append({'path':path,'name':path.split('node_modules/')[-1],**{k:value.get(k) for k in ['version','resolved','integrity','license']},'optional':value.get('optional',False)})
assert all(p['resolved'].startswith('https://registry.npmjs.org/') and p['integrity'].startswith('sha512-') and p['license'] for p in packages)
assert lock['packages']['']['dependencies']=={'age-encryption':'0.3.1','pdfjs-dist':'6.4.299'}
notices=[]
for path in sorted((folder/'node_modules').rglob('*')):
    if path.is_file() and path.name.lower().startswith(('license','licence','copyright','notice')):
        notices.append({'path':str(path.relative_to(folder)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
record={'purpose':'P13 isolated browser streaming age and PDF provenance','lock_sha256':hashlib.sha256((folder/'package-lock.json').read_bytes()).hexdigest(),'packages':packages,'installed_linux_notice_hashes':notices,'source':{'age-encryption':'https://github.com/FiloSottile/typage','pdfjs-dist':'https://github.com/mozilla/pdf.js'},'scope':'Optional native canvas packages are lock resolutions, not embedded browser modules; original dependency locks remain unchanged.'}
target=folder/'dependency-inventory.json'
if sys.argv[1:]==['--write']:target.write_text(json.dumps(record,indent=2)+'\n')
else:
    assert not sys.argv[1:]
    expected=json.loads(target.read_text());assert expected['lock_sha256']==record['lock_sha256'] and expected['packages']==packages
    if sys.platform!='win32':assert expected['installed_linux_notice_hashes']==notices
print(json.dumps({'status':'PASS','frozen_packages':len(packages),'installed_notices':len(notices),'mode':'write' if sys.argv[1:] else 'read-only'}))
