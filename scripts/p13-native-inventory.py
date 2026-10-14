#!/usr/bin/env python3
"""Freeze/check the new core lock and declared package licenses; never rewrite prior locks."""
import argparse,hashlib,json,subprocess,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; crate=ROOT/'packages/content-native';lock=crate/'Cargo.lock'
meta=json.loads(subprocess.check_output(['cargo','metadata','--manifest-path',str(crate/'Cargo.toml'),'--locked','--format-version','1'],text=True))
packages={(p['name'],p['version']):p for p in meta['packages']}
records=[{'name':p['name'],'version':p['version'],'source':p.get('source'),'checksum':p.get('checksum'),'license':packages[(p['name'],p['version'])].get('license')} for p in tomllib.loads(lock.read_text())['package']]
value={'purpose':'P13 native content exact dependency/license inventory; not independent audit or release SBOM','project_release_license':'GPL-3.0-only native derivative; repository-wide release remains UNSELECTED','lock_sha256':hashlib.sha256(lock.read_bytes()).hexdigest(),'packages':records}
args=argparse.ArgumentParser();args.add_argument('--write',action='store_true');a=args.parse_args();path=crate/'dependency-inventory.json'
if a.write:path.write_text(json.dumps(value,indent=2)+'\n')
else:
 expected=json.loads(path.read_text())
 assert expected==value,'Native content inventory drift: '+','.join(k for k in value if expected.get(k)!=value[k])
print('PASS:',len(records),'frozen native content dependency/license records')
