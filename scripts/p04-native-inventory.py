#!/usr/bin/env python3
"""Read-only native public-adapter lock/license drift check; --write is development only."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib
ROOT=Path(__file__).resolve().parents[1]
lock=ROOT/'packages/crypto-native/Cargo.lock'
meta=json.loads(subprocess.check_output(['cargo','metadata','--manifest-path',str(ROOT/'packages/crypto-native/Cargo.toml'),'--locked','--format-version','1'],text=True))
licenses={(p['name'],p['version']):p.get('license') for p in meta['packages']}
records=[{'name':p['name'],'version':p['version'],'source':p.get('source'),'checksum':p.get('checksum'),'license':licenses[(p['name'],p['version'])]} for p in tomllib.loads(lock.read_text())['package']]
value={'purpose':'P05 public-signature slice for P04, not a release SBOM','project_release_license':'UNSELECTED','lock_sha256':hashlib.sha256(lock.read_bytes()).hexdigest(),'packages':records}
output=ROOT/'packages/crypto-native/dependency-inventory.json'
parser=argparse.ArgumentParser();parser.add_argument('--write',action='store_true');args=parser.parse_args()
if args.write:output.write_text(json.dumps(value,indent=2)+'\n')
else:assert json.loads(output.read_text())==value,'Native inventory drift'
print('PASS:',len(records),'frozen native adapter dependency/license records')
