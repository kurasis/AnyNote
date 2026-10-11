#!/usr/bin/env python3
"""Portable copies of frozen codec predicates; default compares, --write is development only."""
import argparse
import re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'packages/protocol/adapters/codecs'
args=argparse.ArgumentParser();args.add_argument('--write',action='store_true');write=args.parse_args().write
names=['codec','identity-codec','state-codec','group-codec','protocol-codec']
for name in names:
    text=(ROOT/'packages/protocol/src'/f'{name}.mjs').read_text()
    text=re.sub(r'import \{ readFileSync \} from [\'"]node:fs[\'"];\n','',text)
    text=re.sub(r'import \{ createHash \} from [\'"]node:crypto[\'"];\n','',text)
    text=text.replace('./strict-json.mjs','../../src/strict-json.mjs')
    text="// Portable P05 codec; frozen predicates preserved by scripts/p05-port-codecs.py.\nimport { Buffer, createHash, readFileSync } from '../bytes.mjs';\n"+text
    path=OUT/f'{name}.mjs'
    if write:path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
    else:assert path.read_text()==text,'Portable codec drift: '+name
print('PASS: five portable codecs preserve frozen schema and semantic predicates')
