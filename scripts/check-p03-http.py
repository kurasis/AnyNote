#!/usr/bin/env python3
"""Run the real HTTP contract client only on this marked synthetic stack's port."""
import importlib.util
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('stack',ROOT/'scripts/dev-stack.py')
stack=importlib.util.module_from_spec(spec);spec.loader.exec_module(stack)
stack.initialize()
port=next(line.partition('=')[2] for line in stack.ENV.read_text().splitlines() if line.startswith('ANYNOTE_DEV_PORT='))
assert port.isdecimal() and 1024<=int(port)<=65535
subprocess.run(['node',str(ROOT/'packages/api-client/http-check.mjs'),port],cwd=ROOT,check=True)
