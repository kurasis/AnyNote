#!/usr/bin/env python3
"""Read-only handoff/baseline validation and actual candidate negative suite."""
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
for name in ['P18_RELEASE.md', 'USER_GUIDE.md', 'OPERATOR_HANDOFF.md']:
    text = (ROOT / 'docs' / name).read_text(encoding='utf-8')
    for target in re.findall(r'\]\(([^)#]+)(?:#[^)]*)?\)', text):
        if not target.startswith(('https://', 'http://')):
            assert (ROOT / 'docs' / target).resolve().is_file(), target
for command in [['python3', 'scripts/check_baseline.py'],
                ['python3', 'scripts/p03-contracts.py'],
                ['python3', 'scripts/test-p18.py'],
                ['node', '--check', 'packages/protocol/p18-journey.mjs']]:
    subprocess.run(command, cwd=ROOT, check=True)
print('PASS: P18 handoff links, frozen protocol/baseline and actual candidate integrity negatives; runtime journey is a separate operations gate')
