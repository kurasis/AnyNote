#!/usr/bin/env python3
"""Offline PHP parser in the existing verified image, without service/SQL mutations."""
import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('owned_p03', ROOT / 'scripts/dev-stack.py')
stack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stack)
stack.initialize()
command = ['docker', 'compose', '--project-name', stack.PROJECT, '--env-file', str(stack.ENV),
           '-f', str(ROOT / 'infra/dev/compose.yaml'), 'run', '--rm', '--no-deps', '-T',
           'php', 'php', 'tests/Support/p17-parser.php']
result = subprocess.run(command, cwd=ROOT, stdin=sys.stdin.buffer, stdout=sys.stdout.buffer,
                        stderr=subprocess.PIPE)
if result.returncode:
    raise SystemExit('Offline parser failed; private command arguments omitted')
