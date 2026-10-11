#!/usr/bin/env python3
"""Verify PUBLIC candidate state fixtures in the owned pinned PHP container."""
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    # Existing P03 setup owns credentials/images; never create another stack.
    if not (ROOT / '.local/p03/owner.json').is_file():
        raise RuntimeError('Run the owned dev-stack.py install/up first')
    spec = importlib.util.spec_from_file_location('anynote_owned_stack', ROOT / 'scripts/dev-stack.py')
    stack = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stack)
    stack.initialize()
    output = stack.compose('run', '--rm', '--no-deps', '-v', f'{ROOT}:/reference:ro',
                           'php', 'php', '/reference/scripts/check-p02-state.php',
                           '/reference/fixtures/protocol/p02/identity-vectors.json',
                           '/reference/fixtures/protocol/p02/state-vectors.json', capture=True)
    result = json.loads(output)
    assert result['status'] == 'PASS' and result['scope'] == 'PUBLIC_FIXTURE_SUBSET_ONLY'
    assert result['php'] == json.loads((ROOT / 'infra/dev/versions.json').read_text())['php']
    assert result['events'] == 5 and result['channel_frames'] == 7
    result['source_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    result['source_tree_dirty'] = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
