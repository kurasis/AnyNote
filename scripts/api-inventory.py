#!/usr/bin/env python3
"""Record or verify exact dependency/license/source records from Composer's lock."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'apps/api/composer.lock'
OUTPUT = ROOT / 'apps/api/dependency-inventory.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    lock = json.loads(LOCK.read_text())
    records = []
    for group in ['packages', 'packages-dev']:
        for package in lock[group]:
            records.append({
                'name': package['name'], 'version': package['version'],
                'development_only': group == 'packages-dev',
                'licenses': package.get('license', []),
                'source': package.get('source'), 'dist': package.get('dist'),
            })
    inventory = {
        'schema_version': 1, 'purpose': 'P03 resolved development dependency inventory, not a release SBOM',
        'project_release_license': 'UNSELECTED',
        'lock_sha256': hashlib.sha256(LOCK.read_bytes()).hexdigest(),
        'packages': sorted(records, key=lambda p: p['name']),
        'limitation': 'Metadata licenses require packaging review; upstream empty dist.shasum is retained, not invented',
    }
    if args.write:
        OUTPUT.write_text(json.dumps(inventory, indent=2) + '\n')
    elif json.loads(OUTPUT.read_text()) != inventory:
        raise RuntimeError('API dependency inventory drift; regenerate and review actual lock changes')
    print(f'PASS: {len(records)} exact locked package/source/license records')


if __name__ == '__main__':
    main()
