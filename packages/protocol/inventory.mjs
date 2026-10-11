import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const lockBytes = readFileSync(new URL('./package-lock.json', import.meta.url));
const lock = JSON.parse(lockBytes);
const inventory = { status: 'DEVELOPMENT_CANDIDATE', root_release_license: 'UNSELECTED',
  lock_sha256: createHash('sha256').update(lockBytes).digest('base64url'),
  packages: Object.entries(lock.packages).filter(([path]) => path).map(([path, entry]) => ({
    path, version: entry.version, license: entry.license, resolved: entry.resolved, integrity: entry.integrity,
  })) };
const path = new URL('./dependency-inventory.json', import.meta.url);
const expected = JSON.stringify(inventory, null, 2) + '\n';
if (process.argv.includes('--write')) writeFileSync(path, expected);
else if (readFileSync(path, 'utf8') !== expected) throw new Error('DEPENDENCY_INVENTORY_DRIFT');
console.log(`PASS: exact lock/license/integrity inventory (${inventory.packages.length} packages)`);
