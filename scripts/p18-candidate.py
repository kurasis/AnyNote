#!/usr/bin/env python3
"""Build and verify offline review candidates. This tool never authorizes publication.

Checksums bind bytes to the observed CI source; they are not publisher signatures.
Archives are inspected as streams, never extracted. Existing outputs are refused.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'anynote-p18-review-candidate-v1'
MAX_MEMBER = 2 * 1024**3
MAX_TOTAL = 4 * 1024**3
STATIC = {'app.js', 'client.js', 'devices.html', 'devices.js', 'icon-192.png',
          'icon-512.png', 'index.html', 'manifest.webmanifest', 'notes.css',
          'notes.html', 'notes.js', 'preview-parser.mjs', 'preview-render.mjs',
          'style.css', 'sw.js', 'vault-client.js', 'vault-store.js', 'vault-worker.js',
          'vault.html', 'vault.js'}


def require(value, message):
    if not value:
        raise ValueError(message)


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def safe_name(name):
    require(isinstance(name, str) and name and '\\' not in name and '\x00' not in name,
            'Invalid archive name')
    p = PurePosixPath(name)
    require(not p.is_absolute() and all(x not in ('', '.', '..') for x in name.split('/')),
            'Unsafe archive path')
    require(not re.search(r'[:\x00-\x1f\x7f]', name), 'Unsafe cross-platform path')
    return name


def regular(path):
    require(path.is_file() and not path.is_symlink(), 'Regular file required: ' + str(path))
    return path


def eligibility():
    # No caller-supplied boolean, manifest, signature or test key can open this.
    # Production needs a separately authorized reviewed ceremony, not a CLI flag.
    return {'production_release_allowed': False, 'status': 'BLOCKED', 'blockers': {
        'qualified_independent_review': 'NOT_RUN',
        'physical_iphone_1gb_and_lifecycle': 'NOT_RUN',
        'physical_windows_hello_tpm': 'NOT_RUN',
        'native_128mib_budget': 'FAIL',
        'physical_device_memory_budget': 'NOT_RUN',
        'actual_100gb_inventory': 'NOT_RUN',
        'authenticode_and_production_updater_signatures': 'NOT_RUN',
        'production_key_custody_and_operator_acceptance': 'NOT_RUN',
        'repository_wide_release_license_selection': 'NOT_RUN',
        'production_publication_authorization': 'NOT_RUN'}}


def report(path, head):
    v = json.loads(regular(ROOT / path).read_text(encoding='utf-8'))
    require(v['status'] == 'PASS' and v['source_commit'] == head and
            v['source_tree_dirty'] is False, 'Clean exact-head PASS required: ' + path)
    return v


def add_tree(files, prefix, base):
    require(base.is_dir() and not base.is_symlink(), 'Missing candidate directory: ' + str(base))
    for p in sorted(base.rglob('*')):
        require(not p.is_symlink(), 'Symlink in candidate input')
        if p.is_file():
            files[safe_name(prefix + '/' + p.relative_to(base).as_posix())] = p


def write_archive(destination, manifest, files):
    require(not destination.exists(), 'Existing candidate is never overwritten')
    require(len(files) <= 10000, 'Too many candidate members')
    total = 0
    manifest['files'] = []
    for name, path in sorted(files.items()):
        safe_name(name)
        regular(path)
        size = path.stat().st_size
        require(size <= MAX_MEMBER, 'Candidate member too large')
        total += size
        require(total <= MAX_TOTAL, 'Candidate archive too large')
        manifest['files'].append({'path': name, 'bytes': size, 'sha256': sha(path)})
    # Exclusive creation, deterministic gzip/tar metadata; no host paths or secrets.
    try:
        with destination.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz, tarfile.open(fileobj=gz, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
            data = canonical(manifest)
            item = tarfile.TarInfo('candidate.json'); item.size = len(data); item.mode = 0o644
            tar.addfile(item, io.BytesIO(data))
            for row in manifest['files']:
                item = tarfile.TarInfo(row['path']); item.size = row['bytes']; item.mode = 0o644
                with files[row['path']].open('rb') as stream:
                    tar.addfile(item, stream)
        return verify(destination)
    except BaseException:
        # Only this invocation's exclusively created partial output may be removed.
        destination.unlink(missing_ok=True)
        raise


def verify(path):
    regular(path)
    require(path.stat().st_size <= MAX_TOTAL, 'Compressed candidate too large')
    # Parse fixed USTAR headers before reading bodies. Generic tar readers may
    # eagerly load PAX/GNU extension bodies before application size checks.
    with path.open('rb') as compressed, gzip.GzipFile(fileobj=compressed, mode='rb') as stream:
        def header():
            raw = stream.read(512)
            require(len(raw) == 512, 'Truncated USTAR header')
            if not any(raw):
                return None
            require(raw[257:265] == tarfile.POSIX_MAGIC, 'Only fixed USTAR headers accepted')
            item = tarfile.TarInfo.frombuf(raw, 'utf-8', 'strict')
            require(item.type in (tarfile.REGTYPE, tarfile.AREGTYPE), 'No links or extension headers')
            safe_name(item.name)
            require(0 <= item.size <= MAX_MEMBER, 'Member exceeds size budget')
            return item

        def content(item, keep=False):
            digest = hashlib.sha256(); remaining = item.size; parts = []
            while remaining:
                block = stream.read(min(1048576, remaining))
                require(bool(block), 'Truncated USTAR member')
                remaining -= len(block); digest.update(block)
                if keep:
                    parts.append(block)
            padding = stream.read((-item.size) % 512)
            require(len(padding) == (-item.size) % 512 and not any(padding), 'Invalid member padding')
            return b''.join(parts) if keep else digest.hexdigest()

        first = header()
        require(first is not None and first.name == 'candidate.json' and first.size <= 4 * 1024**2,
                'Bounded first manifest required')
        raw = content(first, keep=True)
        manifest = json.loads(raw)
        require(raw == canonical(manifest), 'Noncanonical/duplicate-key candidate manifest')
        require(manifest['schema'] == SCHEMA and manifest['role'] in ('windows', 'pwa', 'api'),
                'Unknown candidate schema/role')
        require(re.fullmatch('[0-9a-f]{40}', manifest['source_commit']) and
                re.fullmatch('[0-9a-f]{40}', manifest['source_tree']) and
                manifest['source_tree_dirty'] is False, 'Invalid source binding')
        require(manifest['release_eligibility'] == eligibility() and
                manifest['distribution'] == 'SYNTHETIC_REVIEW_ONLY', 'Candidate cannot authorize production')
        rows = manifest['files']
        require(isinstance(rows, list) and 0 < len(rows) <= 10000, 'Bounded file list required')
        expected = {}
        for row in rows:
            name = safe_name(row['path'])
            require(name != 'candidate.json' and name not in expected and
                    type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_MEMBER and
                    re.fullmatch('[0-9a-f]{64}', row['sha256']), 'Invalid/duplicate file declaration')
            expected[name] = row
        seen = set(); total = 0
        while (member := header()) is not None:
            name = member.name
            require(name not in seen and name in expected, 'Unexpected or duplicate member')
            row = expected[name]
            require(member.size == row['bytes'], 'Member length mismatch')
            total += member.size
            require(total <= MAX_TOTAL, 'Expanded candidate too large')
            require(content(member) == row['sha256'], 'Member digest mismatch')
            seen.add(name)
        require(seen == expected.keys(), 'Missing candidate member')
        # Require the second zero header, bounded zero padding and gzip EOF/CRC.
        padding = stream.read(10241)
        require(512 <= len(padding) <= 10240 and not any(padding), 'Unexpected/truncated archive EOF')
    return manifest


def build(role, output):
    require(not git('status', '--porcelain').strip(), 'Refuse dirty source')
    head = git('rev-parse', 'HEAD').decode().strip()
    tree = git('rev-parse', 'HEAD^{tree}').decode().strip()
    output.mkdir(parents=True, exist_ok=True)
    destination = output / ('AnyNote-0.18.0-review-' + role + '-' + head[:12] + '.tar.gz')
    require(not destination.exists() and not (output / (role + '-candidate-report.json')).exists(), 'Fresh candidate output required')
    with tempfile.TemporaryDirectory(prefix='anynote-p18-') as tmp:
        temp = Path(tmp); files = {}; bindings = []
        source = temp / 'source.tar'
        with source.open('xb') as stream:
            subprocess.run(['git', 'archive', '--format=tar', head], cwd=ROOT, stdout=stream, check=True)
        files['source/AnyNote-source.tar'] = source
        # Historical standalone test locks are corresponding source, never executable profiles.
        for name in ['P18_RELEASE.md', 'USER_GUIDE.md', 'OPERATOR_HANDOFF.md', 'KNOWN_LIMITATIONS.md',
                     'P14_UPDATE_SIGNING.md', 'P16_OPERATIONS.md', 'P13_CONTENT.md']:
            files['docs/' + name] = ROOT / 'docs' / name
        if role == 'windows':
            v = report('artifacts/p14/source-report.json', head)
            installer = ROOT / v['installer']['path']
            require(sha(installer) == v['installer']['sha256'] and v['installer']['production_signed'] is False,
                    'Installer must match executed Windows receipt')
            files['windows/' + installer.name] = installer
            res = ROOT / 'apps/desktop/src-tauri/resources'
            for name in ['SOURCE-COMMIT', 'dependency-inventory.json', 'sbom.cdx.json', 'license-index.json',
                         'THIRD-PARTY-NOTICES.txt', 'COPYING-GPL-3.0', 'NODE-LICENSE']:
                files['windows/' + name] = res / name
            require((res / 'SOURCE-COMMIT').read_text().strip() == head, 'Stale installer notices')
            add_tree(files, 'windows/licenses', res / 'licenses')
            bindings = ['artifacts/p14/source-report.json']
        elif role == 'pwa':
            report('artifacts/p15/source-report.json', head)
            static = ROOT / '.local/p06/static/auth'
            require({p.name for p in static.iterdir()} == STATIC, 'Unexpected PWA static output')
            add_tree(files, 'pwa/auth', static)
            bindings = ['artifacts/p15/source-report.json', 'artifacts/p10/browser-report.json']
        else:
            v = report('artifacts/p16/operations-report.json', head)
            require(v['api_image_source']['source_commit'] == head and
                    v['api_image_source']['source_tree_dirty'] is False, 'Stale tested API image')
            image = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', 'anynote-p16-api:synthetic'], text=True).strip()
            require(image == v['api_image_id'], 'Tested image changed')
            target = temp / 'api-image.tar.gz'
            with target.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz:
                process = subprocess.Popen(['docker', 'image', 'save', image], stdout=subprocess.PIPE)
                try:
                    for block in iter(lambda: process.stdout.read(1048576), b''):
                        gz.write(block)
                    require(process.wait() == 0, 'Image save failed')
                finally:
                    process.stdout.close()
                    if process.poll() is None:
                        process.kill(); process.wait()
            files['api/api-image.tar.gz'] = target
            add_tree(files, 'api/deployment', ROOT / 'infra/operations')
            # Recovery uses the corresponding source and frozen npm ci; no private kit bundled.
            files['api/operations.py'] = ROOT / 'scripts/operations.py'
            bindings = ['artifacts/p16/operations-report.json', 'artifacts/p16/operations-source-report.json']
        # Complete lock metadata + available upstream texts for PWA/API; no dependency install here.
        add_notices(files, role, temp)
        for name in bindings:
            files['evidence/' + Path(name).name] = ROOT / name
        manifest = {'schema': SCHEMA, 'version': '0.18.0-review', 'role': role,
                    'source_commit': head, 'source_tree': tree, 'source_tree_dirty': False,
                    'distribution': 'SYNTHETIC_REVIEW_ONLY', 'windows_binary_version': '0.14.0',
                    'signatures': 'UNSIGNED; CI ephemeral updater/static signatures are test evidence only',
                    'source_scope': 'Complete tracked corresponding source including historical test locks; only the maintained Windows product/helper graph is an executable distribution target',
                    'release_eligibility': eligibility()}
        verify_manifest = write_archive(destination, manifest, files)
    receipt = {'purpose': 'P18 exact tested artifact review package; no production release', 'status': 'PASS',
               'role': role, 'source_commit': head, 'source_tree': tree, 'source_tree_dirty': False,
               'candidate': {'path': destination.name, 'sha256': sha(destination), 'bytes': destination.stat().st_size},
               'manifest_sha256': hashlib.sha256(canonical(verify_manifest)).hexdigest(),
               'release_eligibility': eligibility()}
    (output / (role + '-candidate-report.json')).write_bytes(canonical(receipt))
    print(json.dumps(receipt))


def add_notices(files, role, temp):
    if role == 'windows':
        return
    locks = (['packages/protocol/package-lock.json', 'packages/content-browser/package-lock.json']
             if role == 'pwa' else ['apps/api/composer.lock'])
    components = []; texts = []
    for name in locks:
        lock = json.loads((ROOT / name).read_text())
        files['dependencies/' + name.replace('/', '_')] = ROOT / name
        if name.endswith('composer.lock'):
            for p in lock['packages']:
                components.append({'name': p['name'], 'version': p['version'], 'licenses': p.get('license', []), 'source': p.get('source'), 'dist': p.get('dist'), 'scope': 'Composer production lock'})
                texts.append(ROOT / 'apps/api/vendor' / p['name'])
        else:
            for location, p in lock['packages'].items():
                if not location:
                    continue
                components.append({'name': p.get('name', location.rsplit('node_modules/', 1)[-1]), 'version': p['version'], 'license': p.get('license'), 'resolved': p.get('resolved'), 'integrity': p.get('integrity'), 'scope': 'Conservative frozen closure including build and optional platform packages'})
                texts.append((ROOT / name).parent / location)
    for index, base in enumerate(texts):
        if not base.is_dir():
            continue  # Platform-optional absent package is still identified in the lock inventory.
        for p in sorted(base.iterdir()):
            if p.is_file() and re.match(r'^(license|licence|copying|copyright|notice)([._-].*)?$', p.name, re.I):
                files['dependencies/notices/' + str(index) + '/' + p.name] = regular(p)
    inventory = temp / 'dependencies.json'
    inventory.write_bytes(canonical({'scope': 'Frozen metadata and installed upstream notices; not an exact linked-code census or independent legal/security review', 'components': components}))
    files['dependencies/inventory.json'] = inventory
    sbom = temp / 'sbom.cdx.json'
    sbom.write_bytes(canonical({'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                               'metadata': {'component': {'type': 'application', 'name': 'AnyNote ' + role, 'version': '0.18.0-review'}},
                               'components': [{'type': 'library', 'name': c['name'], 'version': c['version']} for c in components]}))
    files['dependencies/sbom.cdx.json'] = sbom


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    build_args = sub.add_parser('build'); build_args.add_argument('role', choices=['windows', 'pwa', 'api']); build_args.add_argument('--output', type=Path, default=ROOT / 'artifacts/p18')
    verify_args = sub.add_parser('verify'); verify_args.add_argument('path', type=Path)
    sub.add_parser('eligibility')
    args = parser.parse_args()
    if args.action == 'build':
        build(args.role, args.output)
    elif args.action == 'verify':
        print(json.dumps({'status': 'VERIFIED', 'manifest': verify(args.path)}))
    else:
        print(json.dumps(eligibility())); return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
