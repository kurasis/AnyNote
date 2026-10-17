#!/usr/bin/env python3
"""Recheck exact ZIP call-site boundaries; not an upstream fix or release waiver."""
import hashlib
import io
from pathlib import Path
import tarfile
import tomllib


def review(root, metadata):
    packages = {p['id']: p for p in metadata['packages']}
    nodes = {n['id']: n for n in metadata['resolve']['nodes']}
    checksums = {}
    for lock in root.rglob('Cargo.lock'):
        if any(p in lock.parts for p in ['target', 'node_modules', '.local']):
            continue
        for p in tomllib.loads(lock.read_text())['package']:
            if p.get('source') == 'registry+https://github.com/rust-lang/crates.io-index':
                key = (p['name'], p['version'])
                assert key not in checksums or checksums[key] == p['checksum']
                checksums[key] = p['checksum']
    proofs = []

    def source(package, relative):
        directory = Path(package['manifest_path']).parent
        archive = directory.parents[2] / 'cache' / directory.parent.name / (directory.name + '.crate')
        raw = archive.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        assert digest == checksums[(package['name'], package['version'])]
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as bundle:
            member = bundle.getmember(directory.name + '/' + relative)
            assert member.isfile() and member.size <= 4194304
            original = bundle.extractfile(member).read()
        assert (directory / relative).read_bytes() == original, 'Registry source differs from frozen crate'
        proofs.append({'package': package['name'], 'version': package['version'],
                       'crate_sha256': digest, 'member': relative,
                       'member_sha256': hashlib.sha256(original).hexdigest()})
        return original.decode()

    root_id = metadata['resolve']['root']
    runtime, todo = set(), [root_id]
    while todo:
        ident = todo.pop()
        if ident in runtime:
            continue
        runtime.add(ident)
        todo.extend(d['pkg'] for d in nodes[ident]['deps'] if any(k['kind'] is None for k in d['dep_kinds']))
    zip_ids = {ident for ident in nodes if packages[ident]['name'] == 'zip'}
    assert {packages[i]['version'] for i in zip_ids} == {'4.6.1', '8.6.0'}
    assert [(packages[i]['name'], packages[i]['version']) for i in zip_ids & runtime] == [('zip', '4.6.1')]
    incoming = []
    for parent, node in nodes.items():
        for dependency in node['deps']:
            if dependency['pkg'] in zip_ids:
                incoming.append({'parent': packages[parent]['name'], 'parent_version': packages[parent]['version'],
                                 'zip_version': packages[dependency['pkg']]['version'], 'kinds': [d['kind'] for d in dependency['dep_kinds']]})
                if packages[dependency['pkg']]['version'] == '8.6.0':
                    assert packages[parent]['name'] == 'libsodium-sys-stable' and packages[parent]['version'] == '1.24.3'
                    assert all(d['kind'] == 'build' for d in dependency['dep_kinds'])
                else:
                    assert packages[parent]['name'] == 'tauri-plugin-updater' and packages[parent]['version'] == '2.13.3'

    updater = next(p for p in packages.values() if p['name'] == 'tauri-plugin-updater')
    dispatch = source(updater, 'src/updater.rs')
    assert 'if infer::archive::is_zip(bytes)' in dispatch and 'return self.extract_zip(bytes)' in dispatch
    assert 'extractor.extract(&temp_dir)?' in dispatch
    infer = next(p for p in packages.values() if p['name'] == 'infer')
    detection = source(infer, 'src/matchers/archive.rs').split('pub fn is_zip', 1)[1].split('\n}', 1)[0]
    assert 'buf[0] == 0x50' in detection and 'buf[1] == 0x4B' in detection
    host = (root / 'apps/desktop/src-tauri/src/main.rs').read_text()
    guard = 'anynote_windows_native::updates::UpdatePolicy::windows_installer(&bytes)'
    assert host.index('hash(&bytes) != claims.artifact_sha256') < host.index(guard) < host.index('next.install(bytes)')
    policy = (root / 'packages/windows-native/src/updates.rs').read_text()
    assert 'bytes.starts_with(b"MZ")' in policy and 'Some(b"PE\\0\\0")' in policy
    assert 'offset >= 64' in policy and 'offset.saturating_add(4)' in policy
    # Both supported vendor build profiles authenticate the whole archive before
    # ZipArchive::extract. This does not classify arbitrary signed user ZIPs safe.
    vendor_versions = []
    for directory in sorted(Path(updater['manifest_path']).parent.parent.glob('libsodium-sys-stable-*')):
        version = directory.name.removeprefix('libsodium-sys-stable-')
        if version not in ['1.24.1', '1.24.3']:
            continue
        package = {'name': 'libsodium-sys-stable', 'version': version, 'manifest_path': str(directory / 'Cargo.toml')}
        build = source(package, 'build.rs')
        extract = build.split('fn extract_libsodium_precompiled_msvc', 1)[1].split('\n}', 1)[0]
        assert extract.index('retrieve_and_verify_archive(') < extract.index('archive.extract(')
        retrieve = build.split('fn retrieve_and_verify_archive', 1)[1].split('\n}', 1)[0]
        assert retrieve.count('pk.verify(&archive_bin, &signature, false)') == 2
        assert retrieve.count('.expect("Invalid signature")') == 2
        assert 'PublicKey::from_base64(' in retrieve
        vendor_versions.append(version)
    assert '1.24.3' in vendor_versions
    return {'purpose': 'Exact frozen ZIP dependency paths and authenticated input dispatch; AI engineering review only',
            'status': 'PASS', 'supported_target': 'x86_64-pc-windows-msvc', 'incoming_edges': incoming,
            'runtime_zip_4_dispatch': 'Signed and hash-bound PE-only policy precedes Tauri dispatch; MZ and PK prefixes are disjoint',
            'build_zip_8_dispatch': 'Build dependency only; complete vendor archive is verified against the pinned minisign key before extraction',
            'vendor_build_profiles_checked': vendor_versions, 'registry_source_proofs': proofs,
            'upstream_vulnerable_versions_remain': True, 'upstream_fixed_version': '9.0.0',
            'production_release_allowed': False, 'independent_review': 'NOT_RUN',
            'limitations': ['Not an upstream ZIP fix; no blanket exclusion for new versions or advisories',
                            'Signed ZIP updates are explicitly unsupported, including otherwise valid publisher signatures',
                            'Vendor signing authority and build environment compromise require independent supply-chain review',
                            'New targets, archive inputs or disabled signature/PE checks invalidate this disposition']}
