#!/usr/bin/env python3
"""Actual frozen vendor build-script signature-before-ZIP-extraction checks."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile
import tarfile
import tomllib
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
NAME = 'libsodium-1.0.22-stable-msvc.zip'
lock = tomllib.loads((ROOT / 'packages/windows-native/Cargo.lock').read_text())
assert [p['version'] for p in lock['package'] if p['name'] == 'libsodium-sys-stable'] == ['1.24.3']
suffix = '.exe' if sys.platform == 'win32' else ''
candidates = list((ROOT / 'packages/windows-native/target/release/build').glob('libsodium-sys-stable-*/build-script-build' + suffix))
assert candidates, 'Build the actual locked native release driver first'
builder = max(candidates, key=lambda p: p.stat().st_mtime_ns)


def retrieve(name, cap):
    with urllib.request.urlopen('https://download.libsodium.org/libsodium/releases/' + name, timeout=60) as response:
        raw = response.read(cap + 1)
    assert len(raw) <= cap
    return raw


archive = retrieve(NAME, 67108864)
signature = retrieve(NAME + '.minisig', 4096)
# Validate the public positive fixture before asking the vulnerable upstream
# extractor to process it. No archive is extracted by this Python preflight.
with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
    total = 0
    for member in bundle.infolist():
        path = PurePosixPath(member.filename)
        assert not path.is_absolute() and '..' not in path.parts and '\\' not in member.filename and ':' not in member.filename
        mode = member.external_attr >> 16
        assert not stat.S_ISLNK(mode) and not mode & 0o7000
        total += member.file_size
    assert total <= 536870912 and len(bundle.infolist()) <= 10000

results = []
with tempfile.TemporaryDirectory(prefix='anynote-vendor-signature-') as scratch:
    base = Path(scratch)
    metadata=json.loads(subprocess.check_output(['cargo','metadata','--manifest-path',str(ROOT/'packages/windows-native/Cargo.toml'),'--locked','--format-version','1'],cwd=ROOT))
    package=next(p for p in metadata['packages']if p['name']=='libsodium-sys-stable'and p['version']=='1.24.3')
    crate=Path(package['manifest_path']).parent
    build_source=(crate/'build.rs').read_text()
    package_lock=next(p for p in lock['package'] if p['name']=='libsodium-sys-stable')
    crate_archive=crate.parents[2]/'cache'/crate.parent.name/(crate.name+'.crate')
    crate_bytes=crate_archive.read_bytes();assert hashlib.sha256(crate_bytes).hexdigest()==package_lock['checksum']
    with tarfile.open(fileobj=io.BytesIO(crate_bytes),mode='r:gz') as bundle:
        assert bundle.extractfile(crate.name+'/build.rs').read()==build_source.encode()
    assert build_source.count('fn main() {')==1
    # Keep every upstream function unchanged; select its ZIP entry directly
    # instead of letting the original main first try a source-tarball build.
    driver=build_source.replace('fn main() {','fn preserved_upstream_main() {')+'\nfn main(){extract_libsodium_precompiled_msvc("x64",std::path::Path::new("source"),&std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("installed"));}\n'
    source_path=base/'vendor-driver.rs';source_path.write_text(driver)
    libraries=ROOT/'packages/windows-native/target/release/deps'
    builder=base/('vendor-driver'+suffix)
    command=['rustc','--edition=2021','--crate-name','anynote_vendor_signature_boundary',str(source_path),'-L','dependency='+str(libraries),'-o',str(builder)]
    dependency_versions=[]
    for name in ['cc','libflate','minisign_verify','pkg_config','tar','ureq','vcpkg','zip']:
        cargo_name=name.replace('_','-')
        reference=next(d for d in package_lock['dependencies'] if d.split()[0]==cargo_name)
        version=reference.split()[1] if ' ' in reference else next(p['version'] for p in lock['package'] if p['name']==cargo_name)
        matches=[]
        for library in libraries.glob('lib'+name+'-*.rlib'):
            depfile=libraries/(library.name.removeprefix('lib').removesuffix('.rlib')+'.d')
            if depfile.is_file() and '/'+cargo_name+'-'+version+'/' in depfile.read_text().replace('\\','/'):
                matches.append(library)
        assert matches,(name,version)
        dependency_versions.append({'name':cargo_name,'version':version})
        command+=['--extern',name+'='+str(max(matches,key=lambda p:p.stat().st_mtime_ns))]
    compiled=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=120)
    assert compiled.returncode==0,compiled.stderr.decode(errors='replace')[-1500:]
    builder_sha256=hashlib.sha256(builder.read_bytes()).hexdigest()
    driver_sha256=hashlib.sha256(driver.encode()).hexdigest()
    source_sha256=hashlib.sha256(build_source.encode()).hexdigest()
    for label, payload in [('authentic', archive), ('tampered', bytes([archive[0] ^ 1]) + archive[1:])]:
        work = base / label; work.mkdir()
        dist = work / 'dist'; dist.mkdir()
        output = work / 'out'; output.mkdir()
        (dist / NAME).write_bytes(payload)
        (dist / (NAME + '.minisig')).write_bytes(signature)
        environment = {k: v for k, v in os.environ.items() if not k.startswith('SODIUM_')}
        environment.update({'SODIUM_DIST_DIR': str(dist), 'OUT_DIR': str(output),
                            'TARGET': 'x86_64-pc-windows-msvc', 'HOST': 'x86_64-pc-windows-msvc',
                            'PROFILE': 'release', 'NUM_JOBS': '1'})
        result = subprocess.run([str(builder)], cwd=work, env=environment, capture_output=True, timeout=60)
        installed = list((output / 'installed').rglob('*')) if (output / 'installed').exists() else []
        if label == 'authentic':
            assert result.returncode == 0 and any(p.suffix.lower() == '.lib' for p in installed), result.stderr.decode(errors='replace')[-1000:]
        else:
            assert result.returncode != 0 and b'Invalid signature' in result.stderr and not installed
        results.append({'case': label, 'status': 'PASS', 'exit_code': result.returncode,
                        'installed_files': sum(p.is_file() for p in installed),
                        'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
                        'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()})
git = lambda *args: subprocess.check_output(['git', *args], cwd=ROOT).decode().strip()
report = {'purpose': 'Actual locked libsodium vendor build script authenticates before ZIP extraction',
          'status': 'PASS', 'source_commit': git('rev-parse', 'HEAD'), 'source_tree_dirty': bool(git('status', '--porcelain')),
          'platform': sys.platform, 'target': 'x86_64-pc-windows-msvc', 'builder_sha256': builder_sha256, 'upstream_build_source_sha256':source_sha256, 'driver_source_sha256':driver_sha256,
          'driver_scope':'Unchanged upstream build functions; original main renamed and a direct MSVC ZIP entry driver added',
          'locked_build_dependencies':dependency_versions,
          'vendor_archive_sha256': hashlib.sha256(archive).hexdigest(), 'vendor_signature_sha256': hashlib.sha256(signature).hexdigest(),
          'cases': results, 'untrusted_extraction_before_verification': False,
          'upstream_zip_fixed': False, 'production_release_allowed': False, 'independent_review': 'NOT_RUN'}
destination = ROOT / 'artifacts/p14/signed-vendor-zip-development.json'; destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
