#!/usr/bin/env python3
"""Own the loopback-only P03 synthetic Compose project; never migrate product data."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.local/p03'
PROJECT = 'anynote-p03-' + hashlib.sha256(str(ROOT).encode()).hexdigest()[:10]
PURPOSE = 'AnyNote P03 disposable development services'
ENV = STATE / 'stack.env'


def initialize():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.environ.setdefault('DOCKER_CONFIG', str(STATE / 'docker'))
    # The cloud's public proxy CA is a trust anchor, never a TLS verification bypass.
    certificate = os.environ.get('CODEX_PROXY_CERT')
    if certificate:
        shutil.copyfile(certificate, ROOT / 'infra/dev/php/trust/cloud-proxy.crt')
    marker = STATE / 'owner.json'
    expected = {'purpose': PURPOSE, 'root': str(ROOT), 'project': PROJECT}
    if marker.exists():
        if json.loads(marker.read_text()) != expected or not ENV.is_file():
            raise RuntimeError('Existing state does not belong to this development stack')
        return
    if ENV.exists():
        raise RuntimeError('Refusing to overwrite unmarked environment configuration')
    port = int(os.environ.get('ANYNOTE_DEV_PORT', '18080'))
    if not 1024 <= port <= 65535:
        raise RuntimeError('Development port must be between 1024 and 65535')
    values = {
        'ANYNOTE_DEV_DB_PASSWORD': secrets.token_hex(24),
        'ANYNOTE_DEV_ROOT_PASSWORD': secrets.token_hex(24),
        'ANYNOTE_DEV_APP_KEY': 'base64:' + base64.b64encode(secrets.token_bytes(32)).decode(),
        'ANYNOTE_DEV_UID': os.getuid(), 'ANYNOTE_DEV_GID': os.getgid(),
        'ANYNOTE_DEV_PORT': port,
    }
    with open(ENV, 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as f:
        f.write(''.join(f'{key}={value}\n' for key, value in values.items()))
    marker.write_text(json.dumps(expected) + '\n')


def compose(*args, capture=False):
    command = ['docker', 'compose', '--project-name', PROJECT, '--env-file', str(ENV),
               '-f', str(ROOT / 'infra/dev/compose.yaml'), *args]
    return subprocess.run(command, cwd=ROOT, check=True, text=True,
                          capture_output=capture).stdout


def php(*args, capture=False):
    return compose('run', '--rm', '--no-deps', 'php', *args, capture=capture)


def request(path='/health/ready', host='api.anynote.test'):
    values = dict(line.split('=', 1) for line in ENV.read_text().splitlines())
    req = urllib.request.Request(f'http://127.0.0.1:{values["ANYNOTE_DEV_PORT"]}{path}',
                                 headers={'Host': host, 'Accept': 'application/json'})
    try:
        response = urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as e:
        response = e
    with response:
        headers = {key: ', '.join(response.headers.get_all(key)) for key in response.headers.keys()}
        return response.status, headers, response.read(8192)


def ready():
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            status, _, body = request()
            if status == 200 and json.loads(body) == {'status': 'ready'}:
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.5)
    raise RuntimeError('Nginx -> PHP-FPM -> Laravel -> MariaDB readiness failed')


def test():
    ready()
    required = ['intl', 'mbstring', 'sodium', 'pdo_mysql', 'dom', 'zip']
    extensions = json.loads(php('php', '-r', 'echo json_encode(get_loaded_extensions());', capture=True))
    assert all(name in extensions for name in required), 'Native PHP extensions must be loaded'
    php('composer', 'validate', '--strict', '--no-check-publish')
    php('composer', 'check-platform-reqs')
    php('composer', 'audit', '--locked', '--no-interaction')
    php('php', '-l', 'app/Generated/Dtos.php')
    php('composer', 'lint')
    php('composer', 'test')
    transaction = json.loads(php('php', 'artisan', 'foundation:check', capture=True))
    assert transaction['status'] == 'PASS'
    status, headers, body = request()
    assert status == 200 and json.loads(body) == {'status': 'ready'}
    assert 'no-store' in headers.get('Cache-Control', '').split(', ')
    assert headers.get('X-Content-Type-Options') == 'nosniff'
    assert not any(name.lower() == 'x-powered-by' for name in headers)
    path_denials = {}
    for path in ['/login', '/.env', '/composer.json', '/vendor/autoload.php',
                 '/storage/logs/laravel.log', '/other.php', '/%2e%2e/composer.json']:
        path_denials[path] = request(path)[0]
        assert path_denials[path] in [400, 403, 404], path
    assert request(host='unexpected.anynote.test')[0] == 404
    assert request(host='app.anynote.test')[0] == 404
    assert request('/index.php', host='app.anynote.test')[0] == 404
    assert request('/', host='app.anynote.test')[0] == 200
    for service in ['db', 'php']:
        container = compose('ps', '-q', service, capture=True).strip()
        bindings = subprocess.check_output(['docker', 'inspect', '--format',
                                            '{{json .HostConfig.PortBindings}}', container], text=True)
        assert not json.loads(bindings), f'{service} must not publish a host port'
    nginx_id = compose('ps', '-q', 'nginx', capture=True).strip()
    bindings = json.loads(subprocess.check_output(['docker', 'inspect', '--format',
                                                  '{{json .HostConfig.PortBindings}}', nginx_id], text=True))
    assert set(bindings) == {'8080/tcp'}
    assert all(item['HostIp'] == '127.0.0.1' for item in bindings['8080/tcp'])
    for service in ['php', 'nginx']:
        container = compose('ps', '-q', service, capture=True).strip()
        user = subprocess.check_output(['docker', 'inspect', '--format',
                                       '{{.Config.User}}', container], text=True).strip().split(':')[0]
        assert user not in ['', '0', 'root'], f'{service} must run as an unprivileged user'
    compose('stop', 'db', capture=True)
    try:
        status, _, body = request()
        assert status == 503 and json.loads(body) == {'status': 'unavailable'}
    finally:
        compose('up', '-d', '--wait', 'db', capture=True)
    ready()
    visible = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others',
                                       '--exclude-standard'], cwd=ROOT).decode().split('\0')
    prefixes = ('apps/api/', 'infra/dev/', 'scripts/dev-stack.py', 'scripts/api-inventory.py',
                'scripts/install-p03-tools.py', 'scripts/check-secrets.py',
                '.gitleaks.toml', '.github/workflows/foundation.yml', 'packages/contracts/generated/',
                'packages/contracts/p03-', 'packages/api-client/', 'scripts/p03-', 'scripts/check-p03-')
    source_inputs = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                     for p in sorted(set(visible)) if p.startswith(prefixes) and (ROOT / p).is_file()}
    versions = {
        'php': php('php', '-r', 'echo PHP_VERSION;', capture=True).strip(),
        'composer': php('composer', '--version', '--no-ansi', capture=True).strip(),
        'mariadb': transaction['database'],
        'nginx': subprocess.check_output(['docker', 'exec', nginx_id, 'nginx', '-v'],
                                         stderr=subprocess.STDOUT, text=True).strip(),
    }
    pins = json.loads((ROOT / 'infra/dev/versions.json').read_text())
    assert versions['php'] == pins['php']
    assert f'Composer version {pins["composer"]} ' in versions['composer']
    assert versions['mariadb'].startswith(pins['mariadb'] + '-MariaDB')
    assert versions['nginx'] == f'nginx version: nginx/{pins["nginx"]}'
    report = {
        'purpose': PURPOSE, 'environment_kind': 'development_host',
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'source_tree_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
        'foundation_input_sha256': source_inputs,
        'runtime_versions': versions,
        'required_native_extensions_loaded': required,
        'status': 'PASS', 'transaction': transaction,
        'http_database_readiness': 'PASS', 'static_api_separation': 'PASS',
        'private_path_and_unknown_host_denial': 'PASS', 'database_outage_503_and_recovery': 'PASS',
        'path_denial_statuses': path_denials,
        'loopback_only_bindings': 'PASS',
        'production_tooling_denial': 'PASS', 'schema': 'NO PRODUCT TABLES',
        'physical_acceptance': False,
        'limits': ['Development foundation only; no account, wire contract, content crypto or production deployment'],
    }
    output = ROOT / 'artifacts/p03/foundation-report.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: foundation transactions, HTTP/database outage, origin/path isolation and production denial')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['install', 'up', 'check', 'test', 'stop'])
    operation = parser.parse_args().operation
    initialize()
    if operation == 'install':
        if not (ROOT / 'apps/api/composer.lock').is_file():
            raise RuntimeError('Frozen composer.lock is required; setup never resolves dependencies')
        for name in ['bootstrap/cache', 'storage/framework/cache/data', 'storage/framework/sessions',
                     'storage/framework/views', 'storage/logs']:
            (ROOT / 'apps/api' / name).mkdir(parents=True, exist_ok=True)
        compose('build', 'php')
        php('composer', 'install', '--no-interaction', '--prefer-dist', '--no-progress')
        php('composer', 'check-platform-reqs')
    elif operation == 'up':
        example = ROOT / 'apps/api/.env.example'
        local_env = ROOT / 'apps/api/.env'
        if not local_env.exists():
            shutil.copyfile(example, local_env)
        compose('up', '-d', '--wait', '--wait-timeout', '60')
        ready()
        print('PASS: owned loopback development stack is ready')
    elif operation == 'check':
        ready()
        print('PASS: Nginx -> PHP-FPM -> Laravel -> MariaDB')
    elif operation == 'test':
        previous = ROOT / 'artifacts/p03/foundation-report.json'
        if previous.exists():
            if json.loads(previous.read_text()).get('purpose') != PURPOSE:
                raise RuntimeError('Refusing to replace an unowned report')
            previous.unlink()
        test()
    elif operation == 'stop':
        # Preserve this project's disposable DB volume; never prune other resources.
        compose('down')


if __name__ == '__main__':
    main()
