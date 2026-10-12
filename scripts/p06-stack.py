#!/usr/bin/env python3
"""Owned disposable P06 TLS/SQL stack. No production keys, data or migrations."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.local/p06'
PURPOSE = 'AnyNote P06 disposable TLS authentication stack'
OWNER = hashlib.sha256((PURPOSE + str(ROOT)).encode()).hexdigest()
spec = importlib.util.spec_from_file_location('p06_owned_base', ROOT / 'scripts/dev-stack.py')
stack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stack)


def compose(*args, capture=False):
    result = subprocess.run(['docker', 'compose', '--project-name', stack.PROJECT,
                             '--env-file', str(stack.ENV), '-f', str(ROOT / 'infra/dev/compose.yaml'),
                             '-f', str(ROOT / 'infra/dev/p06-compose.yaml'), *args],
                            cwd=ROOT, check=False, text=True, capture_output=capture)
    if result.returncode:
        # A CalledProcessError traceback would serialize command-line owner/env values.
        raise SystemExit(f'Owned P06 command failed (exit {result.returncode}); private arguments omitted')
    return result.stdout


def sql(text):
    return subprocess.run(['docker', 'compose', '--project-name', stack.PROJECT, '--env-file', str(stack.ENV),
                           '-f', str(ROOT / 'infra/dev/compose.yaml'), 'exec', '-T', 'db', 'sh', '-c',
                           'exec mariadb --user=root --password="$MARIADB_ROOT_PASSWORD" --batch --skip-column-names'],
                          input=text, text=True, capture_output=True, check=True).stdout.strip()


def php(*args, capture=False):
    return compose('run', '--rm', '--no-deps', '-e', 'ANYNOTE_P06_TEST_OWNER=' + OWNER,
                   'auth-php', *args, capture=capture)


def initialize():
    stack.initialize()
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = STATE / 'owner.json'
    expected = {'purpose': PURPOSE, 'root': str(ROOT), 'owner': OWNER}
    if marker.exists():
        if json.loads(marker.read_text()) != expected:
            raise RuntimeError('Unowned authentication state')
        return
    if any((STATE / n).exists() for n in ['tls', 'oauth']):
        raise RuntimeError('Unmarked authentication secrets')
    marker.write_text(json.dumps(expected) + '\n')
    for n in ['tls', 'oauth']:
        (STATE / n).mkdir(mode=0o700)
    tls = STATE / 'tls'
    def openssl(*args):
        subprocess.run(['openssl', *args], check=True, capture_output=True)
    openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-keyout', str(tls / 'ca.key'),
            '-out', str(tls / 'ca.crt'), '-days', '30', '-subj', '/CN=AnyNote P06 disposable test CA',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    openssl('req', '-newkey', 'rsa:3072', '-nodes', '-keyout', str(tls / 'server.key'),
            '-out', str(tls / 'server.csr'), '-subj', '/CN=app.anynote.test')
    (tls / 'extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:app.anynote.test,DNS:api.anynote.test\n')
    openssl('x509', '-req', '-in', str(tls / 'server.csr'), '-CA', str(tls / 'ca.crt'),
            '-CAkey', str(tls / 'ca.key'), '-CAcreateserial', '-out', str(tls / 'server.crt'),
            '-days', '20', '-extfile', str(tls / 'extensions'))
    openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(STATE / 'oauth/private.pem'))
    openssl('pkey', '-in', str(STATE / 'oauth/private.pem'), '-pubout', '-out', str(STATE / 'oauth/public.pem'))
    for p in [tls / 'ca.key', tls / 'server.key', STATE / 'oauth/private.pem']:
        p.chmod(0o600)


def database(reset=False):
    exists = sql("SHOW DATABASES LIKE 'anynote_p06_tests';")
    if exists:
        if sql('SELECT owner FROM anynote_p06_tests.p06_test_owner;') != OWNER:
            raise RuntimeError('Refusing an unowned database')
        if not reset:
            # Only this owner-marked synthetic database: additive migrations preserve rows.
            php('php', 'artisan', 'migrate', '--no-interaction')
            return
        sql('DROP DATABASE anynote_p06_tests;')
    sql("CREATE DATABASE anynote_p06_tests CHARACTER SET ascii COLLATE ascii_bin; CREATE TABLE anynote_p06_tests.p06_test_owner (owner CHAR(64) NOT NULL PRIMARY KEY) ENGINE=InnoDB; INSERT INTO anynote_p06_tests.p06_test_owner VALUES ('" + OWNER + "'); GRANT ALL ON anynote_p06_tests.* TO 'anynote_dev'@'%';")
    php('php', 'artisan', 'migrate', '--no-interaction')


def main():
    operation = argparse.ArgumentParser(description=__doc__)
    operation.add_argument('operation', choices=['up', 'reset', 'check', 'stop', 'control'])
    operation.add_argument('arguments', nargs='*')
    args = operation.parse_args()
    initialize()
    if args.operation in ['up', 'reset']:
        stack.compose('up', '-d', '--wait', 'db', capture=True)
        database(args.operation == 'reset')
        subprocess.run(['node', str(ROOT / 'experiments/p01/p06-build.mjs')], cwd=ROOT, check=True)
        compose('up', '-d', 'auth-php', 'auth-nginx', capture=True)
        php('php', 'tests/Support/p06-control.php', 'ready')
        ready()
    elif args.operation == 'check':
        php('php', 'tests/Support/p06-control.php', 'ready')
        ready()
    elif args.operation == 'stop':
        compose('stop', 'auth-nginx', 'auth-php', capture=True)
    else:
        print(php('php', 'tests/Support/p06-control.php', *args.arguments, capture=True).strip())


def ready():
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = subprocess.run(['node', str(ROOT / 'experiments/p01/p06-ready.mjs')], cwd=ROOT, capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout.strip())
            return
        time.sleep(0.5)
    raise RuntimeError('Actual P06 HTTPS/session readiness failed')


if __name__ == '__main__':
    main()
