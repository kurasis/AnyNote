#!/usr/bin/env python3
"""Additive synthetic production-template staging; never touches retained P03/P06."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('operations',ROOT/'scripts/operations.py')
ops=importlib.util.module_from_spec(spec);spec.loader.exec_module(ops)
STATE=ROOT/'.local/p16'


def initialize(name='source',port=19443,image=None):
    if not re.fullmatch(r'(?:source|fault|capacity|restore-[0-9]{12}|fresh-[0-9]{12})',name):
        raise ValueError('Owned synthetic target required')
    target=STATE/name;target.mkdir(parents=True,exist_ok=True,mode=0o700)
    marker={'purpose':'AnyNote P16 synthetic staging only','checkout':str(ROOT),'name':name}
    owner=target/'owner.json'
    if owner.exists():
        if json.loads(owner.read_text())!=marker:raise ValueError('Unowned target')
        return target
    if any(target.iterdir()):raise ValueError('Refusing preexisting unmarked target')
    owner.write_text(json.dumps(marker)+'\n')
    for directory in ['secrets','tls','storage/app/private','storage/app/private/p16-delivery','storage/framework/cache/data','storage/framework/sessions','storage/framework/views','storage/logs','database']:
        (target/directory).mkdir(parents=True,exist_ok=True,mode=0o700)
    secret=target/'secrets'
    for file,value in [('database_password',secrets.token_hex(32)),('database_root',secrets.token_hex(32)),('app_key','base64:'+base64.b64encode(secrets.token_bytes(32)).decode())]:
        (secret/file).write_text(value);(secret/file).chmod(0o600)
    def openssl(*args):return ops.run(['openssl',*args])
    openssl('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',secret/'oauth_private')
    openssl('pkey','-in',secret/'oauth_private','-pubout','-out',secret/'oauth_public')
    tls=target/'tls'
    openssl('req','-x509','-newkey','rsa:3072','-nodes','-keyout',tls/'ca.key','-out',tls/'ca.crt','-days','10','-subj','/CN=AnyNote P16 synthetic CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
    openssl('req','-newkey','rsa:3072','-nodes','-keyout',tls/'server.key','-out',tls/'server.csr','-subj','/CN=api.anynote.test')
    (tls/'extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:api.anynote.test,DNS:app.anynote.test\n')
    openssl('x509','-req','-in',tls/'server.csr','-CA',tls/'ca.crt','-CAkey',tls/'ca.key','-CAcreateserial','-out',tls/'server.crt','-days','7','-extfile',tls/'extensions')
    for path in [tls/'ca.key',tls/'server.key',secret/'oauth_private']:path.chmod(0o600)
    custody=STATE/'offline-operator';custody.mkdir(exist_ok=True,mode=0o700)
    if not (custody/'backup.identity').exists():
        identity=ops.run([ROOT/'.local/p02-tools/age-keygen']);(custody/'backup.identity').write_bytes(identity);(custody/'backup.identity').chmod(0o600)
        openssl('genpkey','-algorithm','ED25519','-out',custody/'backup-signing.pem')
        openssl('pkey','-in',custody/'backup-signing.pem','-pubout','-out',custody/'backup-verification.pem')
        (custody/'backup-signing.pem').chmod(0o600)
    recipient=ops.run([ROOT/'.local/p02-tools/age-keygen','-y',custody/'backup.identity']).decode().strip()
    static=target/'static';static.mkdir(exist_ok=True,mode=0o755)
    api=f'https://api.anynote.test:{port}';app=f'https://app.anynote.test:{port}'
    values={'ANYNOTE_PROJECT':'anynote-p16-'+hashlib.sha256(str(ROOT).encode()).hexdigest()[:8]+'-'+name,'ANYNOTE_DEPLOY_ROOT':target,'ANYNOTE_STATIC_ROOT':static,'ANYNOTE_API_IMAGE':image or 'anynote-p16-api:synthetic','ANYNOTE_UID':os.getuid(),'ANYNOTE_GID':os.getgid(),'ANYNOTE_HTTPS_PORT':port,'ANYNOTE_APP_ORIGIN':app,'ANYNOTE_API_ISSUER':api,'ANYNOTE_RP_ID':'app.anynote.test','ANYNOTE_SERVICE_ID':base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip('=') if name.startswith('fresh-') else 'AAAAAAAAAAAAAAAAAAAAAQ','ANYNOTE_AGE':ROOT/'.local/p02-tools/age','ANYNOTE_BACKUP_RECIPIENT':recipient}
    (target/'environment').write_text(''.join(f'{k}={v}\n' for k,v in values.items()))
    (target/'environment').chmod(0o600)
    return target


def render(target):
    return ops.render(ops.Environment(target/'environment'))


def build():
    # Copy an allowlist, not the checkout: .env, storage, OAuth/TLS, test sources
    # and user profiles cannot enter a runtime image/build layer.
    with tempfile.TemporaryDirectory(prefix='anynote-p16-image-') as tmp:
        ctx=Path(tmp);api=ctx/'rootfs/app';api.mkdir(parents=True)
        for name in ['app','bootstrap','config','public','routes','vendor']:
            shutil.copytree(ROOT/'apps/api'/name,api/name,ignore=shutil.ignore_patterns('cache') if name=='bootstrap' else None)
        for name in ['artisan','composer.json','composer.lock']:shutil.copyfile(ROOT/'apps/api'/name,api/name)
        for name in ['database/migrations','storage/framework/cache/data','storage/framework/sessions','storage/framework/views','storage/logs','storage/app/private','bootstrap/cache']:(api/name).mkdir(parents=True,exist_ok=True)
        shutil.copytree(ROOT/'apps/api/database/migrations',api/'database/migrations',dirs_exist_ok=True)
        provenance={'source_commit':ops.run(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip(),'source_tree_dirty':bool(ops.run(['git','status','--porcelain'],cwd=ROOT).strip()),'inputs':[{'path':str(p.relative_to(ctx)),'sha256':ops.digest(p)} for p in sorted(api.rglob('*')) if p.is_file() and 'vendor' not in p.parts]}
        (api/'release-inputs.json').write_text(json.dumps(provenance,sort_keys=True))
        shutil.copyfile(ROOT/'infra/operations/Dockerfile',ctx/'Dockerfile')
        for source,destination in [('runtime.sh','opt/anynote/runtime.sh'),('php.ini','usr/local/etc/php/conf.d/zz-operations.ini'),('pool.conf','usr/local/etc/php-fpm.d/zz-operations.conf')]:
            path=ctx/'rootfs'/destination;path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/'infra/operations'/source,path)
        # Frozen existing vendor, supported Composer --no-dev removes test deps
        # in the disposable context, never the development checkout.
        ops.run(['docker','run','--rm','--user',f'{os.getuid()}:{os.getgid()}','-v',f'{api}:/app','--entrypoint','composer','anynote-p03-php:8.4.26','install','--no-dev','--no-scripts','--no-interaction','--prefer-dist','--no-progress'])
        ops.run(['docker','build','--tag','anynote-p16-api:synthetic',ctx])
    return ops.run(['docker','image','inspect','--format','{{.Id}}','anynote-p16-api:synthetic']).decode().strip()


def up(target):
    render(target)
    env=ops.Environment(target/'environment')
    env.compose('up','-d','--wait','db')
    env.compose('run','--rm','--no-deps','-T','-v',str(env.state/'secrets/database_root')+':/run/secrets/database_root:ro','--entrypoint','sh','api','-c','export APP_KEY="$(cat /run/secrets/app_key)" DB_PASSWORD="$(cat /run/secrets/database_root)" DB_USERNAME=root; exec php artisan migrate --force --no-interaction')
    # DDL is an operator task. Runtime receives no CREATE/ALTER/DROP/GRANT.
    env.sql("REVOKE ALL PRIVILEGES ON anynote.* FROM 'anynote_runtime'@'%'; GRANT SELECT, INSERT, UPDATE, DELETE ON anynote.* TO 'anynote_runtime'@'%';")
    build_env=os.environ.copy();build_env.update(ANYNOTE_API_ISSUER=env.values['ANYNOTE_API_ISSUER'],ANYNOTE_STATIC_OUTPUT=str(Path(env.values['ANYNOTE_STATIC_ROOT'])/'auth'),ANYNOTE_STATIC_WORK=str(target/'static-build-work'),ANYNOTE_STATIC_POLICY=str(target/'nginx.conf'))
    subprocess.run(['node','experiments/p01/p06-build.mjs'],cwd=ROOT,env=build_env,check=True,stdout=subprocess.DEVNULL)
    env.compose('up','-d','api','queue','scheduler','edge')
    env.compose('exec','-T','edge','nginx','-t')
    return {'status':'PASS','purpose':'isolated synthetic staging','database_public':False,'runtime_ddl_privileges':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['build','up','check','stop','prepare']);p.add_argument('--name',default='source');p.add_argument('--port',type=int,default=19443);a=p.parse_args()
    if a.operation=='build':
        image=build();target=initialize(image=image)
        envfile=target/'environment';text=envfile.read_text();text='\n'.join('ANYNOTE_API_IMAGE='+image if line.startswith('ANYNOTE_API_IMAGE=') else line for line in text.splitlines())+'\n';envfile.write_text(text)
        print(json.dumps({'status':'PASS','image_id':image}));return
    target=initialize(a.name,a.port)
    env=ops.Environment(target/'environment')
    if a.operation=='up':print(json.dumps(up(target)))
    elif a.operation=='check':print(env.php('operations:health'))
    elif a.operation=='stop':env.compose('stop','edge','api','queue','scheduler','db');print('Stopped only owned P16 services; state retained')
    else:print(json.dumps({'status':'PASS','target':str(target)}))


if __name__=='__main__':main()
