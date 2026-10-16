#!/usr/bin/env python3
"""Offline, signed age backup/restore. Explicit external environment; no live restore."""
import argparse
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
WRITERS = ('api', 'queue', 'scheduler')


def run(args, **kw):
    if str(args[0])=='docker':
        os.environ.setdefault('DOCKER_CONFIG',str(ROOT/'.local/operations-docker'))
        Path(os.environ['DOCKER_CONFIG']).mkdir(parents=True,exist_ok=True,mode=0o700)
    result = subprocess.run(list(map(str, args)), capture_output=True, **kw)
    if result.returncode:
        failures=ROOT/'.local/operations-failures'
        failures.mkdir(parents=True,exist_ok=True,mode=0o700)
        log=failures/('failure-'+str(time.time_ns())+'.log')
        log.write_bytes((result.stderr or b'')+(result.stdout or b''))
        log.chmod(0o600)
        raise RuntimeError(f'{Path(str(args[0])).name} failed ({result.returncode}); private arguments/output omitted')
    return result.stdout


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1048576), b''):
            h.update(b)
    return h.hexdigest()


def durable(path):
    with path.open('rb') as f:
        os.fsync(f.fileno())


def durable_directory(path):
    descriptor=os.open(path,os.O_RDONLY)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


def publish(path, target):
    durable(path)
    # Link is an atomic no-replace publication on the same backup filesystem.
    os.link(path, target)
    path.unlink()
    descriptor=os.open(target.parent,os.O_RDONLY)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


class Environment:
    def __init__(self, path):
        self.path = Path(path).resolve(strict=True)
        self.values = dict(line.split('=', 1) for line in self.path.read_text().splitlines() if line and not line.startswith('#'))
        self.state = Path(self.values['ANYNOTE_DEPLOY_ROOT']).resolve(strict=True)
        self.project = self.values['ANYNOTE_PROJECT']
        if not re.fullmatch(r'anynote-[a-z0-9-]{3,64}', self.project):
            raise ValueError('Explicit scoped Compose project required')
        self.command = ['docker', 'compose', '--project-name', self.project, '--env-file', self.path, '-f', ROOT/'infra/operations/compose.yaml']

    def compose(self, *args, **kw):
        return run([*self.command, *args], **kw)

    def php(self, *args):
        return self.compose('run', '--rm', '--no-deps', '-T', 'api', 'php', 'artisan', *args).decode().strip()

    def sql(self, query):
        return self.compose('exec', '-T', 'db', 'sh', '-c', 'export MYSQL_PWD="$(cat /run/secrets/database_root)"; exec mariadb -uroot --batch --skip-column-names anynote', input=query.encode()).decode()

    def assert_runtime_image(self):
        expected=run(['docker','image','inspect','--format','{{.Id}}',self.values['ANYNOTE_API_IMAGE']]).decode().strip()
        ids=run(['docker','ps','--all','--filter','label=com.docker.compose.project='+self.project,'--format','{{.ID}}']).decode().splitlines()
        for identifier in ids:
            details=json.loads(run(['docker','inspect',identifier]))[0]
            if details['Config']['Labels'].get('com.docker.compose.service') in WRITERS and details['Image']!=expected:
                raise ValueError('Stale runtime image; finish the reviewed deployment before backup')
        return expected

    def quiet(self):
        self.compose('stop', '--timeout', '190', *WRITERS)
        running = run(['docker','ps','--filter','label=com.docker.compose.project='+self.project,'--format','{{.Label "com.docker.compose.service"}}']).decode().splitlines()
        if any(s not in ['db','edge'] for s in running):
            raise RuntimeError('A mutation process remains alive')
        return running


def lock(env):
    file = (env.state/'operator.lock').open('a+b')
    fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return file


def sign(path, key):
    message = path.with_name(path.name+'.sha256')
    with message.open('xb') as output:output.write(bytes.fromhex(digest(path)))
    signature = run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', key, '-in', message])
    message.unlink()
    return signature


def verify(path, signature, public_key):
    with tempfile.TemporaryDirectory(prefix='anynote-verify-') as directory:
        message = Path(directory)/'digest'
        with message.open('xb') as output:output.write(bytes.fromhex(digest(path)))
        run(['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', public_key, '-sigfile', signature, '-in', message])


def security_checkpoint(env, directory, signing_key):
    directory = Path(directory).resolve(strict=True)
    # Append-only by name, chain and independent custody. Never delete old points.
    previous = sorted(directory.glob('*.checkpoint.age'))
    predecessor = digest(previous[-1]) if previous else None
    document = json.loads(env.php('operations:security'))
    document['previous_checkpoint_sha256'] = predecessor
    sequence=max(time.time_ns(),int(previous[-1].name.split('.')[0])+1 if previous else 0)
    stamp = f'{sequence:020d}.checkpoint.age'
    target = directory/stamp
    recipient = env.values['ANYNOTE_BACKUP_RECIPIENT']
    with tempfile.TemporaryDirectory(prefix='.checkpoint-', dir=directory) as tmp:
        part = Path(tmp)/'checkpoint.age'
        run([env.values['ANYNOTE_AGE'], '-r', recipient, '-o', part], input=json.dumps(document, sort_keys=True).encode())
        signature = Path(tmp)/'checkpoint.sig'
        signature.write_bytes(sign(part, signing_key))
        publish(signature, target.with_suffix('.age.sig'))
        publish(part, target)
    return {'sha256': digest(target), 'path': target.name, 'previous_sha256': predecessor}


def backup(env, destination, signing_key, checkpoint_dir):
    destination = Path(destination).resolve()
    if destination.exists() or destination.with_suffix(destination.suffix+'.sig').exists():
        raise ValueError('Backup destination already exists')
    if destination.parent == env.state or env.state in destination.parents:
        raise ValueError('Backups require a separate destination outside service state')
    started = time.monotonic()
    with lock(env):
        env.assert_runtime_image()
        running = env.compose('ps', '--status', 'running', '--services').decode().splitlines()
        try:
            env.quiet()
            # No API/job writer or external SQL listener; DB and immutable blob
            # copy share this complete pause. No overlapping maintenance CLI.
            inventory = json.loads(env.php('operations:inventory'))
            release=json.loads(env.compose('run','--rm','--no-deps','-T','api','php','-r','echo file_get_contents("/app/release-inputs.json");').decode())
            release_provenance={'source_commit':release['source_commit'],'source_tree_dirty':release['source_tree_dirty'],'input_count':len(release['inputs']),'manifest_sha256':hashlib.sha256(json.dumps(release,sort_keys=True).encode()).hexdigest()}
            checkpoint = security_checkpoint(env, checkpoint_dir, signing_key)
            data_bytes=sum(p.stat().st_size for p in (env.state/'storage/app/private/p12-blobs').iterdir() if p.is_file() and not p.is_symlink())
            sql_bytes=int(env.sql("SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema='anynote';").strip())
            space=shutil.disk_usage(destination.parent)
            if space.free-data_bytes-sql_bytes*8<max(10737418240,space.total//10):raise ValueError('Insufficient independent backup working reserve')
            with tempfile.TemporaryDirectory(prefix='.anynote-backup-', dir=destination.parent) as tmp:
                work = Path(tmp)
                sql = work/'database.sql'
                with sql.open('wb') as output:
                    command = [*env.command, 'exec', '-T', 'db', 'sh', '-c', 'export MYSQL_PWD="$(cat /run/secrets/database_root)"; exec mariadb-dump -uroot --single-transaction --hex-blob --skip-comments --skip-extended-insert --no-tablespaces anynote']
                    result = subprocess.run(list(map(str, command)), stdout=output, stderr=subprocess.PIPE)
                    if result.returncode:
                        raise RuntimeError('Consistent SQL dump failed; private output omitted')
                members = [{'path':'database.sql', 'bytes':sql.stat().st_size, 'sha256':digest(sql)}]
                blobs = env.state/'storage/app/private/p12-blobs'
                for p in sorted(blobs.iterdir()):
                    if p.is_symlink() or not p.is_file() or not re.fullmatch('[A-Za-z0-9_-]{22}', p.name):
                        raise ValueError('Unsafe blob namespace')
                    members.append({'path':'blobs/'+p.name, 'bytes':p.stat().st_size, 'sha256':digest(p)})
                manifest = {'version':1, 'purpose':'anynote-consistent-backup', 'source_commit':run(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip(), 'created_at_unix_ns':time.time_ns(), 'inventory':inventory, 'members':members, 'security_checkpoint':checkpoint, 'recovery_mode':'offline-quarantine-only', 'api_release':release_provenance,'api_image_id':run(['docker','image','inspect','--format','{{.Id}}',env.values['ANYNOTE_API_IMAGE']]).decode().strip(), 'deployment':{'api_issuer':env.values['ANYNOTE_API_ISSUER'],'app_origin':env.values['ANYNOTE_APP_ORIGIN'],'service_id':env.values['ANYNOTE_SERVICE_ID'],'rp_id':env.values['ANYNOTE_RP_ID'],'nginx_sha256':digest(env.state/'nginx.conf'),'static_inputs':[{'path':str(p.relative_to(Path(env.values['ANYNOTE_STATIC_ROOT']))),'sha256':digest(p)} for p in sorted(Path(env.values['ANYNOTE_STATIC_ROOT']).rglob('*')) if p.is_file()]},'operational_secrets':'reinject separately; no content recovery keys collected'}
                archive = work/'backup.age'
                age = subprocess.Popen([env.values['ANYNOTE_AGE'], '-r', env.values['ANYNOTE_BACKUP_RECIPIENT'], '-o', str(archive)],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                try:
                    with tarfile.open(fileobj=age.stdin, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
                        data = json.dumps(manifest, sort_keys=True).encode()
                        info = tarfile.TarInfo('manifest.json'); info.size=len(data); info.mode=0o600
                        tar.addfile(info, io.BytesIO(data))
                        tar.add(sql, arcname='database.sql', recursive=False)
                        for p in sorted(blobs.iterdir()):
                            tar.add(p, arcname='blobs/'+p.name, recursive=False)
                    age.stdin.close()
                    if age.wait() != 0:
                        raise RuntimeError('Backup encryption failed')
                finally:
                    if age.poll() is None:
                        age.kill(); age.wait()
                signature = work/'backup.sig';signature.write_bytes(sign(archive, signing_key))
                publish(signature, destination.with_suffix(destination.suffix+'.sig'))
                publish(archive, destination)
                return {'status':'PASS','completed_at_unix_ns':time.time_ns(),'archive_sha256':digest(destination),'archive_bytes':destination.stat().st_size,'snapshot_unix_ns':manifest['created_at_unix_ns'],'elapsed_ms':round((time.monotonic()-started)*1000),'inventory':inventory,'api_release':release_provenance,'security_checkpoint':checkpoint,'consistency':'all API/queue/scheduler processes stopped; no external DB listener; exclusive operator lock'}
        finally:
            restart = [s for s in WRITERS if s in running]
            if restart:
                env.compose('up', '-d', *restart)


def unpack(archive, signature, public_key, identity, age, directory):
    # Authenticate the ENTIRE encrypted file before decrypting or touching a DB.
    verify(archive, signature, public_key)
    process = subprocess.Popen([str(age), '-d', '-i', str(identity), str(archive)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    manifest = None; seen=set(); total=0
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as tar:
            for member in tar:
                if not member.isfile() or member.name in seen:
                    raise ValueError('Duplicate or nonregular backup member')
                seen.add(member.name)
                if manifest is None:
                    if member.name!='manifest.json' or member.size>67108864:
                        raise ValueError('Bounded first manifest required')
                    def unique(pairs):
                        result={}
                        for key,value in pairs:
                            if key in result:raise ValueError('Duplicate manifest key')
                            result[key]=value
                        return result
                    manifest=json.load(tar.extractfile(member),object_pairs_hook=unique)
                    if manifest.get('version')!=1 or manifest.get('purpose')!='anynote-consistent-backup':
                        raise ValueError('Unsupported backup')
                    expected={m['path']:m for m in manifest['members']}
                    if len(expected)!=len(manifest['members']) or len(expected)>1000000 or 'database.sql' not in expected:
                        raise ValueError('Invalid member inventory')
                    for path,row in expected.items():
                        if not re.fullmatch(r'(?:database\.sql|blobs/[A-Za-z0-9_-]{22})',path) or type(row['bytes']) is not int or not 0<=row['bytes']<=250000000000 or not re.fullmatch('[0-9a-f]{64}',row['sha256']):raise ValueError('Invalid bounded member metadata')
                    continue
                if not re.fullmatch(r'(?:database\.sql|blobs/[A-Za-z0-9_-]{22})',member.name) or member.name not in expected:
                    raise ValueError('Unsafe or unlisted backup member')
                row=expected[member.name];total+=member.size
                if member.size!=row['bytes'] or total>250000000000:
                    raise ValueError('Backup exceeds inventory/resource limit')
                space=shutil.disk_usage(directory)
                if space.free-member.size<max(10737418240,space.total//10):raise ValueError('Restore extraction would consume the operational reserve')
                output=directory/member.name;output.parent.mkdir(exist_ok=True,mode=0o700)
                with output.open('xb') as dest, tar.extractfile(member) as source:
                    shutil.copyfileobj(source,dest,1048576)
                if digest(output)!=row['sha256']:
                    raise ValueError('Backup member integrity failure')
        # Drain to authenticated EOF; valid tar EOF alone is insufficient.
        trailing=process.stdout.read(10241)
        if len(trailing)>10240 or any(trailing):
            raise ValueError('Unexpected decrypted trailing bytes')
        if process.wait()!=0 or manifest is None or seen!={'manifest.json',*expected}:
            raise ValueError('Incomplete or unauthenticated backup')
        return manifest
    finally:
        if process.poll() is None:
            process.kill();process.wait()
        process.stdout.close();process.stderr.close()


def restore(env, archive, public_key, identity, expected_checkpoint):
    started=time.monotonic()
    # Only an independently provisioned empty target. No overwrite option.
    if (env.state/'database/mysql').exists() or any(p.is_symlink() or p.name!='p16-delivery' or not p.is_dir() or any(p.iterdir()) for p in (env.state/'storage/app/private').iterdir()):
        raise ValueError('Restore requires an empty clean target, never live state')
    if env.compose('ps','--all','--quiet').strip():
        raise ValueError('Restore project must have no existing containers')
    with lock(env), tempfile.TemporaryDirectory(prefix='.restore-',dir=env.state) as tmp:
        root=Path(tmp)
        manifest=unpack(Path(archive),Path(str(archive)+'.sig'),public_key,identity,env.values['ANYNOTE_AGE'],root)
        space=shutil.disk_usage(env.state);required=sum(r['bytes'] for r in manifest['members'])*2
        if space.free-required<max(10737418240,space.total//10):raise ValueError('Insufficient clean-host restore working reserve')
        if not re.fullmatch('[0-9a-f]{64}',expected_checkpoint):
            raise ValueError('Independent latest security-checkpoint digest required')
        actual_image=run(['docker','image','inspect','--format','{{.Id}}',env.values['ANYNOTE_API_IMAGE']]).decode().strip()
        if actual_image!=manifest['api_image_id']:raise ValueError('Restore image differs from the signed backup release')
        # The host fence precedes import and persists across EVERY failure.
        fence=env.state/'storage/app/private/RESTORE_QUARANTINE'
        fence.write_text('Isolated recovery only; ordinary authentication and content access denied.\n')
        durable(fence);durable_directory(fence.parent)
        env.compose('up','-d','--wait','db')
        with (root/'database.sql').open('rb') as source:
            command=[*env.command,'exec','-T','db','sh','-c','export MYSQL_PWD="$(cat /run/secrets/database_root)"; exec mariadb -uroot anynote']
            imported=subprocess.run(list(map(str,command)),stdin=source,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            if imported.returncode:raise RuntimeError('SQL import failed; target stays fenced')
        destination=env.state/'storage/app/private/p12-blobs';destination.mkdir(mode=0o700)
        for p in (root/'blobs').iterdir() if (root/'blobs').exists() else []:
            shutil.copyfile(p,destination/p.name);durable(destination/p.name)
        durable_directory(destination)
        observed=json.loads(env.php('operations:inventory'))
        if observed!=manifest['inventory']:
            raise ValueError('Restored DB/blob/reference inventory mismatch; target stays fenced')
        quarantine=json.loads(env.php('operations:quarantine'))
        return {'status':'QUARANTINED','elapsed_ms':round((time.monotonic()-started)*1000),'snapshot_unix_ns':manifest['created_at_unix_ns'],'inventory':observed,'security_checkpoint_matches_latest':manifest['security_checkpoint']['sha256']==expected_checkpoint,'quarantine':quarantine,'content_decryption':'requires separate offline client kit; no server key or online bypass'}


def render(env):
    api=env.values['ANYNOTE_API_ISSUER'];app=env.values['ANYNOTE_APP_ORIGIN']
    parts=[]
    for value in [api,app]:
        parsed=urlsplit(value)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or not re.fullmatch('[a-z0-9.-]+',parsed.hostname):raise ValueError('Exact distinct HTTPS origins required')
        if parsed.port is not None and not 1<=parsed.port<=65535:raise ValueError('Invalid TLS port')
        parts.append(parsed)
    if parts[0].hostname==parts[1].hostname or env.values['ANYNOTE_RP_ID']!=parts[1].hostname:raise ValueError('Independent API/static hosts and exact RP required')
    if not re.fullmatch(r'(?:sha256:[0-9a-f]{64}|[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64})',env.values['ANYNOTE_API_IMAGE']):raise ValueError('Reviewed immutable API image required')
    if int(env.values.get('ANYNOTE_UID','1000'))==0 or int(env.values.get('ANYNOTE_GID','1000'))==0:raise ValueError('Unprivileged runtime UID/GID required')
    text=(ROOT/'infra/operations/nginx.conf.in').read_text()
    assets=['manifest.webmanifest','icon-192.png','icon-512.png','style.css','vault.html','vault.js','vault-worker.js','vault-client.js','vault-store.js','notes.html','notes.js','notes.css','preview-render.mjs','preview-parser.mjs']
    for key,value in {'@API_HOST@':parts[0].hostname,'@APP_HOST@':parts[1].hostname,'@API_ORIGIN@':api,'@STATIC_ASSETS@':' '.join(app+'/auth/'+name for name in assets)}.items():text=text.replace(key,value)
    (env.state/'nginx.conf').write_text(text)
    return {'status':'PASS','nginx_sha256':digest(env.state/'nginx.conf'),'network_or_deployment_performed':False}

def verify_static(directory,manifest_path,signature,verification_key):
    directory=Path(directory).resolve(strict=True);manifest_path=Path(manifest_path)
    verify(manifest_path,signature,verification_key)
    manifest=json.loads(manifest_path.read_text())
    if manifest.get('purpose')!='anynote-static-release' or not re.fullmatch('[0-9a-f]{40}',manifest['source_commit']):raise ValueError('Unsupported signed static manifest')
    expected={r['path']:r['sha256'] for r in manifest['inputs']}
    if len(expected)!=len(manifest['inputs']):raise ValueError('Duplicate static release path')
    actual={}
    for path in directory.rglob('*'):
        if path.is_symlink():raise ValueError('Static release symlink refused')
        if path.is_file():actual[str(path.relative_to(directory))]=digest(path)
    if actual!=expected:raise ValueError('Static release byte inventory mismatch; isolate this origin')
    return {'status':'PASS','source_commit':manifest['source_commit'],'files':len(actual),'independent_signature_verified':True}

def request_metrics(directory):
    values=[];invalid=0
    allowed={'event','request_id','status','method','elapsed_ms','route_id','code'}
    for path in sorted(directory.glob('content-free*.jsonl'),reverse=True):
        with path.open('rb') as file:
            size=file.seek(0,2);file.seek(max(0,size-2097152))
            if size>2097152:file.readline()
            lines=file.read().splitlines()
        for line in reversed(lines):
            try:row=json.loads(line)
            except (ValueError,UnicodeError):invalid+=1;continue
            if not isinstance(row,dict) or set(row)-allowed:invalid+=1;continue
            if type(row.get('status')) is int and type(row.get('elapsed_ms')) is int:values.append(row)
            if len(values)>=10000:break
        if len(values)>=10000:break
    latency=sorted(v['elapsed_ms'] for v in values)
    return {'samples':len(values),'scope':'at most last 10000 safe request records; bounded 2MiB tail per daily file','p95_elapsed_ms':latency[int(len(latency)*.95)] if latency else None,'errors_5xx':sum(v['status']>=500 for v in values),'failed_signatures':sum(v.get('code')=='INVALID_SIGNATURE' for v in values),'rate_limited':sum(v.get('code')=='RATE_LIMITED' for v in values),'unrecognized_rows_omitted':invalid}

def main():
    signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--environment',required=True)
    sub=p.add_subparsers(dest='operation',required=True)
    b=sub.add_parser('backup');b.add_argument('--output',required=True);b.add_argument('--signing-key',required=True);b.add_argument('--checkpoint-directory',required=True)
    c=sub.add_parser('checkpoint');c.add_argument('--directory',required=True);c.add_argument('--signing-key',required=True)
    r=sub.add_parser('restore');r.add_argument('--archive',required=True);r.add_argument('--verification-key',required=True);r.add_argument('--identity',required=True);r.add_argument('--latest-checkpoint-sha256',required=True)
    sub.add_parser('render')
    v=sub.add_parser('verify-static');v.add_argument('--directory',required=True);v.add_argument('--manifest',required=True);v.add_argument('--signature',required=True);v.add_argument('--verification-key',required=True)
    h=sub.add_parser('health');h.add_argument('--backup-receipt',required=True);h.add_argument('--drill-receipt',required=True)
    a=p.parse_args();env=Environment(a.environment)
    if a.operation=='render':result=render(env)
    elif a.operation=='verify-static':result=verify_static(a.directory,a.manifest,a.signature,a.verification_key)
    elif a.operation=='backup':result=backup(env,a.output,a.signing_key,a.checkpoint_directory)
    elif a.operation=='restore':result=restore(env,a.archive,a.verification_key,a.identity,a.latest_checkpoint_sha256)
    elif a.operation=='checkpoint':
        with lock(env):
            running=env.compose('ps','--status','running','--services').decode().splitlines();env.quiet()
            try:result=security_checkpoint(env,a.directory,a.signing_key)
            finally:
                restart=[s for s in WRITERS if s in running]
                if restart:env.compose('up','-d',*restart)
    else:
        result=json.loads(env.php('operations:health'));result['requests']=request_metrics(env.state/'storage/logs')
        database_space=shutil.disk_usage(env.state/'database');result['database_free_bytes']=database_space.free
        if database_space.free<max(10737418240,database_space.total//10):result['status']='unavailable'
        for name,path,limit in [('backup',a.backup_receipt,86400),('restore_drill',a.drill_receipt,30*86400)]:
            receipt=json.loads(Path(path).read_text());age=time.time_ns()-int(receipt['completed_at_unix_ns']);result[name+'_age_seconds']=age/1e9
            if not 0<=age<=limit*1e9 or receipt['status']!='PASS':result['status']='unavailable'
    print(json.dumps(result,sort_keys=True))
    if a.operation=='health' and result['status']!='ready':raise SystemExit(1)


if __name__=='__main__':
    try:main()
    except (RuntimeError,ValueError,OSError,KeyError,subprocess.SubprocessError):
        raise SystemExit('Operations failed closed; inspect private operator diagnostics. No success receipt issued.')
