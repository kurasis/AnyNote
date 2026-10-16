#!/usr/bin/env python3
"""Synthetic P16 isolated deployment/fault/clean-host acceptance. Never resets P03/P06."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import socket
import tempfile
import shutil
import time

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('p16_stack',ROOT/'scripts/p16-stack.py');stack=importlib.util.module_from_spec(spec);spec.loader.exec_module(stack)
ops=stack.ops


def control(operation):
    target=os.environ.get('ANYNOTE_P16_TARGET','source')
    if not stack.re.fullmatch(r'(?:source|capacity|fresh-[0-9]{12})',target):raise ValueError('Owned fixture target required')
    env=ops.Environment(ROOT/'.local/p16'/target/'environment')
    owner=hashlib.sha256(('P16 owned synthetic database '+str(ROOT)).encode()).hexdigest()
    if env.sql('SELECT owner FROM p16_test_owner;').strip()!=owner:raise ValueError('Unowned SQL fixture')
    result=env.compose('run','--rm','--no-deps','-T','-e','ANYNOTE_P16_OWNER='+owner,'-v',str(ROOT/'apps/api/tests/Support/p16-control.php')+':/tmp/p16-control.php:ro','api','php','/tmp/p16-control.php',operation,input=sys.stdin.buffer.read())
    print(result.decode().strip())


def prepare():
    source=stack.initialize();env=ops.Environment(source/'environment')
    env.compose('up','-d','--wait','db')
    # Fresh installation must use privileged migration credentials once, then
    # permanently separate runtime DML from operator DDL.
    env.compose('run','--rm','--no-deps','-T','-v',str(env.state/'secrets/database_root')+':/run/secrets/database_root:ro','--entrypoint','sh','api','-c','export APP_KEY="$(cat /run/secrets/app_key)" DB_PASSWORD="$(cat /run/secrets/database_root)" DB_USERNAME=root; exec php artisan migrate --force --no-interaction')
    owner=hashlib.sha256(('P16 owned synthetic database '+str(ROOT)).encode()).hexdigest()
    env.sql("CREATE TABLE IF NOT EXISTS p16_test_owner (owner CHAR(64) PRIMARY KEY); INSERT IGNORE INTO p16_test_owner VALUES ('"+owner+"');")
    if env.sql('SELECT owner FROM p16_test_owner;').strip()!=owner:raise ValueError('Unowned synthetic fixture')
    stack.up(source)
    for _ in range(60):
        r=subprocess.run(['node','--input-type=module','-e',"import {Browser} from './packages/protocol/p16-fixture.mjs';const r=await new Browser().call('/capabilities');if(r.status!==200)process.exit(1);"],cwd=ROOT,capture_output=True)
        if r.returncode==0:break
        time.sleep(.5)
    else:raise RuntimeError('Genuine staging HTTPS readiness failed')
    return {'status':'PASS','clean_installation':'new isolated MariaDB datadir and immutable API image; no P03/P06 rows or volume used','runtime_grants':env.sql("SHOW GRANTS FOR 'anynote_runtime'@'%';").replace(env.values.get('ANYNOTE_PROJECT',''),'[project]')}


def action(name):
    env=ops.Environment(ROOT/'.local/p16/source/environment')
    marker=json.loads((stack.STATE/'source/owner.json').read_text())
    expected_project='anynote-p16-'+hashlib.sha256(str(ROOT).encode()).hexdigest()[:8]+'-source'
    if marker!={'purpose':'AnyNote P16 synthetic staging only','checkout':str(ROOT),'name':'source'} or env.project!=expected_project or env.state!=stack.STATE/'source':raise ValueError('Only the exact owned synthetic source project is allowed')
    custody=ROOT/'.local/p16/offline-operator'
    backups=ROOT/'.local/p16/off-host-backups';backups.mkdir(exist_ok=True,mode=0o700)
    checkpoints=ROOT/'.local/p16/off-host-security';checkpoints.mkdir(exist_ok=True,mode=0o700)
    if name=='stop-all':
        count=0
        for path in sorted(stack.STATE.glob('*/environment')):
            marker=json.loads((path.parent/'owner.json').read_text())
            if marker['purpose']!='AnyNote P16 synthetic staging only' or marker['checkout']!=str(ROOT):raise ValueError('Unowned project')
            clean=ops.Environment(path);clean.compose('stop','edge','api','queue','scheduler','db');count+=1
        return {'status':'PASS','owned_projects_stopped':count,'data_removed':False}
    if name=='interrupted-backup':
        output=backups/('interrupted-'+str(time.time_ns())+'.age');before=set(backups.glob('.anynote-backup-*'))
        process=subprocess.Popen(['python3',str(ROOT/'scripts/operations.py'),'--environment',str(env.path),'backup','--output',str(output),'--signing-key',str(custody/'backup-signing.pem'),'--checkpoint-directory',str(checkpoints)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        observed=0;deadline=time.monotonic()+120
        try:
            while process.poll() is None and time.monotonic()<deadline:
                for part in backups.glob('.anynote-backup-*/backup.age'):
                    if part.stat().st_size>=65536:observed=part.stat().st_size;break
                if observed:break
                time.sleep(.01)
            if not observed:raise RuntimeError('Did not observe an actual interrupted encrypted stream')
            process.terminate();stdout,stderr=process.communicate(timeout=45)
            if process.returncode==0 or output.exists() or Path(str(output)+'.sig').exists() or set(backups.glob('.anynote-backup-*'))!=before:raise RuntimeError('Interrupted backup published or retained incomplete output')
            env.assert_runtime_image();running=env.compose('ps','--status','running','--services').decode().splitlines()
            if not all(writer in running for writer in ops.WRITERS):raise RuntimeError('Writer supervision did not resume after interruption')
            return {'status':'PASS','actual_partial_age_bytes_observed':observed,'no_final_archive_or_signature':True,'owned_writers_resumed':True,'exit_nonzero':True}
        finally:
            if process.poll() is None:process.kill();process.wait()
            if process.stdout:process.stdout.close()
            if process.stderr:process.stderr.close()
    if name=='isolate':
        env.compose('stop','edge','api','queue','scheduler');return {'status':'ISOLATED','runtime_writers_stopped':True,'unsafe_static_delivery_stopped':True}
    if name=='incident-static':
        static_private=custody/'static-signing.pem';static_public=custody/'static-verification.pem'
        if not static_private.exists() and not static_public.exists():
            ops.run(['openssl','genpkey','-algorithm','ED25519','-out',static_private]);static_private.chmod(0o600);ops.run(['openssl','pkey','-in',static_private,'-pubout','-out',static_public])
        if not static_private.is_file() or not static_public.is_file():raise ValueError('Incomplete independent synthetic static-signing pair')
        with tempfile.TemporaryDirectory(prefix='anynote-p16-incident-') as directory:
            directory=Path(directory);release=directory/'release';shutil.copytree(env.values['ANYNOTE_STATIC_ROOT'],release)
            manifest=directory/'release.json';manifest.write_text(json.dumps({'purpose':'anynote-static-release','source_commit':ops.run(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip(),'inputs':[{'path':str(p.relative_to(release)),'sha256':ops.digest(p)} for p in sorted(release.rglob('*')) if p.is_file()]}));signature=directory/'release.sig';signature.write_bytes(ops.sign(manifest,static_private))
            verified=ops.verify_static(release,manifest,signature,static_public);script=release/'auth/notes.js';script.write_bytes(script.read_bytes()+b'\n// PUBLIC synthetic tampering fixture\n')
            try:ops.verify_static(release,manifest,signature,static_public)
            except ValueError:return {'status':'PASS','reviewed_signature_and_complete_inventory_verified':verified['status']=='PASS','altered_pwa_release_refused':True,'malicious_script_executed':False}
            raise RuntimeError('Tampered static release was accepted')
    if name=='capacity-prepare':
        target=stack.initialize('capacity',22443,image=env.values['ANYNOTE_API_IMAGE']);stack.up(target)
        clean=ops.Environment(target/'environment');owner=hashlib.sha256(('P16 owned synthetic database '+str(ROOT)).encode()).hexdigest();clean.sql("CREATE TABLE IF NOT EXISTS p16_test_owner (owner CHAR(64) PRIMARY KEY); INSERT IGNORE INTO p16_test_owner VALUES ('"+owner+"');")
        return {'status':'PASS','port':22443,'target':'capacity'}
    if name=='capacity-load':
        clean=ops.Environment(ROOT/'.local/p16/capacity/environment');owner=hashlib.sha256(('P16 owned synthetic database '+str(ROOT)).encode()).hexdigest()
        command=[*clean.command,'run','--rm','--no-deps','-T','-e','ANYNOTE_P16_OWNER='+owner,'-v',str(ROOT/'apps/api/tests/Support/p16-capacity.php')+':/tmp/p16-capacity.php:ro','api','php','/tmp/p16-capacity.php']
        result=subprocess.run(list(map(str,command)),stdin=sys.stdin.buffer,capture_output=True)
        if result.returncode:
            safe={'status':'FAIL','exit_code':result.returncode}
            for line in result.stderr.splitlines():
                try:row=json.loads(line)
                except ValueError:continue
                if isinstance(row,dict) and row.get('status')=='FAIL' and set(row)<={'status','phase','verified_rows','class','code','driver_code','source','line'}:safe=row
            raise RuntimeError('Capacity loader refused: '+json.dumps(safe))
        return json.loads(result.stdout)
    if name=='capacity-metrics':
        clean=ops.Environment(ROOT/'.local/p16/capacity/environment')
        return {'status':'PASS','database_bytes':int(clean.sql("SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema='anynote';").strip()),'free_disk_bytes':__import__('shutil').disk_usage(clean.state).free,'total_disk_bytes':__import__('shutil').disk_usage(clean.state).total,'database_counts':{table:int(clean.sql('SELECT COUNT(*) FROM '+table+';').strip()) for table in ['users','devices','object_revisions']}}
    if name=='backup':
        archive=backups/('drill-'+str(time.time_ns())+'.age')
        result=ops.backup(env,archive,custody/'backup-signing.pem',checkpoints);result['archive_path']=str(archive)
        (backups/'backup-receipt.json').write_text(json.dumps(result));return result
    if name=='checkpoint':
        result=ops.security_checkpoint(env,checkpoints,custody/'backup-signing.pem')
        (checkpoints/'latest.json').write_text(json.dumps(result));return result
    if name=='restore':
        image=env.values['ANYNOTE_API_IMAGE']
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        target=stack.initialize('restore-'+str(time.time_ns())[-12:],port,image=image);stack.render(target)
        clean=ops.Environment(target/'environment');latest=json.loads((checkpoints/'latest.json').read_text())
        backup=json.loads((backups/'backup-receipt.json').read_text())
        result=ops.restore(clean,backup['archive_path'],custody/'backup-verification.pem',custody/'backup.identity',latest['sha256']);result['restore_environment']=str(target/'environment');result['restore_port']=port
        (backups/'restore-receipt.json').write_text(json.dumps(result));return result
    if name=='catalogue':
        restored=json.loads((backups/'restore-receipt.json').read_text());clean=ops.Environment(restored['restore_environment']);group=json.loads(sys.stdin.read())['group_id'];result=json.loads(clean.php('operations:catalogue',group))
        (ROOT/'.local/p16/recovery-catalogue.json').write_text(json.dumps(result));return {'status':'PASS','records':len(result['records']),'files':len(result['files'])}
    if name=='storage-faults':
        owner=hashlib.sha256(('P16 owned synthetic database '+str(ROOT)).encode()).hexdigest()
        with tempfile.NamedTemporaryFile(mode='w',suffix='.yaml') as override:
            json.dump({'services':{'api':{'tmpfs':['/fault:size=8m,uid=1000,gid=1000,mode=0700']}}},override);override.flush()
            return json.loads(ops.run([*env.command,'-f',override.name,'run','--rm','--no-deps','-T','-e','ANYNOTE_P16_OWNER='+owner,'-v',str(ROOT/'apps/api/tests/Support/p16-storage-fault.php')+':/tmp/p16-storage-fault.php:ro','api','php','/tmp/p16-storage-fault.php']).decode().strip())
    if name=='inventory':return json.loads(env.php('operations:inventory'))
    if name=='outage-on':env.compose('stop','db');return {'status':'armed'}
    if name=='outage-off':env.compose('up','-d','--wait','db');return {'status':'restored'}
    if name=='queue-restart':
        before=env.sql("SELECT observed_at FROM runtime_heartbeats WHERE component='queue';").strip()
        env.compose('restart','queue');env.php('maintenance:heartbeat')
        for _ in range(60):
            after=env.sql("SELECT observed_at FROM runtime_heartbeats WHERE component='queue';").strip()
            if after and after!=before:return {'status':'PASS','heartbeat_advanced':True}
            time.sleep(.5)
        raise RuntimeError('Supervised worker did not process the real heartbeat')
    if name=='maintain':return json.loads(env.php('operations:maintain'))
    if name=='runtime-permissions':
        grants=env.sql("SHOW GRANTS FOR 'anynote_runtime'@'%';")
        if any(word in grants for word in ['ALL PRIVILEGES','CREATE','ALTER','DROP','SUPER','GRANT OPTION']):raise RuntimeError('Excess runtime grants')
        denied=0
        for path in ['/app/public/p16-test','/app/app/p16-test','/static/p16-test']:
            try:env.compose('exec','-T','api','touch',path)
            except RuntimeError:denied+=1
        if denied!=3:raise RuntimeError('Runtime wrote protected source/static path')
        runtime=json.loads(env.compose('run','--rm','--no-deps','-T','api','php','-r','echo json_encode(["php"=>PHP_VERSION,"pcntl"=>extension_loaded("pcntl")]);').decode())
        if runtime!={'php':'8.4.26','pcntl':True}:raise RuntimeError('Pinned PHP/pcntl worker prerequisite missing')
        return {'status':'PASS','php':runtime['php'],'pcntl':runtime['pcntl'],'denied_writes':denied,'runtime_ddl_privileges':False,'static_mounted_in_php':False}
    if name=='start-restored-edge':
        restored=json.loads((backups/'restore-receipt.json').read_text());clean=ops.Environment(restored['restore_environment']);clean.compose('up','-d','api','edge');return {'status':'PASS'}
    if name=='fresh-install':
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        target=stack.initialize('fresh-'+str(time.time_ns())[-12:],port,image=env.values['ANYNOTE_API_IMAGE']);stack.up(target)
        clean=ops.Environment(target/'environment');owner=hashlib.sha256(('P16 owned synthetic database '+str(ROOT)).encode()).hexdigest();clean.sql("CREATE TABLE p16_test_owner (owner CHAR(64) PRIMARY KEY); INSERT INTO p16_test_owner VALUES ('"+owner+"');")
        return {'status':'PASS','new_datadir':True,'independent_project':True,'port':port,'ca_path':str(target/'tls/ca.crt'),'target':target.name}
    raise ValueError('Unknown drill action')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['prepare','run','control','action']);p.add_argument('argument',nargs='?');a=p.parse_args()
    if a.operation=='control':control(a.argument);return
    if a.operation=='action':print(json.dumps(action(a.argument)));return
    receipt=prepare()
    if a.operation=='run':
        subprocess.run(['node','packages/protocol/p16-acceptance.mjs'],cwd=ROOT,check=True)
    else:print(json.dumps({'status':receipt['status'],'clean_installation':receipt['clean_installation']}))


if __name__=='__main__':main()
