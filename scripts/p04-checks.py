#!/usr/bin/env python3
"""Real P04 SQL tests in a separately marked disposable database, never product data."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
subprocess.run(['python3',str(ROOT/'scripts/check-p04-compatibility.py')],check=True)
spec = importlib.util.spec_from_file_location('stack', ROOT/'scripts/dev-stack.py')
stack = importlib.util.module_from_spec(spec);spec.loader.exec_module(stack)
stack.initialize()
out=ROOT/'artifacts/p04/backend-report.json'
if out.exists():
    assert json.loads(out.read_text())['purpose']=='P04 isolated actual MariaDB backend evidence', 'Unowned report path'
    out.unlink()
DATABASE = 'anynote_p04_tests'
OWNER = hashlib.sha256(('AnyNote P04 disposable test database/'+str(ROOT)).encode()).hexdigest()
def root_sql(sql):
    # Use the injected synthetic root password only inside its owned DB container.
    command = ['docker','compose','--project-name',stack.PROJECT,'--env-file',str(stack.ENV),'-f',str(ROOT/'infra/dev/compose.yaml'),'exec','-T','db','sh','-c','exec mariadb --user=root --password="$MARIADB_ROOT_PASSWORD" --batch --skip-column-names']
    result = subprocess.run(command,input=sql,text=True,capture_output=True,check=True)
    return result.stdout.strip()
stack.compose('--profile','maintenance','stop','queue','scheduler',capture=True)
if root_sql("SHOW DATABASES LIKE 'anynote_p04_tests';"):
    if root_sql('SELECT owner FROM anynote_p04_tests.p04_test_owner;') != OWNER:
        raise RuntimeError('Refusing to reset an unowned database')
    root_sql('DROP DATABASE anynote_p04_tests;')
root_sql("CREATE DATABASE anynote_p04_tests CHARACTER SET ascii COLLATE ascii_bin; CREATE TABLE anynote_p04_tests.p04_test_owner (owner CHAR(64) NOT NULL PRIMARY KEY) ENGINE=InnoDB; INSERT INTO anynote_p04_tests.p04_test_owner VALUES ('"+OWNER+"'); GRANT ALL ON anynote_p04_tests.* TO 'anynote_dev'@'%';")
subprocess.run(['node',str(ROOT/'packages/protocol/p04-fixtures.mjs')],cwd=ROOT,check=True)
def php(*args,capture=False):
    return stack.compose('run','--rm','--no-deps','-e','APP_ENV=testing','-e','DB_DATABASE='+DATABASE,'php',*args,capture=capture)
php('php','artisan','migrate','--no-interaction')
php('php','vendor/bin/phpunit')
try:
    result = json.loads(php('php','tests/Support/p04-concurrency.php',capture=True))
except subprocess.CalledProcessError as error:
    print(error.stderr[:2000], flush=True)
    raise
assert result['status']=='PASS'
os.environ['ANYNOTE_MAINTENANCE_DB'] = DATABASE
try:
    stack.compose('--profile','maintenance','up','-d','queue','scheduler',capture=True)
    deadline=time.monotonic()+90
    while root_sql("SELECT COUNT(*) FROM anynote_p04_tests.runtime_heartbeats WHERE component IN ('queue','scheduler') AND observed_at > UTC_TIMESTAMP() - INTERVAL 150 SECOND;") != '2':
        if time.monotonic()>deadline: raise RuntimeError('Supervised scheduler/queue heartbeats absent')
        time.sleep(1)
    for component in ['queue','scheduler']:
        identifier=stack.compose('--profile','maintenance','ps','-q',component,capture=True).strip()
        user=subprocess.check_output(['docker','inspect','--format','{{.Config.User}}',identifier],text=True).strip().split(':')[0]
        assert user not in ['', '0', 'root']
        assert subprocess.check_output(['docker','inspect','--format','{{.HostConfig.RestartPolicy.Name}}',identifier],text=True).strip()=='unless-stopped'
        assert json.loads(subprocess.check_output(['docker','inspect','--format','{{json .HostConfig.PortBindings}}',identifier],text=True)) in [None,{}]
        before=int(subprocess.check_output(['docker','inspect','--format','{{.RestartCount}}',identifier],text=True))
        crash=subprocess.run(['docker','exec',identifier,'sh','-c','for status_path in /proc/[0-9]*/comm; do read task_name < "$status_path" || continue; if [ "$task_name" = php ]; then task_pid=${status_path#/proc/}; task_pid=${task_pid%/comm}; kill -KILL "$task_pid"; exit; fi; done; exit 1'],capture_output=True)
        assert crash.returncode in [0,137]
        deadline=time.monotonic()+20
        while int(subprocess.check_output(['docker','inspect','--format','{{.RestartCount}}',identifier],text=True)) <= before:
            if time.monotonic()>deadline: raise RuntimeError('Supervisor failed to restart '+component)
            time.sleep(0.5)
    stack.compose('run','--rm','--no-deps','-e','APP_ENV=testing','-e','DB_DATABASE='+DATABASE,'-e','QUEUE_CONNECTION=database','php','php','artisan','maintenance:heartbeat',capture=True)
    deadline=time.monotonic()+20
    while root_sql('SELECT COUNT(*) FROM anynote_p04_tests.jobs;') != '0':
        if time.monotonic()>deadline: raise RuntimeError('Restarted worker did not consume maintenance job')
        time.sleep(0.5)
    result['supervised_queue_scheduler']='PASS'
    result['actual_restart_after_kill']='PASS'
finally:
    stack.compose('--profile','maintenance','stop','queue','scheduler',capture=True)

visible=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=ROOT).decode().split('\0')
inputs=[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in sorted(set(visible)) if p and (ROOT/p).is_file() and p.startswith(('apps/api/','infra/dev/','packages/contracts/p04-','packages/protocol/adapters/','packages/protocol/p04-','packages/crypto-native/','scripts/p04', 'scripts/check-p04-','.github/workflows/foundation.yml'))]
report={'status':'PASS','purpose':'P04 isolated actual MariaDB backend evidence','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'source_tree_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),'inputs':inputs,'sql':result,'public_fixture_sha256':hashlib.sha256((ROOT/'apps/api/storage/framework/testing/p04-fixtures.json').read_bytes()).hexdigest(),'physical_acceptance':False,'limits':['No production migration/deployment, account login ceremony or independent security review','P05 general native JSON/AEAD/custody adapters remain open']}
out=ROOT/'artifacts/p04/backend-report.json';out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n')
print('PASS: isolated backend, schema, three-account policies, SQL concurrency and rollback')
