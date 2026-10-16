#!/usr/bin/env python3
"""P17 separately named synthetic SQL/HTTPS target; never resets retained P06."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.local/p17/http'
DATABASE = 'anynote_p17_security'
OWNER = hashlib.sha256(('AnyNote P17 isolated security target/' + str(ROOT)).encode()).hexdigest()
spec = importlib.util.spec_from_file_location('p06', ROOT / 'scripts/p06-stack.py')
p06 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p06)
PROJECT = 'anynote-p17-' + OWNER[:10]

def sql(query):
    return p06.sql(query)

def compose(*args, input=None):
    result = subprocess.run(['docker','compose','--project-name',PROJECT,'-f',str(STATE/'compose.json'),*args],
                            cwd=ROOT,input=input,text=True,capture_output=True)
    if result.returncode:
        raise RuntimeError('Owned P17 process failed: ' + str(result.returncode) + '; private arguments omitted')
    return result.stdout.strip()

def owned():
    expected={'purpose':'P17 isolated synthetic HTTPS/SQL','owner':OWNER,'database':DATABASE,'project':PROJECT}
    path=STATE/'owner.json'
    if not path.exists() or json.loads(path.read_text())!=expected:
        raise RuntimeError('P17 target ownership is not established')
    return expected

def initialize():
    p06.initialize()
    if (STATE/'owner.json').exists():
        owned()
        return
    if STATE.exists() and any(STATE.iterdir()):
        raise RuntimeError('Refusing unmarked P17 target directory')
    STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
    if sql("SHOW DATABASES LIKE '"+DATABASE+"';"):
        raise RuntimeError('Refusing preexisting unmarked P17 SQL')
    config=json.loads(p06.compose('config','--format','json',capture=True))
    php=config['services']['auth-php'];edge=config['services']['auth-nginx']
    php.pop('depends_on',None);edge['depends_on']={'p17-php':{'condition':'service_started','required':True}}
    php['environment'].update({'DB_DATABASE':DATABASE,'APP_URL':'https://api.anynote.test:20443',
        'ANYNOTE_APP_ORIGIN':'https://app.anynote.test:20443','ANYNOTE_API_ISSUER':'https://api.anynote.test:20443',
        'ANYNOTE_P17_TEST_OWNER':OWNER})
    (STATE/'logs').mkdir(mode=0o700)
    php['volumes'].append({'type':'bind','source':str(STATE/'logs'),'target':'/app/storage/logs','bind':{'create_host_path':False}})
    edge['ports']=[{'target':8443,'published':'20443','host_ip':'127.0.0.1','protocol':'tcp'}]
    nginx=(ROOT/'infra/dev/p06-nginx.conf').read_text().replace('auth-php:9000','p17-php:9000').replace(':18443',':20443')
    (STATE/'nginx.conf').write_text(nginx)
    for volume in edge['volumes']:
        if volume['target']=='/etc/nginx/nginx.conf':volume['source']=str(STATE/'nginx.conf')
    config={'services':{'p17-php':php,'p17-nginx':edge},'networks':{'frontend':{},'database':{'external':True,'name':p06.stack.PROJECT+'_database'}}}
    path=STATE/'compose.json';path.write_text(json.dumps(config));path.chmod(0o600)
    (STATE/'owner.json').write_text(json.dumps({'purpose':'P17 isolated synthetic HTTPS/SQL','owner':OWNER,'database':DATABASE,'project':PROJECT})+'\n')
    sql('CREATE DATABASE '+DATABASE+' CHARACTER SET ascii COLLATE ascii_bin; CREATE TABLE '+DATABASE+'.p17_test_owner (owner CHAR(64) NOT NULL PRIMARY KEY) ENGINE=InnoDB; INSERT INTO '+DATABASE+".p17_test_owner VALUES ('"+OWNER+"'); GRANT ALL ON "+DATABASE+".* TO 'anynote_dev'@'%';")

def main():
    op=sys.argv[1]
    if op=='up':
        initialize();owned()
        assert sql('SELECT owner FROM '+DATABASE+'.p17_test_owner;')==OWNER
        compose('run','--rm','--no-deps','-T','p17-php','php','artisan','migrate','--no-interaction')
        compose('up','-d','p17-php','p17-nginx')
        subprocess.run(['node','packages/protocol/security/http.mjs','--ready'],cwd=ROOT,check=True)
        print('PASS: separately owned P17 HTTPS/SQL target; retained P06 untouched')
    elif op=='control':
        owned();print(compose('run','--rm','--no-deps','-T','p17-php','php','tests/Support/p17-control.php',sys.argv[2],input=sys.stdin.read()))
    elif op=='stop':
        if not (STATE/'owner.json').exists():
            assert not (STATE/'compose.json').exists(),'Unmarked P17 configuration requires inspection'
            print('P17 target not started; nothing stopped')
        else:
            owned();compose('stop','p17-php','p17-nginx');print('Stopped only P17 services; SQL, logs and binds retained')
    else:raise RuntimeError('Unsupported P17 operation')

if __name__=='__main__':main()
