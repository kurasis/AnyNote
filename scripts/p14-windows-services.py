#!/usr/bin/env python3
"""Real owned Windows CI PHP/MariaDB/TLS services. No Docker substitute or token issuer."""
import argparse,base64,hashlib,json,os,re,secrets,shutil,subprocess,sys,time,urllib.request,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
STATE=ROOT/'.local/p14-windows-services';P06=ROOT/'.local/p06';API=ROOT/'apps/api'
PURPOSE='AnyNote P14 disposable Windows backend'
OWNER=hashlib.sha256(('AnyNote P06 disposable TLS authentication stack'+str(ROOT)).encode()).hexdigest()
PINS=json.loads((ROOT/'scripts/p14-windows-dependencies.json').read_text())
def require_ci():
    if os.name!='nt' or os.getenv('GITHUB_ACTIONS')!='true':raise RuntimeError('Windows GitHub synthetic runner required')
def checked(args,**kw):
    result=subprocess.run([str(a) for a in args],cwd=kw.pop('cwd',ROOT),capture_output=True,**kw)
    if result.returncode:
        detail=(result.stdout+result.stderr).decode(errors='replace')
        if (STATE/'private.json').exists():
            for private in settings().values():detail=detail.replace(private,'[REDACTED]')
        detail=re.sub(r'-----BEGIN[^\n]*PRIVATE KEY-----.*?-----END[^\n]*PRIVATE KEY-----','[REDACTED PRIVATE KEY]',detail,flags=re.S)
        detail=re.sub(r'(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*','Bearer [REDACTED]',detail)
        report={'program':Path(args[0]).name,'exit_code':result.returncode,'sanitized_diagnostic':detail[-2500:]}
        destination=ROOT/'artifacts/p14';destination.mkdir(parents=True,exist_ok=True);(destination/'windows-service-error.json').write_text(json.dumps(report,indent=2))
        print(json.dumps(report),file=sys.stderr)
        raise RuntimeError('Owned Windows dependency/service command failed; private arguments withheld')
    return result.stdout
def marker():
    expected={'purpose':PURPOSE,'root':str(ROOT),'owner':OWNER}
    path=STATE/'owner.json'
    if path.exists():
        if json.loads(path.read_text())!=expected:raise RuntimeError('Unowned Windows service directory')
    else:
        if STATE.exists() and any(STATE.iterdir()):raise RuntimeError('Unmarked Windows service directory')
        STATE.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(expected))
def runtime(name):
    return STATE/('php/php.exe' if name=='php' else 'mariadb/bin/mariadb.exe')
def download(name):
    p=PINS[name];target=STATE/(name+'.zip' if name!='composer' else 'composer.phar')
    if not target.exists() or hashlib.sha256(target.read_bytes()).hexdigest()!=p['sha256']:
        with urllib.request.urlopen(p['url'],timeout=60) as response,target.open('wb') as out:shutil.copyfileobj(response,out)
    if hashlib.sha256(target.read_bytes()).hexdigest()!=p['sha256']:raise RuntimeError('Pinned official runtime hash mismatch')
    if name!='composer':
        destination=STATE/name
        if not destination.exists():
            destination.mkdir()
            with zipfile.ZipFile(target) as archive:
                for item in archive.infolist():
                    parts=Path(item.filename).parts
                    if name=='mariadb':parts=parts[1:]
                    if not parts:continue
                    path=destination.joinpath(*parts)
                    if not path.resolve().is_relative_to(destination.resolve()):raise RuntimeError('Invalid official archive path')
                    if item.is_dir():path.mkdir(parents=True,exist_ok=True)
                    else:
                        path.parent.mkdir(parents=True,exist_ok=True)
                        with archive.open(item) as source,path.open('wb') as out:shutil.copyfileobj(source,out)
def settings():
    return json.loads((STATE/'private.json').read_text())
def environment():
    values=settings();env=os.environ.copy();env.update({
      'APP_ENV':'testing','APP_KEY':values['app_key'],'APP_DEBUG':'false','APP_URL':'https://api.anynote.test:18443',
      'DB_CONNECTION':'mariadb','DB_HOST':'127.0.0.1','DB_PORT':'13306','DB_DATABASE':'anynote_p06_tests','DB_USERNAME':'anynote_dev','DB_PASSWORD':values['database_password'],
      'ANYNOTE_APP_ORIGIN':'https://app.anynote.test:18443','ANYNOTE_API_ISSUER':'https://api.anynote.test:18443','ANYNOTE_RP_ID':'app.anynote.test',
      'ANYNOTE_OAUTH_PRIVATE_KEY':str(P06/'oauth/private.pem'),'ANYNOTE_OAUTH_PUBLIC_KEY':str(P06/'oauth/public.pem'),
      'ANYNOTE_P06_TEST_OWNER':OWNER,'SESSION_DRIVER':'database','CACHE_STORE':'array','QUEUE_CONNECTION':'sync',
      'COMPOSER_HOME':str(STATE/'composer-home'),'COMPOSER_CACHE_DIR':str(STATE/'composer-cache'),'COMPOSER_AUTH':'{}','COMPOSER_ALLOW_SUPERUSER':'1'})
    return env
def php(*args,capture=True,input=None):
    return checked([runtime('php'),'-c',STATE/'php.ini',*args],cwd=API,env=environment(),input=input)
def sql(text,password=True):
    env=os.environ.copy()
    if password:env['MYSQL_PWD']=settings()['root_password']
    return checked([runtime('db'),'--protocol=tcp','--host=127.0.0.1','--port=13306','--user='+('anynote_admin' if password else 'root'),'--batch','--skip-column-names'],env=env,input=text.encode()).decode().strip()
def openssl(*args):
    exe=shutil.which('openssl') or r'C:\Program Files\Git\usr\bin\openssl.exe'
    return checked([exe,*args])
def start_process(name,args,env=None,cwd=None):
    records=json.loads((STATE/'processes.json').read_text()) if (STATE/'processes.json').exists() else {}
    if name in records:raise RuntimeError('Refusing duplicate owned service process')
    log=(STATE/(name+'.private.log')).open('wb')
    p=subprocess.Popen([str(a) for a in args],cwd=cwd or ROOT,env=env,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW)
    records[name]={'pid':p.pid,'executable':str(Path(args[0]).resolve())};(STATE/'processes.json').write_text(json.dumps(records));return p
def initialize():
    require_ci();marker()
    for name in ["php","mariadb","composer"]:download(name)
    if not (STATE/'private.json').exists():
        (STATE/'private.json').write_text(json.dumps({'app_key':'base64:'+base64.b64encode(secrets.token_bytes(32)).decode(),'root_password':secrets.token_hex(24),'database_password':secrets.token_hex(24)}))
    ini='extension_dir="'+str(STATE/'php/ext').replace('\\','/')+'"\n'+'\n'.join('extension='+x for x in ['curl','fileinfo','intl','mbstring','openssl','pdo_mysql','sodium','zip'])+'\nmemory_limit=512M\npost_max_size=12M\nupload_max_filesize=12M\nmax_execution_time=120\ndisplay_errors=Off\nlog_errors=On\n'
    (STATE/'php.ini').write_text(ini)
    if not (P06/'tls/ca.crt').exists():
        if (P06/'tls').exists() or (P06/'oauth').exists():raise RuntimeError('Refusing unmarked partial test TLS/OAuth state')
        (P06/'tls').mkdir(parents=True);(P06/'oauth').mkdir()
        openssl('req','-x509','-newkey','rsa:3072','-nodes','-keyout',P06/'tls/ca.key','-out',P06/'tls/ca.crt','-days','3','-subj','/CN=AnyNote P14 disposable Windows test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
        openssl('req','-newkey','rsa:3072','-nodes','-keyout',P06/'tls/server.key','-out',P06/'tls/server.csr','-subj','/CN=app.anynote.test')
        (P06/'tls/extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:app.anynote.test,DNS:api.anynote.test\n')
        openssl('x509','-req','-in',P06/'tls/server.csr','-CA',P06/'tls/ca.crt','-CAkey',P06/'tls/ca.key','-CAcreateserial','-out',P06/'tls/server.crt','-days','2','-extfile',P06/'tls/extensions')
        openssl('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',P06/'oauth/private.pem')
        openssl('pkey','-in',P06/'oauth/private.pem','-pubout','-out',P06/'oauth/public.pem')
    # Composer resolves only the existing frozen lock; never choose new versions or source fallbacks.
    php(STATE/'composer.phar','config','--global','source-fallback','false')
    success=False
    for _ in range(3):
        try:php(STATE/'composer.phar','install','--no-interaction','--prefer-dist','--no-progress');success=True;break
        except RuntimeError:continue
    if not success:raise RuntimeError('Frozen Composer installation failed after bounded retries')
def up():
    initialize();data=STATE/'database'
    if not data.exists():checked([STATE/'mariadb/bin/mysql_install_db.exe','--datadir='+str(data)])
    (STATE/'my.cnf').write_text('[mysqld]\ndatadir='+str(data).replace('\\','/')+'\nbind-address=127.0.0.1\nport=13306\nskip-name-resolve\ncharacter-set-server=utf8mb4\n')
    start_process('mariadb',[STATE/'mariadb/bin/mariadbd.exe','--defaults-file='+str(STATE/'my.cnf'),'--console'])
    ready=False
    new=False
    for _ in range(120):
        try:sql('SELECT 1;');ready=True;break
        except RuntimeError:pass
        try:sql('SELECT 1;',password=False);ready=True;new=True;break
        except RuntimeError:time.sleep(.5)
    if not ready:raise RuntimeError('Owned MariaDB did not become ready')
    private=settings()
    if new:
        if sql("SHOW DATABASES LIKE 'anynote_p06_tests';",password=False):raise RuntimeError('Refusing existing unowned Windows database')
        sql("CREATE USER 'anynote_admin'@'127.0.0.1' IDENTIFIED BY '"+private['root_password']+"';GRANT ALL ON *.* TO 'anynote_admin'@'127.0.0.1' WITH GRANT OPTION;ALTER USER 'root'@'localhost' IDENTIFIED BY '"+private['root_password']+"';",password=False)
        sql("CREATE DATABASE anynote_p06_tests CHARACTER SET ascii COLLATE ascii_bin;CREATE TABLE anynote_p06_tests.p06_test_owner(owner CHAR(64) PRIMARY KEY) ENGINE=InnoDB;INSERT INTO anynote_p06_tests.p06_test_owner VALUES ('"+OWNER+"');CREATE USER 'anynote_dev'@'127.0.0.1' IDENTIFIED BY '"+private['database_password']+"';GRANT ALL ON anynote_p06_tests.* TO 'anynote_dev'@'127.0.0.1';")
    elif sql('SELECT owner FROM anynote_p06_tests.p06_test_owner;')!=OWNER:raise RuntimeError('Unowned Windows database marker')
    php('artisan','migrate','--no-interaction')
    checked([shutil.which('node'),'experiments/p01/p06-build.mjs'])
    router=STATE/'router.php';router.write_text('<?php if(($_SERVER["REMOTE_ADDR"]??"")!=="127.0.0.1"){http_response_code(404);exit;} $_SERVER["HTTPS"]="on";$_SERVER["SERVER_PORT"]="18443";require '+json.dumps(str(API/'public/index.php').replace('\\','/'))+';')
    start_process('php',[runtime('php'),'-c',STATE/'php.ini','-S','127.0.0.1:18080',router],env=environment(),cwd=API)
    start_process('edge',[shutil.which('node'),ROOT/'scripts/p14-tls-edge.mjs'])
    print('PASS: actual owned Windows PHP/MariaDB/TLS services started')
def control(arguments):
    require_ci();marker()
    return php('tests/Support/p06-control.php',*arguments,input=sys.stdin.buffer.read()).decode().strip()
def stop():
    require_ci();marker();path=STATE/'processes.json'
    if not path.exists():return
    for record in reversed(list(json.loads(path.read_text()).values())):
        # Verify the executable path before touching a recorded PID.
        command='$p=Get-Process -Id '+str(record['pid'])+' -ErrorAction SilentlyContinue;if($p -and $p.Path -eq '+"'"+record['executable'].replace("'","''")+"'){Stop-Process -Id $p.Id}"
        checked(['powershell','-NoProfile','-Command',command])
    path.unlink()
def trust():
    require_ci();marker()
    hosts=Path(os.environ['SystemRoot'])/'System32/drivers/etc/hosts'
    original=hosts.read_bytes()
    if b'app.anynote.test' in original or b'api.anynote.test' in original:raise RuntimeError('Refusing existing test hostname mapping')
    expected=original+b'\r\n127.0.0.1 app.anynote.test api.anynote.test # AnyNote P14 owned CI\r\n'
    (STATE/'hosts.before').write_bytes(original);(STATE/'hosts.after.sha256').write_text(hashlib.sha256(expected).hexdigest())
    hosts.write_bytes(expected)
    certificate=str(P06/'tls/ca.crt').replace("'","''")
    thumb=checked(['powershell','-NoProfile','-Command',"$c=Import-Certificate -FilePath '"+certificate+"' -CertStoreLocation Cert:\\CurrentUser\\Root; $c.Thumbprint"]).decode().strip()
    if not re.fullmatch('[A-Fa-f0-9]{40}',thumb):raise RuntimeError('Synthetic CA installation receipt missing')
    (STATE/'trust-thumbprint').write_text(thumb)
    print('PASS: synthetic test CA trusted through current-user Windows store and owned hostname mapping')
def untrust():
    require_ci();marker()
    thumb=STATE/'trust-thumbprint'
    if thumb.exists():
        value=thumb.read_text().strip()
        if not re.fullmatch('[A-Fa-f0-9]{40}',value):raise RuntimeError('Invalid owned synthetic CA receipt')
        checked(['powershell','-NoProfile','-Command',"Remove-Item -LiteralPath 'Cert:\\CurrentUser\\Root\\"+value+"' -ErrorAction SilentlyContinue"]);thumb.unlink()
    before=STATE/'hosts.before'
    if before.exists():
        hosts=Path(os.environ['SystemRoot'])/'System32/drivers/etc/hosts'
        if hashlib.sha256(hosts.read_bytes()).hexdigest()!=(STATE/'hosts.after.sha256').read_text():raise RuntimeError('Hosts changed independently; refusing to overwrite')
        hosts.write_bytes(before.read_bytes());before.unlink();(STATE/'hosts.after.sha256').unlink()
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['up','control','stop','trust','untrust']);parser.add_argument('arguments',nargs='*');a=parser.parse_args()
    if a.operation=='up':up()
    elif a.operation=='control':print(control(a.arguments))
    elif a.operation=='trust':trust()
    elif a.operation=='untrust':untrust()
    else:stop()
if __name__=='__main__':
    try:main()
    except Exception as e:print(str(e),file=sys.stderr);raise SystemExit(1)
