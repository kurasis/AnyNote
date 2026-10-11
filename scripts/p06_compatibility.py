"""One exact P06 Composer extension, retaining the entire P04 baseline."""
import hashlib,json
from pathlib import Path
ADDED = {'defuse/php-encryption': 'v2.4.0', 'doctrine/deprecations': '1.1.6', 'lcobucci/jwt': '5.6.1', 'league/event': '3.0.3', 'league/oauth2-server': '9.4.1', 'paragonie/constant_time_encoding': 'v3.1.3', 'paragonie/random_compat': 'v9.99.100', 'phpdocumentor/reflection-common': '2.2.1', 'phpdocumentor/reflection-docblock': '6.0.3', 'phpdocumentor/type-resolver': '2.1.0', 'phpstan/phpdoc-parser': '2.3.6', 'psr/http-server-handler': '1.0.2', 'psr/http-server-middleware': '1.0.2', 'spomky-labs/cbor-php': '3.4.2', 'spomky-labs/pki-framework': '1.6.3', 'symfony/polyfill-php81': 'v1.38.1', 'symfony/property-access': 'v8.1.4', 'symfony/property-info': 'v8.1.8', 'symfony/serializer': 'v8.1.8', 'symfony/type-info': 'v8.1.8', 'web-auth/cose-lib': '4.8.2', 'web-auth/webauthn-lib': '5.3.9', 'webmozart/assert': '2.5.0'}
def verify(root: Path):
 r=json.loads((root/'packages/contracts/p06-compatibility.json').read_text())
 assert r['version']==1 and r['phase']=='P06' and r['path']=='apps/api/composer.lock' and r['baseline_path']=='docs/reference/p04/composer-p04.lock'
 old=root/r['baseline_path'];new=root/r['path']
 assert hashlib.sha256(old.read_bytes()).hexdigest()==r['baseline_sha256']=='679c6b23a2ac0ee8b1c9a888a76562649b32c829340ca606cf8bf5f8a69bb568'
 assert hashlib.sha256(new.read_bytes()).hexdigest()==r['current_sha256']
 pk=lambda x:{p['name']:p for k in ['packages','packages-dev'] for p in x[k]}
 a=pk(json.loads(old.read_text()));b=pk(json.loads(new.read_text()))
 assert len(a)==103 and len(b)==126 and all(b.get(n)==p for n,p in a.items()),'Existing package drift'
 assert {n:b[n]['version'] for n in b.keys()-a.keys()}==ADDED==r['added_packages'],'Unreviewed P06 addition'
 return old
