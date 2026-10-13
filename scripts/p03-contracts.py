#!/usr/bin/env python3
"""Deterministic P03 generator. Default is read-only; --write is development only."""
import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ['p02-file-c1', 'p02-identity-c1', 'p02-state-c1', 'p02-group-c2', 'p02-v1', 'p03-api', 'p04-api', 'p06-auth', 'p08-devices', 'p09-notes', 'p10-shared', 'p11-sync', 'p12-files']

def pascal(value):
    return ''.join(part[:1].upper() + part[1:] for part in re.split('[^A-Za-z0-9]+', value))

def outputs():
    lock_path=ROOT/'packages/api-client/package-lock.json'
    lock=json.loads(lock_path.read_text())
    inventory=json.loads((ROOT/'packages/api-client/dependency-inventory.json').read_text())
    records=[{'name':n.removeprefix('node_modules/'),'version':v['version'],'resolved':v.get('resolved'),'integrity':v.get('integrity'),'license':v.get('license'),'development_only':v.get('dev',False)} for n,v in lock['packages'].items() if n]
    assert inventory['lock_sha256']==hashlib.sha256(lock_path.read_bytes()).hexdigest() and inventory['packages']==records, 'Dependency inventory drift'
    ts_package=lock['packages']['node_modules/typescript']
    assert ts_package['integrity']==inventory['typescript_primary_metadata']['dist.integrity'], 'Pinned compiler primary artifact differs'
    documents = {name: json.loads((ROOT / f'packages/contracts/{name}.schema.json').read_text()) for name in COMPONENTS}
    ids = {doc['$id']: name for name, doc in documents.items()}
    definitions = {(name, key): value for name, doc in documents.items() for key, value in doc['$defs'].items()}
    def ref(value, current):
        uri, fragment = value.split('#', 1)
        assert fragment.startswith('/$defs/'), value
        return ids[uri] if uri else current, fragment[len('/$defs/'):]
    def typename(key):return pascal(key[0]) + pascal(key[1])
    def ts(value, current):
        if '$ref' in value:return typename(ref(value['$ref'], current))
        if 'const' in value:return json.dumps(value['const'])
        if 'enum' in value:return ' | '.join(json.dumps(v) for v in value['enum'])
        for union in ('oneOf', 'anyOf'):
            if union in value:return ' | '.join('('+ts(v,current)+')' for v in value[union])
        kind=value.get('type')
        if isinstance(kind,list):return ' | '.join(ts({'type':t},current) for t in kind)
        if kind=='object':
            assert value.get('additionalProperties') is False
            required=value.get('required',[])
            return '{ '+ '; '.join('readonly '+json.dumps(k)+('' if k in required else '?')+': '+ts(v,current) for k,v in value.get('properties',{}).items())+' }'
        if kind=='array':return 'ReadonlyArray<'+ts(value['items'],current)+'>'
        if kind in ('integer','number'):return 'number'
        if kind in ('string','boolean','null'):return kind
        raise ValueError('Unsupported schema structure: '+str(value))
    def php_type(value,current):
        if '$ref' in value:
            n,k=ref(value['$ref'],current);return php_type(definitions[(n,k)],n)
        if 'const' in value:
            v=value['const'];return 'bool' if isinstance(v,bool) else 'int' if isinstance(v,int) else 'string'
        if 'enum' in value:return '|'.join(sorted(set('null' if v is None else 'string' if isinstance(v,str) else 'int' for v in value['enum'])))
        for union in ('oneOf','anyOf'):
            if union in value:return '|'.join(sorted(set(php_type(v,current) for v in value[union])))
        kind=value.get('type')
        if isinstance(kind,list):return '|'.join(php_type({'type':k},current) for k in kind)
        return {'string':'string','integer':'int','number':'float|int','boolean':'bool','null':'null','array':'array','object':'array'}[kind]
    # Runtime schema references keep original IDs; OpenAPI embeds resolvable references.
    def openapi_schema(value,current):
        if isinstance(value,list):return [openapi_schema(v,current) for v in value]
        if not isinstance(value,dict):return value
        return {k:('#/components/schemas/'+typename(ref(v,current)) if k=='$ref' else openapi_schema(v,current)) for k,v in value.items()}
    schema_components={typename(k):openapi_schema(v,k[0]) for k,v in definitions.items()}
    errors=json.loads((ROOT/'packages/contracts/p02-errors.json').read_text())
    operations=json.loads((ROOT/'packages/contracts/p03-operations.json').read_text())['operations']
    paths={}
    for op in operations:
        params=[{'name':n,'in':'path','required':True,'schema':(openapi_schema(documents['p02-file-c1']['$defs']['part']['properties']['index'],'p02-file-c1') if n == 'index' and ('/parts/' in op['path'] or '/chunks/' in op['path']) else {'$ref':'#/components/schemas/P02FileC1Counter'} if n == 'index' else {'$ref':'#/components/schemas/P02FileC1Id'})} for n in re.findall(r'\{([^}]+)\}',op['path'])]
        method={'operationId':op['operation_id'],'summary':op['summary'],'x-implementation-phase':op['phase'],'x-implemented':op['implemented'],'description':op['authorization'],'parameters':params,'security':([{n:[]} for n in op['security']] if 'security' in op else [] if op['implemented'] else [{'CookieSession':[]},{'NativeBearer':[]}]), 'responses':{'default':{'description':'Fixed typed error; unavailable resources are concealed as NOT_FOUND','content':{'application/json':{'schema':{'$ref':'#/components/schemas/P02V1ErrorResponse'}}}}}}
        if 'response' in op:method['responses']['200']={'description':'Strict phase-owned response','content':{'application/json':{'schema':{'$ref':'#/components/schemas/'+typename(op['response'].split('/') if '/' in op['response'] else ['p03-api',op['response']])}}}}
        if op.get('binary_response'):method['responses']['200']={'description':'Authorized immutable ciphertext chunk; clients authenticate the full AEAD frame','content':{'application/octet-stream':{'schema':{'type':'string','format':'binary','x-maximum-observed-bytes':8388624}}}}
        if 'request' in op:
            key=op['request'].split('/') if '/' in op['request'] else ['p03-api',op['request']]
            method['requestBody']={'required':True,'content':{'application/json':{'schema':{'$ref':'#/components/schemas/'+typename(key)}}}}
        elif op['method'] in ('POST','PUT'):
            method['x-request-dto-state']='Transport wrapper is finalized by '+op['phase']+' before endpoint implementation; no generic body is accepted'
        if '/parts/' in op['path'] and op['method']=='PUT':
            method['requestBody']={'required':True,'content':{'application/octet-stream':{'schema':{'type':'string','format':'binary','x-maximum-observed-bytes':8388624}}}}
            method.pop('x-request-dto-state',None)
        paths.setdefault(op['path'],{})[op['method'].lower()]=method
    spec={'x-backend-service-contracts':{'object_commit':{'request':'#/components/schemas/P04ApiObjectCommit','response':'#/components/schemas/P04ApiCommitResult','http_phase':'P09'},'quota_reservation':{'request':'#/components/schemas/P04ApiQuotaRequest','response':'#/components/schemas/P04ApiQuotaResult','http_phase':'P12'},'account_invitation':{'request':'#/components/schemas/P04ApiInviteRequest','response':'#/components/schemas/P04ApiInviteResult','http_phase':'P06'}},'openapi':'3.1.0','jsonSchemaDialect':'https://json-schema.org/draft/2020-12/schema','info':{'title':'AnyNote initial API contract','version':'1.0.0','description':'P03 foundation. Product paths are declarations with explicit future phase ownership, not executable dummy auth/crypto. Semantic authorization and byte predicates remain authoritative P02 requirements.'},'servers':[{'url':'/'}],'paths':paths,'components':{'schemas':schema_components,'securitySchemes':{'CookieSession':{'type':'apiKey','in':'cookie','name':'__Host-vault_session','description':'P06 host-only session + synchronizer CSRF + active device proof'},'NativeBearer':{'type':'http','scheme':'bearer','description':'P06 fixed-issuer native session'}}},'x-protocol-components':COMPONENTS[:5],'x-errors':errors['errors']}
    tsout='// Generated by scripts/p03-contracts.py; do not edit. Runtime validation remains mandatory.\n'
    tsout+='\n'.join('export type '+typename(k)+' = '+ts(v,k[0])+';' for k,v in definitions.items())+'\n'
    tsout+='export interface Operations {\n'
    for op in operations:
        request=typename(op['request'].split('/') if '/' in op['request'] else ['p03-api',op['request']]) if 'request' in op else 'never'
        response=typename(op['response'].split('/') if '/' in op['response'] else ['p03-api',op['response']]) if 'response' in op else 'never'
        tsout+=json.dumps(op['operation_id'])+': { readonly phase: '+json.dumps(op['phase'])+'; readonly implemented: '+json.dumps(op['implemented'])+'; readonly request: '+request+'; readonly response: '+response+' };\n'
    tsout+='}\n'
    php='<?php\n\n// Generated by scripts/p03-contracts.py. Shapes are transport types, not authorization.\nnamespace App\\Generated;\n\n'
    for key,value in definitions.items():
        if value.get('type')!='object':continue
        props=value.get('properties',{});required=value.get('required',[])
        ordered=sorted(props,key=lambda p:p not in required)
        php+='final readonly class '+typename(key)+' implements \\JsonSerializable\n{\n    public function __construct(\n'
        for p in ordered:
            t=php_type(props[p],key[0]);optional=p not in required
            if optional and 'null' not in t.split('|'):t+='|null'
            php+='        public '+t+' $'+p+(' = null' if optional else '')+',\n'
        php+='    ) {}\n\n    public function jsonSerialize(): array\n    {\n        $values = get_object_vars($this);\n'
        for p in ordered:
            if p not in required:php+='        if ($values['+repr(p)+'] === null) { unset($values['+repr(p)+']); }\n'
        php+='        return $values;\n    }\n}\n\n'
    # JSON is a versioned generated data asset; PHP loads bounded trusted source, not network DTOs.
    catalogue={'components':COMPONENTS[:5],'errors':errors,'operations':operations}
    def dumped(v):return json.dumps(v,indent=2,ensure_ascii=False)+'\n'
    products={'packages/contracts/generated/openapi.json':dumped(spec),'packages/contracts/generated/protocol.d.ts':tsout,'packages/contracts/generated/runtime-schemas.json':dumped(list(documents.values())),'apps/api/app/Generated/Dtos.php':php.rstrip()+'\n','apps/api/app/Generated/catalogue.json':dumped(catalogue),'apps/api/app/Generated/schemas.json':dumped(list(documents.values()))}
    inputs=['scripts/p03-contracts.py','scripts/p04_compatibility.py','packages/contracts/p04-compatibility.json','docs/reference/p02/composer-p02.lock','apps/api/app/Crypto/PublicProtocol.php','apps/api/app/Backend/ObjectService.php','apps/api/app/Backend/Authorization.php','apps/api/app/Backend/ReservationService.php','packages/protocol/adapters/public-signatures.mjs','packages/crypto-native/Cargo.toml','packages/crypto-native/Cargo.lock','packages/crypto-native/dependency-inventory.json','apps/api/composer.lock','apps/api/dependency-inventory.json','packages/api-client/package.json','packages/api-client/client.mjs','packages/api-client/package-lock.json','packages/api-client/dependency-inventory.json','packages/contracts/p03-operations.json','packages/contracts/p02-errors.json','packages/contracts/p02-v1.registry.json', 'docs/P02_COMPLETE_CONTRACT.md', 'packages/protocol/src/protocol-codec.mjs', 'packages/protocol/src/codec.mjs', 'packages/protocol/src/identity-codec.mjs', 'packages/protocol/src/state-codec.mjs', 'packages/protocol/src/group-codec.mjs', 'packages/protocol/src/strict-json.mjs']+[f'packages/contracts/{c}.schema.json' for c in COMPONENTS]
    inputs += ['apps/api/bootstrap/app.php','apps/api/routes/web.php','apps/api/routes/console.php','apps/api/app/Http/Controllers/CapabilitiesController.php','scripts/p06_compatibility.py','scripts/check-p06.py','packages/contracts/p06-compatibility.json','docs/reference/p04/composer-p04.lock','apps/api/app/Http/Controllers/AuthController.php','apps/api/app/Http/Middleware/AuthSession.php','apps/api/app/Http/Middleware/SessionCsrf.php','apps/api/config/passkeys.php','apps/api/config/session.php','apps/api/config/auth.php','apps/api/database/migrations/2026_10_11_000004_create_authentication_lifecycle.php','packages/auth-native/Cargo.toml','packages/auth-native/Cargo.lock','packages/auth-native/dependency-inventory.json','packages/protocol/auth-client.mjs','packages/protocol/auth-formats.mjs'] + sorted(p.relative_to(ROOT).as_posix() for p in (ROOT/'apps/api/app/Auth').rglob('*.php'))
    inputs += sorted(p.relative_to(ROOT).as_posix() for p in (ROOT/'apps/api/app/Devices').rglob('*.php')) + ['apps/api/app/Http/Controllers/DevicesController.php','apps/api/database/migrations/2026_10_12_000005_create_trusted_device_lifecycle.php','packages/protocol/devices/client.mjs']
    inputs += sorted(p.relative_to(ROOT).as_posix() for p in (ROOT/'apps/api/app/Groups').rglob('*.php')) + ['apps/api/app/Http/Controllers/GroupsController.php', 'apps/api/database/migrations/2026_10_13_000008_create_shared_group_journal.php', 'scripts/p10-port-group.py', 'packages/protocol/shared/custody-methods.inc.mjs', 'packages/protocol/shared/client.mjs']
    inputs += sorted(p.relative_to(ROOT).as_posix() for p in (ROOT/'apps/api/app/Sync').rglob('*.php')) + ['apps/api/app/Http/Controllers/SyncController.php','apps/api/database/migrations/2026_10_13_000009_create_sync_snapshots.php', 'packages/protocol/sync/codec.mjs', 'packages/protocol/sync/paged-local.mjs', 'packages/protocol/sync/client.mjs']
    manifest={'version':1,'scope':'P03_P04_P06_P08_GENERATION_NOT_RUNTIME_AUTHORITY','inputs':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in inputs],'outputs':[{'path':p,'sha256':hashlib.sha256(v.encode()).hexdigest()} for p,v in products.items()],'structures':len(definitions),'operations':len(operations)}
    products['packages/contracts/generated/manifest.json']=dumped(manifest)
    return products,manifest

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    products,manifest=outputs()
    for path,content in products.items():
        file=ROOT/path
        if args.write:file.parent.mkdir(parents=True,exist_ok=True);file.write_text(content)
        elif not file.is_file() or file.read_bytes()!=content.encode():raise RuntimeError('Generated contract drift: '+path)
    print(json.dumps({'status':'PASS','structures':manifest['structures'],'operations':manifest['operations'],'mode':'write' if args.write else 'read-only'}))
if __name__=='__main__':main()
