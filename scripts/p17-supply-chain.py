#!/usr/bin/env python3
"""Frozen dependency provenance, live OSV query and delivery-boundary review inputs."""
import base64
import importlib.util
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'artifacts/p17'
OUT.mkdir(parents=True,exist_ok=True)
git=lambda *a:subprocess.check_output(['git',*a],cwd=ROOT).decode().strip()
files=git('ls-files').splitlines()
components={}
locks=[]
def add(ecosystem,name,version,source):
    key=(ecosystem,name,version)
    components.setdefault(key,set()).add(source)
for name in files:
    p=ROOT/name
    if p.name not in ['package-lock.json','Cargo.lock','composer.lock'] or name.startswith(('docs/','fixtures/')):continue
    raw=p.read_bytes();locks.append({'path':name,'sha256':hashlib.sha256(raw).hexdigest()})
    if p.name=='package-lock.json':
        value=json.loads(raw)
        for location,row in value['packages'].items():
            if not location:continue
            assert row.get('integrity','').startswith(('sha512-','sha256-')),name+': missing npm integrity'
            assert row.get('resolved','').startswith('https://registry.npmjs.org/'),name+': unexpected npm source'
            alg,encoded=row['integrity'].split('-',1);assert len(base64.b64decode(encoded,validate=True))=={'sha512':64,'sha256':32}[alg]
            add('npm',row.get('name') or location.rsplit('node_modules/',1)[-1],row['version'],name)
    elif p.name=='Cargo.lock':
        for row in tomllib.loads(raw.decode())['package']:
            if 'source' not in row:continue
            assert row['source']=='registry+https://github.com/rust-lang/crates.io-index'
            assert re.fullmatch('[0-9a-f]{64}',row['checksum'])
            add('crates.io',row['name'],row['version'],name)
    else:
        value=json.loads(raw)
        for row in value['packages']+value['packages-dev']:
            assert row['dist']['url'].startswith('https://') and re.fullmatch('[0-9a-f]{40}',row['dist']['reference'])
            add('Packagist',row['name'],row['version'].removeprefix('v'),name)

actions=[]
for path in sorted((ROOT/'.github/workflows').glob('*.yml')):
    text=path.read_text()
    assert 'pull_request_target' not in text,'Privileged untrusted PR workflow'
    for action in re.findall(r'\buses:\s*([^\s#]+)',text):
        if action.startswith('./'):
            target=action[2:]
            assert target in files and '..' not in Path(target).parts and target.startswith('.github/workflows/')
            actions.append({'workflow':str(path.relative_to(ROOT)),'action':action,'same_commit_workflow_sha256':hashlib.sha256((ROOT/target).read_bytes()).hexdigest()})
        else:
            assert re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}',action),'Unpinned action: '+action
            actions.append({'workflow':str(path.relative_to(ROOT)),'action':action})
    # Publication-only workflow scopes and production credentials are reviewed
    # explicitly in the review record; this assertion is not a credential audit.
    assert not re.search(r'\bpermissions:\s*write-all',text)

queries=[{'package':{'ecosystem':e,'name':n},'version':v}for e,n,v in sorted(components)]
answers=[];responses=[];upstream_reports={}
for start in range(0,len(queries),500):
    request=urllib.request.Request('https://api.osv.dev/v1/querybatch',data=json.dumps({'queries':queries[start:start+500]}).encode(),
        headers={'Content-Type':'application/json','User-Agent':'AnyNote-P17-owned-lock-review'})
    with urllib.request.urlopen(request,timeout=60)as response:
        raw=response.read(16777217);assert len(raw)<=16777216
    result=json.loads(raw);assert len(result['results'])==len(queries[start:start+500])
    path=OUT/('osv-batch-'+str(start)+'.json');path.write_bytes(raw)
    ref={'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(raw).hexdigest()}
    upstream_reports['batch-'+str(start)]=ref
    answers.extend(result['results']);responses.append({'batch_start':start,**ref,'bytes':len(raw)})
findings=[]
for query,result in zip(queries,answers,strict=True):
    if result.get('vulns'):findings.append({'query':query,'advisories':result['vulns']})
# Resolve the actual supported target, including its build/test features. A
# cross-target lock listing alone cannot establish shipped reachability.
metadata_raw=subprocess.check_output(['cargo','metadata','--manifest-path','apps/desktop/src-tauri/Cargo.toml','--locked','--all-features','--filter-platform','x86_64-pc-windows-msvc','--format-version','1'],cwd=ROOT)
metadata=json.loads(metadata_raw);packages={p['id']:p for p in metadata['packages']};nodes={p['id']:p for p in metadata['resolve']['nodes']}
pending=[metadata['resolve']['root']];seen=set()
while pending:
    key=pending.pop()
    if key in seen:continue
    seen.add(key);pending.extend(d['pkg']for d in nodes[key]['deps'])
reachable=[{'name':packages[k]['name'],'version':packages[k]['version'],'features':nodes[k]['features']}for k in sorted(seen)]
assert not any(p['name']in ['glib','proc-macro-error']for p in reachable)
tls=[p for p in reachable if p['name']=='rustls'];assert len(tls)==1 and tls[0]['version']=='0.23.46' and set(tls[0]['features'])=={'ring','std','tls12'}
zip_spec=importlib.util.spec_from_file_location('zip_review',ROOT/'scripts/p17-zip-review.py');zip_module=importlib.util.module_from_spec(zip_spec);zip_spec.loader.exec_module(zip_module)
zip_review=zip_module.review(ROOT,metadata);zip_review.update({'source_commit':git('rev-parse','HEAD'),'source_tree_dirty':bool(git('status','--porcelain'))})
zip_path=OUT/'zip-boundary-review.json';zip_path.write_text(json.dumps(zip_review,indent=2)+'\n')
upstream_reports['zip-boundary-review']={'path':str(zip_path.relative_to(ROOT)),'sha256':hashlib.sha256(zip_path.read_bytes()).hexdigest()}
triage=json.loads((ROOT/'docs/security/p17-advisory-triage.json').read_text());assert triage['production_release_allowed']is False
reviewed={(e['ecosystem'],e['name'],e['version']):e for e in triage['entries']}
assert len(reviewed)==len(triage['entries']),'Duplicate advisory policy component/version'
def disposition(query,ids):
    key=(query['package']['ecosystem'],query['package']['name'],query['version']);entry=reviewed.get(key)
    return entry if entry is not None and ids and ids<=set(entry['advisories']) else None
unreviewed=[]
for finding in findings:
    q=finding['query'];key=(q['package']['ecosystem'],q['package']['name'],q['version'])
    ids={v['id']for v in finding['advisories']}
    entry=disposition(q,ids)
    if entry is None:unreviewed.append(finding);continue
    finding['disposition']=entry['disposition']
    if entry['disposition']=='FROZEN_SYNTHETIC_PROFILES_ONLY':
        assert components[key]==set(entry['affected_lockfiles'])
    elif entry['disposition']=='EXCLUDED_WINDOWS_TARGET':
        assert not any(p['name']==key[1]for p in reachable)
        if 'affected_lockfiles' in entry:assert components[key]==set(entry['affected_lockfiles'])
    elif entry['disposition'] in ['SCOPED_PE_ONLY_UPDATER','BUILD_ONLY_SIGNED_VENDOR_ARCHIVE']:
        assert components[key]==set(entry['affected_lockfiles']) and zip_review['status']=='PASS'
        assert key[0]=='crates.io' and key[1]=='zip'
        assert key[2]=={'SCOPED_PE_ONLY_UPDATER':'4.6.1','BUILD_ONLY_SIGNED_VENDOR_ARCHIVE':'8.6.0'}[entry['disposition']]
    else:raise RuntimeError('Unknown advisory disposition')
# A new advisory for any package/version is never hidden by an existing entry.
for entry in triage['entries']:
    query={'package':{'ecosystem':entry['ecosystem'],'name':entry['name']},'version':entry['version']}
    assert disposition(query,set(entry['advisories'])|{'P17-UNREVIEWED-CONTROL'})is None
    assert disposition({**query,'version':query['version']+'-unreviewed'},set(entry['advisories']))is None
for ident in sorted({v['id']for f in findings for v in f['advisories']}):
    assert re.fullmatch('[A-Za-z0-9-]+',ident)
    with urllib.request.urlopen('https://api.osv.dev/v1/vulns/'+ident,timeout=60)as response:
        raw=response.read(4194305);assert len(raw)<=4194304
    assert json.loads(raw)['id']==ident
    path=OUT/('osv-advisory-'+ident+'.json');path.write_bytes(raw)
    upstream_reports[ident]={'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(raw).hexdigest()}
report={'purpose':'P17 frozen lock provenance and live OSV advisory query; not independent audit','status':'FINDINGS' if unreviewed else 'PASS_WITH_TRACKED_FINDINGS' if findings else 'PASS',
    'source_commit':git('rev-parse','HEAD'),'source_tree_dirty':bool(git('status','--porcelain')),
    'queried_at':datetime.now(timezone.utc).isoformat(),'advisory_service':'https://api.osv.dev/v1/querybatch',
    'lockfiles':locks,'unique_component_versions':len(queries),'queries':queries,'response_digests':responses,'findings':findings,'unreviewed_findings':unreviewed,
    'supported_target':'x86_64-pc-windows-msvc','reachable_components':reachable,'fixed_windows_rustls':tls,'new_advisory_negative_controls':len(triage['entries'])*2,'reports':upstream_reports,
    'pinned_action_occurrences':actions,'independent_review':'NOT_RUN',
    'limitations':['Advisory database observations are time-scoped, not proof of safe dependencies or absence of vulnerabilities',
    'Composer dist commit references have no archive checksum in frozen lock; TLS/provider trust remains',
    'OS/browser/kernel/container base OS packages and independent release credential custody require owner-host review',
    'Multiple target/build/dev closures are included; inventory does not claim exact shipped reachability']}
(OUT/'supply-chain-report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k]for k in ['status','unique_component_versions','queried_at']})+'; '+str(len(findings))+' advisory component findings')
if unreviewed:raise SystemExit('New live advisory findings require explicit triage; see public report')
