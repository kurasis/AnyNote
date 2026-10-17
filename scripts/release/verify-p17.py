#!/usr/bin/env python3
"""Exact P17 plus inherited P15/P16 acceptance after raw ZIP/Git audit."""
import hashlib,json,subprocess,sys,zipfile
from pathlib import Path
setup=Path(__file__).resolve().parent;root=Path(__file__).resolve().parents[2];folder=Path(sys.argv[1]);output=Path(sys.argv[2]);a=json.loads((folder/'audit-receipt.json').read_text())
assert a['status']=='VERIFIED' and a['cohort_status_when_downloaded']=='PASS'
assert len(a['artifacts'])==28 and len({r['name']for r in a['artifacts']})==28
head=a['candidate_head'];tree=a['candidate_tree']
def raw(artifact,suffix):
 rows=[r for r in a['reports']if r['artifact_name']==artifact and r['member'].endswith(suffix)];assert len(rows)==1,(artifact,suffix)
 row=rows[0]
 with zipfile.ZipFile(folder/(str(row['artifact_id'])+'.zip'))as z:b=z.read(row['member'])
 assert hashlib.sha256(b).hexdigest()==row['sha256'];return json.loads(b)
p16=output.with_name(output.stem+'-p16.json');subprocess.run(['python3',str(setup/'verify-p16.py'),str(folder),str(p16)],cwd=root,check=True,capture_output=True)
art={r['name']:r for r in a['artifacts']};pwa=art['p15-linux-pwa-report'];web=art['p15-webkit-shell-report'];p15=output.with_name(output.stem+'-p15.json')
subprocess.run(['python3',str(setup/'verify-p15.py'),head,str(folder/(str(pwa['id'])+'.json')),str(folder/(str(pwa['id'])+'.zip')),str(folder/(str(web['id'])+'.json')),str(folder/(str(web['id'])+'.zip')),str(p15)],cwd=root,check=True,capture_output=True)
roles=['fuzz','portable','http','supply-chain','traceability','remediation','source'];reports={role:raw('p17-security-report',role+'-report.json')for role in roles}
for role,r in reports.items():
 assert r['source_commit']==head and r['source_tree_dirty']is False
 assert r['status']in (['PASS','PASS_WITH_TRACKED_FINDINGS']if role=='supply-chain'else ['PASS'])
f=reports['fuzz'];assert f['seed']=='AnyNote/P17/bounded-mutation/v1' and f['corpus_sha256']=='48d9e6b09197f264ba72b4404074ec48fd3f8df6eb284f1f45dbaacd20a465de'
assert {k:v['cases']for k,v in f['families'].items()}=={'file':1280,'identity':768,'state':512,'group':256,'object':1536,'raw_control':2376}
assert f['authenticated_envelope_rejections']==f['archive_header_rejections']==512 and f['kdf_preallocation_rejections']==5 and f['archive_positive_visits']==1
p=reports['portable'];counts=p['counts'];assert p['exit_code']==0 and counts['tests']==counts['pass']>=69 and all(counts[k]==0 for k in ['fail','cancelled','skipped','todo'])
for title in ['consumed response chunks can be collected before end of body','nonprogressing response is cancelled and response errors release reader lock','noncanonical base64 padding is a typed schema denial in the portable verifier']:assert title in p['test_names']
h=reports['http'];assert h['accounts']==3 and h['concurrent_publications']==24 and h['max_inflight']==8 and h['discarded_response_retries']==8 and h['exactly_once_operations']==25
assert h['actual_file_bytes']==1048577 and h['full_file_hash_verified'] and h['disabled_push_outbound_requests']==0
assert h['inspection']['status']=='PASS' and h['inspection']['positive_canary_detected'] and h['inspection']['canaries']>=11 and h['inspection']['operation_revision_counts']==[1]*25
s=reports['supply-chain'];assert s['unique_component_versions']==1075 and not s['unreviewed_findings'] and s['supported_target']=='x86_64-pc-windows-msvc'
triage=json.loads(subprocess.check_output(['git','show',head+':docs/security/p17-advisory-triage.json'],cwd=root))
assert triage['production_release_allowed']is False and s['new_advisory_negative_controls']==2*len(triage['entries'])
assert s['fixed_windows_rustls']==[{'name':'rustls','version':'0.23.46','features':['ring','std','tls12']}]
assert {x['disposition']for x in s['findings']}<={'EXCLUDED_WINDOWS_TARGET','FROZEN_SYNTHETIC_PROFILES_ONLY','SCOPED_PE_ONLY_UPDATER','BUILD_ONLY_SIGNED_VENDOR_ARCHIVE'}
if any(f['query']['package']['name']=='zip'for f in s['findings']):
 assert s['new_advisory_negative_controls']>=10
 z=raw('p17-security-report','zip-boundary-review.json');assert z['status']=='PASS' and z['source_commit']==head and z['source_tree_dirty']is False and z['production_release_allowed']is False
 assert {f['query']['version']for f in s['findings']if f['query']['package']['name']=='zip'}=={'4.6.1','8.6.0'}
 vendor=raw('p14-windows-development-installer','signed-vendor-zip-development.json');assert vendor['status']=='PASS' and vendor['source_commit']==head and vendor['source_tree_dirty']is False and vendor['platform']=='win32'
 assert vendor['cases'][0]['exit_code']==0 and vendor['cases'][0]['installed_files']>0 and vendor['cases'][1]['exit_code']!=0 and vendor['cases'][1]['installed_files']==0
 assert vendor['upstream_build_source_sha256']==next(p['member_sha256']for p in z['registry_source_proofs']if p['package']=='libsodium-sys-stable'and p['version']=='1.24.3')
 host=raw('p14-windows-development-installer','windows-webview-development.json');assert host['updater']['unsupported_signed_zip_rejected']is True
t=reports['traceability'];assert t['regressions']==24 and {x['regression']for x in t['bindings']}=={f'R{n:02}'for n in range(1,25)}
r=reports['remediation'];assert r['before']=={'consumed_chunk_collectible_before_eof':False,'reader_locked_after_failure':True} and r['after']=={'consumed_chunk_collectible_before_eof':True,'reader_locked_after_failure':False}
src=reports['source'];assert src['source_tree']==tree and src['independent_review']=='NOT_RUN' and src['production_release_allowed']is False and src['review_booking']=='TRACKED_NOT_BOOKED'
b=raw('p03-foundation-report','backend-report.json');observations=b['sql']['counter_observations'];assert len(observations)==2 and {x['a_outcome']for x in observations}=={'commit','rollback'}
for row in observations:
 before=int(row['before_sequence']);assert int(row['a_uncommitted_sequence'])==before+1 and int(row['observer_while_b_blocked'])==before and int(row['b_committed_sequence'])==int(row['after_sequence'])==before+(2 if row['a_outcome']=='commit'else 1)
result={'purpose':'P17 exact raw acceptance plus inherited full1GB/PWA/update/WebKit/operations/capacity semantics','status':'PASS','aggregate_acceptance':True,'source_commit':head,'source_tree':tree,'ordinary_cohort_status_when_verified':'PASS','mandatory_jobs':30,'artifact_zip_digests_verified':len(a['artifacts']),'raw_reports_verified':len(a['reports']),'git_input_rows_verified':a['git_input_rows_verified'],'p17_client_tests':counts['tests'],'mutation_cases':6728,'authenticated_envelope_rejections':512,'archive_header_rejections':512,'kdf_preallocation_rejections':5,'accounts':3,'concurrent_publications':24,'exactly_once_operations':25,'typed_transient_retries':h['typed_transient_retries'],'inspection':h['inspection'],'http_latency_ms':h['http_latency_ms'],'dependency_component_versions':1075,'advisory_component_findings':len(s['findings']),'qualified_independent_review':'NOT_RUN','review_booking':'TRACKED_NOT_BOOKED','production_release_allowed':False,'physical_acceptance':False,'physical_100gb_fixture':'NOT_RUN','inherited_p15_proof_sha256':hashlib.sha256(p15.read_bytes()).hexdigest(),'inherited_p16_proof_sha256':hashlib.sha256(p16.read_bytes()).hexdigest()}
output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
