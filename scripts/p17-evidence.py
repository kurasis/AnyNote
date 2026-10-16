#!/usr/bin/env python3
"""Final clean-source P17 receipt; qualified review remains unbooked/NOT_RUN."""
import hashlib
import json
from pathlib import Path
import subprocess
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'artifacts/p17'
git=lambda *a:subprocess.check_output(['git',*a],cwd=ROOT).decode().strip()
head=git('rev-parse','HEAD');assert not git('status','--porcelain'),'Final receipt refuses dirty source'
reports={}
for role in ['fuzz','portable','http','supply-chain','traceability','remediation']:
    path=OUT/(role+'-report.json');value=json.loads(path.read_text())
    assert value['source_commit']==head and value['source_tree_dirty']is False,role
    assert value['status']in (['PASS','PASS_WITH_TRACKED_FINDINGS']if role=='supply-chain'else ['PASS']),role
    reports[role]={'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    if role=='fuzz':
        assert sum(x['cases']for x in value['families'].values())==6728
        assert value['authenticated_envelope_rejections']==value['archive_header_rejections']==512 and value['kdf_preallocation_rejections']==5
    elif role=='portable':assert value['counts']['tests']==value['counts']['pass']>=69 and value['exit_code']==0
    elif role=='http':
        assert value['accounts']==3 and value['concurrent_publications']==24 and value['max_inflight']==8
        assert value['discarded_response_retries']==8 and value['exactly_once_operations']==25
        assert value['actual_file_bytes']==1048577 and value['full_file_hash_verified']
        assert value['disabled_push_outbound_requests']==0 and value['inspection']['positive_canary_detected']
        assert value['inspection']['operation_revision_counts']==[1]*25
    elif role=='supply-chain':assert not value['unreviewed_findings'] and value['fixed_windows_rustls'][0]['version']=='0.23.46'
    elif role=='traceability':assert value['regressions']==24
    elif role=='remediation':
        assert value['before']=={'consumed_chunk_collectible_before_eof':False,'reader_locked_after_failure':True}
        assert value['after']=={'consumed_chunk_collectible_before_eof':True,'reader_locked_after_failure':False}
paths=[p for p in git('ls-files').splitlines()if not p.startswith(('docs/evidence/','artifacts/'))]
receipt={'purpose':'P17 exact-source executed adversarial acceptance; synthetic scope only','status':'PASS','source_commit':head,'source_tree':git('rev-parse','HEAD^{tree}'),'source_tree_dirty':False,'timestamp':datetime.now(timezone.utc).isoformat(),'reports':reports,'inputs':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()}for p in paths],'independent_review':'NOT_RUN','review_booking':'TRACKED_NOT_BOOKED','production_release_allowed':False,'physical_acceptance':False}
(OUT/'source-report.json').write_text(json.dumps(receipt,indent=2)+'\n')
print('PASS: six executed P17 reports and complete clean Git input binding; independent review NOT_RUN; synthetic evaluation only')
