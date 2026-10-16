#!/usr/bin/env python3
"""Audit exact public raw reports without relabelling inherited merge commits."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

root=Path(__file__).resolve().parents[2]
directory=Path(sys.argv[1]);download=json.loads((directory/'download-receipt.json').read_text())
head=download['source_commit']
def git(*args):return subprocess.check_output(['git',*args],cwd=root)
tree=git('rev-parse',head+'^{tree}').decode().strip()
tracked=set(git('ls-tree','-r','-z','--name-only',head).decode().split('\0'))-{''}
full=tracked-{p for p in tracked if p.startswith(('docs/evidence/','artifacts/'))}
blob_hashes={};sources={};reports=[];total=0
def member(z,path):
    found=[n for n in z.namelist() if n==path or path.endswith('/'+n) or n.endswith('/'+path)]
    assert len(found)==1,'Missing/ambiguous declared report member: '+path
    return z.read(found[0])

for a in download['artifacts']:
    path=directory/(str(a['id'])+'.zip')
    assert hashlib.file_digest(path.open('rb'),'sha256').hexdigest()==a['zip_sha256']
    z=zipfile.ZipFile(path)
    for name in z.namelist():
        if not name.endswith('.json') or 'fixtures/' in name:continue
        raw=z.read(name)
        value=json.loads(raw)
        if not isinstance(value,dict):continue
        source=value.get('source_commit')
        if source is not None:
            assert re.fullmatch('[0-9a-f]{40}',source)
            actual_tree=git('rev-parse',source+'^{tree}').decode().strip()
            assert actual_tree==tree,'Report source tree differs from candidate: '+name
            if 'source_tree' in value:assert value['source_tree']==actual_tree
            sources[source]=actual_tree
        if 'source_tree_dirty' in value:assert value['source_tree_dirty'] is False,name
        count=0
        for key in ['inputs','fixture_inputs','source_inputs','foundation_input_sha256']:
            values=value.get(key)
            if not values:continue
            assert source,'Input hash list without an actual report source commit: '+name
            rows=[{'path':k,'sha256':v} for k,v in values.items()] if isinstance(values,dict) else values
            assert isinstance(rows,list) and len({r['path'] for r in rows})==len(rows)
            if key=='inputs' and value.get('purpose','').startswith(('P13 exact-source','P14 exact-source','P15 exact-source','P15 actual hosted WebKit','P16 exact-source','P17 exact-source')):
                assert {r['path'] for r in rows}==full,'Incomplete full source array: '+name
            for row in rows:
                p=row['path'];assert p in tracked,'Input is not an actual tracked Git blob: '+p
                cache=(source,p)
                if cache not in blob_hashes:blob_hashes[cache]=hashlib.sha256(git('show',source+':'+p)).hexdigest()
                assert blob_hashes[cache]==row['sha256'],'Input digest mismatch: '+p
                count+=1
        for ref in value.get('reports',{}).values():
            assert hashlib.sha256(member(z,ref['path'])).hexdigest()==ref['sha256'],'Declared raw report digest mismatch'
        if isinstance(value.get('installer'),dict):
            ref=value['installer'];assert hashlib.sha256(member(z,ref['path'])).hexdigest()==ref['sha256'],'Installer digest mismatch'
        total+=count
        reports.append({'artifact_id':a['id'],'artifact_name':a['name'],'member':name,
            'sha256':hashlib.sha256(raw).hexdigest(),'source_commit':source,
            'status_as_reported':value.get('status'),'git_input_rows_verified':count})

receipt={'purpose':'Public raw report hashes, actual declared Git blobs and source-tree qualification; not aggregate test acceptance',
 'status':'VERIFIED','candidate_head':head,'candidate_tree':tree,
 'cohort_status_when_downloaded':download['cohort_status_when_downloaded'],
 'actual_report_source_trees':sources,'git_input_rows_verified':total,
 'unique_git_blobs_verified':len(blob_hashes),'reports':reports,'artifacts':download['artifacts'],
 'physical_acceptance':False,'independent_review':'NOT_RUN'}
(directory/'audit-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print('VERIFIED:',len(reports),'raw reports,',total,'Git input rows,',len(sources),'actual source commits with the same tracked tree; cohort',download['cohort_status_when_downloaded'])
