#!/usr/bin/env python3
"""Execute maintained client security suites; retain actual counts, exit and test names."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'artifacts/p17';OUT.mkdir(parents=True,exist_ok=True)
tests=['security/test-transport','vault/test-engine','devices/test-workflow','notes/test-notes','shared/test-shared','sync/test-sync','files/test-files','files/test-sink','content/test-content','content/test-portable','content/test-offline','content/test-import','content/test-archive-ui']
command=['node','--expose-gc','--test','--test-reporter=tap','--test-concurrency=1']+['packages/protocol/'+p+'.mjs'for p in tests]
started=time.monotonic();result=subprocess.run(command,cwd=ROOT,text=True,capture_output=True)
counts={key:int(re.search(r'^# '+key+r' (\d+)$',result.stdout,re.M)[1])for key in ['tests','pass','fail','cancelled','skipped','todo']}
names=re.findall(r'^# Subtest: (.+)$',result.stdout,re.M)
git=lambda *a:subprocess.check_output(['git',*a],cwd=ROOT).decode().strip()
report={'purpose':'P17 actual maintained client adversarial suite execution','status':'PASS'if result.returncode==0 and counts['tests']==counts['pass'] and counts['tests']>=69 and not any(counts[k]for k in ['fail','cancelled','skipped','todo'])else 'FAIL','source_commit':git('rev-parse','HEAD'),'source_tree_dirty':bool(git('status','--porcelain')),'command':command,'exit_code':result.returncode,'counts':counts,'test_names':names,'stdout_sha256':hashlib.sha256(result.stdout.encode()).hexdigest(),'stderr_sha256':hashlib.sha256(result.stderr.encode()).hexdigest(),'elapsed_seconds':time.monotonic()-started,'store_model':'Owned in-memory transactional fixture with genuine maintained crypto; actual SQL/OPFS/SQLite are separate inherited hosted gates','independent_review':'NOT_RUN','physical_acceptance':False}
(OUT/'portable-report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k]for k in ['status','counts','elapsed_seconds']}),flush=True)
if report['status']!='PASS':
    print(result.stdout);print(result.stderr);raise SystemExit(result.returncode or 1)
