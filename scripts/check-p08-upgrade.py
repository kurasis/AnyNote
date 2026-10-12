#!/usr/bin/env python3
"""Actual legacy-schema upgrade in the separately owner-marked synthetic P06 DB only."""
import json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def run(*args):subprocess.run(args,cwd=ROOT,check=True)
def control(op):return json.loads(subprocess.check_output(['python3','scripts/p06-stack.py','control',op],cwd=ROOT,text=True))
run('python3','scripts/p06-stack.py','reset')
run('node','packages/protocol/p07-http.mjs')
before=control('counts');assert before['users']==1 and before['devices']==1 and before['account_roster_events']==1
control('p08-legacy-fixture')
run('python3','scripts/p06-stack.py','up')
run('python3','scripts/p06-stack.py','check')
after=control('counts');assert before==after,'Owned additive upgrade must preserve all P06 rows'
assert control('p08-state')['device_transition_receipts']==0
print('PASS: actual populated P06 legacy-schema upgrade preserves every account/device/roster/session/token count')
