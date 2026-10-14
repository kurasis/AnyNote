#!/usr/bin/env python3
"""Generate public signature fixtures with the maintained Tauri CLI; discard synthetic private keys."""
import base64,hashlib,json,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'fixtures/windows/p14/updates';OUT.mkdir(parents=True,exist_ok=True)
CLI=ROOT/'apps/desktop/node_modules/.bin/tauri'
def command(*args):
    result=subprocess.run([str(CLI),*map(str,args)],cwd=ROOT/'apps/desktop',capture_output=True)
    if result.returncode:raise RuntimeError('Synthetic Tauri signer failed; private output withheld')
with tempfile.TemporaryDirectory(prefix='anynote-public-updater-fixture-') as path:
    work=Path(path);key=work/'synthetic.key';command('signer','generate','--ci','-p','','-w',key)
    artifact=work/'synthetic-artifact.bin';artifact.write_bytes(b'P14 PUBLIC SYNTHETIC UPDATER SIGNATURE FIXTURE\n')
    digest=base64.urlsafe_b64encode(hashlib.sha256(artifact.read_bytes()).digest()).decode().rstrip('=')
    claims={'protocol':'anynote-update-v1','application_id':'org.anynote.desktop','version':'0.14.1','platform':'windows-x86_64','channel':'candidate','url':'https://updates.synthetic.example/AnyNote-0.14.1.exe','artifact_sha256':digest}
    document=work/'claims.json';document.write_text(json.dumps(claims,sort_keys=True,separators=(',',':')))
    for target in [artifact,document]:command('signer','sign','--private-key-path',key,'--password','','--app-version','0.14.1',target)
    value={'purpose':'Public synthetic signature-verification corpus; artifact is not executable, installer, production key or acceptance report','policy':{'endpoint':'https://updates.synthetic.example/candidate.json','public_key':Path(str(key)+'.pub').read_text().strip(),'channel':'candidate'},'claims':claims,'claims_signature':Path(str(document)+'.sig').read_text().strip(),'artifact_base64':base64.b64encode(artifact.read_bytes()).decode(),'artifact_signature':Path(str(artifact)+'.sig').read_text().strip()}
    (OUT/'signatures.json').write_text(json.dumps(value,indent=2)+'\n')
print('PASS: public standard minisign fixtures generated; synthetic private key removed')
